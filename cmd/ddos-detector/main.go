package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ddos-detector/internal/aggregator"
	"ddos-detector/internal/collector"
	"ddos-detector/internal/config"
	"ddos-detector/internal/dashboard"
	"ddos-detector/internal/detector"
	"ddos-detector/internal/loadgen"
	"ddos-detector/internal/ml"
	"ddos-detector/internal/runtime"
)

func main() {
	cfgPath := flag.String("config", "./configs/config.example.json", "Path to config JSON")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Println("Config error:", err)
		os.Exit(1)
	}

	whitelist, err := config.LoadWhitelist(cfg.WhitelistPath)
	if err != nil {
		fmt.Println("Whitelist warning:", err)
		whitelist = config.EmptyWhitelist()
	}

	var model *ml.LogisticModel
	if cfg.ModelPath != "" {
		m, err := ml.Load(cfg.ModelPath)
		if err != nil {
			fmt.Println("Model load failed (fallback to heuristic):", err)
		} else {
			model = m
		}
	}

	params := runtime.NewParams(cfg.Threshold, cfg.ConfirmWindows, cfg.RelaxWindows, cfg.WindowMs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Если backend_url == "builtin" или не задан — поднимаем встроенный echo-сервер.
	if cfg.BackendURL == "" || cfg.BackendURL == "builtin" {
		addr, err := startBuiltinBackend(ctx)
		if err != nil {
			fmt.Println("Builtin backend error:", err)
			os.Exit(1)
		}
		cfg.BackendURL = "http://" + addr
		fmt.Println("Builtin echo backend started on", cfg.BackendURL)
	}

	pktCh := make(chan collector.PacketEvent, 50000)
	winCh := make(chan aggregator.WindowStats, 100)

	go func() {
		opt := collector.Options{
			ListenAddr: cfg.ListenAddr,
			BackendURL: cfg.BackendURL,
			Interface:  cfg.Interface,
			BPF:        cfg.BPF,
			Promisc:    true,
		}
		if err := collector.Run(ctx, opt, pktCh); err != nil {
			fmt.Println("Collector error:", err)
			cancel()
		}
	}()

	agg := aggregator.New(whitelist)
	window := time.Duration(cfg.WindowMs) * time.Millisecond
	go func() {
		if err := agg.Run(ctx, pktCh, window, winCh); err != nil {
			fmt.Println("Aggregator error:", err)
			cancel()
		}
	}()

	det := detector.New(model, params)
	det.WebhookURL = cfg.AlertWebhookURL
	det.EnableMitigation = cfg.EnableMitigation
	det.MitigationScript = cfg.MitigationScript

	store := dashboard.NewStore(300)
	det.Store = store

	lg := loadgen.New(cfg.ListenAddr)

	auth := dashboard.AdminAuth{
		User: os.Getenv("ADMIN_USER"),
		Pass: os.Getenv("ADMIN_PASS"),
	}

	go func() {
		err := dashboard.Start(ctx, cfg.DashboardAddr, dashboard.Deps{
			Store:     store,
			Params:    params,
			Whitelist: whitelist,
			LoadGen:   lg,
			Auth:      auth,
		})
		if err != nil && err != http.ErrServerClosed {
			fmt.Println("Dashboard error:", err)
			cancel()
		}
	}()

	fmt.Println("DDoS detector started")
	fmt.Println("Window:", window, "Threshold:", params.Threshold())
	fmt.Println("HTTP mode:", cfg.ListenAddr, "->", cfg.BackendURL)
	if model != nil {
		fmt.Println("Model loaded:", cfg.ModelPath)
	} else {
		fmt.Println("Model: NONE (heuristic mode)")
	}
	fmt.Println("Dashboard:", "http://127.0.0.1"+cfg.DashboardAddr)
	fmt.Println("Loadgen target:", lg.Target())
	if auth.User == "" {
		fmt.Println("Admin: DISABLED (set ADMIN_USER and ADMIN_PASS to enable mutations)")
	} else {
		fmt.Println("Admin: enabled (user:", auth.User+")")
	}

	if err := det.Run(ctx, winCh); err != nil {
		fmt.Println("Detector stopped:", err)
		os.Exit(1)
	}
	fmt.Println("Stopped")
}

// startBuiltinBackend запускает HTTP "защищаемый сервис" на свободном порту.
// Отдаёт HTML страницу для визуальной демонстрации доступности (опрашивает
// /ping раз в секунду) и JSON /ping для проб.
func startBuiltinBackend(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `{"ok":true,"ts":%q}`, time.Now().UTC().Format(time.RFC3339Nano))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "OK")
	})
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write([]byte(faviconSVG))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		// browsers default to /favicon.ico — redirect to svg
		http.Redirect(w, r, "favicon.svg", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(protectedServiceHTML))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "OK path=%s\n", r.URL.Path)
	})
	srv := &http.Server{Handler: mux}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		_ = srv.Serve(ln)
	}()

	return addr, nil
}

// protectedServiceHTML — простая страница, которую раз в секунду пингует
// саму себя через ddos-proxy. Показывает UP/SLOW/DOWN и статистику ответов.
const protectedServiceHTML = `<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Protected Service · DDoS Guardian</title>
<link rel="icon" type="image/svg+xml" href="favicon.svg">
<style>
 *{box-sizing:border-box} body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f1320;color:#e4e8f1}
 .wrap{max-width:720px;margin:0 auto;padding:32px 20px}
 h1{margin:0 0 4px;font-size:24px} .sub{color:#9ba3b4;margin:0 0 24px;font-size:14px}
 .card{background:#181d2e;border:1px solid #2a3050;border-radius:12px;padding:20px;margin-bottom:14px}
 .big{display:flex;align-items:center;gap:14px;margin-bottom:6px}
 .dot{width:18px;height:18px;border-radius:50%;background:#9ba3b4;box-shadow:0 0 0 0 rgba(0,0,0,0)}
 .dot.up{background:#7be29e;box-shadow:0 0 18px rgba(123,226,158,0.7)}
 .dot.slow{background:#f6c177;box-shadow:0 0 18px rgba(246,193,119,0.6)}
 .dot.down{background:#ff6b6b;box-shadow:0 0 18px rgba(255,107,107,0.7)}
 .state{font-size:28px;font-weight:700;letter-spacing:-0.01em}
 .state.up{color:#7be29e} .state.slow{color:#f6c177} .state.down{color:#ff6b6b}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:12px}
 .m{background:#1f2438;border:1px solid #2a3050;border-radius:8px;padding:10px 12px}
 .ml{color:#9ba3b4;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
 .mv{font-size:20px;font-weight:600;font-variant-numeric:tabular-nums;margin-top:2px}
 .muted{color:#9ba3b4;font-size:12px}
 .log{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#9ba3b4;max-height:140px;overflow-y:auto;background:#1f2438;border-radius:6px;padding:8px 10px;border:1px solid #2a3050}
 .log .e{color:#ff6b6b}.log .s{color:#f6c177}
</style></head>
<body>
<div class="wrap">
  <h1>Protected service</h1>
  <p class="sub">Эта страница стоит за reverse-proxy DDoS Guardian. Каждую секунду она опрашивает себя через тот же proxy и показывает что видит клиент.</p>

  <div class="card">
    <div class="big"><div id="dot" class="dot"></div><div id="state" class="state">checking…</div></div>
    <div class="muted" id="hint">первый запрос…</div>
    <div class="grid">
      <div class="m"><div class="ml">success (60s)</div><div class="mv" id="rate">—</div></div>
      <div class="m"><div class="ml">avg latency</div><div class="mv" id="lat">—</div></div>
      <div class="m"><div class="ml">ok / fail</div><div class="mv" id="okfail">0 / 0</div></div>
      <div class="m"><div class="ml">last response</div><div class="mv" id="last">—</div></div>
    </div>
  </div>

  <div class="card">
    <div class="muted" style="margin-bottom:6px">Лог последних запросов</div>
    <div id="log" class="log"></div>
  </div>

  <p class="muted" style="text-align:center">Открой админку → запусти нагрузочный тест → смотри как тут меняются цвета и latency.</p>
</div>

<script>
const W = 60; // window in samples (~60s)
let oks=0, fails=0, lats=[];
const logEl = document.getElementById("log");
const stateEl = document.getElementById("state");
const dotEl   = document.getElementById("dot");
const hintEl  = document.getElementById("hint");

function setState(cls, text, hint) {
  stateEl.className = "state " + cls;
  dotEl.className   = "dot "   + cls;
  stateEl.textContent = text;
  hintEl.textContent  = hint;
}

function logLine(cls, msg) {
  const line = document.createElement("div");
  line.className = cls;
  line.textContent = new Date().toLocaleTimeString() + "  " + msg;
  logEl.insertBefore(line, logEl.firstChild);
  while (logEl.childElementCount > 60) logEl.removeChild(logEl.lastChild);
}

async function probe() {
  const t0 = performance.now();
  try {
    const r = await fetch("ping?_=" + Date.now(), { cache: "no-store" });
    const dt = Math.round(performance.now() - t0);
    if (!r.ok) throw new Error("HTTP " + r.status);
    await r.json();
    oks++; lats.push(dt); if (lats.length > W) lats.shift();
    logLine("", "OK  " + dt + "ms");
  } catch (e) {
    const dt = Math.round(performance.now() - t0);
    fails++; lats.push(dt); if (lats.length > W) lats.shift();
    logLine("e", "FAIL  " + dt + "ms  " + e.message);
  }
  render();
}

function render() {
  const total = oks + fails;
  const avg = lats.length ? Math.round(lats.reduce((a,b)=>a+b,0)/lats.length) : 0;
  const rate = total ? (oks/total*100) : 0;
  document.getElementById("rate").textContent = rate.toFixed(1) + "%";
  document.getElementById("lat").textContent  = avg + " ms";
  document.getElementById("okfail").textContent = oks + " / " + fails;
  document.getElementById("last").textContent = (lats[lats.length-1] || 0) + " ms";

  if (total < 3) { setState("", "checking…", "собираем данные…"); return; }
  if (rate < 80)        setState("down", "DOWN",  "сервис проседает: " + (100-rate).toFixed(0) + "% запросов теряются");
  else if (avg > 300)   setState("slow", "SLOW",  "сервис под нагрузкой, latency " + avg + " ms");
  else                  setState("up",   "UP",    "сервис отвечает нормально (" + avg + " ms)");
}

probe();
setInterval(probe, 1000);
</script>
</body></html>
`

const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#7aa2ff"/><stop offset="1" stop-color="#4a6bcc"/>
  </linearGradient></defs>
  <path d="M16 2 L28 6 V15 C28 22 22 28 16 30 C10 28 4 22 4 15 V6 Z" fill="url(#g)" stroke="#2a3050" stroke-width="0.6"/>
  <path d="M10.5 16 L14.5 20 L22 11.5" stroke="white" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`
