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
	"ddos-detector/internal/ml"
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
		fmt.Println("Whitelist error:", err)
		os.Exit(1)
	}

	var model *ml.LogisticModel
	if cfg.ModelPath != "" {
		m, err := ml.Load(cfg.ModelPath)
		if err != nil {
			fmt.Println("Model load failed (fallback to heuristic):", err)
		} else {
			model = m
			if cfg.Threshold > 0 {
				model.Threshold = cfg.Threshold
			}
		}
	}

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

	// Collector (по умолчанию HTTP proxy collector; в pcap режиме — сбор пакетов)
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

	// Aggregator
	agg := aggregator.New(whitelist)
	window := time.Duration(cfg.WindowMs) * time.Millisecond
	go func() {
		if err := agg.Run(ctx, pktCh, window, winCh); err != nil {
			fmt.Println("Aggregator error:", err)
			cancel()
		}
	}()

	// Detector
	det := detector.New(model, cfg.Threshold, cfg.ConfirmWindows, cfg.RelaxWindows)
	det.WebhookURL = cfg.AlertWebhookURL
	det.EnableMitigation = cfg.EnableMitigation
	det.MitigationScript = cfg.MitigationScript

	// Dashboard (web UI)
	store := dashboard.NewStore(300)
	det.Store = store
	go func() {
		if err := dashboard.Start(ctx, cfg.DashboardAddr, store); err != nil && err != http.ErrServerClosed {
			fmt.Println("Dashboard error:", err)
			cancel()
		}
	}()

	fmt.Println("DDoS detector started")
	fmt.Println("Window:", window, "Threshold:", det.Threshold)
	if cfg.BackendURL != "" {
		fmt.Println("HTTP mode:", cfg.ListenAddr, "->", cfg.BackendURL)
	} else {
		fmt.Println("PCAP mode:", cfg.Interface, "BPF:", cfg.BPF)
	}
	if model != nil {
		fmt.Println("Model loaded:", cfg.ModelPath)
	} else {
		fmt.Println("Model: NONE (heuristic mode)")
	}
	fmt.Println("Dashboard:", "http://127.0.0.1"+cfg.DashboardAddr)

	if err := det.Run(ctx, winCh); err != nil {
		fmt.Println("Detector stopped:", err)
		os.Exit(1)
	}
	fmt.Println("Stopped")
}

// startBuiltinBackend запускает простой HTTP echo-сервер на свободном порту.
// Используется для тестирования без внешнего бэкенда.
func startBuiltinBackend(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "OK ip=%s path=%s\n", r.RemoteAddr, r.URL.Path)
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
