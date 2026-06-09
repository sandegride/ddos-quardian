// ---------- helpers ----------------------------------------------------
async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (res.status === 204) return null;
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

async function sendJSON(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let payload = null;
  try { payload = await res.json(); } catch (_) {}
  if (!res.ok) {
    const err = (payload && payload.error) || `HTTP ${res.status}`;
    throw new Error(err);
  }
  return payload;
}

function fmtNum(n) {
  if (n === null || n === undefined) return "—";
  if (typeof n !== "number") return String(n);
  if (Number.isInteger(n)) return n.toLocaleString();
  return n.toFixed(3);
}

function fmtBytes(b) {
  if (b === null || b === undefined) return "—";
  const units = ["B","KB","MB","GB","TB"];
  let v = b, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(2)) + " " + units[i];
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function showMsg(id, text, ok) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className = "form-msg " + (ok ? "ok" : "err");
  setTimeout(() => { el.textContent = ""; el.className = "form-msg"; }, 4000);
}

// ---------- tabs --------------------------------------------------------
function switchTab(name) {
  document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("active", p.id === "tab-" + name));
}
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});
// Honor URL hash so screenshots can target a specific tab: e.g. /#admin
if (location.hash === "#admin" || location.hash === "#dashboard") {
  switchTab(location.hash.slice(1));
}

// ---------- charts -----------------------------------------------------
const MAX_POINTS = 120;
const MAX_PROTO_POINTS = 30;

const commonScale = {
  x: { ticks: { color: "#9ba3b4", maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
       grid: { color: "rgba(255,255,255,0.05)" } },
  y: { beginAtZero: true, ticks: { color: "#9ba3b4" }, grid: { color: "rgba(255,255,255,0.05)" } },
};

Chart.defaults.color = "#cbd2e0";
Chart.defaults.font.family = "ui-sans-serif, system-ui, sans-serif";
Chart.defaults.animation = false;

const healthChart = new Chart(document.getElementById("healthChart"), {
  type: "line",
  data: { labels: [], datasets: [
    { label: "success rate (%)", data: [], yAxisID: "y", borderColor: "#7be29e", backgroundColor: "rgba(123,226,158,0.15)", fill: true, tension: 0.25, pointRadius: 0 },
    { label: "avg latency (ms)", data: [], yAxisID: "y1", borderColor: "#ff8a65", pointRadius: 0, tension: 0.25 },
  ]},
  options: {
    responsive: true, maintainAspectRatio: false,
    scales: {
      x: commonScale.x,
      y:  { position: "left",  min: 0, max: 100, ticks: { color: "#7be29e", callback: v => v + "%" }, grid: { color: "rgba(255,255,255,0.05)" } },
      y1: { position: "right", beginAtZero: true, ticks: { color: "#ff8a65", callback: v => v + "ms" }, grid: { drawOnChartArea: false } },
    },
    plugins: { legend: { labels: { color: "#cbd2e0" } } },
  },
});

const probChart = new Chart(document.getElementById("probChart"), {
  type: "line",
  data: { labels: [], datasets: [
    { label: "probability", data: [], borderColor: "#7aa2ff", backgroundColor: "rgba(122,162,255,0.15)", fill: true, tension: 0.25, pointRadius: 0 },
    { label: "threshold",   data: [], borderColor: "#ff8a65", borderDash: [6, 4], pointRadius: 0, fill: false },
  ]},
  options: {
    responsive: true, maintainAspectRatio: false,
    scales: { ...commonScale, y: { ...commonScale.y, min: 0, max: 1 } },
    plugins: { legend: { labels: { color: "#cbd2e0" } } },
  },
});

const trafficChart = new Chart(document.getElementById("trafficChart"), {
  type: "line",
  data: { labels: [], datasets: [
    { label: "packets", data: [], yAxisID: "y", borderColor: "#7be29e", backgroundColor: "rgba(123,226,158,0.12)", fill: true, tension: 0.25, pointRadius: 0 },
    { label: "unique IPs", data: [], yAxisID: "y1", borderColor: "#f6c177", pointRadius: 0, tension: 0.25 },
  ]},
  options: {
    responsive: true, maintainAspectRatio: false,
    scales: {
      x: commonScale.x,
      y:  { position: "left",  beginAtZero: true, ticks: { color: "#7be29e" }, grid: { color: "rgba(255,255,255,0.05)" } },
      y1: { position: "right", beginAtZero: true, ticks: { color: "#f6c177" }, grid: { drawOnChartArea: false } },
    },
    plugins: { legend: { labels: { color: "#cbd2e0" } } },
  },
});

const protoChart = new Chart(document.getElementById("protoChart"), {
  type: "bar",
  data: { labels: [], datasets: [
    { label: "TCP",  data: [], backgroundColor: "#7aa2ff" },
    { label: "UDP",  data: [], backgroundColor: "#7be29e" },
    { label: "ICMP", data: [], backgroundColor: "#f6c177" },
    { label: "SYN",  data: [], backgroundColor: "#ff8a65" },
  ]},
  options: {
    responsive: true, maintainAspectRatio: false,
    scales: { x: { ...commonScale.x, stacked: true }, y: { ...commonScale.y, stacked: true } },
    plugins: { legend: { labels: { color: "#cbd2e0" } } },
  },
});

function pushPoint(chart, label, values) {
  chart.data.labels.push(label);
  values.forEach((v, i) => chart.data.datasets[i].data.push(v));
  if (chart.data.labels.length > MAX_POINTS) {
    chart.data.labels.shift();
    chart.data.datasets.forEach(d => d.data.shift());
  }
  chart.update("none");
}

function rebuildProtoChart(records) {
  const last = records.slice(-MAX_PROTO_POINTS);
  protoChart.data.labels = last.map(r => new Date(r.ts).toLocaleTimeString());
  protoChart.data.datasets[0].data = last.map(r => r.metrics?.tcp_packets || 0);
  protoChart.data.datasets[1].data = last.map(r => r.metrics?.udp_packets || 0);
  protoChart.data.datasets[2].data = last.map(r => r.metrics?.icmp_packets || 0);
  protoChart.data.datasets[3].data = last.map(r => r.metrics?.tcp_syn || 0);
  protoChart.update("none");
}

let lastSeenTs = null;

function rebuildLineCharts(records) {
  // Full rebuild on first load / large lag.
  const slice = records.slice(-MAX_POINTS);
  probChart.data.labels = slice.map(r => new Date(r.ts).toLocaleTimeString());
  probChart.data.datasets[0].data = slice.map(r => r.probability ?? 0);
  probChart.data.datasets[1].data = slice.map(r => r.threshold ?? 0);
  probChart.update("none");

  trafficChart.data.labels = probChart.data.labels.slice();
  trafficChart.data.datasets[0].data = slice.map(r => r.metrics?.total_packets || 0);
  trafficChart.data.datasets[1].data = slice.map(r => r.metrics?.unique_src_ips || 0);
  trafficChart.update("none");

  const withBackend = slice.filter(r => (r.metrics?.backend_requests || 0) > 0);
  healthChart.data.labels = withBackend.map(r => new Date(r.ts).toLocaleTimeString());
  healthChart.data.datasets[0].data = withBackend.map(r => (r.metrics.backend_success_rate || 0) * 100);
  healthChart.data.datasets[1].data = withBackend.map(r => r.metrics.backend_avg_latency_ms || 0);
  healthChart.update("none");
}

// ---------- dashboard updaters ----------------------------------------
function updateLatest(rec) {
  if (!rec) return;
  const state = rec.state || "—";
  const p   = rec.probability ?? null;
  const thr = rec.threshold ?? null;
  const ts  = rec.ts ? new Date(rec.ts).toLocaleTimeString() : "—";

  const pill = document.getElementById("statePill");
  pill.textContent = state;
  pill.dataset.state = state;

  setText("probValue", p === null ? "—" : p.toFixed(3));
  setText("thrValue", thr === null ? "—" : thr.toFixed(2));
  setText("tsValue", ts);

  const m = rec.metrics || {};
  setText("mPackets", fmtNum(m.total_packets));
  setText("mBytes",   fmtBytes(m.total_bytes));
  setText("mUniq",    fmtNum(m.unique_src_ips));
  setText("mMax",     fmtNum(m.max_per_src));
  setText("mProto",   `${fmtNum(m.tcp_packets)} / ${fmtNum(m.udp_packets)} / ${fmtNum(m.icmp_packets)}`);
  setText("mSyn",     fmtNum(m.tcp_syn));

  // Backend health metrics
  const reqs = m.backend_requests || 0;
  setText("mBackendReqs", fmtNum(reqs));
  if (reqs > 0) {
    setText("mSuccess", (m.backend_success_rate * 100).toFixed(1) + "%");
    setText("mLatency", fmtNum(m.backend_avg_latency_ms) + " ms");
    setText("mBackendCodes", `${fmtNum(m.backend_2xx)} / ${fmtNum(m.backend_4xx)} / ${fmtNum(m.backend_5xx)}`);
    const sEl = document.getElementById("mSuccess");
    const r = m.backend_success_rate;
    sEl.style.color = r >= 0.95 ? "var(--ok)" : r >= 0.5 ? "var(--warn)" : "var(--bad)";
  } else {
    setText("mSuccess", "—"); setText("mLatency", "—"); setText("mBackendCodes", "—");
    document.getElementById("mSuccess").style.color = "";
  }

  const top = rec.top_sources || [];
  const topList = document.getElementById("topList");
  topList.innerHTML = "";
  if (top.length === 0) {
    const li = document.createElement("li");
    li.textContent = "—";
    topList.appendChild(li);
  } else {
    for (const ip of top) {
      const li = document.createElement("li");
      li.textContent = ip;
      topList.appendChild(li);
    }
  }
}

function updateTable(recs) {
  const tbody = document.querySelector("#tbl tbody");
  tbody.innerHTML = "";
  if (!recs || recs.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = "<td colspan='5' class='muted'>Нет данных — дождитесь первого окна Δt.</td>";
    tbody.appendChild(tr);
    return;
  }
  for (let i = recs.length - 1; i >= 0; i--) {
    const r = recs[i];
    const m = r.metrics || {};
    const tr = document.createElement("tr");
    tr.dataset.state = r.state || "";
    const ts = r.ts ? new Date(r.ts).toLocaleTimeString() : "—";
    const p  = (r.probability === null || r.probability === undefined) ? "—" : r.probability.toFixed(3);
    tr.innerHTML = `<td>${ts}</td><td>${r.state || "—"}</td><td>${p}</td><td>${fmtNum(m.total_packets)}</td><td>${fmtNum(m.unique_src_ips)}</td>`;
    tbody.appendChild(tr);
  }
}

async function tickDashboard() {
  try {
    const latest = await getJSON("/api/latest");
    if (latest) {
      updateLatest(latest);
      // Append-only update for line charts when a new window arrives.
      if (latest.ts !== lastSeenTs) {
        lastSeenTs = latest.ts;
        const ts = new Date(latest.ts).toLocaleTimeString();
        pushPoint(probChart, ts, [latest.probability ?? 0, latest.threshold ?? 0]);
        pushPoint(trafficChart, ts, [latest.metrics?.total_packets || 0, latest.metrics?.unique_src_ips || 0]);
        // health chart: only push if backend handled at least one request,
        // otherwise carry forward last value (so the line doesn't drop to 0).
        if ((latest.metrics?.backend_requests || 0) > 0) {
          pushPoint(healthChart, ts, [
            (latest.metrics.backend_success_rate || 0) * 100,
            latest.metrics.backend_avg_latency_ms || 0,
          ]);
        }
      }
    }
    const windows = await getJSON("/api/windows?limit=120");
    if (windows) {
      updateTable(windows);
      rebuildProtoChart(windows);
      // If we have nothing yet in line charts, full-rebuild from history.
      if (probChart.data.labels.length === 0 && windows.length > 0) {
        rebuildLineCharts(windows);
        lastSeenTs = windows[windows.length - 1].ts;
      }
    }
  } catch (e) {
    console.error("dashboard tick:", e);
  }
}

// ---------- loadtest status -------------------------------------------
async function tickLoadtest() {
  try {
    const s = await getJSON("/api/loadtest/status");
    if (!s) return;
    const phaseEl = document.getElementById("lPhase");
    phaseEl.textContent = s.phase || "idle";
    phaseEl.dataset.phase = s.phase || "idle";
    const elapsed = s.elapsed_sec || 0;
    const total = s.total_sec || 0;
    setText("lElapsed", `${elapsed}s / ${total}s` + (s.running ? ` · фаза ${s.phase_index + 1}/${s.phases_total}` : ""));
    const pct = total > 0 ? Math.min(100, Math.round((elapsed / total) * 100)) : 0;
    document.getElementById("lProgress").style.width = pct + "%";
    document.getElementById("lProgress").dataset.phase = s.phase || "idle";
    setText("lSent",   fmtNum(s.sent));
    setText("lErrors", fmtNum(s.errors));
    setText("lRps",    fmtNum(s.rps));
  } catch (e) { /* ignore */ }
}

// ---------- admin: params form ----------------------------------------
async function loadParams() {
  try {
    const p = await getJSON("/api/config");
    document.getElementById("pThreshold").value = p.threshold;
    document.getElementById("pConfirm").value   = p.confirm_windows;
    document.getElementById("pRelax").value     = p.relax_windows;
    document.getElementById("pWindow").value    = p.window_ms;
    document.getElementById("thrPreview").textContent = `(${Number(p.threshold).toFixed(2)})`;
  } catch (e) { console.error(e); }
}
document.getElementById("pThreshold").addEventListener("input", e => {
  document.getElementById("thrPreview").textContent = `(${Number(e.target.value).toFixed(2)})`;
});
document.getElementById("paramsForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    threshold:       parseFloat(document.getElementById("pThreshold").value),
    confirm_windows: parseInt(document.getElementById("pConfirm").value, 10),
    relax_windows:   parseInt(document.getElementById("pRelax").value, 10),
  };
  try {
    await sendJSON("POST", "/api/config", body);
    showMsg("paramsMsg", "Сохранено", true);
  } catch (err) { showMsg("paramsMsg", err.message, false); }
});

// ---------- admin: whitelist -------------------------------------------
async function loadWhitelist() {
  try {
    const r = await getJSON("/api/whitelist");
    document.getElementById("wlText").value = (r.entries || []).join("\n");
  } catch (e) { console.error(e); }
}
document.getElementById("wlForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = document.getElementById("wlText").value;
  try {
    await sendJSON("POST", "/api/whitelist", { text });
    showMsg("wlMsg", "Применён", true);
  } catch (err) { showMsg("wlMsg", err.message, false); }
});

// ---------- admin: loadtest controls -----------------------------------
function buildScenarioFromForm() {
  return {
    phases: [
      { name: "normal",   duration_sec: +document.getElementById("lNormalDur").value, workers: +document.getElementById("lNormalW").value, rps_per_worker: 1.0, spoof_ips: false },
      { name: "attack",   duration_sec: +document.getElementById("lAttackDur").value, workers: +document.getElementById("lAttackW").value, rps_per_worker: 0,   spoof_ips: true  },
      { name: "recovery", duration_sec: +document.getElementById("lRecDur").value,    workers: +document.getElementById("lRecW").value,    rps_per_worker: 1.0, spoof_ips: false },
    ],
  };
}
document.getElementById("lStart").addEventListener("click", async () => {
  try {
    await sendJSON("POST", "/api/loadtest/start", { scenario: buildScenarioFromForm() });
    showMsg("loadMsg", "Запущено", true);
  } catch (err) { showMsg("loadMsg", err.message, false); }
});
document.getElementById("lDemo").addEventListener("click", async () => {
  try {
    await sendJSON("POST", "/api/loadtest/start", { preset: "demo" });
    showMsg("loadMsg", "Demo preset запущен", true);
  } catch (err) { showMsg("loadMsg", err.message, false); }
});
document.getElementById("lStop").addEventListener("click", async () => {
  try {
    await sendJSON("POST", "/api/loadtest/stop");
    showMsg("loadMsg", "Остановлено", true);
  } catch (err) { showMsg("loadMsg", err.message, false); }
});

// ---------- bootstrap --------------------------------------------------
async function bootstrap() {
  try {
    const h = await getJSON("/api/health");
    if (h && h.target) {
      setText("targetHint", "loadgen → " + h.target);
      setText("lgTarget", h.target);
    }
  } catch (_) {}
  await loadParams();
  await loadWhitelist();
}

bootstrap();
tickDashboard();
tickLoadtest();
setInterval(tickDashboard, 1000);
setInterval(tickLoadtest, 1000);
