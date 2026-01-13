async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (res.status === 204) return null;
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

function fmtNum(n) {
  if (n === null || n === undefined) return "—";
  if (typeof n !== "number") return String(n);
  if (Number.isInteger(n)) return n.toString();
  return n.toFixed(3);
}

function fmtBytes(b) {
  if (b === null || b === undefined) return "—";
  const units = ["B","KB","MB","GB","TB"];
  let v = b;
  let i = 0;
  while (v >= 1024 && i < units.length-1) {
    v /= 1024;
    i++;
  }
  return (i === 0 ? v.toFixed(0) : v.toFixed(2)) + " " + units[i];
}

function statePillClass(state) {
  // Keep styling dependency-free: just encode severity in text.
  return state || "—";
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = value;
}

function updateLatest(rec) {
  if (!rec) return;

  const state = rec.state || "—";
  const p = rec.probability ?? null;
  const thr = rec.threshold ?? null;
  const ts = rec.ts ? new Date(rec.ts).toLocaleString() : "—";

  const pill = document.getElementById("statePill");
  pill.textContent = statePillClass(state);

  setText("probValue", (p === null ? "—" : p.toFixed(3)));
  setText("thrValue", (thr === null ? "—" : thr.toFixed(2)));
  setText("tsValue", ts);

  const m = rec.metrics || {};
  setText("mPackets", fmtNum(m.total_packets));
  setText("mBytes", fmtBytes(m.total_bytes));
  setText("mUniq", fmtNum(m.unique_src_ips));
  setText("mMax", fmtNum(m.max_per_src));
  setText("mProto", `${fmtNum(m.tcp_packets)} / ${fmtNum(m.udp_packets)} / ${fmtNum(m.icmp_packets)}`);
  setText("mSyn", fmtNum(m.tcp_syn));

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
    const ts = r.ts ? new Date(r.ts).toLocaleTimeString() : "—";
    const p = (r.probability === null || r.probability === undefined) ? "—" : r.probability.toFixed(3);
    tr.innerHTML = `
      <td>${ts}</td>
      <td>${r.state || "—"}</td>
      <td>${p}</td>
      <td>${fmtNum(m.total_packets)}</td>
      <td>${fmtNum(m.unique_src_ips)}</td>
    `;
    tbody.appendChild(tr);
  }
}

async function tick() {
  try {
    const latest = await getJSON("/api/latest");
    if (latest) updateLatest(latest);

    const windows = await getJSON("/api/windows?limit=120");
    if (windows) updateTable(windows);
  } catch (e) {
    console.error(e);
  }
}

tick();
setInterval(tick, 1000);
