/* ═══════════════════════════════════════════════════════════════
   AI-SIEM  — Frontend Logic
   Pure Vanilla JS, no dependencies
═══════════════════════════════════════════════════════════════ */

const API = "";          // Same origin — FastAPI serves both

/* ── Page Navigation ──────────────────────────────────────────── */
function showPage(name) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  document.getElementById(`page-${name}`).classList.add("active");
  document.getElementById(`btn-${name}`).classList.add("active");

  // Lazy-load data when switching tabs
  if (name === "dashboard") loadDashboard();
  if (name === "threats")   loadThreats();
  if (name === "blocked")   loadBlocked();
}

/* ── Toast Notifications ──────────────────────────────────────── */
let toastTimer;
function showToast(msg, type = "info") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = `toast ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 4000);
}

/* ── Fetch Helper ─────────────────────────────────────────────── */
async function apiFetch(path, options = {}) {
  const res = await fetch(API + path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Request failed");
  }
  return res.json();
}

/* ── Log Submission ───────────────────────────────────────────── */
async function submitLog(event) {
  event.preventDefault();

  const btn = document.getElementById("submit-btn");
  btn.disabled = true;
  btn.innerHTML = `<span class="btn-icon">⏳</span> Analysing…`;

  const payload = {
    source_ip:    document.getElementById("source_ip").value.trim(),
    port:         parseInt(document.getElementById("port").value),
    payload_size: parseInt(document.getElementById("payload_size").value),
    action:       document.getElementById("action").value,
  };

  try {
    const data = await apiFetch("/log", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderResult(data.log);
    showToast("Log submitted and analysed ✓", "success");
    refreshStats();
  } catch (e) {
    showToast(`Error: ${e.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span class="btn-icon">🔍</span> Analyse &amp; Submit`;
  }
}

function renderResult(log) {
  const card = document.getElementById("result-card");
  card.classList.remove("hidden");

  // Badge
  const badge = document.getElementById("result-severity");
  badge.textContent = log.severity;
  badge.className = `severity-badge ${log.severity}`;

  // Grid fields
  const fields = [
    { label: "Source IP",    value: log.source_ip },
    { label: "Port",         value: log.port },
    { label: "Payload",      value: `${log.payload_size.toLocaleString()} B` },
    { label: "Action",       value: log.action },
    { label: "Rule Score",   value: `+${log.rule_score}` },
    { label: "ML Score",     value: `+${log.ml_score}` },
  ];
  document.getElementById("result-grid").innerHTML = fields
    .map(f => `<div class="result-item">
                 <div class="ri-label">${f.label}</div>
                 <div class="ri-value">${f.value}</div>
               </div>`)
    .join("");

  // Score bar
  const total = log.total_score;
  document.getElementById("result-score-num").textContent = total;
  const bar = document.getElementById("score-bar");
  const color =
    total > 60 ? "linear-gradient(90deg,#ef4444,#dc2626)" :
    total > 30 ? "linear-gradient(90deg,#eab308,#ca8a04)" :
                 "linear-gradient(90deg,#22c55e,#16a34a)";
  bar.style.width = `${total}%`;
  bar.style.background = color;
  bar.style.boxShadow =
    total > 60 ? "0 0 12px rgba(239,68,68,.6)" :
    total > 30 ? "0 0 12px rgba(234,179,8,.5)" :
                 "0 0 12px rgba(34,197,94,.5)";

  // Flags
  const flags = [];
  if (log.ml_anomaly)   flags.push({ cls: "danger",  icon: "🤖", text: "ML Anomaly Detected" });
  if (log.blocked)      flags.push({ cls: "danger",  icon: "🚫", text: "IP Auto-Blocked" });
  if (log.rule_score > 0)flags.push({ cls: "warning", icon: "⚠️", text: `Rule Score +${log.rule_score}` });
  if (log.is_threat)    flags.push({ cls: "warning", icon: "🚨", text: "Threat Flagged" });
  if (!log.is_threat)   flags.push({ cls: "success", icon: "✅", text: "No Threat" });

  document.getElementById("result-flags").innerHTML = flags
    .map(f => `<span class="flag ${f.cls}">${f.icon} ${f.text}</span>`)
    .join("");
}

/* ── Dashboard ────────────────────────────────────────────────── */
async function loadDashboard() {
  const tbody = document.getElementById("logs-body");
  const empty = document.getElementById("logs-empty");
  tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:2rem;color:var(--text-muted)">Loading…</td></tr>`;

  try {
    const logs = await apiFetch("/logs");
    if (!logs.length) {
      tbody.innerHTML = "";
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");
    tbody.innerHTML = logs
      .slice().reverse()
      .map(l => `
        <tr class="row-${l.severity.toLowerCase()}">
          <td>${fmtTime(l.timestamp)}</td>
          <td>${l.source_ip}</td>
          <td>${l.port}</td>
          <td>${l.payload_size.toLocaleString()}</td>
          <td>${l.action}</td>
          <td>${l.rule_score}</td>
          <td>${l.ml_score}</td>
          <td><b>${l.total_score}</b></td>
          <td>${severityBadge(l.severity)}</td>
        </tr>`)
      .join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" style="color:var(--high);text-align:center">${e.message}</td></tr>`;
  }
}

/* ── Threats ──────────────────────────────────────────────────── */
async function loadThreats() {
  const tbody = document.getElementById("threats-body");
  const empty = document.getElementById("threats-empty");
  tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--text-muted)">Loading…</td></tr>`;

  try {
    const threats = await apiFetch("/threats");
    if (!threats.length) {
      tbody.innerHTML = "";
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");
    tbody.innerHTML = threats
      .slice().reverse()
      .map(l => `
        <tr class="row-${l.severity.toLowerCase()}">
          <td>${fmtTime(l.timestamp)}</td>
          <td>${l.source_ip}</td>
          <td>${l.port}</td>
          <td><b>${l.total_score}</b></td>
          <td>${severityBadge(l.severity)}</td>
          <td>${yesNo(l.ml_anomaly)}</td>
          <td>${yesNo(l.blocked)}</td>
        </tr>`)
      .join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--high);text-align:center">${e.message}</td></tr>`;
  }
}

/* ── Blocked IPs ──────────────────────────────────────────────── */
async function loadBlocked() {
  const grid  = document.getElementById("blocked-grid");
  const empty = document.getElementById("blocked-empty");
  grid.innerHTML = "";

  try {
    const blocked = await apiFetch("/blocked-ips");
    if (!blocked.length) {
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");
    grid.innerHTML = blocked
      .slice().reverse()
      .map(b => `
        <div class="blocked-card">
          <div class="blocked-ip">🚫 ${b.ip}</div>
          <div class="blocked-time">⏱ ${fmtTime(b.blocked_at)}</div>
          <div class="blocked-reason">${b.reason}</div>
        </div>`)
      .join("");
  } catch (e) {
    showToast(`Failed to load blocked IPs: ${e.message}`, "error");
  }
}

/* ── Sidebar Stats ────────────────────────────────────────────── */
async function refreshStats() {
  try {
    const [logs, threats, blocked] = await Promise.all([
      apiFetch("/logs"),
      apiFetch("/threats"),
      apiFetch("/blocked-ips"),
    ]);
    document.getElementById("stat-total").textContent   = logs.length;
    document.getElementById("stat-threats").textContent  = threats.length;
    document.getElementById("stat-blocked").textContent  = blocked.length;
  } catch (_) { /* non-critical */ }
}

/* ── Health Check ─────────────────────────────────────────────── */
async function checkHealth() {
  try {
    const h = await apiFetch("/health");
    const el = document.getElementById("health-status");
    if (h.status === "ok") {
      el.innerHTML = `<span class="pulse"></span> Live`;
      el.style.color = "var(--low)";
    }
  } catch (_) {
    const el = document.getElementById("health-status");
    el.innerHTML = `⚠ Offline`;
    el.style.color = "var(--high)";
  }
}

/* ── Helpers ──────────────────────────────────────────────────── */
function fmtTime(iso) {
  if (!iso) return "—";
  try {
    // Handle both timezone-aware (e.g. +00:00) and naive ISO strings.
    // If no timezone info is present, treat as UTC by appending "Z".
    const hasTimezone = /[Zz]$|[+\-]\d{2}:\d{2}$/.test(iso);
    const d = new Date(hasTimezone ? iso : iso + "Z");
    if (isNaN(d.getTime())) return iso;  // Fallback to raw string if parse fails
    return d.toLocaleString(undefined, {
      month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch { return iso; }
}

function severityBadge(s) {
  const cls = s === "HIGH" ? "high" : s === "MEDIUM" ? "medium" : "low";
  return `<span class="badge badge-${cls}">${s}</span>`;
}

function yesNo(v) {
  return v
    ? `<span class="badge badge-yes">Yes</span>`
    : `<span class="badge badge-no">No</span>`;
}

/* ── Init ─────────────────────────────────────────────────────── */
(function init() {
  checkHealth();
  refreshStats();
  // Poll stats every 15 s
  setInterval(() => { refreshStats(); checkHealth(); }, 15_000);
})();
