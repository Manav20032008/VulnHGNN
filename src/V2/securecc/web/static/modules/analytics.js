import { $ } from "../lib/dom.js";

const STORAGE_KEY = "securecc_metric_snapshots";
let charts = {};
let lastAnalyticsPayload = null;

function loadSnapshots() {
  try {
    return JSON.parse(sessionStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveSnapshot(snap) {
  const list = loadSnapshots();
  list.push(snap);
  while (list.length > 12) list.shift();
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

export function compositeScores(data) {
  const scan = data.scan || {};
  const findings = scan.findings || [];
  let secure = 100;
  findings.forEach((f) => {
    const s = (f.severity || "").toLowerCase();
    if (s === "critical") secure -= 25;
    else if (s === "high") secure -= 15;
    else if (s === "medium") secure -= 8;
    else secure -= 3;
  });
  secure = Math.max(0, Math.min(100, secure));
  const diags = data.diagnostics?.diagnostics || [];
  let diagScore = 100;
  diags.forEach((d) => {
    if (d.category === "ERROR") diagScore -= 20;
    else diagScore -= 5;
  });
  diagScore = Math.max(0, Math.min(100, diagScore));
  const code = data.compile?.ok === false ? 40 : Math.round((secure + diagScore) / 2);
  if (data.fix?.status === "VERIFIED" && (scan.finding_count || 0) === 0) secure = 100;
  return { code, secure, diagnostics: diagScore };
}

export function recordAnalyzeSnapshot(data) {
  const scores = compositeScores(data);
  const scan = data.scan || {};
  saveSnapshot({
    t: Date.now(),
    finding_count: scan.finding_count || 0,
    critical: (scan.findings || []).filter((f) => (f.severity || "").toLowerCase() === "critical")
      .length,
    ...scores,
  });
}

function destroyChart(id) {
  if (charts[id]) {
    charts[id].destroy();
    delete charts[id];
  }
}

export function renderAnalytics(data) {
  lastAnalyticsPayload = data;
  const slot = $("#overview-analytics-slot");
  if (slot) slot.innerHTML = "";
  return;
  if (!slot || typeof Chart === "undefined") return;
  const textColor = getComputedStyle(document.documentElement).getPropertyValue("--text-muted").trim() || "#64748b";
  const gridColor = getComputedStyle(document.documentElement).getPropertyValue("--border").trim() || "#e2e8f0";
  const scan = data.scan || {};
  const findings = scan.findings || [];
  const sevCounts = {};
  findings.forEach((f) => {
    const k = (f.severity || "info").toLowerCase();
    sevCounts[k] = (sevCounts[k] || 0) + 1;
  });
  const scores = compositeScores(data);
  const snaps = loadSnapshots();

  slot.innerHTML = `
    <div class="chart-row">
      <div class="chart-card">
        <h4>Composite scores</h4>
        <p class="muted small">SecureCC heuristics · not a formal grade</p>
        <canvas id="chart-scores"></canvas>
      </div>
      <div class="chart-card">
        <h4>Severity distribution</h4>
        <canvas id="chart-severity"></canvas>
      </div>
    </div>
    <p class="muted small" style="margin-top:0.5rem">Session history: ${snaps.length} snapshot(s) in this browser.</p>`;

  destroyChart("scores");
  destroyChart("severity");

  const scoreLabels =
    snaps.length >= 2
      ? snaps.map((s, i) => `#${i + 1}`)
      : ["Code quality", "Secure code", "Diagnostics"];
  const scoreData =
    snaps.length >= 2
      ? {
          code: snaps.map((s) => s.code),
          secure: snaps.map((s) => s.secure),
          diagnostics: snaps.map((s) => s.diagnostics),
        }
      : {
          code: [scores.code],
          secure: [scores.secure],
          diagnostics: [scores.diagnostics],
        };

  charts.scores = new Chart($("#chart-scores"), {
    type: snaps.length >= 2 ? "line" : "bar",
    data: {
      labels: scoreLabels,
      datasets: [
        { label: "Code quality", data: scoreData.code, borderColor: "#3b82f6", backgroundColor: "#3b82f6" },
        { label: "Secure code", data: scoreData.secure, borderColor: "#10b981", backgroundColor: "#10b981" },
        { label: "Diagnostics", data: scoreData.diagnostics, borderColor: "#f59e0b", backgroundColor: "#f59e0b" },
      ],
    },
    options: {
      responsive: true,
      scales: {
        y: { min: 0, max: 100, ticks: { color: textColor }, grid: { color: gridColor } },
        x: { ticks: { color: textColor }, grid: { color: gridColor } },
      },
      plugins: { legend: { labels: { color: textColor } } },
    },
  });

  charts.severity = new Chart($("#chart-severity"), {
    type: "doughnut",
    data: {
      labels: Object.keys(sevCounts).length ? Object.keys(sevCounts) : ["none"],
      datasets: [
        {
          data: Object.keys(sevCounts).length ? Object.values(sevCounts) : [1],
          backgroundColor: ["#ef4444", "#f97316", "#f59e0b", "#3b82f6", "#94a3b8"],
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: textColor } } },
    },
  });
}

export function refreshAnalytics() {
  if (lastAnalyticsPayload) renderAnalytics(lastAnalyticsPayload);
}