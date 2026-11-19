/* global Chart */
import { $, escapeHtml } from "../lib/dom.js";
import { pushActivity } from "./activity-feed.js";

const LIVE_HISTORY_KEY = "securecc_live_trend_history";
const SPARK_GRAPH_KEY = "securecc_preview_graph_spark";
const LINT_LAT_KEY = "securecc_lint_lat_spark";
const PREVIEW_LAT_KEY = "securecc_preview_lat_spark";
const MAX_HISTORY = 40;
const SPARK_MAX = 30;

let issuesBarChart = null;
let trendChart = null;
let graphSparkChart = null;
let latencySparkChart = null;
let lastPreviewMs = null;
let lastLintMs = null;
let lastCounts = { errors: 0, warnings: 0, hints: 0, total: 0 };
let prevCounts = null;
let lastDiagnostics = [];
let resizeObserver = null;
let deltaFadeTimer = null;
let healthAnimFrame = null;
let displayedTotal = 0;
let activeProblemLine = 0;

const SOURCE_LABELS = {
  heuristic: "heuristic",
  compiler: "compiler",
  semantic: "semantic",
  java: "java",
};

function severityRank(d) {
  if (d.category === "ERROR") return 0;
  if (d.source === "heuristic" || d.category === "SUGGESTION") return 2;
  return 1;
}

function isHint(d) {
  return d.source === "heuristic" || d.category === "SUGGESTION";
}

function countSeverities(diagnostics) {
  let errors = 0;
  let warnings = 0;
  let hints = 0;
  for (const d of diagnostics || []) {
    if (d.category === "ERROR") errors += 1;
    else if (isHint(d)) hints += 1;
    else warnings += 1;
  }
  return { errors, warnings, hints, total: (diagnostics || []).length };
}

function loadHistory() {
  try {
    return JSON.parse(sessionStorage.getItem(LIVE_HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveHistory(list) {
  sessionStorage.setItem(LIVE_HISTORY_KEY, JSON.stringify(list));
}

function pushHistory(counts) {
  const list = loadHistory();
  list.push({
    t: Date.now(),
    errors: counts.errors,
    warnings: counts.warnings,
  });
  while (list.length > MAX_HISTORY) list.shift();
  saveHistory(list);
  return list;
}

function loadSpark(key) {
  try {
    return JSON.parse(sessionStorage.getItem(key) || "[]");
  } catch {
    return [];
  }
}

function saveSpark(key, list) {
  sessionStorage.setItem(key, JSON.stringify(list));
}

function pushGraphSpark(preview) {
  const g = preview?.graph || {};
  const list = loadSpark(SPARK_GRAPH_KEY);
  list.push({
    findings: Number(preview?.finding_count) || 0,
    highlights: (g.nodes || []).filter((n) => n.highlight).length,
  });
  while (list.length > SPARK_MAX) list.shift();
  saveSpark(SPARK_GRAPH_KEY, list);
  return list;
}

function pushLintLatency(ms) {
  const list = loadSpark(LINT_LAT_KEY);
  list.push(Number(ms) || 0);
  while (list.length > SPARK_MAX) list.shift();
  saveSpark(LINT_LAT_KEY, list);
}

function pushPreviewLatency(ms) {
  const list = loadSpark(PREVIEW_LAT_KEY);
  list.push(Number(ms) || 0);
  while (list.length > SPARK_MAX) list.shift();
  saveSpark(PREVIEW_LAT_KEY, list);
}

export function renderSparklines() {
  if (typeof Chart === "undefined") return;
  const { muted, grid } = chartColors();
  const accent = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#0891b2";
  const graphHist = loadSpark(SPARK_GRAPH_KEY);
  const lintHist = loadSpark(LINT_LAT_KEY);
  const previewHist = loadSpark(PREVIEW_LAT_KEY);
  const latLen = Math.max(lintHist.length, previewHist.length, 1);
  const latLabels = Array.from({ length: latLen }, (_, i) => String(i + 1));
  const labels = graphHist.length ? graphHist.map((_, i) => String(i + 1)) : ["1"];

  const gsCanvas = $("#live-spark-graph-canvas");
  if (gsCanvas) {
    graphSparkChart?.destroy();
    graphSparkChart = new Chart(gsCanvas, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Findings",
            data: graphHist.length ? graphHist.map((h) => h.findings ?? h.nodes ?? 0) : [0],
            borderColor: getComputedStyle(document.documentElement).getPropertyValue("--danger").trim(),
            tension: 0.35,
            fill: true,
            backgroundColor: "rgba(220, 38, 38, 0.08)",
            pointRadius: 0,
          },
          {
            label: "IR highlights",
            data: graphHist.length ? graphHist.map((h) => h.highlights ?? h.edges ?? 0) : [0],
            borderColor: accent,
            tension: 0.35,
            pointRadius: 0,
          },
        ],
      },
      options: sparkOptions(muted, grid, "Preview history"),
    });
  }

  const latLabel = $("#live-spark-latency-label");
  if (latLabel) {
    const bits = [];
    if (lastLintMs != null) bits.push(`lint ${Math.round(lastLintMs)} ms`);
    if (lastPreviewMs != null) bits.push(`preview ${Math.round(lastPreviewMs)} ms`);
    latLabel.textContent = bits.length ? bits.join(" · ") : "—";
  }
}

function sparkOptions(muted, grid, title) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: "top",
        align: "start",
        labels: { color: muted, font: { size: 9 }, boxWidth: 8 },
      },
      title: { display: true, text: title, color: muted, font: { size: 11, weight: "600" } },
    },
    scales: {
      x: { ticks: { display: false }, grid: { display: false } },
      y: { beginAtZero: true, ticks: { color: muted, font: { size: 9 }, maxTicksLimit: 4 }, grid: { color: grid } },
    },
  };
}

export function clearLiveSession() {
  saveHistory([]);
  saveSpark(SPARK_GRAPH_KEY, []);
  saveSpark(LINT_LAT_KEY, []);
  saveSpark(PREVIEW_LAT_KEY, []);
  lastPreviewMs = null;
  lastLintMs = null;
  prevCounts = null;
  if (deltaFadeTimer) clearTimeout(deltaFadeTimer);
  $("#live-health-deltas") && ($("#live-health-deltas").innerHTML = "");
  lastCounts = { errors: 0, warnings: 0, hints: 0, total: 0 };
  lastDiagnostics = [];
  displayedTotal = 0;
  renderIssuesBarChart(lastCounts);
  renderTrendChart([]);
  renderSparklines();
  renderHealthCard(lastCounts, true);
  renderProblemsList([]);
  updateCenterStrip(lastCounts, null, false);
  clearPreviewStripSummary();
  window.SecureCCLiveMiniGraph?.clearMiniGraph?.();
  window.SecureCCLiveUnsafe?.clearUnsafeScan?.();
  window.SecureCCLiveEngine?.clearEnginePanel?.();
  window.SecureCCLiveFlow?.clearFlowPanels?.();
  window.SecureCCLiveCode?.clearCodePanel?.();
}

function clearPreviewStripSummary() {
  const findingsEl = $("#live-preview-findings");
  const graphEl = $("#live-preview-graph");
  if (findingsEl) findingsEl.textContent = "";
  if (graphEl) graphEl.textContent = "";
}

function chartColors() {
  const muted = getComputedStyle(document.documentElement).getPropertyValue("--text-muted").trim() || "#64748b";
  const grid = getComputedStyle(document.documentElement).getPropertyValue("--border").trim() || "#e2e8f0";
  const danger = getComputedStyle(document.documentElement).getPropertyValue("--danger").trim() || "#dc2626";
  const warning = getComputedStyle(document.documentElement).getPropertyValue("--warning").trim() || "#d97706";
  return { muted, grid, danger, warning };
}

export function resizeLiveCharts() {
  try {
    issuesBarChart?.resize();
    trendChart?.resize();
    graphSparkChart?.resize();
  } catch {
    /* Chart may be destroyed */
  }
  window.SecureCCLiveMiniGraph?.resizeMiniGraph?.();
  window.SecureCCMonaco?.getEditor?.()?.layout?.();
}

export function refreshEngineWidgets() {
  renderSparklines();
  resizeLiveCharts();
  window.SecureCCLiveEngine?.flushPendingGraph?.();
  window.SecureCCLiveEngine?.resizeEngineGraph?.();
  window.SecureCCLiveCode?.resizeCodePanel?.();
  window.SecureCCLiveCallGraph?.resizeCallGraph?.();
  window.SecureCCLiveFlow?.resizeFlowPanels?.();
}

export function initLiveVizResize() {
  const host = $("#live-viz-charts");
  if (!host || resizeObserver) return;
  resizeObserver = new ResizeObserver(() => resizeLiveCharts());
  resizeObserver.observe(host);
  window.addEventListener("resize", () => resizeLiveCharts());
}

function destroyChart(ref) {
  if (ref) ref.destroy();
  return null;
}

function maxBarAxis(counts) {
  const m = Math.max(counts.errors || 0, counts.warnings || 0, counts.hints || 0, 1);
  return m < 5 ? 5 : m + 1;
}

function renderIssuesBarChart(counts) {
  if (typeof Chart === "undefined") return;
  const canvas = $("#live-issues-bar-chart");
  if (!canvas) return;

  const safe = {
    errors: counts?.errors || 0,
    warnings: counts?.warnings || 0,
    hints: counts?.hints || 0,
  };

  const { muted, grid, danger, warning } = chartColors();
  const accent =
    getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#2563eb";
  const yMax = maxBarAxis(safe);

  issuesBarChart = destroyChart(issuesBarChart);
  issuesBarChart = new Chart(canvas, {
    type: "bar",
    data: {
      labels: ["Errors", "Warnings", "Hints"],
      datasets: [
        {
          label: "Count",
          data: [safe.errors, safe.warnings, safe.hints],
          backgroundColor: [`${danger}cc`, `${warning}cc`, `${accent}99`],
          borderColor: [danger, warning, accent],
          borderWidth: 1,
          borderRadius: 6,
          barPercentage: 0.55,
          categoryPercentage: 0.65,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      layout: { padding: { top: 8, bottom: 4, left: 4, right: 8 } },
      plugins: {
        legend: { display: false },
        title: {
          display: true,
          text: "Current errors & warnings",
          color: muted,
          font: { size: 11, weight: "600" },
          padding: { bottom: 8 },
        },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.label}: ${ctx.parsed.y}`,
          },
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          suggestedMax: yMax,
          title: {
            display: true,
            text: "Issue count",
            color: muted,
            font: { size: 10, weight: "600" },
          },
          ticks: {
            stepSize: 1,
            color: muted,
            font: { size: 10 },
            precision: 0,
          },
          grid: { color: grid },
        },
        x: {
          border: { display: false },
          ticks: { color: muted, font: { size: 10, weight: "500" } },
          grid: { display: false },
        },
      },
    },
  });
  requestAnimationFrame(resizeLiveCharts);
}

function renderTrendChart(history) {
  if (typeof Chart === "undefined") return;
  const canvas = $("#live-trend-chart");
  if (!canvas) return;

  const list = Array.isArray(history) && history.length ? history : loadHistory();
  const labels = list.length ? list.map((_, i) => String(i + 1)) : ["1"];
  const errors = list.length ? list.map((h) => h.errors ?? 0) : [0];
  const warnings = list.length ? list.map((h) => h.warnings ?? 0) : [0];
  const { muted, grid, danger, warning } = chartColors();
  const yMax = Math.max(...errors, ...warnings, 1);
  const suggestedMax = yMax < 5 ? 5 : yMax + 1;

  trendChart = destroyChart(trendChart);
  trendChart = new Chart(canvas, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Errors",
          data: errors,
          borderColor: danger,
          backgroundColor: `${danger}22`,
          fill: true,
          tension: 0.3,
          pointRadius: list.length > 12 ? 0 : 2,
          pointHoverRadius: 3,
        },
        {
          label: "Warnings",
          data: warnings,
          borderColor: warning,
          backgroundColor: `${warning}18`,
          fill: true,
          tension: 0.3,
          pointRadius: list.length > 12 ? 0 : 2,
          pointHoverRadius: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      layout: { padding: { top: 8, bottom: 4, left: 4, right: 8 } },
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          display: true,
          position: "top",
          align: "end",
          labels: { color: muted, font: { size: 10 }, boxWidth: 10, padding: 8 },
        },
        title: {
          display: true,
          text: "Errors & warnings (session)",
          color: muted,
          font: { size: 11, weight: "600" },
          padding: { bottom: 6 },
        },
        tooltip: {
          callbacks: {
            title: (items) => `Lint pass ${items[0]?.label ?? ""}`,
          },
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          suggestedMax,
          title: {
            display: true,
            text: "Issue count",
            color: muted,
            font: { size: 10, weight: "600" },
          },
          ticks: { stepSize: 1, color: muted, font: { size: 10 }, precision: 0 },
          grid: { color: grid },
        },
        x: {
          border: { display: false },
          ticks: { color: muted, font: { size: 10 } },
          grid: { display: false },
        },
      },
    },
  });
  requestAnimationFrame(resizeLiveCharts);
}

function prefersReducedMotion() {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
}

function animateHealthNumber(target) {
  const el = $("#live-health-total");
  if (!el) return;
  if (prefersReducedMotion()) {
    displayedTotal = target;
    el.textContent = String(target);
    return;
  }
  if (healthAnimFrame) cancelAnimationFrame(healthAnimFrame);
  const from = displayedTotal;
  const start = performance.now();
  const duration = 220;
  const step = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const v = Math.round(from + (target - from) * t);
    el.textContent = String(v);
    if (t < 1) healthAnimFrame = requestAnimationFrame(step);
    else displayedTotal = target;
  };
  healthAnimFrame = requestAnimationFrame(step);
}

function renderDeltaChips(prev, next) {
  const host = $("#live-health-deltas");
  if (!host) return;
  if (deltaFadeTimer) clearTimeout(deltaFadeTimer);
  host.innerHTML = "";
  if (!prev) return;

  const chips = [];
  const add = (key, label, severityClass) => {
    const d = (next[key] || 0) - (prev[key] || 0);
    if (d === 0) return;
    const sign = d > 0 ? "+" : "";
    const cls = d < 0 ? "live-delta-good" : severityClass;
    chips.push(`<span class="live-delta-chip ${cls}">${sign}${d} ${label}</span>`);
  };
  add("errors", "error", "live-delta-error");
  add("warnings", "warning", "live-delta-warning");
  add("hints", "hint", "live-delta-hint");

  if (!chips.length) {
    host.innerHTML = `<span class="live-delta-chip live-delta-neutral">no change</span>`;
  } else {
    host.innerHTML = chips.join("");
  }

  deltaFadeTimer = setTimeout(() => {
    host.innerHTML = "";
  }, 4000);
}

function statusBreakdown(counts) {
  if (!counts.total) {
    return "";
  }
  const parts = [];
  if (counts.errors) parts.push(`${counts.errors} error${counts.errors !== 1 ? "s" : ""}`);
  if (counts.warnings) parts.push(`${counts.warnings} warning${counts.warnings !== 1 ? "s" : ""}`);
  if (counts.hints) parts.push(`${counts.hints} hint${counts.hints !== 1 ? "s" : ""}`);
  return escapeHtml(parts.join(" · "));
}

function renderHealthCard(counts, skipDelta) {
  animateHealthNumber(counts.total);
  const status = $("#live-health-status");
  if (status) status.innerHTML = statusBreakdown(counts);
  if (!skipDelta && prevCounts != null) renderDeltaChips(prevCounts, counts);
}

function renderProblemsList(diagnostics) {
  const list = $("#live-problems-list");
  if (!list) return;
  const items = [...(diagnostics || [])].sort(
    (a, b) => severityRank(a) - severityRank(b) || (a.line || 0) - (b.line || 0)
  );

  if (!items.length) {
    list.innerHTML = `<li class="live-problems-empty muted">None</li>`;
    return;
  }

  list.innerHTML = items
    .map((d) => {
      const sev = d.category === "ERROR" ? "error" : isHint(d) ? "hint" : "warning";
      const src = SOURCE_LABELS[d.source] || d.source || "";
      const msg = escapeHtml(d.message || d.title || "Issue");
      const line = d.line || 0;
      const cwe = d.cwe_id ? `<span class="live-problem-cwe">${escapeHtml(d.cwe_id)}</span>` : "";
      const srcLabel = src ? `<span class="live-problem-source">${escapeHtml(src)}</span>` : "";
      const tags =
        srcLabel || cwe
          ? `<div class="live-problem-tags">${srcLabel}${cwe}</div>`
          : "";
      return `<li class="live-problem-row" data-line="${line}" data-sev="${sev}" role="button" tabindex="0">
        <span class="live-problem-dot live-problem-dot-${sev}" aria-hidden="true"></span>
        <div class="live-problem-body">
          <div class="live-problem-meta">
            <span class="live-problem-line">Line ${line || "—"}</span>
            ${tags}
          </div>
          <p class="live-problem-msg">${msg}</p>
        </div>
      </li>`;
    })
    .join("");

  list.querySelectorAll(".live-problem-row").forEach((row) => {
    const go = () => {
      const line = parseInt(row.dataset.line, 10);
      if (!line) return;
      window.SecureCCMonaco?.goToLine?.(line) ?? window.SecureCCMonaco?.highlightLine?.(line);
      activeProblemLine = line;
      highlightProblemRow(line);
    };
    row.addEventListener("click", go);
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        go();
      }
    });
  });
  highlightProblemRow(activeProblemLine);
}

function highlightProblemRow(line) {
  $("#live-problems-list")?.querySelectorAll(".live-problem-row").forEach((row) => {
    row.classList.toggle("is-active", line > 0 && parseInt(row.dataset.line, 10) === line);
  });
}

export function bindProblemsCursorSync() {
  const editor = window.SecureCCMonaco?.getEditor?.();
  if (!editor || editor.__liveProblemsBound) return;
  editor.__liveProblemsBound = true;
  editor.onDidChangeCursorPosition((e) => {
    activeProblemLine = e.position.lineNumber;
    highlightProblemRow(activeProblemLine);
  });
}

function updateCenterStrip(counts, data, previewOn) {
  const ms = data?.stats?.elapsed_ms;
  const msEl = $("#live-kpi-ms");
  if (msEl) msEl.textContent = ms != null ? `${ms} ms` : "—";

  const set = (id, n) => {
    const el = $(id);
    if (el) el.textContent = String(n);
  };
  set("#live-kpi-errors", counts.errors);
  set("#live-kpi-warnings", counts.warnings);
  set("#live-kpi-hints", counts.hints);
  set("#live-panel-kpi-errors", counts.errors);
  set("#live-panel-kpi-warnings", counts.warnings);
  set("#live-panel-kpi-hints", counts.hints);
}

function formatPreviewSummary(preview) {
  const compileOk = preview?.compile?.ok !== false;
  if (!compileOk) return "Engine preview: compile failed";
  const fc = preview?.finding_count ?? 0;
  const g = preview?.graph_counts || {};
  const ir =
    g.nodes != null ? ` · IR ${g.nodes} nodes / ${g.edges ?? "—"} edges` : "";
  return `${fc} engine finding${fc === 1 ? "" : "s"}${ir}`;
}

export function onLintResult(data) {
  const diagnostics = data?.diagnostics || [];
  const counts = countSeverities(diagnostics);

  updateCenterStrip(counts, data, false);

  renderHealthCard(counts, false);
  prevCounts = { ...counts };
  lastCounts = counts;
  lastDiagnostics = diagnostics;

  const history = pushHistory(counts);
  renderIssuesBarChart(counts);
  renderTrendChart(history);
  renderProblemsList(diagnostics);

  window.SecureCCMonaco?.applyLintDecorations?.(diagnostics);

  const ms = data?.stats?.elapsed_ms;
  if (ms != null) {
    lastLintMs = ms;
    pushLintLatency(ms);
    renderSparklines();
  }
  window.SecureCCLiveCode?.onLintDiagnostics?.(diagnostics);
}

export function onPreviewResult(preview) {
  const findingsEl = $("#live-preview-findings");
  const graphEl = $("#live-preview-graph");
  const toggle = $("#live-preview-toggle");
  if (!toggle?.checked) {
    if (findingsEl) findingsEl.textContent = "";
    if (graphEl) graphEl.textContent = "";
    $("#live-preview-strip")?.classList.add("hidden");
    return;
  }

  $("#live-preview-strip")?.classList.add("hidden");
  const summary = formatPreviewSummary(preview);
  if (findingsEl) {
    findingsEl.textContent = summary;
    findingsEl.classList.toggle("live-preview-fail", preview?.compile?.ok === false);
  }
  if (graphEl) graphEl.textContent = "";

  if (toggle?.checked) {
    pushGraphSpark(preview);
    if (preview?._clientMs != null) {
      lastPreviewMs = preview._clientMs;
      pushPreviewLatency(preview._clientMs);
    }
    renderSparklines();
  }

  window.SecureCCLiveEngine?.updateFromPreview?.(preview);
  window.SecureCCLiveFlow?.updateFromPreview?.(preview);
  if (preview?.graph) {
    window.SecureCCLivePreview?.updateGraph?.(preview.graph, preview);
  }

  const compileOk = preview?.compile?.ok !== false;
  const fc = preview?.finding_count ?? 0;
  pushActivity(`Engine preview · ${compileOk ? `${fc} finding(s)` : "compile failed"}`);
}

export function refreshLiveCharts() {
  const history = loadHistory();
  const latest = history.length ? history[history.length - 1] : lastCounts;
  renderIssuesBarChart({
    errors: latest.errors,
    warnings: latest.warnings,
    hints: latest.hints ?? 0,
  });
  renderTrendChart(history);
  renderSparklines();
}

export function bootstrapLiveChartsEmpty() {
  const history = loadHistory();
  const latest = history.length ? history[history.length - 1] : { errors: 0, warnings: 0, hints: 0 };
  renderIssuesBarChart(latest);
  renderTrendChart(history);
  const emptyCounts = { errors: 0, warnings: 0, hints: 0, total: 0 };
  renderHealthCard(emptyCounts, true);
  updateCenterStrip(emptyCounts, null, false);
  renderProblemsList([]);
}

window.SecureCCLiveViz = {
  onLintResult,
  onPreviewResult,
  refreshLiveCharts,
  resizeLiveCharts,
  initLiveVizResize,
  bootstrapLiveChartsEmpty,
  clearLiveSession,
  bindProblemsCursorSync,
  refreshEngineWidgets,
  renderSparklines,
};