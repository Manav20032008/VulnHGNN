import { $, escapeHtml } from "../lib/dom.js";
import { readCssVar } from "./theme.js";

const STAGE_ORDER = [
  "compile",
  "parse",
  "graph",
  "detect",
  "localize",
  "explain",
  "diagnose",
  "learn",
  "repair",
];

let activeId = null;
let loadingTimer = null;
let loadingIndex = 0;
let lastStages = null;
let lastLoading = false;

function statusClass(status) {
  const s = (status || "complete").toLowerCase();
  if (s === "failed") return "failed";
  if (s === "partial" || s === "warning") return "warning";
  if (s === "running" || s === "active") return "active";
  if (s === "pending") return "pending";
  return "complete";
}

function statusColor(cls) {
  if (cls === "failed") return readCssVar("--danger") || "#dc2626";
  if (cls === "warning") return readCssVar("--warning") || "#d97706";
  if (cls === "active") return readCssVar("--accent-bright") || "#3b82f6";
  if (cls === "pending") return readCssVar("--border") || "#cbd5e1";
  return readCssVar("--success") || "#059669";
}

function renderSvg(stages, { loading = false } = {}) {
  const host = $("#pipeline-viz-host");
  if (!host) return;
  const list = stages?.length ? stages : STAGE_ORDER.map((id) => ({ id, label: id, status: "pending" }));
  const w = Math.max(720, list.length * 88);
  const h = 120;
  const nodeFill = readCssVar("--pipeline-node-fill") || "#ffffff";
  const nodes = list.map((st, i) => {
    const x = 56 + i * 82;
    const y = 56;
    const cls = loading && loadingIndex === i ? "active" : statusClass(st.status);
    const stroke = statusColor(cls);
    return { st, x, y, cls, stroke, nodeFill };
  });

  const edges = nodes
    .slice(0, -1)
    .map((n, i) => {
      const n2 = nodes[i + 1];
      const active = loading && (loadingIndex === i || loadingIndex === i + 1);
      return `<line class="pipeline-edge ${active ? "active" : ""}" x1="${n.x + 18}" y1="${n.y}" x2="${n2.x - 18}" y2="${n2.y}" />`;
    })
    .join("");

  const circles = nodes
    .map(
      ({ st, x, y, stroke, nodeFill, cls }) => `
    <g class="pipeline-node ${st.status === "pending" ? "dim" : ""}" data-stage-id="${escapeHtml(st.id)}">
      <circle cx="${x}" cy="${y}" r="16" fill="${escapeHtml(nodeFill)}" stroke="${escapeHtml(stroke)}" stroke-width="${cls === "active" ? 3.5 : 2.5}" />
      <circle cx="${x}" cy="${y}" r="6" fill="${escapeHtml(stroke)}" opacity="0.85" />
      <text class="pipeline-node-label" x="${x}" y="${y + 32}" text-anchor="middle">${escapeHtml((st.label || st.id).split(" ")[0])}</text>
      <title>${escapeHtml(st.summary || st.label || "")}</title>
    </g>`
    )
    .join("");

  host.innerHTML = `
    <div class="pipeline-svg-wrap">
      <h3 class="pipeline-heading">Compiler pipeline</h3>
      <svg class="pipeline-svg" viewBox="0 0 ${w} ${h}" width="100%" height="${h}" role="img" aria-label="Pipeline stages">
        ${edges}
        ${circles}
      </svg>
      <pre id="pipeline-stage-detail" class="pipeline-detail code-block" style="margin:0.75rem 0 0;max-height:160px;overflow:auto"></pre>
    </div>`;

  const detail = $("#pipeline-stage-detail");
  const pick = (id) => list.find((s) => s.id === id) || list[0];
  const show = (id) => {
    activeId = id;
    const stage = pick(id);
    if (detail) detail.textContent = stage?.detail || stage?.summary || "";
    $("#pipeline-detail") && ($("#pipeline-detail").textContent = detail?.textContent || "");
  };
  if (!activeId || !list.find((s) => s.id === activeId)) activeId = list[0]?.id;
  show(activeId);

  host.querySelectorAll(".pipeline-node").forEach((g) => {
    g.addEventListener("click", () => show(g.dataset.stageId));
  });
}

export function setPipelineLoading(on) {
  lastLoading = on;
  if (on) {
    loadingIndex = 0;
    renderSvg([], { loading: true });
    loadingTimer = window.setInterval(() => {
      loadingIndex = (loadingIndex + 1) % STAGE_ORDER.length;
      renderSvg([], { loading: true });
    }, 450);
  } else {
    if (loadingTimer) clearInterval(loadingTimer);
    loadingTimer = null;
  }
}

export function renderPipeline(stages) {
  lastStages = stages;
  setPipelineLoading(false);
  renderSvg(stages || []);
  window.SecureCCWorkbench?.renderPipelineRailCompat?.(stages);
}

export function refreshPipeline() {
  if (lastLoading) renderSvg([], { loading: true });
  else renderSvg(lastStages || []);
}

window.SecureCCPipeline = { refresh: refreshPipeline };