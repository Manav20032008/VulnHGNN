/* global d3 */
import { $ } from "../lib/dom.js";
import { parseCallGraph } from "./call-graph-parse.js";

const NODE_W = 112;
const NODE_H = 36;
const PAD = 28;

let resizeObserver = null;
let refreshTimer = null;
const REFRESH_MS = 400;

function cssVar(name, fallback) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

function layoutGraph(graph) {
  const internal = graph.nodes.filter((n) => n.kind !== "external");
  const external = graph.nodes.filter((n) => n.kind === "external");
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));

  const out = new Map();
  const inn = new Map();
  for (const e of graph.edges || []) {
    out.set(e.source, [...(out.get(e.source) || []), e.target]);
    inn.set(e.target, [...(inn.get(e.target) || []), e.source]);
  }

  const layers = new Map();
  const roots = internal.filter((n) => !(inn.get(n.id) || []).some((id) => byId.get(id)?.kind !== "external"));
  if (!roots.length && internal.length) roots.push(internal.find((n) => n.kind === "entry") || internal[0]);

  const queue = roots.map((n) => ({ id: n.id, layer: 0 }));
  const seen = new Set();
  while (queue.length) {
    const { id, layer } = queue.shift();
    if (seen.has(id)) continue;
    seen.add(id);
    layers.set(id, Math.max(layers.get(id) || 0, layer));
    for (const t of out.get(id) || []) {
      const node = byId.get(t);
      if (node?.kind === "external") continue;
      if (byId.has(t)) queue.push({ id: t, layer: layer + 1 });
    }
  }

  for (const n of internal) {
    if (!layers.has(n.id)) layers.set(n.id, 0);
  }

  const maxLayer = Math.max(0, ...[...layers.values()]);
  const layerBuckets = new Map();
  for (const n of internal) {
    const L = layers.get(n.id) || 0;
    if (!layerBuckets.has(L)) layerBuckets.set(L, []);
    layerBuckets.get(L).push(n);
  }

  for (const [L, bucket] of layerBuckets) {
    bucket.sort((a, b) => a.label.localeCompare(b.label));
    bucket.forEach((n, i) => {
      n.x = PAD + L * (NODE_W + 72);
      n.y = PAD + i * (NODE_H + 44);
    });
  }

  const maxInternalY =
    internal.reduce((m, n) => Math.max(m, (n.y || 0) + NODE_H), PAD) + 24;
  const extX = PAD + (maxLayer + 1) * (NODE_W + 72);
  external.forEach((n, i) => {
    n.x = extX;
    n.y = PAD + i * (NODE_H + 28);
  });

  if (!internal.length && external.length) {
    external.forEach((n, i) => {
      n.x = PAD;
      n.y = PAD + i * (NODE_H + 28);
    });
  }

  const width = Math.max(
    320,
    extX + NODE_W + PAD,
    ...internal.map((n) => (n.x || 0) + NODE_W + PAD)
  );
  const height = Math.max(
    200,
    maxInternalY,
    external.length ? external[external.length - 1].y + NODE_H + PAD : 0
  );

  return { width, height, byId };
}

function linkPath(sx, sy, tx, ty) {
  const mx = (sx + tx) / 2;
  return `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ty}, ${tx} ${ty}`;
}

export function renderCallGraph(host, graph) {
  if (!host || typeof d3 === "undefined") return;
  d3.select(host).selectAll("*").remove();

  if (!graph?.nodes?.length) {
    host.innerHTML = '<p class="muted small live-call-graph-empty">No functions found in source</p>';
    return;
  }

  const { width, height, byId } = layoutGraph(graph);
  const colors = {
    stroke: cssVar("--border", "#cbd5e1"),
    accent: cssVar("--accent", "#2563eb"),
    purple: cssVar("--purple", "#7c3aed"),
    warn: cssVar("--warning", "#d97706"),
    danger: cssVar("--danger", "#dc2626"),
    fill: cssVar("--bg-secondary", "#f8fafc"),
    fillExt: cssVar("--bg", "#fff"),
    text: cssVar("--text", "#0f172a"),
    muted: cssVar("--text-muted", "#64748b"),
  };

  const svg = d3
    .select(host)
    .append("svg")
    .attr("width", "100%")
    .attr("height", "100%")
    .attr("viewBox", `0 0 ${width} ${height}`)
    .attr("role", "img")
    .attr("aria-label", "Call graph");

  const defs = svg.append("defs");
  defs
    .append("marker")
    .attr("id", "live-call-arrow")
    .attr("viewBox", "0 0 10 10")
    .attr("refX", 9)
    .attr("refY", 5)
    .attr("markerWidth", 6)
    .attr("markerHeight", 6)
    .attr("orient", "auto-start-reverse")
    .append("path")
    .attr("d", "M 0 0 L 10 5 L 0 10 Z")
    .attr("fill", colors.stroke);

  const g = svg.append("g");

  const nodeCenterY = (n) => (n.y ?? 0) + NODE_H / 2;
  const nodeRight = (n) => (n.x ?? 0) + NODE_W;
  const nodeLeft = (n) => n.x ?? 0;

  for (const e of graph.edges || []) {
    const s = byId.get(e.source);
    const t = byId.get(e.target);
    if (!s || !t) continue;
    const sx = nodeRight(s);
    const sy = nodeCenterY(s);
    const tx = t.kind === "external" ? nodeLeft(t) : nodeLeft(t);
    const ty = nodeCenterY(t);
    g.append("path")
      .attr("class", "live-call-edge")
      .attr("d", linkPath(sx, sy, tx, ty))
      .attr("fill", "none")
      .attr("stroke", colors.stroke)
      .attr("stroke-width", 1.5)
      .attr("marker-end", "url(#live-call-arrow)");
  }

  for (const e of graph.loops || []) {
    const n = byId.get(e.source);
    if (!n) continue;
    const x0 = (n.x ?? 0) + NODE_W * 0.75;
    const y0 = n.y ?? 0;
    const loop = `M ${x0} ${y0} C ${x0 + 50} ${y0 - 28}, ${x0 + 50} ${y0 + NODE_H + 28}, ${x0} ${y0 + NODE_H}`;
    g.append("path")
      .attr("class", "live-call-edge live-call-edge-loop")
      .attr("d", loop)
      .attr("fill", "none")
      .attr("stroke", colors.danger)
      .attr("stroke-width", 2)
      .attr("marker-end", "url(#live-call-arrow)");
  }

  const groups = g
    .selectAll(".live-call-node")
    .data(graph.nodes)
    .join("g")
    .attr("class", (d) => `live-call-node live-call-node-${d.kind}${d.risky ? " is-risky" : ""}`)
    .attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`)
    .style("cursor", "default");

  groups
    .append("rect")
    .attr("width", NODE_W)
    .attr("height", NODE_H)
    .attr("rx", 6)
    .attr("ry", 6)
    .attr("fill", (d) => (d.kind === "external" ? colors.fillExt : colors.fill))
    .attr("stroke", (d) => {
      if (d.risky) return colors.warn;
      if (d.kind === "entry") return colors.purple;
      if (d.kind === "external") return colors.warn;
      return colors.accent;
    })
    .attr("stroke-width", (d) => (d.kind === "entry" || d.risky ? 2 : 1.5))
    .attr("stroke-dasharray", (d) => (d.kind === "external" ? "5 3" : null));

  groups
    .append("text")
    .attr("x", NODE_W / 2)
    .attr("y", NODE_H / 2)
    .attr("text-anchor", "middle")
    .attr("dominant-baseline", "middle")
    .attr("fill", colors.text)
    .attr("font-size", 11)
    .attr("font-family", "JetBrains Mono, ui-monospace, monospace")
    .text((d) => (d.label.length > 14 ? `${d.label.slice(0, 12)}…` : d.label));

  groups.append("title").text((d) => d.label);
}

function currentSource() {
  return window.SecureCCMonaco?.getValue?.() ?? $("#source-editor")?.value ?? "";
}

export function scheduleCallGraph() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refreshCallGraph, REFRESH_MS);
}

export function refreshCallGraph() {
  const host = $("#live-call-graph-host");
  const meta = $("#live-call-graph-meta");
  if (!host) return;
  const lang = window.SecureCCApp?.getEditorLanguage?.() || "c";
  const graph = parseCallGraph(currentSource(), lang);
  renderCallGraph(host, graph);
  if (meta) {
    const { functions, calls, externals } = graph.stats || {};
    meta.textContent =
      functions != null
        ? `${functions} fn · ${calls || 0} edges${externals ? ` · ${externals} ext` : ""}`
        : "";
  }
}

export function resizeCallGraph() {
  refreshCallGraph();
}

export function initCallGraphResize() {
  const host = $("#live-call-graph-host");
  if (!host || resizeObserver) return;
  resizeObserver = new ResizeObserver(() => refreshCallGraph());
  resizeObserver.observe(host);
}

window.SecureCCLiveCallGraph = {
  refreshCallGraph,
  scheduleCallGraph,
  resizeCallGraph,
  initCallGraphResize,
};