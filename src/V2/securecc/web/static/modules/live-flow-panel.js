/* global d3 */
import { $ } from "../lib/dom.js";
import { summarizeFromGraph, branchHint } from "./flow-block-meta.js";

const BLOCK_W = 128;
const BLOCK_H = 46;
const PAD = 28;

let lastFlow = null;
let lastGraph = null;
let selectedFunc = null;
let selectedBlockId = null;
let resizeObs = null;

function previewEnabled() {
  return Boolean($("#live-preview-toggle")?.checked);
}

function cssVar(name, fallback) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

function flowFromSerializedGraph(graph) {
  if (!graph?.nodes?.length) return { functions: [] };
  lastGraph = graph;
  const blocks = graph.nodes.filter((n) => n.type === "block");
  const byFunc = new Map();
  for (const b of blocks) {
    const fn = b.function || "unknown";
    if (!byFunc.has(fn)) byFunc.set(fn, []);
    byFunc.get(fn).push(b);
  }

  const cfgEdges = (graph.edges || []).filter((e) => e.type === "control_flow");
  const blockIds = new Set(blocks.map((b) => b.id));
  const functions = [];

  for (const [name, blist] of [...byFunc.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(0, 4)) {
    const ids = new Set(blist.map((b) => b.id));
    const edges = cfgEdges.filter((e) => ids.has(e.source) && ids.has(e.target));
    const preds = new Map();
    for (const e of edges) {
      if (!preds.has(e.target)) preds.set(e.target, []);
      preds.get(e.target).push(e.source);
    }
    let entry = blist.find((b) => !(preds.get(b.id) || []).length)?.id;
    if (!entry) entry = blist[0]?.id;

    const domEdges = computeIdoms(blist.map((b) => b.id), edges, entry);
    const idomByTarget = new Map(domEdges.map((e) => [e.target, e.source]));

    const blocksOut = blist.map((b) => {
      const meta = summarizeFromGraph(graph, b.id, b.label || b.id);
      const parent = idomByTarget.get(b.id);
      let idom_title = null;
      if (parent) {
        const p = blist.find((x) => x.id === parent);
        idom_title = p ? summarizeFromGraph(graph, p.id, p.label).title : parent;
      }
      return {
        id: b.id,
        label: meta.ir_label,
        ...meta,
        highlight: b.highlight,
        idom_title,
      };
    });

    functions.push({
      name,
      entry,
      blocks: blocksOut,
      cfg_edges: edges.map((e) => ({
        source: e.source,
        target: e.target,
        branch: branchHint(graph, e.source, e.target),
      })),
      dom_edges: domEdges,
      block_count: blist.length,
    });
  }
  return { functions };
}

function computeIdoms(nodes, edges, entry) {
  if (!entry || !nodes.length) return [];
  const N = new Set(nodes);
  const preds = new Map(nodes.map((n) => [n, []]));
  const succs = new Map(nodes.map((n) => [n, []]));
  for (const e of edges) {
    if (!N.has(e.source) || !N.has(e.target)) continue;
    succs.get(e.source).push(e.target);
    preds.get(e.target).push(e.source);
  }

  const dom = new Map();
  for (const n of nodes) dom.set(n, new Set(nodes));

  const domEntry = new Set([entry]);
  for (const n of nodes) {
    if (n !== entry) dom.set(n, new Set(nodes.filter((x) => x !== entry)));
  }
  dom.set(entry, domEntry);

  let changed = true;
  while (changed) {
    changed = false;
    for (const n of nodes) {
      if (n === entry) continue;
      let newDom = new Set([...dom.get(n)].filter((x) => x !== n));
      const p = preds.get(n);
      if (p.length) {
        let inter = new Set(dom.get(p[0]));
        for (let i = 1; i < p.length; i++) {
          const d = dom.get(p[i]);
          inter = new Set([...inter].filter((x) => d.has(x)));
        }
        newDom = new Set([...inter, n]);
      }
      const cur = dom.get(n);
      if (newDom.size !== cur.size || [...newDom].some((x) => !cur.has(x))) {
        dom.set(n, newDom);
        changed = true;
      }
    }
  }

  const idoms = [];
  for (const n of nodes) {
    if (n === entry) continue;
    const d = [...dom.get(n)].filter((x) => x !== n);
    if (!d.length) continue;
    const strict = d.filter((x) => x !== entry || d.length === 1);
    const parent = strict.sort((a, b) => dom.get(a).size - dom.get(b).size)[0];
    if (parent) idoms.push({ source: parent, target: n });
  }
  return idoms;
}

function activeFunctionView() {
  if (!lastFlow?.functions?.length) return null;
  const name = selectedFunc || lastFlow.functions[0].name;
  return lastFlow.functions.find((f) => f.name === name) || lastFlow.functions[0];
}

function layoutCfg(view) {
  const byId = new Map(view.blocks.map((b) => [b.id, { ...b }]));
  const out = new Map();
  const inn = new Map();
  for (const e of view.cfg_edges || []) {
    out.set(e.source, [...(out.get(e.source) || []), e.target]);
    inn.set(e.target, [...(inn.get(e.target) || []), e.source]);
  }

  const layers = new Map();
  const queue = [{ id: view.entry, layer: 0 }];
  const seen = new Set();
  while (queue.length) {
    const { id, layer } = queue.shift();
    if (seen.has(id)) continue;
    seen.add(id);
    layers.set(id, Math.max(layers.get(id) || 0, layer));
    for (const t of out.get(id) || []) {
      if (byId.has(t)) queue.push({ id: t, layer: layer + 1 });
    }
  }
  for (const b of view.blocks) {
    if (!layers.has(b.id)) layers.set(b.id, 0);
  }

  const bucket = new Map();
  for (const b of view.blocks) {
    const L = layers.get(b.id) || 0;
    if (!bucket.has(L)) bucket.set(L, []);
    bucket.get(L).push(byId.get(b.id));
  }

  let maxLayer = 0;
  for (const [L, list] of bucket) {
    maxLayer = Math.max(maxLayer, L);
    list.sort((a, b) => (a.source_line || 9999) - (b.source_line || 9999) || (a.label || "").localeCompare(b.label || ""));
    list.forEach((n, i) => {
      n.x = PAD + L * (BLOCK_W + 64);
      n.y = PAD + i * (BLOCK_H + 40);
    });
  }

  const width = PAD * 2 + (maxLayer + 1) * (BLOCK_W + 64);
  const height =
    PAD * 2 +
    Math.max(1, ...[...bucket.values()].map((list) => list.length)) * (BLOCK_H + 40);

  return { byId, width, height };
}

function layoutDom(view) {
  const byId = new Map(view.blocks.map((b) => [b.id, { ...b }]));
  const children = new Map();
  for (const e of view.dom_edges || []) {
    children.set(e.source, [...(children.get(e.source) || []), e.target]);
  }

  const depth = new Map();
  function walk(id, d) {
    depth.set(id, Math.max(depth.get(id) || 0, d));
    for (const c of children.get(id) || []) walk(c, d + 1);
  }
  walk(view.entry, 0);
  for (const b of view.blocks) {
    if (!depth.has(b.id)) depth.set(b.id, 0);
  }

  const byLevel = new Map();
  for (const b of view.blocks) {
    const L = depth.get(b.id) || 0;
    if (!byLevel.has(L)) byLevel.set(L, []);
    byLevel.get(L).push(byId.get(b.id));
  }

  let maxDepth = 0;
  for (const [L, list] of byLevel) {
    maxDepth = Math.max(maxDepth, L);
    const span = list.length * (BLOCK_W + 24);
    list.sort((a, b) => (a.source_line || 9999) - (b.source_line || 9999));
    list.forEach((n, i) => {
      n.x = PAD + i * (BLOCK_W + 28) - span / 2 + (PAD + maxDepth * 88);
      n.y = PAD + L * (BLOCK_H + 48);
    });
  }

  const maxRow = Math.max(1, ...[...byLevel.values()].map((l) => l.length));
  const width = Math.max(360, PAD * 2 + maxRow * (BLOCK_W + 28));
  const height = PAD * 2 + (maxDepth + 1) * (BLOCK_H + 48);
  return { byId, width, height, children, depth };
}

function renderCfgHost(host, view) {
  if (!host || typeof d3 === "undefined") return;
  d3.select(host).selectAll("*").remove();
  if (!view?.blocks?.length) {
    host.innerHTML = '<p class="muted small live-flow-empty">No basic blocks</p>';
    return;
  }

  const { byId, width, height } = layoutCfg(view);
  const colors = palette();

  const svg = d3
    .select(host)
    .append("svg")
    .attr("width", "100%")
    .attr("height", "100%")
    .attr("viewBox", `0 0 ${width} ${height}`);

  svg
    .append("defs")
    .append("marker")
    .attr("id", "live-cfg-arrow")
    .attr("viewBox", "0 0 10 10")
    .attr("refX", 9)
    .attr("refY", 5)
    .attr("markerWidth", 5)
    .attr("markerHeight", 5)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M 0 0 L 10 5 L 0 10 Z")
    .attr("fill", colors.cfg);

  const g = svg.append("g");

  for (const e of view.cfg_edges || []) {
    const s = byId.get(e.source);
    const t = byId.get(e.target);
    if (!s || !t) continue;
    const sx = s.x + BLOCK_W;
    const sy = s.y + BLOCK_H / 2;
    const tx = t.x;
    const ty = t.y + BLOCK_H / 2;
    const mx = (sx + tx) / 2;
    g.append("path")
      .attr("d", `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ty}, ${tx} ${ty}`)
      .attr("fill", "none")
      .attr("stroke", colors.cfg)
      .attr("stroke-width", 1.5)
      .attr("marker-end", "url(#live-cfg-arrow)");
    if (e.branch) {
      g.append("text")
        .attr("x", mx)
        .attr("y", (sy + ty) / 2 - 4)
        .attr("text-anchor", "middle")
        .attr("fill", colors.muted)
        .attr("font-size", 8)
        .text(e.branch);
    }
  }

  drawBlocks(g, byId, colors, view.entry, false, "cfg");
}

function renderDomHost(host, view) {
  if (!host || typeof d3 === "undefined") return;
  d3.select(host).selectAll("*").remove();
  if (!view?.blocks?.length) {
    host.innerHTML = '<p class="muted small live-flow-empty">No dominator tree</p>';
    return;
  }

  const { byId, width, height } = layoutDom(view);
  const colors = palette();
  const svg = d3
    .select(host)
    .append("svg")
    .attr("width", "100%")
    .attr("height", "100%")
    .attr("viewBox", `0 0 ${width} ${height}`);

  svg
    .append("defs")
    .append("marker")
    .attr("id", "live-dom-arrow")
    .attr("viewBox", "0 0 10 10")
    .attr("refX", 9)
    .attr("refY", 5)
    .attr("markerWidth", 5)
    .attr("markerHeight", 5)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M 0 0 L 10 5 L 0 10 Z")
    .attr("fill", colors.dom);

  const g = svg.append("g");
  for (const e of view.dom_edges || []) {
    const s = byId.get(e.source);
    const t = byId.get(e.target);
    if (!s || !t) continue;
    const sx = s.x + BLOCK_W / 2;
    const sy = s.y + BLOCK_H;
    const tx = t.x + BLOCK_W / 2;
    const ty = t.y;
    g.append("path")
      .attr("d", `M ${sx} ${sy} C ${sx} ${(sy + ty) / 2}, ${tx} ${(sy + ty) / 2}, ${tx} ${ty}`)
      .attr("fill", "none")
      .attr("stroke", colors.dom)
      .attr("stroke-width", 1.5)
      .attr("stroke-opacity", 0.9)
      .attr("marker-end", "url(#live-dom-arrow)");
  }

  drawBlocks(g, byId, colors, view.entry, true, "dom");
}

function palette() {
  return {
    fill: cssVar("--bg-secondary", "#f8fafc"),
    stroke: cssVar("--accent", "#2563eb"),
    entry: cssVar("--purple", "#7c3aed"),
    hot: cssVar("--danger", "#dc2626"),
    text: cssVar("--text", "#0f172a"),
    cfg: cssVar("--cyan", "#0891b2"),
    dom: cssVar("--warning", "#d97706"),
    muted: cssVar("--text-muted", "#64748b"),
  };
}

function displayTitle(d) {
  return d.title || d.label || d.id;
}

function displaySubtitle(d, domView) {
  if (domView && d.idom_title) return `idom: ${d.idom_title}`;
  return d.subtitle || "";
}

function selectBlock(d, kind) {
  selectedBlockId = d.id;
  const detail = $(kind === "dom" ? "#live-dom-block-detail" : "#live-cfg-block-detail");
  if (detail) {
    const parts = [d.summary || `${displayTitle(d)} · ${d.subtitle || ""}`];
    if (d.idom_title) parts.push(`Immediate dominator: ${d.idom_title}`);
    if (d.source_line) parts.push(`Double-click to open line ${d.source_line}`);
    detail.textContent = parts.filter(Boolean).join(" · ");
  }
  if (d.source_line) window.SecureCCMonaco?.goToLine?.(d.source_line);
  paintFlowPanels();
}

function drawBlocks(g, byId, colors, entry, domView, kind) {
  const nodes = [...byId.values()];
  const groups = g
    .selectAll(".live-flow-block")
    .data(nodes)
    .join("g")
    .attr("class", (d) =>
      `live-flow-block${d.id === selectedBlockId ? " is-selected" : ""}${d.highlight ? " is-hot" : ""}`
    )
    .attr("transform", (d) => `translate(${d.x},${d.y})`)
    .style("cursor", "pointer")
    .on("click", (_, d) => selectBlock(d, kind))
    .on("dblclick", (_, d) => {
      if (d.source_line) window.SecureCCMonaco?.goToLine?.(d.source_line);
    });

  groups
    .append("rect")
    .attr("width", BLOCK_W)
    .attr("height", BLOCK_H)
    .attr("rx", 5)
    .attr("fill", colors.fill)
    .attr("stroke", (d) => {
      if (d.id === selectedBlockId) return colors.entry;
      if (d.highlight) return colors.hot;
      if (d.id === entry) return colors.entry;
      return colors.stroke;
    })
    .attr("stroke-width", (d) =>
      d.id === entry || d.highlight || d.id === selectedBlockId ? 2 : 1.25
    );

  groups
    .append("text")
    .attr("class", "live-flow-block-title")
    .attr("x", BLOCK_W / 2)
    .attr("y", 17)
    .attr("text-anchor", "middle")
    .attr("fill", colors.text)
    .attr("font-size", 9)
    .attr("font-weight", 600)
    .text((d) => {
      const t = displayTitle(d);
      return t.length > 22 ? `${t.slice(0, 20)}…` : t;
    });

  groups
    .append("text")
    .attr("class", "live-flow-block-sub")
    .attr("x", BLOCK_W / 2)
    .attr("y", 33)
    .attr("text-anchor", "middle")
    .attr("fill", colors.muted)
    .attr("font-size", 8)
    .text((d) => {
      const s = displaySubtitle(d, domView);
      return s.length > 26 ? `${s.slice(0, 24)}…` : s;
    });

  groups.append("title").text((d) => d.summary || `${displayTitle(d)}\n${d.subtitle || ""}`);
}

function syncFuncPicker() {
  const fns = lastFlow?.functions || [];
  const sels = document.querySelectorAll(".live-flow-func-select");
  if (!sels.length) return;
  const cur = selectedFunc || fns[0]?.name;
  sels.forEach((sel) => {
    if (!fns.length) {
      sel.innerHTML = "";
      sel.classList.add("hidden");
      return;
    }
    sel.classList.toggle("hidden", fns.length <= 1);
    sel.innerHTML = fns
      .map((f) => `<option value="${f.name}" ${f.name === cur ? "selected" : ""}>${f.name}</option>`)
      .join("");
    sel.value = cur;
  });
}

function setPlaceholders(show) {
  $("#live-cfg-placeholder")?.classList.toggle("hidden", !show);
  $("#live-cfg-live")?.classList.toggle("hidden", show);
  $("#live-dom-placeholder")?.classList.toggle("hidden", !show);
  $("#live-dom-live")?.classList.toggle("hidden", show);
}

export function paintFlowPanels() {
  const view = activeFunctionView();
  const cfgMeta = $("#live-cfg-meta");
  const domMeta = $("#live-dom-meta");
  if (cfgMeta) {
    cfgMeta.textContent = view
      ? `${view.block_count} blocks · ${view.cfg_edges?.length || 0} edges`
      : "";
  }
  if (domMeta) {
    domMeta.textContent = view
      ? `${view.dom_edges?.length || 0} tree edges`
      : "";
  }
  renderCfgHost($("#live-cfg-host"), view);
  renderDomHost($("#live-dom-host"), view);
}

export function updateFromPreview(preview) {
  if (!previewEnabled()) {
    setPlaceholders(true);
    return;
  }
  setPlaceholders(preview?.compile?.ok === false);

  if (preview?.compile?.ok === false) {
    lastFlow = null;
    paintFlowPanels();
    return;
  }

  lastGraph = preview?.graph || null;
  lastFlow =
    preview?.flow?.functions?.length != null
      ? preview.flow
      : flowFromSerializedGraph(preview?.graph);

  if (!selectedFunc && lastFlow?.functions?.[0]) {
    selectedFunc = lastFlow.functions[0].name;
  }
  syncFuncPicker();
  paintFlowPanels();
}

export function setPreviewEnabled(enabled) {
  setPlaceholders(!enabled);
  if (!enabled) {
    lastFlow = null;
    selectedFunc = null;
    paintFlowPanels();
  }
}

export function clearFlowPanels() {
  lastFlow = null;
  lastGraph = null;
  selectedFunc = null;
  selectedBlockId = null;
  $("#live-cfg-block-detail") && ($("#live-cfg-block-detail").textContent = "Select a block");
  $("#live-dom-block-detail") && ($("#live-dom-block-detail").textContent = "Select a block");
  paintFlowPanels();
}

export function resizeFlowPanels() {
  paintFlowPanels();
}

export function initLiveFlowPanels() {
  document.querySelectorAll(".live-flow-func-select").forEach((sel) => {
    sel.addEventListener("change", (e) => {
      selectedFunc = e.target.value;
      syncFuncPicker();
      paintFlowPanels();
    });
  });

  for (const id of ["live-cfg-enable-btn", "live-dom-enable-btn"]) {
    $(`#${id}`)?.addEventListener("click", () => {
      const toggle = $("#live-preview-toggle");
      if (toggle) {
        toggle.checked = true;
        toggle.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  }

  if (resizeObs) return;
  const hosts = [$("#live-cfg-host"), $("#live-dom-host")].filter(Boolean);
  if (!hosts.length || !window.ResizeObserver) return;
  resizeObs = new ResizeObserver(() => paintFlowPanels());
  hosts.forEach((h) => resizeObs.observe(h));
}

window.SecureCCLiveFlow = {
  updateFromPreview,
  setPreviewEnabled,
  clearFlowPanels,
  resizeFlowPanels,
  initLiveFlowPanels,
};