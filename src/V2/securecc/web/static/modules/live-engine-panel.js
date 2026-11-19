/* global SecureCCGraph */
import { $ } from "../lib/dom.js";

let lastPreview = null;
let prevHighlightCount = 0;
let lastFindings = [];
let graphReady = false;
let pendingGraph = null;
let graphResizeObserver = null;

function previewEnabled() {
  return Boolean($("#live-preview-toggle")?.checked);
}

function engineSectionVisible() {
  const section = $("#live-section-engine");
  return section && !section.classList.contains("hidden");
}

function setPlaceholder(show) {
  $("#live-engine-placeholder")?.classList.toggle("hidden", !show);
  $("#live-engine-live")?.classList.toggle("hidden", show);
}

function setGraphHostVisible(visible) {
  const host = $("#live-preview-graph-host");
  if (!host) return;
  host.classList.toggle("hidden", !visible);
}

export function setPreviewEnabled(enabled) {
  setPlaceholder(!enabled);
  setGraphHostVisible(enabled);
  if (!enabled) {
    clearGraphHost();
    setPipelineProgress(-1);
    lastFindings = [];
  } else if (lastPreview) {
    updateFromPreview(lastPreview);
    requestAnimationFrame(() => flushPendingGraph());
  } else {
    setPipelineProgress(0);
  }
}

const STAGE_PCT = { source: 15, compile: 40, ir: 70, detect: 100 };

export function setPipelineStage(stage) {
  const pct = stage === "idle" ? -1 : STAGE_PCT[stage] ?? 0;
  setPipelineProgress(pct);
}

export function setPipelineProgress(pct) {
  const bar = $("#live-engine-progress-fill");
  if (!bar) return;
  if (pct < 0) {
    bar.style.width = "0%";
    bar.setAttribute("aria-valuenow", "0");
    return;
  }
  bar.style.width = `${Math.min(100, Math.max(0, pct))}%`;
  bar.setAttribute("aria-valuenow", String(pct));
}

function countHighlights(graph) {
  return (graph?.nodes || []).filter((n) => n.highlight).length;
}

export function buildEgoGraph(graph) {
  if (!graph?.nodes?.length) return graph;
  const nodes = graph.nodes;
  const edges = graph.edges || [];
  if (nodes.length <= 120) return graph;

  const hi = new Set(nodes.filter((n) => n.highlight).map((n) => String(n.id)));
  let keep;
  if (hi.size) {
    keep = new Set(hi);
    for (const e of edges) {
      const s = String(e.source);
      const t = String(e.target);
      if (hi.has(s) || hi.has(t)) {
        keep.add(s);
        keep.add(t);
      }
    }
    for (const n of nodes) {
      if (n.type === "block" && [...keep].some((id) => edges.some((e) => String(e.source) === id || String(e.target) === id))) {
        /* keep blocks adjacent */
      }
    }
  } else {
    keep = new Set(nodes.filter((n) => n.type === "block").slice(0, 60).map((n) => String(n.id)));
    for (const e of edges) {
      if (keep.has(String(e.source)) || keep.has(String(e.target))) {
        keep.add(String(e.source));
        keep.add(String(e.target));
      }
    }
  }

  const filteredNodes = nodes.filter((n) => keep.has(String(n.id)));
  const ids = new Set(filteredNodes.map((n) => String(n.id)));
  const filteredEdges = edges.filter(
    (e) => ids.has(String(e.source)) && ids.has(String(e.target))
  );
  return {
    ...graph,
    nodes: filteredNodes,
    edges: filteredEdges,
    truncated: true,
    shown_nodes: filteredNodes.length,
    total_nodes: graph.total_nodes ?? nodes.length,
  };
}

function updateGraphMeta(graph, preview) {
  const meta = $("#live-engine-graph-meta");
  if (!meta || !graph) return;
  const hi = countHighlights(graph);
  const shown = graph.shown_nodes ?? graph.nodes?.length ?? 0;
  const total = graph.total_nodes ?? shown;
  const fc = preview?.finding_count ?? lastFindings.length;
  meta.textContent = `${shown} nodes · ${hi} hot · ${fc} findings`;
}

function syncFindingsLegend(findings) {
  const strip = $("#live-engine-cwe-legend");
  if (!strip) return;
  lastFindings = findings || [];
  const cwes = [...new Set(lastFindings.map((f) => f.cwe_id).filter(Boolean))].slice(0, 8);
  if (!cwes.length) {
    strip.innerHTML = "";
    strip.classList.add("hidden");
    return;
  }
  strip.classList.remove("hidden");
  strip.innerHTML = cwes
    .map((c) => `<span class="live-cwe-pip" title="${c}"></span>`)
    .join("");
}

function clearGraphHost() {
  const host = $("#live-preview-graph-host");
  if (host && typeof SecureCCGraph !== "undefined") SecureCCGraph.destroy(host);
  graphReady = false;
  pendingGraph = null;
}

function ensureGraphHostSize(host) {
  if (!host) return;
  const h = Math.max(host.clientHeight, 300);
  const w = host.clientWidth || host.parentElement?.clientWidth;
  if (w) host.style.width = "100%";
  host.style.minHeight = "300px";
  host.style.height = `${h}px`;
}

function paintGraph(graph) {
  const host = $("#live-preview-graph-host");
  if (!host || typeof SecureCCGraph === "undefined") return;
  if (!previewEnabled()) return;

  if (!graph?.nodes?.length) {
    clearGraphHost();
    host.innerHTML =
      '<p class="muted small" style="padding:1.5rem;text-align:center">No IR nodes in this preview.</p>';
    return;
  }

  ensureGraphHostSize(host);
  if (host.clientWidth < 50) {
    pendingGraph = graph;
    return;
  }

  const view = buildEgoGraph(graph);
  SecureCCGraph.render(host, view);
  graphReady = true;
  const hi = countHighlights(view);
  if (prevHighlightCount > 0 && hi > prevHighlightCount) {
    host.classList.add("live-ir-pulse");
    setTimeout(() => host.classList.remove("live-ir-pulse"), 600);
  }
  prevHighlightCount = hi;

  requestAnimationFrame(() => {
    SecureCCGraph.fitView?.(host);
    setTimeout(() => SecureCCGraph.fitView?.(host), 120);
  });
}

export function renderLiveIrGraph(graph) {
  if (!graph?.nodes?.length) {
    clearGraphHost();
    const host = $("#live-preview-graph-host");
    if (host) host.innerHTML = "";
    return;
  }
  if (!engineSectionVisible()) {
    pendingGraph = graph;
    return;
  }
  pendingGraph = null;
  paintGraph(graph);
}

export function flushPendingGraph() {
  if (pendingGraph && previewEnabled()) {
    paintGraph(pendingGraph);
    pendingGraph = null;
  } else if (lastPreview?.graph) {
    renderLiveIrGraph(lastPreview.graph);
  }
}

export function resizeEngineGraph() {
  if (!previewEnabled()) return;
  flushPendingGraph();
  const host = $("#live-preview-graph-host");
  if (!host) return;
  if (lastPreview?.graph?.nodes?.length) {
    paintGraph(lastPreview.graph);
  } else if (pendingGraph) {
    paintGraph(pendingGraph);
  }
}

export function updateFromPreview(preview) {
  lastPreview = preview;
  if (!previewEnabled()) {
    setPlaceholder(true);
    return;
  }
  setPlaceholder(false);
  setPipelineStage("detect");
  syncFindingsLegend(preview.findings || []);
  if (preview.graph) {
    updateGraphMeta(buildEgoGraph(preview.graph), preview);
    renderLiveIrGraph(preview.graph);
  } else if (preview.compile?.ok === false) {
    clearGraphHost();
    $("#live-engine-graph-meta") && ($("#live-engine-graph-meta").textContent = "Compile failed");
  }
}

export function clearEnginePanel() {
  lastPreview = null;
  prevHighlightCount = 0;
  lastFindings = [];
  clearGraphHost();
  setPipelineProgress(-1);
  $("#live-engine-graph-meta") && ($("#live-engine-graph-meta").textContent = "");
  $("#live-engine-cwe-legend")?.classList.add("hidden");
}

export function findingForNode(nodeId) {
  return lastFindings.find((f) => String(f.node_id) === String(nodeId));
}

export function initLiveEngineGraphResize() {
  const host = $("#live-preview-graph-host");
  if (!host || graphResizeObserver) return;
  graphResizeObserver = new ResizeObserver(() => {
    if (
      host.clientWidth > 50 &&
      host.clientHeight > 50 &&
      (pendingGraph || lastPreview?.graph) &&
      previewEnabled() &&
      engineSectionVisible()
    ) {
      const g = pendingGraph || lastPreview.graph;
      pendingGraph = null;
      paintGraph(g);
    }
  });
  graphResizeObserver.observe(host);
  if (host.parentElement) graphResizeObserver.observe(host.parentElement);
}

window.SecureCCLiveEngine = {
  updateFromPreview,
  setPreviewEnabled,
  setPipelineStage,
  setPipelineProgress,
  resizeEngineGraph,
  flushPendingGraph,
  clearEnginePanel,
  findingForNode,
  buildEgoGraph,
  initLiveEngineGraphResize,
};