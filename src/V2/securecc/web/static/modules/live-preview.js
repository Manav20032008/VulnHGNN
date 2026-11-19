import { $ } from "../lib/dom.js";
import { onPreviewResult } from "./live-viz.js";

const DEBOUNCE_MS = 2800;
let timer = null;
let abort = null;
let enabled = false;
let lastPayload = null;
let previewRequestSeq = 0;

function getSource() {
  return window.SecureCCMonaco?.getValue?.() ?? $("#source-editor")?.value ?? "";
}

async function runPreview() {
  const source = getSource();
  if (!enabled || !source.trim()) return;

  if (abort) abort.abort();
  abort = new AbortController();
  const reqSeq = ++previewRequestSeq;

  const t0 = performance.now();
  window.SecureCCLiveEngine?.setPipelineStage?.("compile");
  try {
    const res = await fetch("/api/analyze/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: abort.signal,
      body: JSON.stringify({
        source,
        language: window.SecureCCApp?.getEditorLanguage?.() || "c",
        filename:
          window.SecureCCApp?.getEditorLanguage?.() === "cpp"
            ? "editor_workspace.cpp"
            : window.SecureCCApp?.getEditorLanguage?.() === "java"
              ? "editor_workspace.java"
              : "editor_workspace.c",
      }),
    });
    const data = await res.json();
    if (reqSeq !== previewRequestSeq) return;
    if (!res.ok) throw new Error(data.error || "preview failed");
    window.SecureCCLiveEngine?.setPipelineStage?.("ir");
    lastPayload = data;
    onPreviewResult({ ...data, _clientMs: performance.now() - t0 });
  } catch (err) {
    if (err.name === "AbortError") return;
    window.SecureCCLiveEngine?.setPipelineStage?.("idle");
  }
}

export function schedulePreview() {
  if (!enabled) return;
  clearTimeout(timer);
  timer = setTimeout(runPreview, DEBOUNCE_MS);
}

export function initLivePreview() {
  const toggle = $("#live-preview-toggle");
  if (!toggle) return;

  toggle.addEventListener("change", (e) => {
    enabled = e.target.checked;
    const chip = $("#editor-analysis-chip");
    chip?.classList.add("hidden");
    window.SecureCCLiveMiniGraph?.setPreviewEnabled?.(enabled);
    if (enabled) schedulePreview();
    else onPreviewResult({ finding_count: 0, graph_counts: {}, compile: { ok: true } });
  });
  window.SecureCCLiveMiniGraph?.setPreviewEnabled?.(toggle.checked);
}

function updateGraph(graph, preview) {
  if (!graph) return;
  window.SecureCCPreviewGraph = { graph, preview };
  window.SecureCCMonaco?.applyFindingDecorations?.(preview?.findings || []);
  const panel = $("#panel-graph");
  if (panel?.classList.contains("active") && typeof SecureCCGraph !== "undefined") {
    SecureCCGraph.render($("#graph-container"), graph);
    const gstats = $("#graph-stats");
    if (gstats && preview?.graph_counts) {
      gstats.textContent = `Live preview · ${preview.graph_counts.nodes} nodes shown`;
    }
  }
}

window.SecureCCLivePreview = { schedulePreview, updateGraph, getLastPreview: () => lastPayload };