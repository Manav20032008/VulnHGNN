/** @deprecated — use SecureCCLiveEngine */
import { resizeEngineGraph, setPreviewEnabled, updateFromPreview, clearEnginePanel } from "./live-engine-panel.js";

export function setPreviewEnabledWrapped(enabled) {
  setPreviewEnabled(enabled);
  window.SecureCCLiveFlow?.setPreviewEnabled?.(enabled);
}

export function updateMiniGraph(graph) {
  updateFromPreview({ graph, findings: window.SecureCCLivePreview?.getLastPreview?.()?.findings });
}

export function resizeMiniGraph() {
  resizeEngineGraph();
}

export function clearMiniGraph() {
  clearEnginePanel();
}

window.SecureCCLiveMiniGraph = {
  updateMiniGraph,
  resizeMiniGraph,
  clearMiniGraph,
  setPreviewEnabled: setPreviewEnabledWrapped,
};