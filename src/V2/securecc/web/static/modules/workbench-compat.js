window.SecureCCWorkbench = (function () {
  function onAnalysis(payload) {
    return payload;
  }

  function onAgentPipeline(agentData) {
    if (!agentData?.pipeline?.stages?.length) return null;
    const merged = {
      ...(window.SecureCCApp?.getLastPayload?.() || {}),
      pipeline: agentData.pipeline,
    };
    if (agentData.display_scan) merged.scan = agentData.display_scan;
    else if (agentData.engine_scan) {
      merged.scan = {
        ...(merged.scan || {}),
        finding_count: agentData.engine_scan.finding_count,
        cwes: agentData.engine_scan.cwes,
      };
    }
    if (agentData.display_graph) merged.graph = agentData.display_graph;
    if (merged.scan && window.SecureCCApp?.renderDashboard) {
      window.SecureCCApp.renderDashboard(merged);
    }
    return merged;
  }

  function renderPipelineRailCompat() {}

  function showAttackSimulation(text) {
    const panel = document.querySelector("#attack-sim-panel");
    const el = document.querySelector("#attack-sim-text");
    if (panel && el) {
      el.textContent = text || "";
      panel.classList.toggle("hidden", !text);
    }
  }

  function simulateFromFinding(cweId, title) {
    const payload = window.SecureCCApp?.getLastPayload?.();
    if (!payload) return;
    const explain = (payload.explain?.explanations || payload.scan?.explanations || []).find(
      (e) => e.cwe_id === cweId
    );
    const impact =
      explain?.security_impact ||
      `An attacker could trigger ${title || cweId} by supplying inputs that reach the vulnerable IR path.`;
    const root = explain?.root_cause ? ` Root cause: ${explain.root_cause}` : "";
    showAttackSimulation(`${impact}${root}`);
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelector("#attack-sim-dismiss")?.addEventListener("click", () => showAttackSimulation(""));
  });

  return { onAnalysis, onAgentPipeline, renderPipelineRailCompat, simulateFromFinding, showAttackSimulation };
})();