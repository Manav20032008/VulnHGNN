window.SecureCCWorkbench = (function () {
  let activeStageId = "compile";
  let lastPipeline = null;

  function $(sel) {
    return document.querySelector(sel);
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function focusPipelineStage(pipeline) {
    const stages = pipeline?.stages || [];
    const detect = stages.find((s) => s.id === "detect");
    if (detect) {
      const m = String(detect.summary || "").match(/(\d+)\s+finding/);
      if (m && parseInt(m[1], 10) > 0) {
        return "detect";
      }
      if (detect) return "detect";
    }
    return stages[0]?.id || "compile";
  }

  function scrollStageIntoView(stageId) {
    const rail = $("#pipeline-rail");
    const btn = rail?.querySelector(`[data-stage-id="${stageId}"]`);
    btn?.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "center" });
  }

  function renderPipelineRail(stages) {
    const rail = $("#pipeline-rail");
    if (!rail) return;
    rail.innerHTML = (stages || [])
      .map((s) => {
        return `
      <button type="button" class="pipeline-step done ${s.id === activeStageId ? "active" : ""}" data-stage-id="${escapeHtml(s.id)}">
        <span class="pipeline-step-label">${escapeHtml(s.label)}</span>
        <span class="pipeline-step-summary">${escapeHtml(s.summary || "")}</span>
      </button>`;
      })
      .join("");

    rail.querySelectorAll(".pipeline-step").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeStageId = btn.dataset.stageId;
        renderPipelineDetail(lastPipeline);
        renderPipelineRail(lastPipeline?.stages || []);
      });
    });
  }

  function renderPipelineDetail(pipeline) {
    const pre = $("#pipeline-detail");
    if (!pre || !pipeline) return;
    const stage = (pipeline.stages || []).find((s) => s.id === activeStageId);
    pre.textContent = stage?.detail || stage?.summary || "(no detail)";
  }

  function showAttackSimulation(text) {
    const panel = $("#attack-sim-panel");
    const el = $("#attack-sim-text");
    if (!panel || !el) return;
    el.textContent = text || "";
    panel.classList.toggle("hidden", !text);
  }

  function onAnalysis(payload) {
    lastPipeline = payload.pipeline || null;
    $("#workbench-empty")?.classList.add("hidden");
    $("#pipeline-panel")?.classList.remove("hidden");
    if (lastPipeline?.stages?.length) {
      activeStageId = focusPipelineStage(lastPipeline);
      renderPipelineRail(lastPipeline.stages);
      renderPipelineDetail(lastPipeline);
      scrollStageIntoView(activeStageId);
    }
  }

  function onAgentPipeline(agentData) {
    if (!agentData?.pipeline?.stages?.length) return;
    const merged = {
      ...(window.SecureCCApp?.getLastPayload?.() || {}),
      pipeline: agentData.pipeline,
    };
    if (agentData.display_scan) {
      merged.scan = agentData.display_scan;
    } else if (agentData.engine_scan) {
      merged.scan = {
        ...(merged.scan || {}),
        finding_count: agentData.engine_scan.finding_count,
        cwes: agentData.engine_scan.cwes,
      };
    }
    if (agentData.display_graph) {
      merged.graph = agentData.display_graph;
    }
    lastPipeline = agentData.pipeline;
    $("#workbench-empty")?.classList.add("hidden");
    $("#pipeline-panel")?.classList.remove("hidden");
    activeStageId = focusPipelineStage(agentData.pipeline);
    renderPipelineRail(agentData.pipeline.stages);
    renderPipelineDetail(agentData.pipeline);
    scrollStageIntoView(activeStageId);
    if (merged.scan && window.SecureCCApp?.renderDashboard) {
      window.SecureCCApp.renderDashboard(merged);
    }
    return merged;
  }

  function simulateFromFinding(cweId, title) {
    const payload = window.SecureCCApp?.getLastPayload?.();
    if (!payload) return;
    const explain = (payload.explain?.explanations || payload.scan?.explanations || []).find(
      (e) => e.cwe_id === cweId
    );
    const impact =
      explain?.security_impact ||
      `An attacker could trigger ${title || cweId} by supplying inputs that reach the vulnerable IR path shown in Localization.`;
    const root = explain?.root_cause ? ` Root cause: ${explain.root_cause}` : "";
    showAttackSimulation(`${impact}${root}`);
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("#attack-sim-dismiss")?.addEventListener("click", () => showAttackSimulation(""));
  });

  return {
    onAnalysis,
    onAgentPipeline,
    simulateFromFinding,
    showAttackSimulation,
  };
})();
