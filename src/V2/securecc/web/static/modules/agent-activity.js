import { $, escapeHtml } from "../lib/dom.js";

export function renderAgentSwimlane() {
  const el = $("#agent-swimlane");
  if (el) el.innerHTML = "";
}

export function renderAgentTimeline(session) {
  const el = $("#agent-timeline");
  if (!el || !session) {
    if (el) el.innerHTML = "";
    return;
  }
  const items = (session.steps || []).map((s) => {
    const tool = s.tool || s.decision?.tool || s.phase || s.action;
    const reason = s.reason || s.decision?.reason || "";
    const sum = s.result_summary;
    let extra = "";
    if (sum?.finding_count !== undefined) extra = `${sum.finding_count} findings`;
    else if (sum?.status) extra = sum.status;
    return `<div class="agent-timeline-item">
      <strong>${escapeHtml(String(s.action || "step"))}</strong>
      ${tool ? `<span class="cwe-tag">${escapeHtml(String(tool))}</span>` : ""}
      <p class="muted small">${escapeHtml(reason)} ${extra ? `· ${escapeHtml(extra)}` : ""}</p>
    </div>`;
  });
  el.innerHTML = items.length ? items.join("") : "";
}