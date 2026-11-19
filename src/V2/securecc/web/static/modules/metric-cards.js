import { $ } from "../lib/dom.js";
import { graphMetricCounts } from "./metrics-util.js";

function animateValue(el, target) {
  const str = String(target);
  if (str === "—" || Number.isNaN(Number(str))) {
    el.textContent = str;
    return;
  }
  const end = Number(str);
  const card = el.closest(".metric-card");
  card?.classList.add("value-animate");
  const start = Number(el.dataset.prev || 0);
  const dur = 400;
  const t0 = performance.now();
  const step = (t) => {
    const p = Math.min(1, (t - t0) / dur);
    el.textContent = String(Math.round(start + (end - start) * p));
    if (p < 1) requestAnimationFrame(step);
    else {
      el.dataset.prev = String(end);
      setTimeout(() => card?.classList.remove("value-animate"), 200);
    }
  };
  requestAnimationFrame(step);
}

export function renderMetricCards(data) {
  const scan = data.scan || {};
  const count = scan.finding_count || 0;
  const critical = (scan.findings || []).filter(
    (f) => (f.severity || "").toLowerCase() === "critical" || (f.severity || "").toLowerCase() === "high"
  ).length;
  const adj = data.adjudication || {};
  const engineCandidates = adj.engine_candidate_count ?? data.engine_scan?.finding_count ?? count;
  const verification = data.verification || (data.fix ? data.fix.status : "—");
  const fix = data.fix;
  const graphCounts = graphMetricCounts(data);
  const healed =
    fix?.status === "VERIFIED"
      ? Object.values({ ...(fix.per_cwe || {}), ...(fix.advisory_per_cwe || {}) }).filter(Boolean).length
      : 0;

  $("#metrics").innerHTML = `
    <div class="metric-card"><div class="label">Confirmed</div><div class="value" data-metric="findings">0</div></div>
    <div class="metric-card"><div class="label">HGNN candidates</div><div class="value" data-metric="engine">0</div></div>
    <div class="metric-card"><div class="label">Critical / High</div><div class="value" data-metric="critical">0</div></div>
    <div class="metric-card"><div class="label">CWE categories</div><div class="value" data-metric="cwes">0</div></div>
    <div class="metric-card"><div class="label">Graph nodes</div><div class="value" data-metric="nodes">0</div></div>
    <div class="metric-card"><div class="label">Graph edges</div><div class="value" data-metric="edges">0</div></div>
    <div class="metric-card"><div class="label">Healed (verified)</div><div class="value" data-metric="healed">0</div></div>
    <div class="metric-card"><div class="label">Verification</div><div class="value" data-metric="verify">${verification}</div></div>`;

  animateValue($('[data-metric="findings"]'), count);
  animateValue($('[data-metric="engine"]'), engineCandidates);
  animateValue($('[data-metric="critical"]'), critical);
  animateValue($('[data-metric="cwes"]'), (scan.cwes || []).length);
  animateValue($('[data-metric="nodes"]'), graphCounts.nodes);
  animateValue($('[data-metric="edges"]'), graphCounts.edges);
  animateValue($('[data-metric="healed"]'), healed);
}