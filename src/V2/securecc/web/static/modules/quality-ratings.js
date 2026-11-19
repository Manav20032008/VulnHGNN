import { $, escapeHtml } from "../lib/dom.js";

const DIM_META = {
  code_quality: { title: "Code quality", icon: "CQ" },
  secure_code: { title: "Secure code", icon: "SC" },
  compiler_diagnostics: { title: "Compiler health", icon: "CC" },
};

function barClass(score) {
  if (score >= 80) return "quality-bar-fill is-high";
  if (score >= 60) return "quality-bar-fill is-mid";
  return "quality-bar-fill is-low";
}

function rowHtml(key, dim) {
  if (!dim) return "";
  const meta = DIM_META[key] || { title: key, icon: "•" };
  const score = Number(dim.score) || 0;
  const label = dim.label || "";
  const summary = dim.summary || "";
  return `
    <div class="quality-rating-row">
      <div class="quality-rating-head">
        <span class="quality-rating-icon" aria-hidden="true">${meta.icon}</span>
        <div class="quality-rating-titles">
          <span class="quality-rating-name">${escapeHtml(meta.title)}</span>
          <span class="quality-rating-grade muted small">${escapeHtml(label)}</span>
        </div>
        <span class="quality-rating-score tabular-nums" aria-label="Score ${score} out of 100">${score}</span>
      </div>
      <div class="quality-bar-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${score}">
        <div class="${barClass(score)}" style="width: ${Math.max(0, Math.min(100, score))}%"></div>
      </div>
      ${summary ? `<p class="quality-rating-summary muted small">${escapeHtml(summary)}</p>` : ""}
    </div>`;
}

export function renderQualityRatings(data) {
  const mount = $("#analyze-quality-ratings");
  if (!mount) return;

  const qr = data?.quality_ratings;
  if (!qr?.dimensions || !Object.keys(qr.dimensions).length) {
    mount.innerHTML = "";
    mount.classList.add("hidden");
    return;
  }

  const dims = qr.dimensions;
  const overall = qr.overall;
  const status = qr.status || "";
  const note =
    status === "HEURISTIC" || status === "FALLBACK"
      ? `<p class="quality-ratings-note muted small">${escapeHtml(qr.message || "Estimated scores (AI rating partial or unavailable).")}</p>`
      : status === "COMPLETE"
        ? ""
        : qr.message
          ? `<p class="quality-ratings-note muted small">${escapeHtml(qr.message)}</p>`
          : "";

  const overallScore = overall?.score != null ? Number(overall.score) : null;
  const overallHtml =
    overallScore != null
      ? `<div class="quality-overall-pill" title="${escapeHtml(overall?.summary || "")}">
          <span class="quality-overall-label">Overall</span>
          <span class="quality-overall-score tabular-nums">${overallScore}</span>
        </div>`
      : "";

  mount.classList.remove("hidden");
  mount.innerHTML = `
    <section class="quality-ratings-card" aria-label="Code quality ratings">
      <header class="quality-ratings-header">
        <h3 class="quality-ratings-title">Quality overview</h3>
        ${overallHtml}
      </header>
      ${note}
      <div class="quality-ratings-grid">
        ${rowHtml("code_quality", dims.code_quality)}
        ${rowHtml("secure_code", dims.secure_code)}
        ${rowHtml("compiler_diagnostics", dims.compiler_diagnostics)}
      </div>
    </section>`;
}