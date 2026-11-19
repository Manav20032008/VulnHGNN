import { $, escapeHtml } from "../lib/dom.js";
import { navigateToTab } from "./tab-nav.js";
import { renderQualityRatings } from "./quality-ratings.js";

export function outcomeKind(data) {
  if (data?.compile?.ok === false) return "compile_failed";
  const confirmed = data?.scan?.finding_count || 0;
  if (confirmed > 0) return "findings";
  const verification = (data?.verification || "").toUpperCase();
  if (verification === "CLEAN") return "verified_clean";
  if (verification === "PARTIAL") return "partial_clean";
  return "engine_clean";
}

function updateEditorChip(kind) {
  const chip = $("#editor-analysis-chip");
  if (!chip) return;
  chip.classList.remove("hidden", "editor-chip-clean", "editor-chip-partial", "editor-chip-findings", "editor-chip-error");
  if (kind === "compile_failed") {
    chip.textContent = "Compile failed";
    chip.classList.add("editor-chip-error");
    return;
  }
  if (kind === "findings") {
    chip.textContent = "Findings";
    chip.classList.add("editor-chip-findings");
    return;
  }
  chip.textContent =
    kind === "verified_clean" ? "Verified clean" : kind === "partial_clean" ? "Clean · partial" : "Clean";
  chip.classList.toggle("editor-chip-clean", kind === "verified_clean" || kind === "engine_clean");
  chip.classList.toggle("editor-chip-partial", kind === "partial_clean");
}

export function renderAnalyzeOutcome(data) {
  const slot = $("#analyze-outcome-slot");
  if (!slot) return outcomeKind(data);

  const kind = outcomeKind(data);
  slot.className = "analyze-outcome-slot";

  if (kind === "compile_failed") {
    const msg = (data.compile?.message || "Compilation failed").split("\n")[0];
    slot.innerHTML = `
      <article class="analyze-outcome-card outcome-card-error" role="alert">
        <div class="analyze-outcome-icon outcome-icon-error" aria-hidden="true">!</div>
        <div class="analyze-outcome-body">
          <span class="outcome-badge outcome-badge-error">Compile failed</span>
          <h2 class="analyze-outcome-title">Analysis blocked</h2>
          <p class="analyze-outcome-sub muted">Fix compile errors in the editor, then run Analyze again for full IR detection.</p>
          <p class="mono small outcome-error-line">${escapeHtml(msg)}</p>
        </div>
      </article>`;
    updateEditorChip(kind);
    return kind;
  }

  if (kind === "findings") {
    const scan = data.scan || {};
    const confirmed = scan.finding_count || 0;
    const cwes = (scan.cwes || []).join(", ") || "—";
    const crit = (scan.findings || []).filter((f) => /critical|high/i.test(f.severity || "")).length;
    const verification = (data.verification || "—").toUpperCase();
    const adj = data.adjudication || {};
    const engineN = adj.engine_candidate_count ?? data.engine_scan?.finding_count ?? confirmed;

    slot.innerHTML = `
      <article class="analyze-outcome-card outcome-card-findings" role="status">
        <div class="analyze-outcome-icon outcome-icon-findings tabular-nums" aria-hidden="true">${confirmed}</div>
        <div class="analyze-outcome-body">
          <span class="outcome-badge outcome-badge-findings">${escapeHtml(verification)}</span>
          <h2 class="analyze-outcome-title">${confirmed} confirmed vulnerabilit${confirmed === 1 ? "y" : "ies"}</h2>
          <p class="analyze-outcome-sub muted">AI-confirmed from ${engineN} HGNN candidate${engineN === 1 ? "" : "s"}. See Detection → Findings for detail.</p>
          <dl class="analyze-outcome-stats">
            <div><dt>CWEs</dt><dd class="mono">${escapeHtml(cwes)}</dd></div>
            <div><dt>High / critical</dt><dd class="tabular-nums">${crit}</dd></div>
            <div><dt>Confirmed</dt><dd class="tabular-nums">${confirmed}</dd></div>
          </dl>
          <button type="button" class="btn btn-primary btn-sm outcome-goto-btn" data-goto="findings">View findings</button>
        </div>
      </article>`;

    slot.querySelector(".outcome-goto-btn")?.addEventListener("click", () => navigateToTab("findings"));
    renderQualityRatings(data);
    renderQualityRatings(null);
    updateEditorChip(kind);
    return kind;
  }

  const adj = data.adjudication || {};
  const engineN = adj.engine_candidate_count ?? data.engine_scan?.finding_count ?? 0;
  const rejected = adj.rejected_count ?? 0;
  const graphN = data.graph?.total_nodes ?? data.graph?.shown_nodes;
  const sourceName = data.source?.name || "Source";
  const heal = data.fix?.status === "VERIFIED" && (data.scan?.finding_count || 0) === 0;

  const title = heal
    ? "Remediated · no vulnerabilities"
    : kind === "verified_clean"
      ? "No vulnerabilities confirmed"
      : "No confirmed issues";

  const subtitle =
    kind === "verified_clean"
      ? "HGNN detection and AI adjudication found nothing to report for this source."
      : kind === "partial_clean"
        ? "Nothing confirmed. Review is partial — ensure Groq adjudication ran for a full AI verdict."
        : "Engine scan returned zero confirmed CWEs for this run.";

  const badge =
    kind === "verified_clean"
      ? `<span class="outcome-badge outcome-badge-clean">AI verified</span>`
      : kind === "partial_clean"
        ? `<span class="outcome-badge outcome-badge-partial">Partial review</span>`
        : `<span class="outcome-badge outcome-badge-neutral">Engine clean</span>`;

  const pr = data.program_run;
  let programOutputHtml = "";
  if (pr) {
    const status = pr.status || "";
    const stdout = (pr.stdout || "").trim();
    const stderr = (pr.stderr || "").trim();
    const showBody =
      status === "ok" || status === "run_failed" || status === "timeout"
        ? stdout || stderr || pr.message
        : status === "compile_failed"
          ? stderr || stdout || pr.message
          : status !== "skipped" && (stdout || stderr);
    if (showBody) {
      const label =
        status === "ok"
          ? "Program output"
          : status === "timeout"
            ? "Program output (timed out)"
            : status === "run_failed"
              ? `Program output (exit ${pr.exit_code ?? "?"})`
              : status === "compile_failed"
                ? "Build output"
                : "Program output";
      const body = stdout || stderr || pr.message || "—";
      programOutputHtml = `
        <section class="analyze-outcome-program" aria-label="Program execution output">
          <h3 class="analyze-outcome-program-title">${escapeHtml(label)}</h3>
          <pre class="program-run-output mono small">${escapeHtml(body)}</pre>
          ${stdout && stderr ? `<details class="program-run-stderr-details"><summary class="small muted">stderr</summary><pre class="program-run-output mono small">${escapeHtml(stderr)}</pre></details>` : ""}
        </section>`;
    } else if (status === "skipped" && pr.message) {
      programOutputHtml = `<p class="small muted analyze-outcome-program-skipped">${escapeHtml(pr.message)}</p>`;
    }
  }

  slot.innerHTML = `
    <article class="analyze-outcome-card ${kind === "verified_clean" ? "is-verified" : ""}" role="status" aria-live="polite">
      <div class="analyze-outcome-icon" aria-hidden="true">
        <svg viewBox="0 0 48 48" width="48" height="48" fill="none" aria-hidden="true">
          <circle cx="24" cy="24" r="22" class="outcome-icon-ring" fill="currentColor"/>
          <path class="outcome-icon-check" d="M14 25l7 7 13-14" stroke="currentColor" fill="none" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="analyze-outcome-body">
        <div class="outcome-badge-row">${badge}</div>
        <h2 class="analyze-outcome-title">${escapeHtml(title)}</h2>
        <p class="analyze-outcome-sub muted">${escapeHtml(subtitle)}</p>
        <dl class="analyze-outcome-stats">
          <div><dt>File</dt><dd class="mono">${escapeHtml(sourceName)}</dd></div>
          <div><dt>Confirmed</dt><dd class="tabular-nums">0</dd></div>
          <div><dt>HGNN candidates</dt><dd class="tabular-nums">${engineN}</dd></div>
          ${rejected ? `<div><dt>Rejected</dt><dd class="tabular-nums">${rejected}</dd></div>` : ""}
          ${graphN != null ? `<div><dt>IR nodes</dt><dd class="tabular-nums">${graphN}</dd></div>` : ""}
        </dl>
        ${programOutputHtml}
      </div>
    </article>`;

  renderQualityRatings(data);
  updateEditorChip(kind);
  return kind;
}

export function renderCleanFindingsEmpty(data) {
  const kind = outcomeKind(data);
  if (kind === "findings" || kind === "compile_failed") return null;

  const verification = (data?.verification || "—").toUpperCase();
  return `
    <div class="findings-clean-state" role="status">
      <div class="findings-clean-icon" aria-hidden="true">✓</div>
      <h3 class="findings-clean-title">All clear</h3>
      <p class="muted small findings-clean-copy">
        No confirmed CWEs. Full verdict on <strong>Output</strong> · ${escapeHtml(verification)}.
      </p>
      <button type="button" class="btn btn-ghost btn-sm outcome-goto-output">Open Output</button>
    </div>`;
}