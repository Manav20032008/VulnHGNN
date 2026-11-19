/* global SecureCCGraph */

import { state, AGENT_PRESETS } from "../lib/state.js";
import { $, escapeHtml, showToast } from "../lib/dom.js";
import { renderPipeline, setPipelineLoading } from "./pipeline-viz.js";
import { pushActivity } from "./activity-feed.js";
import { recordAnalyzeSnapshot, refreshAnalytics } from "./analytics.js";
import { renderAgentSwimlane, renderAgentTimeline } from "./agent-activity.js";
import { renderRepairDiff } from "./repair-diff.js";
import { destroyFindingsChart, renderFindingsConfidenceChart } from "./findings-viz.js";
import {
  outcomeKind,
  renderAnalyzeOutcome,
  renderCleanFindingsEmpty,
} from "./analyze-outcome.js";
import { renderWelcome } from "./welcome.js";
import { setNavMode, navigateToTab } from "./tab-nav.js";
import { applyFindingDecorations } from "./monaco-shell.js";
window.showToast = showToast;

function getEditorSource() {
  return window.SecureCCMonaco?.getValue?.() ?? $("#source-editor")?.value ?? "";
}

function setEditorSource(v) {
  window.SecureCCMonaco?.setValue?.(v);
  const ta = $("#source-editor");
  if (ta) ta.value = v;
}

window.SecureCCApp = {
  hasPayload: () => Boolean(state.lastPayload),
  getLastPayload: () => state.lastPayload,
  getSelectedPath: () => state.selectedPath,
  getEditorLanguage: () => state.editorLanguage,
  getMeta: () => state.meta,
  renderDashboard,
  loadAaiSecurity,
  refreshRepairDiff: () => {
    if (state.lastPayload) renderRepairDiff(state.lastPayload, state.lastPayload.fix);
  },
  refreshCharts: () => refreshAnalytics(),
};

function editorWorkspaceName() {
  return state.languageMeta[state.editorLanguage]?.workspace || "editor_workspace.c";
}

function setEditorPathDisplay(name, { unsaved = false } = {}) {
  const pathEl = $("#editor-path");
  const badge = $("#editor-unsaved-badge");
  const label = name || "Untitled";
  if (pathEl) {
    pathEl.textContent = label;
    pathEl.title = label;
  }
  if (badge) badge.classList.toggle("hidden", !unsaved);
  $("#editor-title").textContent = name || "Source editor";
}

function resetLiveSessionState() {
  window.SecureCCLiveViz?.clearLiveSession?.();
}

function syncLanguageUi() {
  const lang = state.editorLanguage;
  const fixWrap = $("#include-fix-wrap");
  const fixBox = $("#include-fix");
  if (fixWrap) fixWrap.title = "";
  if (fixBox) fixBox.disabled = false;
  const sel = $("#editor-language");
  if (sel && sel.value !== lang) sel.value = lang;
  window.SecureCCSemanticLint?.schedule();
}

function setEditorLanguage(lang, { updatePlaceholder = false } = {}) {
  if (!state.languageMeta[lang]) lang = "c";
  state.editorLanguage = lang;
  syncLanguageUi();
  window.SecureCCMonaco?.setLanguage?.();
  if (updatePlaceholder) {
    if (!getEditorSource().trim()) {
      setEditorSource(state.languageMeta[lang].placeholder);
    }
  }
  setEditorPathDisplay(editorWorkspaceName(), { unsaved: true });
}

function setLoading(on) {
  const btn = $("#analyze-btn");
  if (btn) btn.disabled = on;
  const loading = $("#workbench-loading");
  if (loading) loading.classList.toggle("hidden", !on);
}

export async function fetchMeta() {
  const res = await fetch("/api/meta");
  const data = await res.json();
  state.meta = data;
  const el = $("#env-status");
  const parts = [];
  if (data.clang_available) parts.push("clang OK");
  else parts.push("clang missing");
  if (data.javac_available) parts.push("JDK OK");
  else parts.push("JDK off");
  if (data.java_llvm_available) parts.push("jllvm OK");
  if (data.groq_configured) parts.push("AI OK");
  else if (data.groq_hint) parts.push("AI: fix .env");
  else parts.push("AI off");
  el.textContent = `${data.tool} ${data.version} · ${parts.join(" · ")}`;
  el.className = data.clang_available && data.groq_configured ? "env-status ok" : "env-status warn";
  el.title = data.groq_hint || "";
  return data;
}

async function loadSourceIntoEditor(path) {
  const res = await fetch(`/api/source?path=${encodeURIComponent(path)}`);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "failed to load source");
  setEditorSource(data.content || "");
  state.selectedPath = data.path || path;
  setEditorPathDisplay(data.name || data.path || path, { unsaved: false });
  resetLiveSessionState();
  if (data.language) setEditorLanguage(data.language);
  else if (data.name?.endsWith(".java")) setEditorLanguage("java");
  else if (/\.(cpp|cc|cxx)$/i.test(data.name || "")) setEditorLanguage("cpp");
  else setEditorLanguage("c");
  window.SecureCCEditor?.refreshLineNumbers();
}

const SAMPLE_GROUP_ALIASES = {
  "Test suite": "Test & CWE samples",
  "CWE fixtures": "Test & CWE samples",
};

function groupSamples(samples) {
  const groups = new Map();
  for (const s of samples) {
    let cat = s.category || s.language || "Other";
    cat = SAMPLE_GROUP_ALIASES[cat] || cat;
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat).push(s);
  }
  return groups;
}

export async function loadSamples() {
  const res = await fetch("/api/samples");
  const { samples } = await res.json();
  const container = $("#sample-groups");
  if (!container) return;
  container.innerHTML = "";
  const groups = groupSamples(samples);
  let firstBtn = null;
  for (const [cat, items] of groups) {
    const section = document.createElement("div");
    section.className = "sample-group";
    const title = document.createElement("div");
    title.className = "sample-group-title";
    title.textContent = `${cat} (${items.length})`;
    const list = document.createElement("ul");
    list.className = "sample-list";
    items.forEach((s) => {
      const li = document.createElement("li");
      li.className = "sample-item";
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = s.label;
      btn.title = s.path;
      btn.dataset.path = s.path;
      btn.addEventListener("click", () => selectSample(s.path, btn));
      li.appendChild(btn);
      list.appendChild(li);
      if (!firstBtn) firstBtn = btn;
    });
    section.appendChild(title);
    section.appendChild(list);
    container.appendChild(section);
  }
  if (firstBtn && samples.length) {
    selectSample(samples[0].path, firstBtn);
  }
}

function selectSample(path, btn) {
  state.selectedPath = path;
  document.querySelectorAll(".sample-list button").forEach((b) => {
    b.classList.remove("active");
    b.closest(".sample-item")?.classList.remove("selected");
  });
  if (btn) {
    btn.classList.add("active");
    btn.closest(".sample-item")?.classList.add("selected");
  }
  loadSourceIntoEditor(path).catch((e) => showToast(e.message));
}

async function uploadFile(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch("/api/upload", { method: "POST", body: form });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "upload failed");
  state.selectedPath = data.path;
  loadSourceIntoEditor(data.path).catch((e) => showToast(e.message));
  if (data.language) setEditorLanguage(data.language);
  showToast(`Uploaded ${data.name}`);
}

export async function runAnalyze() {
  const source = getEditorSource();
  if (!source.trim()) {
    showToast("Add source in the editor first");
    return;
  }
  setLoading(true);
  setPipelineLoading(true);
  $("#editor-analysis-chip")?.classList.remove("hidden");
  $("#editor-analysis-chip") && ($("#editor-analysis-chip").textContent = "Analyzing…");
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source,
        language: state.editorLanguage,
        filename: editorWorkspaceName(),
        include_fix: $("#include-fix")?.checked,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "analysis failed");
    state.lastPayload = data;
    if (data.source?.path) state.selectedPath = data.source.path;
    renderWelcome(state.meta || {});
    renderDashboard(data);
    recordAnalyzeSnapshot(data);
    const confirmed = data.scan?.finding_count ?? 0;
    const engine = data.adjudication?.engine_candidate_count ?? confirmed;
    pushActivity(`Analyze complete · ${confirmed} confirmed (${engine} HGNN candidates)`);
    const kind = outcomeKind(data);
    if (data.compile?.ok === false) {
      showToast("Compile failed — see Overview for errors. Fix code to run full CWE scan.");
      pushActivity("Compilation failed");
    } else if (kind === "verified_clean" || kind === "engine_clean") {
      showToast(
        kind === "verified_clean"
          ? "No vulnerabilities confirmed · AI verified"
          : "No confirmed vulnerabilities in this run"
      );
      pushActivity("Analysis complete · clean");
    } else if (kind === "partial_clean") {
      showToast("No confirmed findings · partial AI review");
      pushActivity("Analysis complete · 0 confirmed (partial)");
    } else {
      pushActivity("IR graph built · detection finished");
    }
    const postKind = outcomeKind(data);
    const chip = $("#editor-analysis-chip");
    if (chip && (data.compile?.ok === false || postKind === "findings")) {
      chip.textContent = "Analysis ready";
      chip.classList.remove("editor-chip-clean", "editor-chip-partial");
    }
  } catch (err) {
    showToast(err.message);
    pushActivity(`Analyze error: ${err.message}`);
  } finally {
    setLoading(false);
    setPipelineLoading(false);
  }
}

export function renderDashboard(data) {
  $("#workbench-empty")?.classList.add("hidden");
  setNavMode(true);

  const scan = data.scan || {};
  const count = scan.finding_count || 0;
  const fix = data.fix;
  const compileFailed = data.compile && data.compile.ok === false;
  const verification = (data.verification || "").toUpperCase();

  $("#source-title").textContent = data.source?.name || "Source";
  $("#source-path").textContent = data.source?.path || "";

  const pill = $("#overall-status");
  pill.className = "status-pill";
  if (compileFailed) {
    pill.textContent = "Compile failed";
    pill.classList.add("rejected");
  } else if (verification === "CLEAN" && count === 0) {
    pill.textContent = "Clean · AI verified";
    pill.classList.add("clean");
  } else if (verification === "PARTIAL") {
    pill.textContent = count ? `${count} confirmed · partial` : "Review partial";
    pill.classList.add("findings");
  } else if (fix?.status === "VERIFIED" && count === 0) {
    pill.textContent = "Repair verified · clean";
    pill.classList.add("verified");
  } else if (fix?.status === "VERIFIED" && count > 0) {
    pill.textContent = `${count} finding(s) · engine not clean`;
    pill.classList.add("findings");
  } else if (count === 0) {
    pill.textContent = "Clean";
    pill.classList.add("clean");
  } else if (fix?.status === "REJECTED") {
    pill.textContent = "Findings · repair rejected";
    pill.classList.add("rejected");
  } else {
    pill.textContent = `${count} finding(s)`;
    pill.classList.add("findings");
  }

  renderPipeline(data.pipeline?.stages || []);
  applyFindingDecorations(scan.findings || []);

  renderAnalyzeOutcome(data);
  import("./code-chat.js")
    .then((m) => m.refreshCodeChatUi?.())
    .catch(() => {});
  renderOverview(data);
  renderFindings(scan, data);
  renderLocalization(scan);
  renderRepair(fix, data);
  renderRepairDiff(data, fix);
  $("#source-view").textContent = data.source?.content || "";
  if (data.compile_repair?.status === "repaired" && data.source?.content) {
    setEditorSource(data.source.content);
    pushActivity("Compile repair applied — editor source updated");
  }
  $("#raw-json").textContent = JSON.stringify(data, null, 2);

  const gstats = $("#graph-stats");
  if (data.graph) {
    const total = data.graph.total_nodes ?? data.graph.shown_nodes ?? 0;
    const shown = data.graph.shown_nodes ?? total;
    gstats.textContent =
      shown === total ? `${total} nodes` : `${shown} / ${total} nodes`;
    SecureCCGraph.render($("#graph-container"), data.graph);
  } else {
    gstats.textContent = "No IR graph (compile or analyze required).";
    $("#graph-container").innerHTML = "";
  }

  window.SecureCCWorkbench?.onAnalysis(data);
  window.SecureCCLiveFlow?.updateFromPreview?.({
    graph: data.graph,
    flow: data.flow,
    findings: data.scan?.findings,
    finding_count: data.scan?.finding_count,
    compile: data.compile || { ok: true },
  });
  navigateToTab("output");
}

function renderOverview(data) {
  const scan = data.scan || {};
  const cwes = (scan.cwes || []).join(", ") || "none";
  const compileFailed = data.compile && data.compile.ok === false;
  const compileDiags = data.compile?.diagnostics || [];

  let compileBlock = "";
  if (compileFailed) {
    const rows = compileDiags
      .map(
        (d) =>
          `<li><strong>L${escapeHtml(d.line)}</strong> [${escapeHtml(d.source || "compiler")}] ${escapeHtml(d.message || d.title || "")}</li>`
      )
      .join("");
    compileBlock = `
    <div class="card banner blocked">
      <h3>Compilation failed</h3>
      <p class="muted">${escapeHtml((data.compile.message || "").split("\n")[0])}</p>
      <p>Fix errors below, then run <strong>Analyze</strong> again for full IR CWE detection (division by zero, overflow, etc.).</p>
      ${rows ? `<ul class="compile-error-list">${rows}</ul>` : ""}
    </div>`;
  }

  const cr = data.compile_repair || {};
  const compileRepairBlock =
    cr.status === "repaired"
      ? `<div class="card card-accent"><h3 class="summary-card-title">Compile repair</h3><p class="muted small">Source auto-fixed before IR. Editor updated.</p></div>`
      : "";
  const adj = data.adjudication || {};
  const engineN = adj.engine_candidate_count ?? data.engine_scan?.finding_count ?? 0;
  const confirmed = scan.finding_count || 0;
  const graphN = data.graph?.total_nodes ?? data.graph?.shown_nodes ?? "—";
  const verification = (data.verification || "—").toUpperCase();
  const crit = (scan.findings || []).filter((f) => /critical|high/i.test(f.severity || "")).length;
  const cleanPass = !compileFailed && confirmed === 0;
  const slot = $("#overview-summary-slot") || $("#panel-overview");
  const summaryCard = cleanPass
    ? ""
    : `
    <article class="card analysis-summary-card">
      <header class="analysis-summary-head">
        <h3 class="summary-card-title">Analysis summary</h3>
        <span class="summary-verification-pill ${verification === "CLEAN" ? "clean" : ""}">${escapeHtml(verification)}</span>
      </header>
      <div class="analysis-summary-grid">
        <div class="summary-tile">
          <span class="summary-tile-val tabular-nums">${confirmed}</span>
          <span class="summary-tile-label">Confirmed</span>
        </div>
        <div class="summary-tile">
          <span class="summary-tile-val tabular-nums">${engineN}</span>
          <span class="summary-tile-label">HGNN candidates</span>
        </div>
        <div class="summary-tile">
          <span class="summary-tile-val tabular-nums">${crit}</span>
          <span class="summary-tile-label">High / critical</span>
        </div>
        <div class="summary-tile">
          <span class="summary-tile-val tabular-nums">${escapeHtml(String(graphN))}</span>
          <span class="summary-tile-label">IR nodes</span>
        </div>
      </div>
      <p class="summary-cwe-row muted small">CWEs: <strong class="mono">${escapeHtml(cwes)}</strong></p>
    </article>`;
  slot.innerHTML = `
    ${compileBlock}
    ${compileRepairBlock}
    ${summaryCard}
  `;
}

function renderFindings(scan, data) {
  const findings = scan.findings || [];
  const adj = data?.adjudication;
  destroyFindingsChart();

  const rows = findings
    .map(
      (f) => `
    <tr class="findings-row">
      <td><span class="cwe-tag">${escapeHtml(f.cwe_id)}</span></td>
      <td class="findings-title-cell">${escapeHtml(f.title || "")}
        ${f.adjudication_rationale ? `<p class="muted small">${escapeHtml(f.adjudication_rationale)}</p>` : ""}
      </td>
      <td><span class="severity ${escapeHtml(f.severity || "")}">${escapeHtml(f.severity || "")}</span></td>
      <td class="tabular-nums findings-conf-cell">${typeof f.confidence === "number" ? (f.confidence * 100).toFixed(0) : "—"}%</td>
      <td class="mono">${f.line ? `<button type="button" class="btn btn-ghost btn-sm line-jump" data-line="${f.line}">L${f.line}</button>` : "—"}</td>
    </tr>`
    )
    .join("");

  const rejected = (adj?.rejected || [])
    .map(
      (f) =>
        `<li class="muted small"><span class="cwe-tag">${escapeHtml(f.cwe_id || "")}</span> ${escapeHtml(f.title || "")}</li>`
    )
    .join("");
  const rejectedBlock = rejected
    ? `<details class="rejected-findings-block"><summary class="muted small">Rejected (${adj.rejected_count})</summary><ul>${rejected}</ul></details>`
    : "";

  const vizBlock =
    findings.length > 0
      ? `<div class="findings-viz-card card">
      <h3 class="summary-card-title">CWE · confidence</h3>
      <p class="muted small">Bar length = model confidence; color = severity.</p>
      <div class="findings-chart-wrap"><canvas id="findings-confidence-chart"></canvas></div>
    </div>`
      : "";

  const cleanEmpty = findings.length === 0 ? renderCleanFindingsEmpty(data) : null;
  $("#panel-findings").innerHTML =
    findings.length === 0
      ? `${cleanEmpty || '<p class="muted">No confirmed findings.</p>'}${rejectedBlock}`
      : `${vizBlock}
      <div class="table-wrap findings-table-wrap"><table class="data findings-table">
      <thead><tr><th>CWE</th><th>Issue</th><th>Severity</th><th>Conf.</th><th>Line</th></tr></thead>
      <tbody>${rows}</tbody></table></div>${rejectedBlock}`;

  if (findings.length) {
    const canvas = $("#findings-confidence-chart");
    requestAnimationFrame(() => renderFindingsConfidenceChart(canvas, findings));
  }

  $("#panel-findings").querySelector(".outcome-goto-output")?.addEventListener("click", () => {
    navigateToTab("output");
  });

  $("#panel-findings").querySelectorAll(".line-jump").forEach((btn) => {
    btn.addEventListener("click", () => {
      const line = parseInt(btn.dataset.line, 10);
      window.SecureCCMonaco?.highlightLine?.(line);
    });
  });
}

function renderLocalization(scan) {
  const items = scan.localization || [];
  if (!items.length) {
    $("#panel-localization").innerHTML = '<p class="muted">No localization data.</p>';
    return;
  }
  $("#panel-localization").innerHTML = items
    .map((loc) => {
      const steps = (loc.evidence || [])
        .map(
          (e) => `
        <div class="timeline-step">
          <strong>${escapeHtml(e.role || "evidence")}</strong>
          <p class="mono muted">${escapeHtml(e.node_id)}</p>
          <p class="mono">${escapeHtml(e.instruction || "")}</p>
        </div>`
        )
        .join("");
      return `
      <div class="card">
        <h3><span class="cwe-tag">${escapeHtml(loc.cwe_id)}</span>${escapeHtml(loc.title || "")}</h3>
        <p class="muted">Function: <span class="mono">${escapeHtml(loc.function || "")}</span> · Block: <span class="mono">${escapeHtml(String(loc.vulnerable_block || ""))}</span></p>
        <p class="mono">${escapeHtml(loc.vulnerable_instruction || "")}</p>
        <p class="muted">${escapeHtml(loc.rationale || "")}</p>
        <div class="timeline">${steps}</div>
      </div>`;
    })
    .join("");
}

function renderExplain(explain) {
  const list = explain?.explanations || [];
  if (!list.length) {
    $("#panel-explain").innerHTML = '<p class="muted">No explanations available.</p>';
    return;
  }
  $("#panel-explain").innerHTML = list
    .map((e) => {
      const ev = (e.evidence || [])
        .map(
          (item) =>
            `<li><strong>${escapeHtml(item.role)}</strong> ${escapeHtml(item.node_id)}: ${escapeHtml(item.instruction)}</li>`
        )
        .join("");
      return `
      <div class="card">
        <h3><span class="cwe-tag">${escapeHtml(e.cwe_id)}</span>${escapeHtml(e.title)}</h3>
        <p><span class="severity ${escapeHtml(e.severity)}">${escapeHtml(e.severity)}</span></p>
        <p><strong>Root cause</strong><br>${escapeHtml(e.root_cause)}</p>
        <p><strong>Impact</strong><br>${escapeHtml(e.security_impact)}</p>
        <p><strong>Repair strategy</strong><br>${escapeHtml(e.repair_strategy)}</p>
        <p><strong>Verification</strong><br>${escapeHtml(e.verification)}</p>
        <p class="muted">${escapeHtml(e.confidence_basis)}</p>
        <ul>${ev}</ul>
      </div>`;
    })
    .join("");
}

function renderDiagnostics(diag) {
  const items = diag?.diagnostics || [];
  if (!items.length) {
    $("#panel-diagnostics").innerHTML = `<p class="muted">Status: ${escapeHtml(diag?.status || "CLEAN")}</p>`;
    return;
  }
  $("#panel-diagnostics").innerHTML = items
    .map(
      (d) => `
    <div class="card">
      <h3><span class="cwe-tag">${escapeHtml(d.cwe_id)}</span>${escapeHtml(d.title)}</h3>
      <p class="mono">${escapeHtml(d.instruction)}</p>
      <p><strong>Root cause</strong> ${escapeHtml(d.root_cause)}</p>
      <p><strong>Impact</strong> ${escapeHtml(d.security_impact)}</p>
      <p><strong>Repair</strong> ${escapeHtml(d.repair_strategy)}</p>
    </div>`
    )
    .join("");
}

function renderLearn(learn) {
  const lessons = learn?.lessons || [];
  if (!lessons.length) {
    $("#panel-learn").innerHTML = '<p class="muted">No security lessons required — source passed current rules.</p>';
    return;
  }
  $("#panel-learn").innerHTML = lessons
    .map(
      (l) => `
    <div class="card">
      <h3><span class="cwe-tag">${escapeHtml(l.cwe_id)}</span>${escapeHtml(l.topic)}</h3>
      <p><strong>What is happening?</strong><br>${escapeHtml(l.concept)}</p>
      <p><strong>Why it matters</strong><br>${escapeHtml(l.why)}</p>
      <p><strong>Secure practice</strong><br>${escapeHtml(l.secure_practice)}</p>
      <p class="muted mono">${escapeHtml(l.function || "")} · ${escapeHtml(l.instruction || "")}</p>
    </div>`
    )
    .join("");
}

function renderRepair(fix) {
  const content = $("#repair-content");
  if (!content) return;
  state.lastPatchedSource = fix?.patched_source || null;
  content.innerHTML = "";
}

function renderEvidence(report) {
  if (!report) {
    $("#panel-evidence").innerHTML = '<p class="muted">No evidence report.</p>';
    return;
  }
  const items = (report.evidence || [])
    .map(
      (e) =>
        `<tr><td>${escapeHtml(e.cwe_id)}</td><td>${escapeHtml(e.role)}</td><td class="mono">${escapeHtml(e.node_id)}</td><td class="mono">${escapeHtml(e.instruction)}</td></tr>`
    )
    .join("");

  $("#panel-evidence").innerHTML = `
    <div class="card">
      <h3>Evidence report v${escapeHtml(String(report.report_version))}</h3>
      <p class="muted">Status: ${escapeHtml(report.status)} · Items: ${(report.evidence || []).length}</p>
    </div>
    <div class="table-wrap"><table class="data">
      <thead><tr><th>CWE</th><th>Role</th><th>Node</th><th>Instruction</th></tr></thead>
      <tbody>${items}</tbody>
    </table></div>
  `;
}


function initUpload() {
  const input = $("#file-input");
  const zone = $("#upload-zone");
  zone.addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    if (input.files[0]) uploadFile(input.files[0]).catch((e) => showToast(e.message));
  });
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.style.borderColor = "var(--accent)";
  });
  zone.addEventListener("dragleave", () => {
    zone.style.borderColor = "";
  });
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.style.borderColor = "";
    const file = e.dataTransfer.files[0];
    if (file) uploadFile(file).catch((err) => showToast(err.message));
  });
}

export function initApp() {
  setEditorLanguage("c", { updatePlaceholder: true });
  $("#editor-language")?.addEventListener("change", (e) => {
    setEditorLanguage(e.target.value, { updatePlaceholder: true });
  });
  $("#editor-new-btn")?.addEventListener("click", () => {
    setEditorSource(state.languageMeta[state.editorLanguage].placeholder);
    state.selectedPath = null;
    setEditorPathDisplay(editorWorkspaceName(), { unsaved: true });
    setEditorLanguage(state.editorLanguage);
    resetLiveSessionState();
    showToast("New editor buffer");
  });
  initUpload();
  $("#analyze-btn")?.addEventListener("click", runAnalyze);
  $("#graph-reset")?.addEventListener("click", () => {
    SecureCCGraph.resetView($("#graph-container"));
    SecureCCGraph.fitView?.($("#graph-container"));
  });
  $("#graph-search")?.addEventListener("input", (e) => {
    SecureCCGraph.filterNodes?.(e.target.value);
  });
  $("#agent-run")?.addEventListener("click", runAgent);
  document.querySelectorAll(".preset-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.preset;
      if (AGENT_PRESETS[key]) $("#agent-message").value = AGENT_PRESETS[key];
      document.querySelectorAll(".preset-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
    });
  });
  document.querySelector('.preset-btn[data-preset="benign"]')?.classList.add("active");
  $("#aai-run")?.addEventListener("click", () => loadAaiSecurity(true));
  $("#aai-refresh")?.addEventListener("click", () => loadAaiSecurity(false));
  const agentMsg = $("#agent-message");
  if (agentMsg && !agentMsg.value.trim() && AGENT_PRESETS.benign) {
    agentMsg.value = AGENT_PRESETS.benign;
  }
  renderAgentSwimlane(null);
}

function renderAgentSummary(data) {
  const el = $("#agent-summary");
  const blocked = data.blocked || data.status === "blocked";
  const bannerClass = blocked ? "blocked" : "ok";
  const title = blocked
    ? "Blocked by AAI security layer"
    : data.status === "completed"
      ? "AI analysis completed"
      : `Status: ${escapeHtml(data.status)}`;

  const steps = (data.steps || [])
    .map((s) => {
      const tool = s.tool ? ` → ${s.tool}` : "";
      const sum = s.result_summary;
      let extra = "";
      if (sum && sum.finding_count !== undefined) extra = ` (${sum.finding_count} findings)`;
      else if (sum && sum.status) extra = ` (${sum.status})`;
      else if (s.reason) extra = ` — ${s.reason}`;
      return `<li><strong>${escapeHtml(s.action)}</strong>${escapeHtml(tool)}${escapeHtml(extra)}</li>`;
    })
    .join("");

  el.innerHTML = `
    <div class="card banner ${bannerClass}">
      <h3>${title}</h3>
      <p>${escapeHtml(data.final_message || "")}</p>
      <p class="muted mono">session: ${escapeHtml(data.session_id || "")}</p>
    </div>
    ${steps ? `<div class="card"><h3>Analysis steps</h3><ul class="agent-step-list">${steps}</ul></div>` : ""}
  `;
  el.classList.remove("hidden");
  renderAgentArtifacts(data.tool_outputs || {});
}

function renderAgentArtifacts(outputs) {
  const container = $("#agent-artifacts");
  container.innerHTML = "";
  const parts = [];

  const scan = outputs.scan || outputs.rescan;
  const aiReview = outputs.ai_source_review;
  let findings = scan?.findings || [];
  if (!findings.length && aiReview?.issues?.length) {
    findings = aiReview.issues.map((i) => ({
      cwe_id: i.cwe_id,
      title: i.title,
      message: i.message,
      severity: i.severity,
    }));
  }
  if (findings.length) {
    const rows = findings
      .map(
        (f) =>
          `<tr><td><span class="cwe-tag">${escapeHtml(f.cwe_id)}</span></td>
          <td>${escapeHtml(f.title || "")}</td>
          <td class="mono">${escapeHtml(f.message || f.instruction || "")}</td></tr>`
      )
      .join("");
    parts.push(`<div class="card"><h3>Findings</h3>
      <div class="table-wrap"><table class="data"><thead><tr><th>CWE</th><th>Title</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table></div></div>`);
  } else if (scan && scan.finding_count === 0) {
    parts.push(`<div class="card"><h3>Findings</h3><p class="muted">No supported findings.</p></div>`);
  }

  const explain = outputs.explain;
  if (explain && explain.explanations && explain.explanations.length) {
    parts.push(
      explain.explanations
        .map((e) => {
          const ev = (e.evidence || [])
            .map((x) => `<li><strong>${escapeHtml(x.role)}</strong> ${escapeHtml(x.instruction || x.node_id)}</li>`)
            .join("");
          return `<div class="card"><h3><span class="cwe-tag">${escapeHtml(e.cwe_id)}</span> Explanation</h3>
            <p><strong>Root cause</strong><br>${escapeHtml(e.root_cause)}</p>
            <p><strong>Security impact</strong><br>${escapeHtml(e.security_impact)}</p>
            <p><strong>Repair strategy</strong><br>${escapeHtml(e.repair_strategy)}</p>
            ${ev ? `<ul>${ev}</ul>` : ""}</div>`;
        })
        .join("")
    );
  }

  const learn = outputs.learn;
  if (learn && learn.lessons && learn.lessons.length) {
    parts.push(
      learn.lessons
        .map(
          (l) =>
            `<div class="card"><h3><span class="cwe-tag">${escapeHtml(l.cwe_id)}</span> ${escapeHtml(l.topic)}</h3>
            <p>${escapeHtml(l.concept)}</p>
            <p class="muted"><strong>Practice:</strong> ${escapeHtml(l.secure_practice)}</p></div>`
        )
        .join("")
    );
  }

  const diag = outputs.diagnose;
  if (diag && diag.diagnostics && diag.diagnostics.length) {
    parts.push(
      diag.diagnostics
        .map(
          (d) =>
            `<div class="card"><h3>Diagnostic — ${escapeHtml(d.cwe_id)}</h3>
            <p>${escapeHtml(d.root_cause)}</p>
            <p class="muted mono">${escapeHtml(d.instruction || "")}</p></div>`
        )
        .join("")
    );
  }

  const fix = outputs.fix || outputs.catalog_heal;
  if (fix) {
    parts.push(`<div class="card"><h3>Repair pipeline</h3>
      <p><strong>Status:</strong> ${escapeHtml(fix.status || "unknown")}</p>
      <p>${escapeHtml(fix.message || "")}</p></div>`);
  }

  if (!parts.length) {
    container.innerHTML = `<p class="muted">No tool output to display yet.</p>`;
    return;
  }
  container.innerHTML = `<h3 class="agent-artifacts-title">SecureCC tool output (from AI analysis)</h3>${parts.join("")}`;
}

async function runAgent() {
  const source = getEditorSource();
  if (!source.trim()) {
    showToast("Add source in the editor first");
    return;
  }
  const message = $("#agent-message").value.trim();
  if (!message) {
    showToast("Enter a message for AI analysis");
    return;
  }
  $("#agent-summary").classList.add("hidden");
  $("#agent-artifacts").innerHTML = "";
  $("#agent-output").classList.add("hidden");
  $("#agent-summary").innerHTML = "<p class='muted'>Running AI analysis…</p>";
  $("#agent-summary").classList.remove("hidden");
  try {
    const res = await fetch("/api/agent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source,
        language: state.editorLanguage,
        filename: editorWorkspaceName(),
        path: state.selectedPath,
        message,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "agent failed");
    renderAgentSummary(data);
    renderAgentTimeline(data);
    pushActivity(`Agent ${data.status}${data.blocked ? " (blocked)" : ""}`);
    const merged = window.SecureCCWorkbench?.onAgentPipeline?.(data);
    if (merged) {
      state.lastPayload = merged;
      if (data.source_path) state.selectedPath = data.source_path;
      $("#dashboard")?.classList.remove("hidden");
    }
    loadAaiLog();
  } catch (err) {
    $("#agent-summary").innerHTML = `<div class="card banner blocked"><p>${escapeHtml(err.message)}</p></div>`;
    showToast(err.message);
  }
}

function renderAaiReport(report) {
  const m = report.metrics || {};
  $("#aai-metrics").innerHTML = `
    <div class="metric-card"><div class="label">Detection recall</div><div class="value">${(m.detection_recall_tpr * 100).toFixed(0)}%</div></div>
    <div class="metric-card"><div class="label">False positive rate</div><div class="value">${(m.false_positive_rate * 100).toFixed(0)}%</div></div>
    <div class="metric-card"><div class="label">Attack success (ASR)</div><div class="value">${(m.attack_success_rate_asr * 100).toFixed(0)}%</div></div>
    <div class="metric-card"><div class="label">F1 score</div><div class="value">${(m.f1_score * 100).toFixed(0)}%</div></div>
    <div class="metric-card"><div class="label">Block rate (attacks)</div><div class="value">${(m.malicious_block_rate * 100).toFixed(0)}%</div></div>
    <div class="metric-card"><div class="label">Mean detect time</div><div class="value">${m.mean_time_to_detect_ms} ms</div></div>
  `;

  const rows = (report.results || [])
    .map((r) => {
      const badge = r.blocked
        ? '<span class="badge-block">BLOCK</span>'
        : '<span class="badge-allow">ALLOW</span>';
      return `<tr>
        <td>${escapeHtml(r.scenario_id)}</td>
        <td>${escapeHtml(r.family)}</td>
        <td>${badge}</td>
        <td>${r.risk_score}</td>
        <td>${escapeHtml(r.attempted_tool || "")}</td>
        <td>${r.detected}</td>
      </tr>`;
    })
    .join("");

  $("#aai-results").innerHTML = `<table class="data">
    <thead><tr><th>ID</th><th>Family</th><th>Action</th><th>Risk</th><th>Tool</th><th>Detected</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

async function loadAaiLog() {
  try {
    const res = await fetch("/api/aai-security/log?limit=25");
    const data = await res.json();
    $("#aai-log").textContent = (data.entries || [])
      .map((e) => JSON.stringify(e))
      .join("\n");
  } catch {
    $("#aai-log").textContent = "(log unavailable)";
  }
}

export async function loadAaiSecurity(runSuite) {
  if (runSuite) {
    $("#aai-metrics").innerHTML = "<p class='muted'>Running attack simulation…</p>";
    try {
      const res = await fetch("/api/aai-security/run", { method: "POST" });
      const report = await res.json();
      if (!res.ok) throw new Error(report.error || "simulation failed");
      renderAaiReport(report);
      loadAaiLog();
      return;
    } catch (err) {
      showToast(err.message);
    }
  }
  try {
    const res = await fetch("/api/aai-security/report");
    if (res.ok) {
      renderAaiReport(await res.json());
    } else {
      $("#aai-metrics").innerHTML =
        '<p class="muted">No report yet. Click <strong>Run attack simulation</strong>.</p>';
      $("#aai-results").innerHTML = "";
    }
  } catch (err) {
    showToast(err.message);
  }
  loadAaiLog();
}
