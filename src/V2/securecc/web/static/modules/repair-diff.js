import { $, escapeHtml, showToast } from "../lib/dom.js";
import { getMonacoThemeId } from "./theme.js";

function applyDiffTheme() {
  if (diffEditor && window.monaco) {
    window.monaco.editor.setTheme(getMonacoThemeId());
  }
}

window.addEventListener?.("securecc-theme-change", applyDiffTheme);

let diffEditor = null;

export async function renderRepairDiff(data, fix) {
  const host = $("#repair-diff-host");
  const stepper = $("#repair-stepper");
  const content = $("#repair-content");
  if (!host) return;

  const original = data.source?.content || "";
  const patched = fix?.patched_source || "";

  const steps = [
    { id: "id", label: "Vulnerability identified", done: (data.scan?.finding_count || 0) > 0 },
    { id: "rc", label: "Root cause analyzed", done: !!(data.explain?.explanations?.length) },
    { id: "gen", label: "Patch generated", done: !!patched && patched !== original },
    { id: "app", label: "Patch applied", done: !!patched },
    { id: "compile", label: "Compilation checked", done: data.compile?.ok !== false },
    { id: "scan", label: "Security re-analysis", done: !!fix },
    {
      id: "verify",
      label: "Verification",
      done: fix?.status === "VERIFIED",
    },
  ];

  if (stepper) stepper.innerHTML = "";

  if (!fix) {
    host.innerHTML = '<p class="muted">Enable Catalog heal and run Analyze to see repair diff.</p>';
    if (content) content.innerHTML = "";
    return;
  }

  await ensureDiffEditor();
  if (diffEditor && window.monaco) {
    const monaco = window.monaco;
    const origModel = monaco.editor.createModel(original, "c");
    const modModel = monaco.editor.createModel(patched || original, "c");
    diffEditor.setModel({ original: origModel, modified: modModel });
    host.style.display = "block";
  } else {
    host.innerHTML = `<div class="code-compare-fallback">
      <pre class="code-block half">${escapeHtml(original.slice(0, 8000))}</pre>
      <pre class="code-block half">${escapeHtml((patched || "").slice(0, 8000))}</pre>
    </div>`;
  }

  if (content && patched) {
    content.innerHTML = `
      <button type="button" class="btn btn-primary btn-sm" id="apply-patch-btn">Apply patched source to editor</button>`;
    $("#apply-patch-btn")?.addEventListener("click", () => {
      window.SecureCCMonaco?.setValue(patched);
      showToast("Patched source applied — run Analyze to verify");
    });
  } else if (content) {
    content.innerHTML = "";
  }
}

async function ensureDiffEditor() {
  const host = $("#repair-diff-host");
  if (!host || diffEditor) return;
  if (!window.SecureCCMonaco?.getMonaco?.()) {
    await window.SecureCCMonacoLoad?.();
  }
  const monaco = window.SecureCCMonaco?.getMonaco?.();
  if (!monaco) return;
  host.innerHTML = "";
  diffEditor = monaco.editor.createDiffEditor(host, {
    theme: getMonacoThemeId(),
    automaticLayout: true,
    readOnly: true,
    renderSideBySide: true,
  });
}