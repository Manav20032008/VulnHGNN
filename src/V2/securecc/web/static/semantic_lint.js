window.SecureCCSemanticLint = (function () {
  const DEBOUNCE_MS = 450;
  let timer = null;
  let abort = null;
  let lintRequestSeq = 0;

  const SOURCE_LABELS = {
    heuristic: "Quick check",
    compiler: "Compiler",
    semantic: "Naming",
    java: "Java",
  };

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

  function severityRank(d) {
    if (d.category === "ERROR") return 0;
    const sem = d.semantic?.confidence_label;
    if (sem === "HIGH") return 1;
    if (d.source === "compiler") return 2;
    return 3;
  }

  function topicKey(d) {
    const msg = (d.message || d.title || "").toLowerCase();
    if (
      msg.includes("division by zero") ||
      msg.includes("divides by literal zero") ||
      msg.includes("modulo by zero") ||
      msg.includes("may be zero")
    ) {
      return "div-zero";
    }
    if (msg.includes("printf") && msg.includes("format")) return "printf-format";
    if (msg.includes("semantic type") || d.source === "semantic") return `semantic-${d.semantic?.variable || d.line}`;
    return `${d.source}-${(d.title || msg).slice(0, 48)}`;
  }

  function friendlyTitle(d) {
    if (d.title && !/^semantic type mismatch/i.test(d.title)) {
      return d.title.replace(/^Semantic type mismatch:\s*/i, "Naming: ");
    }
    const msg = d.message || "";
    if (/division by zero|divides by literal zero/i.test(msg)) return "Division by zero";
    if (/printf.*format|format string/i.test(msg)) return "Unsafe or invalid printf usage";
    if (/strcpy|gets|sprintf|scanf/i.test(msg)) return "Risky memory or I/O call";
    if (d.category === "ERROR") return "Won't compile";
    if (d.source === "semantic") return `Naming: ${d.semantic?.variable || "variable"}`;
    return d.title || "Issue";
  }

  function groupDiagnostics(diagnostics) {
    const groups = new Map();
    for (const d of diagnostics) {
      const line = d.line || 0;
      const key = `${line}:${topicKey(d)}`;
      if (!groups.has(key)) {
        groups.set(key, {
          line,
          worst: d,
          items: [d],
        });
      } else {
        const g = groups.get(key);
        g.items.push(d);
        if (severityRank(d) < severityRank(g.worst)) g.worst = d;
      }
    }
    return [...groups.values()].sort((a, b) => a.line - b.line || severityRank(a.worst) - severityRank(b.worst));
  }

  function summaryMeta(diagnostics) {
    let errors = 0;
    let warnings = 0;
    let hints = 0;
    for (const d of diagnostics) {
      if (d.category === "ERROR") errors += 1;
      else if (d.source === "heuristic" || d.category === "SUGGESTION") hints += 1;
      else warnings += 1;
    }
    const parts = [];
    if (errors) parts.push(`${errors} error${errors > 1 ? "s" : ""}`);
    if (warnings) parts.push(`${warnings} warning${warnings > 1 ? "s" : ""}`);
    if (hints) parts.push(`${hints} hint${hints > 1 ? "s" : ""}`);
    return parts.length ? parts.join(" · ") : "All clear";
  }

  function getSource() {
    return window.SecureCCMonaco?.getValue?.() ?? $("#source-editor")?.value ?? "";
  }

  function setSource(v) {
    window.SecureCCMonaco?.setValue?.(v);
    const ta = $("#source-editor");
    if (ta) ta.value = v;
  }

  function render(diagnostics, stats, partial) {
    const list = $("#semantic-lint-list");
    const meta = $("#semantic-lint-meta");
    if (!list) return;

    const count = diagnostics?.length || 0;
    if (meta) {
      const summary = count ? summaryMeta(diagnostics) : "";
      const extra = partial && count ? " (partial)" : "";
      meta.textContent = summary + extra;
      meta.classList.toggle("live-issues-ok", !count);
      meta.classList.toggle("live-issues-warn", count > 0);
    }

    if (!count) {
      list.innerHTML = "";
      return;
    }

    const groups = groupDiagnostics(diagnostics);
    list.innerHTML = groups
      .map((g) => {
        const d = g.worst;
        const isError = g.items.some((x) => x.category === "ERROR");
        const title = friendlyTitle(d);
        const sources = [...new Set(g.items.map((x) => SOURCE_LABELS[x.source] || x.source).filter(Boolean))];
        const details = g.items
          .map((x) => {
            const fix = x.fix || x.semantic?.suggested_fix;
            const autoFix =
              x.semantic?.can_auto_fix ||
              (x.source === "heuristic" && /printf first argument/i.test(x.message || "")) ||
              (x.source === "heuristic" && /gets is unsafe/i.test(x.message || ""));
            const msg = x.message || x.title || "";
            const suffix = autoFix
              ? `<span class="live-issues-suggestion">Safe auto-fix available</span>`
              : fix
                ? `<span class="live-issues-suggestion">${escapeHtml(fix)}</span>`
                : "";
            return `<li>${escapeHtml(msg)}${suffix}</li>`;
          })
          .join("");
        const single = g.items[0];
        const singleAuto =
          single.semantic?.can_auto_fix ||
          (single.source === "heuristic" && /printf first argument/i.test(single.message || "")) ||
          (single.source === "heuristic" && /gets is unsafe/i.test(single.message || ""));
        const body =
          g.items.length === 1
            ? `<p class="live-issues-subtitle">${escapeHtml(single.message || single.title || "")}${
                singleAuto
                  ? `<span class="live-issues-suggestion">Safe auto-fix available — click Fix safe issues</span>`
                  : single.fix || single.semantic?.suggested_fix
                    ? `<span class="live-issues-suggestion">${escapeHtml(single.fix || single.semantic?.suggested_fix)}</span>`
                    : ""
              }</p>`
            : `<ul class="live-issues-details">${details}</ul>`;
        return `<button type="button" class="semantic-lint-item ${isError ? "is-error" : "is-warning"}" data-line="${escapeHtml(g.line)}">
          <div class="live-issues-item-head">
            <span class="semantic-lint-line">Line ${escapeHtml(g.line)}</span>
            <span class="live-issues-title">${escapeHtml(title)}</span>
            ${sources.map((s) => `<span class="live-issues-source-pill">${escapeHtml(s)}</span>`).join("")}
          </div>
          ${body}
        </button>`;
      })
      .join("");

    list.querySelectorAll(".semantic-lint-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        const line = parseInt(btn.dataset.line, 10);
        if (!line) return;
        window.SecureCCMonaco?.highlightLine?.(line);
        window.SecureCCEditor?.highlightLine?.(line);
      });
    });
  }

  async function runLint() {
    const source = getSource();
    if (!source.trim()) {
      const empty = { diagnostics: [], stats: { elapsed_ms: 0 }, partial: false };
      render([], {}, false);
      window.SecureCCLiveViz?.onLintResult?.(empty);
      return;
    }

    if (abort) abort.abort();
    abort = new AbortController();
    const reqSeq = ++lintRequestSeq;

    try {
      const res = await fetch("/api/lint/live", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: abort.signal,
        body: JSON.stringify({
          source,
          language: window.SecureCCApp?.getEditorLanguage?.() || "c",
        }),
      });
      const data = await res.json();
      if (reqSeq !== lintRequestSeq) return;
      if (!res.ok) throw new Error(data.error || "lint failed");
      render(data.diagnostics || [], data.stats || {}, data.partial);
      window.SecureCCLiveViz?.onLintResult?.(data);
    } catch (err) {
      if (err.name === "AbortError") return;
      render([], { error: err.message }, false);
    }
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(runLint, DEBOUNCE_MS);
  }

  async function applySafeFixes() {
    const lang = window.SecureCCApp?.getEditorLanguage?.() || "c";
    try {
      const res = await fetch("/api/lint/live/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source: getSource(),
          language: lang,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "apply failed");
      if (data.note && !data.applied_count) {
        window.showToast?.(data.note);
        return;
      }
      if (data.source != null && data.applied_count > 0) {
        setSource(data.source);
        schedule();
        const summary = (data.applied || [])
          .slice(0, 3)
          .map((a) => a.description || a.kind)
          .join("; ");
        window.showToast?.(
          `Applied ${data.applied_count} fix(es)${summary ? `: ${summary}` : ""}${
            data.applied_count > 3 ? "…" : ""
          }`
        );
      } else {
        window.showToast?.("No automatic fixes available for current issues.");
      }
    } catch (err) {
      window.showToast?.(err.message);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("#editor-language")?.addEventListener("change", schedule);
    $("#semantic-lint-apply")?.addEventListener("click", applySafeFixes);
    schedule();
  });

  return { schedule, runLint, applySafeFixes };
})();
