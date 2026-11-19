import { state } from "../lib/state.js";
import { getMonacoThemeId } from "./theme.js";

const LANG_MAP = { c: "c", cpp: "cpp", java: "java" };

let editor = null;
let monacoReady = null;

function monacoLanguage() {
  return LANG_MAP[state.editorLanguage] || "c";
}

export function defineMonacoThemes(monaco) {
  monaco.editor.defineTheme("securecc-light", {
    base: "vs",
    inherit: true,
    rules: [],
    colors: {
      "editor.background": "#fafbfc",
      "editorGutter.background": "#f1f5f9",
      "editorLineNumber.foreground": "#94a3b8",
      "editor.lineHighlightBackground": "#eff6ff",
    },
  });
  monaco.editor.defineTheme("securecc-dark", {
    base: "vs-dark",
    inherit: true,
    rules: [],
    colors: {
      "editor.background": "#0d1117",
      "editorGutter.background": "#161b26",
    },
  });
}

function applyEditorTheme() {
  if (editor && window.monaco) {
    window.monaco.editor.setTheme(getMonacoThemeId());
  }
}

export function loadMonaco() {
  if (monacoReady) return monacoReady;
  monacoReady = new Promise((resolve, reject) => {
    const host = document.getElementById("monaco-host");
    const fallback = document.getElementById("source-editor");
    if (!host) {
      reject(new Error("no monaco host"));
      return;
    }
    const loader = document.createElement("script");
    loader.src = "https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js";
    loader.onload = () => {
      window.require.config({
        paths: { vs: "https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs" },
      });
      window.require(["vs/editor/editor.main"], () => {
        const monaco = window.monaco;
        defineMonacoThemes(monaco);
        const initial = fallback?.value || state.languageMeta.c.placeholder;
        editor = monaco.editor.create(host, {
          value: initial,
          language: monacoLanguage(),
          theme: getMonacoThemeId(),
          automaticLayout: true,
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 13,
          lineNumbers: "on",
          minimap: { enabled: true, scale: 1 },
          scrollBeyondLastLine: false,
          glyphMargin: true,
        });
        if (fallback) {
          fallback.value = initial;
          fallback.classList.add("source-editor-fallback");
        }
        host.querySelector(".monaco-skeleton")?.remove();
        editor.onDidChangeModelContent(() => {
          if (fallback) fallback.value = editor.getValue();
          window.SecureCCSemanticLint?.schedule?.();
          window.SecureCCLivePreview?.schedulePreview?.();
          window.SecureCCLiveUnsafe?.scheduleUnsafeScan?.();
          window.SecureCCLiveCallGraph?.scheduleCallGraph?.();
        });
        window.SecureCCMonaco = {
          getValue: () => editor?.getValue() ?? fallback?.value ?? "",
          setValue: (v) => {
            if (editor) editor.setValue(v);
            if (fallback) fallback.value = v;
          },
          highlightLine,
          goToLine,
          getEditor: () => editor,
          getMonaco: () => monaco,
          setLanguage: () => {
            const model = editor?.getModel();
            if (model) monaco.editor.setModelLanguage(model, monacoLanguage());
          },
          setEditorTheme: () => applyEditorTheme(),
          applyLintDecorations,
          applyUnsafeApiDecorations,
        };
        window.addEventListener("securecc-theme-change", applyEditorTheme);
        resolve(editor);
      });
    };
    loader.onerror = () => {
      fallback?.classList.remove("source-editor-fallback");
      window.SecureCCMonaco = {
        getValue: () => fallback?.value ?? "",
        setValue: (v) => {
          if (fallback) fallback.value = v;
        },
        highlightLine: (line) => window.SecureCCEditor?.highlightLine?.(line),
        setLanguage: () => {},
        setEditorTheme: () => {},
      };
      resolve(null);
    };
    document.head.appendChild(loader);
  });
  return monacoReady;
}

let highlightDecorationIds = [];
let findingDecorationIds = [];
let lintDecorationIds = [];
let unsafeDecorationIds = [];

export function goToLine(line) {
  if (!editor || !line) return;
  const monaco = window.monaco;
  const model = editor.getModel();
  const col = model ? model.getLineMaxColumn(line) : 1;
  editor.revealLineInCenter(line);
  editor.setSelection(new monaco.Selection(line, 1, line, col));
  editor.focus();
}

export function highlightLine(line) {
  goToLine(line);
  if (!editor || !line) return;
  const monaco = window.monaco;
  highlightDecorationIds = editor.deltaDecorations(highlightDecorationIds, [
    {
      range: new monaco.Range(line, 1, line, 1),
      options: {
        isWholeLine: true,
        className: "monaco-line-highlight",
        glyphMarginClassName: "monaco-glyph-flash",
      },
    },
  ]);
  setTimeout(() => {
    highlightDecorationIds = editor.deltaDecorations(highlightDecorationIds, []);
  }, 2200);
}

function lintSeverity(d) {
  const monaco = window.monaco;
  if (d.category === "ERROR") return monaco.MarkerSeverity.Error;
  if (d.source === "heuristic" || d.category === "SUGGESTION") return monaco.MarkerSeverity.Hint;
  return monaco.MarkerSeverity.Warning;
}

export function applyLintDecorations(diagnostics) {
  if (!editor || !window.monaco) return;
  const monaco = window.monaco;
  const model = editor.getModel();
  const decos = (diagnostics || [])
    .filter((d) => d.line)
    .map((d) => {
      const isError = d.category === "ERROR";
      const isHint = d.source === "heuristic" || d.category === "SUGGESTION";
      return {
        range: new monaco.Range(d.line, 1, d.line, 1),
        options: {
          glyphMarginClassName: isError ? "monaco-glyph-critical" : isHint ? "monaco-glyph-low" : "monaco-glyph-medium",
          isWholeLine: true,
          className: isError ? "monaco-lint-error-line" : isHint ? "monaco-lint-hint-line" : "monaco-lint-warn-line",
          overviewRuler: {
            color: isError
              ? getComputedStyle(document.documentElement).getPropertyValue("--danger").trim() || "#dc2626"
              : isHint
                ? getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#2563eb"
                : getComputedStyle(document.documentElement).getPropertyValue("--warning").trim() || "#d97706",
            position: monaco.editor.OverviewRulerLane.Right,
          },
        },
      };
    });
  lintDecorationIds = editor.deltaDecorations(lintDecorationIds, decos);

  if (model) {
    const markers = (diagnostics || [])
      .filter((d) => d.line)
      .map((d) => {
        const line = d.line;
        return {
          severity: lintSeverity(d),
          startLineNumber: line,
          startColumn: 1,
          endLineNumber: line,
          endColumn: model.getLineMaxColumn(line),
          message: d.message || d.title || "Issue",
        };
      });
    monaco.editor.setModelMarkers(model, "securecc-lint", markers);
  }
}

export function applyUnsafeApiDecorations(lines) {
  if (!editor || !window.monaco) return;
  const monaco = window.monaco;
  const warn = getComputedStyle(document.documentElement).getPropertyValue("--warning").trim() || "#d97706";
  const decos = (lines || []).map((line) => ({
    range: new monaco.Range(line, 1, line, 1),
    options: {
      glyphMarginClassName: "monaco-glyph-unsafe-api",
      className: "monaco-unsafe-api-line",
      isWholeLine: true,
      overviewRuler: {
        color: warn,
        position: monaco.editor.OverviewRulerLane.Center,
      },
    },
  }));
  unsafeDecorationIds = editor.deltaDecorations(unsafeDecorationIds, decos);
}

export function applyFindingDecorations(findings) {
  lintDecorationIds = editor?.deltaDecorations(lintDecorationIds, []) || [];
  if (!editor || !window.monaco) return;
  const monaco = window.monaco;
  const decos = (findings || [])
    .filter((f) => f.line)
    .map((f) => {
      const sev = (f.severity || "medium").toLowerCase();
      const glyph =
        sev === "critical" || sev === "high"
          ? "monaco-glyph-critical"
          : sev === "medium"
            ? "monaco-glyph-medium"
            : "monaco-glyph-low";
      return {
        range: new monaco.Range(f.line, 1, f.line, 1),
        options: {
          glyphMarginClassName: glyph,
          isWholeLine: true,
          className: "monaco-finding-line",
        },
      };
    });
  findingDecorationIds = editor.deltaDecorations(findingDecorationIds, decos);
}