const STORAGE_KEY = "securecc-theme";

export function getTheme() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === "dark" || stored === "light") return stored;
  return "light";
}

export function getMonacoThemeId() {
  return getTheme() === "dark" ? "securecc-dark" : "securecc-light";
}

export function applyTheme(theme) {
  const next = theme === "dark" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem(STORAGE_KEY, next);
  updateToggleUi(next);
  window.SecureCCMonaco?.setEditorTheme?.(next);
  if (window.SecureCCApp?.getLastPayload?.()) {
    window.SecureCCGraph?.rerenderLast?.();
    window.SecureCCApp?.refreshCharts?.();
    window.SecureCCLiveViz?.refreshLiveCharts?.();
    window.SecureCCLiveViz?.resizeLiveCharts?.();
    window.SecureCCPipeline?.refresh?.();
    window.SecureCCApp?.refreshRepairDiff?.();
  }
  window.dispatchEvent(new CustomEvent("securecc-theme-change", { detail: { theme: next } }));
}

function updateToggleUi(theme) {
  const btn = document.querySelector("#theme-toggle");
  if (!btn) return;
  const isLight = theme === "light";
  btn.setAttribute("aria-pressed", isLight ? "true" : "false");
  btn.title = isLight ? "Switch to dark mode" : "Switch to light mode";
  btn.innerHTML = isLight
    ? `<span class="theme-toggle-icon" aria-hidden="true">☀</span> Light`
    : `<span class="theme-toggle-icon" aria-hidden="true">☾</span> Dark`;
}

export function initTheme() {
  applyTheme(getTheme());
}

export function initThemeToggle() {
  const btn = document.querySelector("#theme-toggle");
  if (!btn) return;
  btn.addEventListener("click", () => {
    applyTheme(getTheme() === "light" ? "dark" : "light");
  });
  updateToggleUi(getTheme());
}

export function readCssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}