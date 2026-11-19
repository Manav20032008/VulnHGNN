import { $ } from "../lib/dom.js";

const STORAGE_KEY = "securecc_live_section";
const SECTIONS = ["health", "code", "engine"];

let active = "health";
let onVisible = null;

function loadSaved() {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && SECTIONS.includes(v)) return v;
  } catch {
    /* private mode */
  }
  return "health";
}

function save() {
  try {
    localStorage.setItem(STORAGE_KEY, active);
  } catch {
    /* ignore */
  }
}

function showSection(id) {
  active = id;
  save();
  SECTIONS.forEach((s) => {
    const panel = $(`#live-section-${s}`);
    panel?.classList.toggle("hidden", s !== id);
    panel?.classList.toggle("active", s === id);
  });
  document.querySelectorAll(".live-segment-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.section === id);
    btn.setAttribute("aria-selected", btn.dataset.section === id ? "true" : "false");
  });
  if (id === "code")
    requestAnimationFrame(() => {
      window.SecureCCLiveCallGraph?.resizeCallGraph?.();
      window.SecureCCLiveCode?.resizeCodePanel?.();
    });
  if (id === "engine") {
    requestAnimationFrame(() => {
      window.SecureCCLiveEngine?.flushPendingGraph?.();
      window.SecureCCLiveEngine?.resizeEngineGraph?.();
    });
  }
  if (onVisible) onVisible(id);
}

export function getLiveSection() {
  return active;
}

export function initLiveSections(handler) {
  onVisible = handler || null;
  active = loadSaved();
  const nav = $("#live-section-nav");
  nav?.querySelectorAll(".live-segment-btn").forEach((btn) => {
    btn.addEventListener("click", () => showSection(btn.dataset.section));
  });
  $("#live-engine-enable-btn")?.addEventListener("click", () => {
    const toggle = $("#live-preview-toggle");
    if (toggle) {
      toggle.checked = true;
      toggle.dispatchEvent(new Event("change", { bubbles: true }));
    }
    showSection("engine");
  });
  showSection(active);
}

export function refreshLiveSectionLayout() {
  if (onVisible) onVisible(active);
}