import { $ } from "../lib/dom.js";

const GROUPS = {
  live: {
    label: "Live",
    tabs: [{ id: "live", label: "Live" }],
  },
  output: {
    label: "Output",
    tabs: [{ id: "output", label: "Result" }],
  },
  chat: {
    label: "Chat",
    tabs: [{ id: "chat", label: "Ask AI" }],
  },
  overview: {
    label: "Overview",
    tabs: [{ id: "overview", label: "Summary" }],
  },
  detection: {
    label: "Detection",
    tabs: [
      { id: "findings", label: "Findings" },
      { id: "localization", label: "Localization" },
      { id: "graph", label: "IR Graph" },
    ],
  },
  intelligence: {
    label: "Intelligence",
    tabs: [
      { id: "agent", label: "Agent Activity" },
      { id: "aai", label: "AAI Security" },
    ],
  },
  remediation: {
    label: "Remediation",
    tabs: [{ id: "repair", label: "Repair diff" }],
  },
};

let activeGroup = "live";
let activeTab = "live";
let onTabChange = null;
let fullResultsNav = false;

function showPanel(tabId) {
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
  const panel = $(`#panel-${tabId}`);
  if (panel) panel.classList.add("active");
  activeTab = tabId;
  if (onTabChange) onTabChange(tabId);
}

function renderSubTabs() {
  const nav = $("#intel-tabs");
  if (!nav) return;
  const group = GROUPS[activeGroup];
  const tabs = group?.tabs || [];
  if (tabs.length <= 1) {
    nav.classList.add("hidden");
    nav.innerHTML = "";
    return;
  }
  nav.classList.remove("hidden");
  nav.innerHTML = tabs
    .map(
      (t) =>
        `<button type="button" class="intel-tab ${t.id === activeTab ? "active" : ""}" data-tab="${t.id}">${t.label}</button>`
    )
    .join("");
  nav.querySelectorAll(".intel-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      showPanel(btn.dataset.tab);
      renderSubTabs();
    });
  });
}

function renderGroupButtons() {
  const groupsEl = $("#intel-groups");
  if (!groupsEl) return;
  const earlyNav = new Set(["live", "chat"]);
  const entries = Object.entries(GROUPS).filter(
    ([key]) => fullResultsNav || earlyNav.has(key)
  );
  groupsEl.innerHTML = entries
    .map(
      ([key, g]) =>
        `<button type="button" class="intel-group-btn ${key === activeGroup ? "active" : ""}" data-group="${key}">${g.label}</button>`
    )
    .join("");
  groupsEl.querySelectorAll(".intel-group-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      activeGroup = btn.dataset.group;
      const first = GROUPS[activeGroup].tabs[0].id;
      groupsEl.querySelectorAll(".intel-group-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      showPanel(first);
      renderSubTabs();
    });
  });
}

export function setNavMode(full) {
  fullResultsNav = full;
  const dash = $("#dashboard");
  dash?.classList.toggle("dashboard-live-only", !full);
  $("#dash-header-results")?.classList.add("hidden");
  $("#metrics")?.classList.add("hidden");
  if (!full && activeGroup !== "live" && activeGroup !== "chat") {
    activeGroup = "live";
    activeTab = "live";
    showPanel("live");
  }
  renderGroupButtons();
  renderSubTabs();
}

export function initTabNav(handlers = {}) {
  onTabChange = handlers.onTabChange || null;
  fullResultsNav = false;
  renderGroupButtons();
  renderSubTabs();
  showPanel("live");
}

export function navigateToTab(tabId) {
  if (tabId === "live") {
    activeGroup = "live";
    activeTab = "live";
    renderGroupButtons();
    showPanel("live");
    renderSubTabs();
    return;
  }
  for (const [groupKey, group] of Object.entries(GROUPS)) {
    if (group.tabs.some((t) => t.id === tabId)) {
      activeGroup = groupKey;
      $("#intel-groups")
        ?.querySelectorAll(".intel-group-btn")
        .forEach((b) => b.classList.toggle("active", b.dataset.group === groupKey));
      showPanel(tabId);
      renderSubTabs();
      return;
    }
  }
}