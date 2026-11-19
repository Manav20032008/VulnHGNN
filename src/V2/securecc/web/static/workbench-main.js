/* global SecureCCGraph */
import { initApp, fetchMeta, loadSamples } from "./modules/app-core.js";
import { initTabNav, navigateToTab } from "./modules/tab-nav.js";
import {
  bootstrapLiveChartsEmpty,
  bindProblemsCursorSync,
  initLiveVizResize,
  refreshEngineWidgets,
  renderSparklines,
  resizeLiveCharts,
} from "./modules/live-viz.js";
import { initLiveSections } from "./modules/live-sections.js";
import { initUnsafeScan } from "./modules/live-unsafe-scan.js";
import "./modules/live-engine-panel.js";
import "./modules/live-code-panel.js";
import "./modules/live-call-graph.js";
import { loadMonaco } from "./modules/monaco-shell.js";
import { initActivityDrawer } from "./modules/activity-feed.js";
import { renderWelcome, renderHealthStrip } from "./modules/welcome.js";
import { initTheme, initThemeToggle } from "./modules/theme.js";
import { initLivePreview } from "./modules/live-preview.js";
import { initCodeChat, onCodeChatTabShown, refreshCodeChatUi } from "./modules/code-chat.js";

import "./semantic_lint.js";
import "./modules/workbench-compat.js";

window.SecureCCMonacoLoad = loadMonaco;
window.navigateToTab = navigateToTab;

function safeInit(label, fn) {
  try {
    fn();
  } catch (err) {
    console.warn(`[SecureCC] ${label} init failed:`, err);
  }
}

async function boot() {
  initTheme();
  initThemeToggle();
  initActivityDrawer();
  await loadMonaco();
  safeInit("editor problem sync", () => bindProblemsCursorSync());
  const left = document.querySelector(".workbench-left");
  if (left && window.ResizeObserver) {
    new ResizeObserver(() => window.SecureCCMonaco?.getEditor?.()?.layout?.()).observe(left);
  }
  safeInit("live charts", () => {
    initLiveVizResize();
    bootstrapLiveChartsEmpty();
    renderSparklines();
  });
  safeInit("live preview", () => initLivePreview());
  safeInit("live engine graph resize", () => window.SecureCCLiveEngine?.initLiveEngineGraphResize?.());
  safeInit("unsafe API scan", () => initUnsafeScan());
  safeInit("call graph", () => {
    window.SecureCCLiveCallGraph?.initCallGraphResize?.();
    window.SecureCCLiveCallGraph?.scheduleCallGraph?.();
  });
  safeInit("live sections", () =>
    initLiveSections((section) => {
      if (section === "engine") requestAnimationFrame(() => refreshEngineWidgets());
      if (section === "health") requestAnimationFrame(() => resizeLiveCharts());
    })
  );
  initTabNav({
    onTabChange: (tabId) => {
      if (tabId === "live") {
        requestAnimationFrame(() => {
          resizeLiveCharts();
          refreshEngineWidgets();
        });
      }
      if (tabId === "graph") {
        const full = window.SecureCCApp?.getLastPayload?.()?.graph;
        const prev = window.SecureCCPreviewGraph?.graph;
        const graph = full || prev;
        if (graph) {
          SecureCCGraph.render(document.querySelector("#graph-container"), graph);
        }
      }
      if (tabId === "aai") {
        window.SecureCCApp?.loadAaiSecurity?.(false);
      }
      if (tabId === "repair" && window.SecureCCApp?.getLastPayload?.()) {
        window.SecureCCApp?.refreshRepairDiff?.();
      }
      if (tabId === "chat") {
        onCodeChatTabShown();
      }
    },
  });
  safeInit("code chat", () => initCodeChat());
  initApp();
  const meta = await fetchMeta();
  refreshCodeChatUi(meta);
  renderHealthStrip(meta);
  renderWelcome(meta);
  await loadSamples();
}

document.addEventListener("DOMContentLoaded", () => {
  boot().catch((e) => {
    console.error(e);
    window.showToast?.(String(e.message || e));
  });
});