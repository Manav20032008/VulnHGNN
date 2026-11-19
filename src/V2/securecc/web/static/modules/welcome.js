import { $, escapeHtml } from "../lib/dom.js";
import { state } from "../lib/state.js";

function dotClass(ok, warn) {
  if (ok) return "ok";
  if (warn) return "warn";
  return "bad";
}

export function renderWelcome(meta) {
  state.meta = meta;
  $("#live-status-strip") && ($("#live-status-strip").innerHTML = "");
  $("#live-howto-list") && ($("#live-howto-list").innerHTML = "");
}

export function renderHealthStrip(meta) {
  const strip = $("#health-strip");
  if (!strip || !meta) return;
  const dot = (ok, warn) => (ok ? "ok" : warn ? "warn" : "bad");
  strip.innerHTML = `
    <span class="health-dot-item"><span class="health-dot ${dot(meta.clang_available)}"></span>clang</span>
    <span class="health-dot-item"><span class="health-dot ${dot(meta.groq_configured, !meta.groq_hint)}"></span>AI</span>
    <span class="health-dot-item"><span class="health-dot ok"></span>API</span>
  `;
  const hint = $("#upload-hint");
  if (hint && meta.supported_suffixes) {
    hint.innerHTML = `Drop ${meta.supported_suffixes.map((s) => `<code>${escapeHtml(s)}</code>`).join(", ")}`;
  }
}