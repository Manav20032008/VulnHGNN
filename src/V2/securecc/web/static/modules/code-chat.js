import { $, escapeHtml, showToast } from "../lib/dom.js";
import { renderAssistantMarkdown } from "../lib/markdown-render.js";
import { pushActivity } from "./activity-feed.js";

const PRESETS = {
  explain:
    "Explain what this program does in simple terms for a beginner—what it prints and how each part fits together.",
  risks:
    "In beginner-friendly language, what security or safety issues could exist in this code (only what applies)?",
  analysis:
    "Summarize the latest SecureCC analysis in plain language: verdict, any findings, and what that means for me.",
  fix: "If there are issues, suggest simple fixes a beginner could understand—no huge rewrites unless needed.",
};

let history = [];
let busy = false;

function getSource() {
  return window.SecureCCMonaco?.getValue?.() ?? $("#source-editor")?.value ?? "";
}

function buildAnalysisContext(payload) {
  if (!payload) return null;
  const scan = payload.scan || {};
  const findings = (scan.findings || []).slice(0, 12).map((f) => ({
    cwe_id: f.cwe_id,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    function: f.function,
    message: (f.message || "").slice(0, 280),
  }));
  const ctx = {
    verification: payload.verification,
    compile_ok: payload.compile?.ok,
    finding_count: scan.finding_count,
    cwes: scan.cwes,
    findings,
    engine_candidates: payload.adjudication?.engine_candidate_count ?? payload.engine_scan?.finding_count,
    adjudication_status: payload.adjudication?.status,
    program_output: payload.program_run?.stdout ? String(payload.program_run.stdout).slice(0, 1500) : undefined,
  };
  return ctx;
}

function renderMessages() {
  const box = $("#code-chat-messages");
  if (!box) return;
  if (!history.length) {
    box.innerHTML = "";
    return;
  }
  box.innerHTML = history
    .map((m) => {
      if (m.thinking) {
        return `<div class="code-chat-bubble code-chat-bubble-assistant code-chat-thinking" aria-busy="true">
          <span class="code-chat-role">Assistant</span>
          <div class="code-chat-thinking-dots" aria-hidden="true"><span></span><span></span><span></span></div>
          <span class="visually-hidden">Composing reply…</span>
        </div>`;
      }
      const role = m.role === "user" ? "user" : "assistant";
      const body =
        role === "user"
          ? `<div class="code-chat-bubble-body code-chat-plain">${escapeHtml(m.content)}</div>`
          : `<div class="code-chat-bubble-body code-chat-md">${renderAssistantMarkdown(m.content)}</div>`;
      return `<div class="code-chat-bubble code-chat-bubble-${role}">
        <span class="code-chat-role">${role === "user" ? "You" : "Assistant"}</span>
        ${body}
      </div>`;
    })
    .join("");
  box.scrollTop = box.scrollHeight;
}

function setGroqBanner(meta) {
  const el = $("#code-chat-groq-banner");
  if (!el) return;
  if (meta?.groq_configured) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  el.innerHTML = `<p class="small">${escapeHtml(meta?.groq_hint || "Configure GROQ_API_KEY in .env to enable chat.")}</p>`;
}

function setStatus(text) {
  const el = $("#code-chat-status");
  if (el) el.textContent = text || "";
}

async function sendMessage(text) {
  const message = (text || "").trim();
  if (!message || busy) return;
  const source = getSource();
  if (!source.trim()) {
    showToast("Add source in the editor first");
    return;
  }

  busy = true;
  const sendBtn = $("#code-chat-send");
  sendBtn?.setAttribute("disabled", "true");
  setStatus("Thinking…");

  const userTurn = { role: "user", content: message };
  history.push(userTurn);
  history.push({ role: "assistant", content: "", thinking: true });
  renderMessages();

  const prior = history.slice(0, -1);
  const payload = window.SecureCCApp?.getLastPayload?.();
  const lang = window.SecureCCApp?.getEditorLanguage?.() || "c";
  const filename = $("#editor-path")?.textContent || "editor_workspace.c";

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message,
        source,
        language: lang,
        filename,
        path: window.SecureCCApp?.getSelectedPath?.() || undefined,
        history: prior,
        analysis_context: buildAnalysisContext(payload),
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Chat request failed");
    if (history.at(-1)?.thinking) history.pop();
    history.push({ role: "assistant", content: data.reply || "" });
    renderMessages();
    pushActivity("Code assistant replied");
    setStatus(data.model ? `Model: ${data.model}` : "");
  } catch (err) {
    if (history.at(-1)?.thinking) history.pop();
    renderMessages();
    showToast(err.message);
    setStatus("");
    pushActivity(`Chat error: ${err.message}`);
  } finally {
    busy = false;
    sendBtn?.removeAttribute("disabled");
  }
}

export function refreshCodeChatUi(meta) {
  setGroqBanner(meta || window.SecureCCApp?.getMeta?.());
}

export function initCodeChat() {
  document
    .querySelectorAll("#code-chat-context-line, #panel-chat .code-chat-sub")
    .forEach((el) => el.remove());

  $("#code-chat-form")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("#code-chat-input");
    const text = input?.value || "";
    if (input) input.value = "";
    sendMessage(text);
  });

  $("#code-chat-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      $("#code-chat-form")?.requestSubmit();
    }
  });

  $("#code-chat-clear")?.addEventListener("click", () => {
    history = [];
    renderMessages();
    setStatus("");
  });

  document.querySelectorAll(".code-chat-preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.preset;
      const text = PRESETS[key] || btn.textContent;
      const input = $("#code-chat-input");
      if (input) input.value = text;
      input?.focus();
    });
  });

  renderMessages();
}

export function onCodeChatTabShown() {
  requestAnimationFrame(() => {
    $("#code-chat-messages")?.scrollTo?.(0, 99999);
  });
}