import { escapeHtml } from "./dom.js";

let markedReady = false;

function configureMarked() {
  if (markedReady || typeof window.marked?.setOptions !== "function") return;
  window.marked.setOptions({
    breaks: true,
    gfm: true,
    headerIds: false,
    mangle: false,
  });
  markedReady = true;
}

function plainFallback(text) {
  const escaped = escapeHtml(text);
  const paras = escaped.split(/\n\n+/).filter(Boolean);
  if (!paras.length) return "";
  return paras.map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`).join("");
}

/** Safe HTML for assistant chat bubbles (Markdown → sanitized HTML). */
export function renderAssistantMarkdown(raw) {
  const text = String(raw || "").trim();
  if (!text) return "";

  if (typeof window.marked?.parse === "function" && typeof window.DOMPurify?.sanitize === "function") {
    configureMarked();
    const dirty = window.marked.parse(text);
    return window.DOMPurify.sanitize(dirty, {
      USE_PROFILES: { html: true },
      ALLOWED_TAGS: [
        "p",
        "br",
        "strong",
        "em",
        "code",
        "pre",
        "ul",
        "ol",
        "li",
        "h2",
        "h3",
        "h4",
        "blockquote",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "a",
        "hr",
      ],
      ALLOWED_ATTR: ["href", "target", "rel", "class"],
    });
  }

  return plainFallback(text);
}