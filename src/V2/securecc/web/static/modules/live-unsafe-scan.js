import { $, escapeHtml } from "../lib/dom.js";

const DEBOUNCE_MS = 380;
const FUNCS = [
  { name: "gets", cwe: "CWE-242" },
  { name: "strcpy", cwe: "CWE-120" },
  { name: "strcat", cwe: "CWE-120" },
  { name: "sprintf", cwe: "CWE-120" },
  { name: "vsprintf", cwe: "CWE-120" },
  { name: "scanf", cwe: null },
  { name: "memcpy", cwe: "CWE-120" },
  { name: "system", cwe: "CWE-78" },
  { name: "popen", cwe: "CWE-78" },
  { name: "atoi", cwe: "CWE-190" },
  { name: "malloc", cwe: null, countOnly: true },
  { name: "free", cwe: null, countOnly: true },
];

let timer = null;
let lastLinesByFunc = {};

function stripLineForScan(line) {
  let s = line.replace(/\/\/.*$/, "");
  s = s.replace(/"(?:\\.|[^"\\])*"/g, '""');
  s = s.replace(/'(?:\\.|[^'\\])*'/g, "''");
  return s;
}

function scanSource(source) {
  const lines = source.split(/\r?\n/);
  const agg = new Map();

  for (const spec of FUNCS) {
    const re = new RegExp(`\\b${spec.name}\\s*\\(`, "g");
    lines.forEach((rawLine, idx) => {
      const lineNo = idx + 1;
      const stripped = stripLineForScan(rawLine);
      if (!stripped.trim() || stripped.trim().startsWith("/*")) return;
      let m;
      while ((m = re.exec(stripped)) !== null) {
        if (!agg.has(spec.name)) {
          agg.set(spec.name, { spec, lines: new Set() });
        }
        agg.get(spec.name).lines.add(lineNo);
      }
    });
  }

  const rows = [...agg.entries()]
    .map(([name, { spec, lines }]) => ({
      name,
      cwe: spec.cwe,
      countOnly: spec.countOnly,
      count: lines.size,
      lines: [...lines].sort((a, b) => a - b),
    }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  const allLines = new Set();
  rows.forEach((r) => r.lines.forEach((ln) => allLines.add(ln)));
  return { rows, allLines: [...allLines] };
}

function renderList(rows) {
  const list = $("#live-unsafe-list");
  if (!list) return;

  if (!rows.length) {
    list.innerHTML = `<li class="live-unsafe-empty muted"><span class="live-check-icon" aria-hidden="true">✓</span> No risky API calls found</li>`;
    return;
  }

  list.innerHTML = rows
    .map((r) => {
      const cwe = r.cwe ? `<span class="live-problem-cwe">${escapeHtml(r.cwe)}</span>` : "";
      const lineLinks = r.lines
        .map(
          (ln) =>
            `<button type="button" class="live-unsafe-line-link" data-line="${ln}">L${ln}</button>`
        )
        .join(" ");
      return `<li class="live-unsafe-row">
        <span class="live-unsafe-fn mono">${escapeHtml(r.name)}</span>
        <span class="live-unsafe-count tabular-nums">${r.count}×</span>
        ${cwe}
        <span class="live-unsafe-lines">${lineLinks}</span>
      </li>`;
    })
    .join("");

  list.querySelectorAll(".live-unsafe-line-link").forEach((btn) => {
    btn.addEventListener("click", () => {
      const line = parseInt(btn.dataset.line, 10);
      window.SecureCCMonaco?.goToLine?.(line);
    });
  });
}

function runScan() {
  const source =
    window.SecureCCMonaco?.getValue?.() ?? document.querySelector("#source-editor")?.value ?? "";
  const { rows, allLines } = scanSource(source);
  lastLinesByFunc = allLines;
  renderList(rows);
  window.SecureCCMonaco?.applyUnsafeApiDecorations?.(allLines);
  window.SecureCCLiveCode?.onUnsafeRows?.(rows);
  window.SecureCCLiveCode?.onUnsafeLines?.([...allLines]);
}

export function scheduleUnsafeScan() {
  clearTimeout(timer);
  timer = setTimeout(runScan, DEBOUNCE_MS);
}

export function clearUnsafeScan() {
  lastLinesByFunc = [];
  renderList([]);
  window.SecureCCMonaco?.applyUnsafeApiDecorations?.([]);
  window.SecureCCLiveCode?.onUnsafeRows?.([]);
  window.SecureCCLiveCode?.onUnsafeLines?.([]);
}

export function initUnsafeScan() {
  runScan();
}

window.SecureCCLiveUnsafe = { scheduleUnsafeScan, clearUnsafeScan, initUnsafeScan };