/* global Chart */
import { $ } from "../lib/dom.js";

let sourceChart = null;
let unsafeChart = null;
let unsafeLines = new Set();
let lastDiagnostics = [];
let lastUnsafeRows = [];

function lineWeight(d) {
  if (d.category === "ERROR") return 3;
  if (d.source === "heuristic" || d.category === "SUGGESTION") return 1;
  return 2;
}

function aggregateByLine(diagnostics, extraLines) {
  const map = new Map();
  for (const d of diagnostics || []) {
    const ln = d.line;
    if (!ln) continue;
    map.set(ln, (map.get(ln) || 0) + lineWeight(d));
  }
  for (const ln of extraLines || []) {
    map.set(ln, (map.get(ln) || 0) + 1);
  }
  return map;
}

export function onLintDiagnostics(diagnostics) {
  lastDiagnostics = diagnostics || [];
  paintRiskLane();
  renderSourceBars(lastDiagnostics);
}

export function onUnsafeRows(rows) {
  lastUnsafeRows = rows || [];
  renderUnsafeBars(lastUnsafeRows);
  const lines = [];
  for (const r of lastUnsafeRows) lines.push(...(r.lines || []));
  unsafeLines = new Set(lines);
  paintRiskLane();
}

export function onUnsafeLines(lines) {
  unsafeLines = new Set(lines || []);
  paintRiskLane();
}

function paintRiskLane() {
  const canvas = $("#live-risk-lane");
  if (!canvas) return;
  const source =
    window.SecureCCMonaco?.getValue?.() ?? document.querySelector("#source-editor")?.value ?? "";
  const lineCount = Math.max(1, source.split(/\r?\n/).length);
  const map = aggregateByLine(lastDiagnostics, unsafeLines);

  const dpr = window.devicePixelRatio || 1;
  const width = canvas.parentElement?.clientWidth || canvas.clientWidth || 320;
  const height = 140;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = "100%";
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);

  const styles = getComputedStyle(document.documentElement);
  const err = styles.getPropertyValue("--danger").trim() || "#dc2626";
  const warn = styles.getPropertyValue("--warning").trim() || "#d97706";
  const hint = styles.getPropertyValue("--accent").trim() || "#2563eb";
  const bg = styles.getPropertyValue("--bg-secondary").trim() || "#f1f5f9";
  const grid = styles.getPropertyValue("--border").trim() || "#e2e8f0";
  const muted = styles.getPropertyValue("--text-muted").trim() || "#64748b";

  const maxBars = Math.min(lineCount, Math.floor(width / 3));
  const barW = width / maxBars;

  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, width, height);
  for (let g = 0; g < 4; g++) {
    const y = height - (g / 3) * (height - 16) - 8;
    ctx.strokeStyle = grid;
    ctx.globalAlpha = 0.35;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }
  ctx.globalAlpha = 1;

  let hasData = false;
  for (let i = 0; i < maxBars; i++) {
    const ln = Math.max(1, Math.round((i / Math.max(1, maxBars - 1)) * (lineCount - 1)) + 1);
    const w = map.get(ln) || 0;
    if (!w) continue;
    hasData = true;
    const color = w >= 3 ? err : w >= 2 ? warn : hint;
    const h = Math.min(height - 12, 10 + w * 22);
    ctx.fillStyle = color;
    ctx.globalAlpha = 0.9;
    ctx.fillRect(i * barW + 0.5, height - h - 6, Math.max(1.5, barW - 1), h);
  }
  ctx.globalAlpha = 1;

  if (!hasData) {
    ctx.fillStyle = grid;
    ctx.globalAlpha = 0.5;
    const midH = 8;
    for (let i = 0; i < maxBars; i++) {
      ctx.fillRect(i * barW + 1, height - midH - 20, Math.max(1, barW - 2), midH);
    }
    ctx.globalAlpha = 1;
  }
}

function chartMuted() {
  return getComputedStyle(document.documentElement).getPropertyValue("--text-muted").trim() || "#64748b";
}

function renderSourceBars(diagnostics) {
  const canvas = $("#live-code-source-chart");
  if (!canvas || typeof Chart === "undefined") return;

  const counts = { heuristic: 0, compiler: 0, semantic: 0, java: 0 };
  for (const d of diagnostics || []) {
    const src = d.source || "heuristic";
    if (counts[src] != null) counts[src] += 1;
    else counts.heuristic += 1;
  }
  const labels = Object.keys(counts);
  const data = labels.map((k) => counts[k]);
  const muted = chartMuted();

  sourceChart?.destroy();
  sourceChart = new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          data,
          backgroundColor: ["#2563eb", "#d97706", "#7c3aed", "#059669"],
          borderRadius: 4,
          barThickness: 18,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        title: {
          display: true,
          text: "By checker",
          color: muted,
          font: { size: 11, weight: "600" },
        },
      },
      scales: {
        x: {
          beginAtZero: true,
          title: { display: true, text: "Issue count", color: muted, font: { size: 9 } },
          ticks: { stepSize: 1, color: muted, font: { size: 9 } },
          grid: { color: "rgba(0,0,0,0.06)" },
        },
        y: { ticks: { color: muted, font: { size: 10 } }, grid: { display: false } },
      },
    },
  });
}

function renderUnsafeBars(rows) {
  const canvas = $("#live-unsafe-bar-chart");
  if (!canvas || typeof Chart === "undefined") return;
  const top = (rows || []).slice(0, 10);
  const muted = chartMuted();
  const warn = getComputedStyle(document.documentElement).getPropertyValue("--warning").trim();

  unsafeChart?.destroy();
  if (!top.length) {
    unsafeChart = new Chart(canvas, {
      type: "bar",
      data: { labels: ["(none)"], datasets: [{ data: [0], backgroundColor: muted, borderRadius: 4 }] },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          title: {
            display: true,
            text: "Risky APIs",
            color: muted,
            font: { size: 11, weight: "600" },
          },
        },
        scales: {
          x: { display: false, max: 1 },
          y: { ticks: { color: muted, font: { size: 10 } }, grid: { display: false } },
        },
      },
    });
    return;
  }

  unsafeChart = new Chart(canvas, {
    type: "bar",
    data: {
      labels: top.map((r) => r.name),
      datasets: [
        {
          data: top.map((r) => r.count),
          backgroundColor: warn,
          borderRadius: 4,
          barThickness: 16,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        title: {
          display: true,
          text: "Risky APIs",
          color: muted,
          font: { size: 11, weight: "600" },
        },
      },
      scales: {
        x: {
          beginAtZero: true,
          title: { display: true, text: "Calls", color: muted, font: { size: 9 } },
          ticks: { stepSize: 1, color: muted, font: { size: 9 } },
          grid: { display: false },
        },
        y: { ticks: { color: muted, font: { size: 10 }, fontFamily: "JetBrains Mono, monospace" }, grid: { display: false } },
      },
    },
  });
}

export function resizeCodePanel() {
  paintRiskLane();
  sourceChart?.resize();
  unsafeChart?.resize();
}

export function clearCodePanel() {
  lastDiagnostics = [];
  unsafeLines = new Set();
  lastUnsafeRows = [];
  paintRiskLane();
  sourceChart?.destroy();
  unsafeChart?.destroy();
  sourceChart = null;
  unsafeChart = null;
}

window.SecureCCLiveCode = {
  onLintDiagnostics,
  onUnsafeLines,
  onUnsafeRows,
  resizeCodePanel,
  clearCodePanel,
};