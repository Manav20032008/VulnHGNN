import { readCssVar } from "./theme.js";

const SEV_COLOR = {
  critical: () => readCssVar("--danger") || "#dc2626",
  high: () => readCssVar("--danger") || "#dc2626",
  medium: () => readCssVar("--warning") || "#d97706",
  low: () => readCssVar("--accent-bright") || "#3b82f6",
  info: () => readCssVar("--text-muted") || "#64748b",
};

let chartInstance = null;

export function destroyFindingsChart() {
  if (chartInstance) {
    chartInstance.destroy();
    chartInstance = null;
  }
}

export function renderFindingsConfidenceChart(canvas, findings) {
  if (!canvas || typeof Chart === "undefined") return;
  destroyFindingsChart();
  if (!findings?.length) return;

  const labels = findings.map((f) => f.cwe_id || "CWE");
  const conf = findings.map((f) =>
    typeof f.confidence === "number" ? Math.round(f.confidence * 100) : 0
  );
  const colors = findings.map((f) => {
    const k = (f.severity || "info").toLowerCase();
    const fn = SEV_COLOR[k] || SEV_COLOR.info;
    return fn();
  });

  const textColor = readCssVar("--text-muted") || "#64748b";
  const gridColor = readCssVar("--border") || "#e2e8f0";

  chartInstance = new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "Confidence %",
          data: conf,
          backgroundColor: colors.map((c) => c + "cc"),
          borderColor: colors,
          borderWidth: 1,
          borderRadius: 6,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            afterLabel(ctx) {
              const f = findings[ctx.dataIndex];
              if (!f) return "";
              return [f.title, f.severity ? `Severity: ${f.severity}` : ""].filter(Boolean).join("\n");
            },
          },
        },
      },
      scales: {
        x: {
          min: 0,
          max: 100,
          grid: { color: gridColor },
          ticks: { color: textColor, callback: (v) => `${v}%` },
          title: { display: true, text: "Confidence", color: textColor, font: { size: 11 } },
        },
        y: {
          grid: { display: false },
          ticks: { color: textColor, font: { family: "JetBrains Mono, monospace", size: 11 } },
          title: { display: true, text: "CWE", color: textColor, font: { size: 11 } },
        },
      },
    },
  });
}