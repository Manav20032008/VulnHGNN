/** Shared block summaries for CFG/DOM when API flow payload is missing. */

const CALL_RE = /\bcall\b.*@(\w+)/i;
const BR_COND_RE = /br\s+i1.*label\s+%(\w+).*label\s+%(\w+)/i;
const RET_RE = /\bret\b/i;

function labelToLine(label) {
  if (label === "entry") return 1;
  if (/^\d+$/.test(label)) return parseInt(label, 10);
  return null;
}

function blockTitle(label) {
  if (label === "entry") return "Function entry";
  const ln = labelToLine(label);
  return ln ? `≈ source line ${ln}` : `Block ${label}`;
}

export function summarizeFromGraph(graph, blockId, label) {
  const irLabel = (label || "").replace(/^block\s+/, "");
  const contains = (graph.edges || []).filter(
    (e) => e.type === "contains" && e.source === blockId
  );
  const insts = contains
    .map((e) => graph.nodes.find((n) => n.id === e.target))
    .filter((n) => n && n.type === "instruction");

  let subtitle = "straight-line code";
  let terminator = "";
  const calls = [];

  for (let i = insts.length - 1; i >= 0; i--) {
    const text = insts[i].text || insts[i].label || "";
    const op = insts[i].opcode || "";
    if (op === "call" || CALL_RE.test(text)) {
      const m = text.match(CALL_RE);
      if (m) calls.push(m[1]);
    }
    if (op === "br" || op === "switch" || op === "ret" || RET_RE.test(text)) {
      terminator = text;
      break;
    }
  }

  if (terminator) {
    if (/switch/i.test(terminator)) subtitle = "switch branch";
    else if (BR_COND_RE.test(terminator)) subtitle = "conditional branch";
    else if (RET_RE.test(terminator)) subtitle = "return";
    else if (/br\s+label/i.test(terminator)) subtitle = "unconditional jump";
    else subtitle = terminator.slice(0, 36);
  } else if (calls.length) {
    subtitle = `call ${calls[0]}`;
  }

  const title = blockTitle(irLabel);
  return {
    ir_label: irLabel,
    title,
    subtitle,
    source_line: labelToLine(irLabel),
    summary: `${title} · ${subtitle}`,
    calls,
  };
}

export function branchHint(graph, srcId, dstId) {
  const dstNode = graph.nodes.find((n) => n.id === dstId);
  const dstLabel = (dstNode?.label || "").replace(/^block\s+/, "");
  const insts = (graph.edges || [])
    .filter((e) => e.type === "contains" && e.source === srcId)
    .map((e) => graph.nodes.find((n) => n.id === e.target))
    .filter((n) => n?.type === "instruction");

  for (let i = insts.length - 1; i >= 0; i--) {
    const text = insts[i].text || "";
    const m = text.match(BR_COND_RE);
    if (m) {
      if (dstLabel === m[1]) return "then";
      if (dstLabel === m[2]) return "else";
      break;
    }
  }
  return null;
}