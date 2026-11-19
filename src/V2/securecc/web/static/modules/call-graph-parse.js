const DEF_KEYWORDS = new Set([
  "if",
  "while",
  "for",
  "switch",
  "return",
  "sizeof",
  "catch",
  "throw",
]);

const CALL_KEYWORDS = new Set([
  ...DEF_KEYWORDS,
  "else",
  "do",
  "case",
  "break",
  "continue",
  "goto",
  "typedef",
  "struct",
  "union",
  "enum",
  "new",
  "delete",
]);

const RISKY_EXTERNAL = new Set([
  "gets",
  "strcpy",
  "strcat",
  "sprintf",
  "vsprintf",
  "scanf",
  "memcpy",
  "system",
  "popen",
  "atoi",
]);

function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\/\/.*$/gm, " ");
}

function findMatchingBrace(s, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < s.length; i++) {
    if (s[i] === "{") depth++;
    else if (s[i] === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function parenEnd(s, openParenIdx) {
  let depth = 0;
  for (let i = openParenIdx; i < s.length; i++) {
    if (s[i] === "(") depth++;
    else if (s[i] === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function extractCallSites(body) {
  const counts = new Map();
  const re = /\b([A-Za-z_]\w*)\s*\(/g;
  let m;
  while ((m = re.exec(body))) {
    const name = m[1];
    if (CALL_KEYWORDS.has(name)) continue;
    counts.set(name, (counts.get(name) || 0) + 1);
  }
  return counts;
}

function extractCFunctions(source) {
  const clean = stripComments(source);
  const defs = [];
  const re = /\b([A-Za-z_]\w*)\s*\(/g;
  let m;
  while ((m = re.exec(clean))) {
    const name = m[1];
    if (DEF_KEYWORDS.has(name)) continue;
    const parenOpen = m.index + m[0].length - 1;
    const parenClose = parenEnd(clean, parenOpen);
    if (parenClose < 0) continue;
    let j = parenClose + 1;
    while (j < clean.length && /\s/.test(clean[j])) j++;
    if (clean[j] !== "{") continue;
    const braceClose = findMatchingBrace(clean, j);
    if (braceClose < 0) continue;
    const body = clean.slice(j + 1, braceClose);
    defs.push({ name, body });
    re.lastIndex = braceClose + 1;
  }
  const byName = new Map();
  for (const d of defs) {
    if (!byName.has(d.name)) byName.set(d.name, d);
  }
  return [...byName.values()];
}

const JAVA_SKIP = new Set(["if", "for", "while", "switch", "catch", "synchronized"]);

function extractJavaFunctions(source) {
  const s = stripComments(source);
  const defs = [];
  const re =
    /(?:^|[;}])\s*(?:@[\w.]+\s*)*(?:(?:public|private|protected)\s+)?(?:static\s+)?(?:final\s+)?(?:[\w.<>\[\],\s]+\s+)(\w+)\s*\(/gm;
  let m;
  while ((m = re.exec(s))) {
    const name = m[1];
    if (JAVA_SKIP.has(name)) continue;
    const open = s.indexOf("{", m.index);
    if (open < 0) continue;
    const braceClose = findMatchingBrace(s, open);
    if (braceClose < 0) continue;
    defs.push({ name, body: s.slice(open + 1, braceClose) });
    re.lastIndex = braceClose + 1;
  }
  const byName = new Map();
  for (const d of defs) {
    if (!byName.has(d.name)) byName.set(d.name, d);
  }
  return [...byName.values()];
}

export function parseCallGraph(source, language = "c") {
  const empty = { nodes: [], edges: [], stats: { functions: 0, calls: 0 } };
  if (!source?.trim()) return empty;

  const defs =
    language === "java" ? extractJavaFunctions(source) : extractCFunctions(source);
  if (!defs.length) return empty;

  const defined = new Set(defs.map((d) => d.name));
  const edgeMap = new Map();
  const externals = new Set();

  for (const fn of defs) {
    const calls = extractCallSites(fn.body);
    for (const [callee, count] of calls) {
      const key = `${fn.name}\t${callee}`;
      if (!edgeMap.has(key)) {
        edgeMap.set(key, { source: fn.name, target: callee, count, recursive: fn.name === callee });
      } else {
        edgeMap.get(key).count += count;
      }
      if (!defined.has(callee)) externals.add(callee);
    }
  }

  const nodes = defs.map((d) => ({
    id: d.name,
    label: d.name,
    kind: d.name === "main" ? "entry" : "internal",
    risky: false,
  }));

  for (const ext of [...externals].sort()) {
    nodes.push({
      id: ext,
      label: ext,
      kind: "external",
      risky: RISKY_EXTERNAL.has(ext),
    });
  }

  const edges = [...edgeMap.values()].filter((e) => e.source !== e.target);
  const loops = [...edgeMap.values()].filter((e) => e.source === e.target);

  return {
    nodes,
    edges,
    loops,
    stats: {
      functions: defs.length,
      calls: edgeMap.size,
      externals: externals.size,
    },
  };
}