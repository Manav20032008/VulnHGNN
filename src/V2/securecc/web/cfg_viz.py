from __future__ import annotations

import re
from typing import Any

import networkx as nx

from src.V2.detection.cfg_utils import blocks_by_function, cfg_successors

MAX_FUNCTIONS = 4
MAX_BLOCKS_PER_FUNC = 48

_CALL_RE = re.compile(r"call\s+(?:\w+\s+)?@(\w+)", re.I)
_BR_RE = re.compile(r"br\s+i1.*label\s+%(\w+).*label\s+%(\w+)", re.I)
_BR_UNCOND_RE = re.compile(r"br\s+label\s+%(\w+)", re.I)
_RET_RE = re.compile(r"\bret\b", re.I)


def _cfg_predecessors(graph, block_node: str, block_set: set[str]) -> list[str]:
    out = []
    for pred, _, edge in graph.in_edges(block_node, data=True):
        if edge.get("edge_type") != "control_flow":
            continue
        if pred in block_set:
            out.append(pred)
    return out


def _find_entry(blocks: list[str], graph) -> str | None:
    if not blocks:
        return None
    block_set = set(blocks)
    candidates = [
        b
        for b in blocks
        if not _cfg_predecessors(graph, b, block_set)
    ]
    if candidates:
        return sorted(candidates, key=str)[0]
    return blocks[0]


def _block_instructions(graph, block_node: str) -> list[dict]:
    items = []
    for _, inst, edge in graph.out_edges(block_node, data=True):
        if edge.get("edge_type") != "contains":
            continue
        data = graph.nodes.get(inst, {})
        if data.get("node_type") != "instruction":
            continue
        items.append(data)
    return items


def _label_to_line(ir_label: str) -> int | None:
    if ir_label == "entry":
        return 1
    if ir_label.isdigit():
        return int(ir_label)
    return None


def _shorten(text: str, n: int = 42) -> str:
    t = " ".join(text.split())
    return t if len(t) <= n else f"{t[: n - 1]}…"


def _summarize_block(graph, block_node: str, ir_label: str) -> dict[str, Any]:
    insts = _block_instructions(graph, block_node)
    source_line = _label_to_line(str(ir_label))
    title = "Function entry" if ir_label == "entry" else (
        f"≈ source line {source_line}" if source_line else f"Block {ir_label}"
    )

    subtitle = "straight-line code"
    terminator = ""
    calls: list[str] = []

    for inst in reversed(insts):
        text = inst.get("text") or ""
        opcode = inst.get("opcode") or ""
        if opcode == "call" or " call " in text.lower():
            m = _CALL_RE.search(text)
            if m:
                calls.append(m.group(1))
        if opcode in {"br", "switch"} or _RET_RE.search(text):
            terminator = text
            break
        if opcode == "ret" or text.strip().startswith("ret "):
            terminator = text
            subtitle = "return"
            break

    if terminator and subtitle == "straight-line code":
        if "switch" in terminator.lower():
            subtitle = "switch branch"
        elif _BR_RE.search(terminator):
            subtitle = "conditional branch"
        elif _BR_UNCOND_RE.search(terminator):
            subtitle = "unconditional jump"
        elif _RET_RE.search(terminator):
            subtitle = "return"
        else:
            subtitle = _shorten(terminator, 36)

    if calls and subtitle == "straight-line code":
        subtitle = f"call {calls[0]}" + (f" +{len(calls)-1}" if len(calls) > 1 else "")

    parts = [title, subtitle]
    if calls:
        parts.append("Calls: " + ", ".join(calls[:4]))
    if terminator and subtitle not in ("return", "conditional branch", "unconditional jump", "switch branch"):
        parts.append(_shorten(terminator, 80))

    return {
        "title": title,
        "subtitle": subtitle,
        "source_line": source_line,
        "summary": " · ".join(parts),
        "calls": calls,
    }


def _block_label_for_id(graph, block_id: str) -> str:
    return str(graph.nodes.get(block_id, {}).get("label", block_id))


def _edge_branch_hint(graph, src: str, dst: str) -> str | None:
    """Guess true/false/succ for conditional branches."""
    src_label = _block_label_for_id(graph, src)
    dst_label = _block_label_for_id(graph, dst)
    for inst in reversed(_block_instructions(graph, src)):
        text = inst.get("text") or ""
        m = _BR_RE.search(text)
        if m:
            t1, t2 = m.group(1), m.group(2)
            if dst_label == t1:
                return "then"
            if dst_label == t2:
                return "else"
            break
        if _BR_UNCOND_RE.search(text):
            return None
    succs = cfg_successors(graph, src)
    if len(succs) == 1:
        return None
    if len(succs) == 2 and dst in succs:
        return "then" if succs[0] == dst else "else"
    return None


def _function_cfg(graph, func: str, highlight: set[str]) -> dict[str, Any] | None:
    groups = blocks_by_function(graph)
    blocks = groups.get(func) or []
    if not blocks:
        return None
    blocks = sorted(blocks, key=str)[:MAX_BLOCKS_PER_FUNC]
    block_set = set(blocks)

    g_cfg = nx.DiGraph()
    for b in blocks:
        g_cfg.add_node(b)
    for b in blocks:
        for dst in cfg_successors(graph, b):
            if dst in block_set:
                g_cfg.add_edge(b, dst)

    entry = _find_entry(blocks, graph)
    if not entry or entry not in g_cfg:
        return None

    nodes_out = []
    for bid in blocks:
        attrs = graph.nodes.get(bid, {})
        ir_label = str(attrs.get("label") or bid)
        meta = _summarize_block(graph, bid, ir_label)
        nodes_out.append(
            {
                "id": str(bid),
                "label": ir_label,
                "ir_label": ir_label,
                "title": meta["title"],
                "subtitle": meta["subtitle"],
                "source_line": meta["source_line"],
                "summary": meta["summary"],
                "highlight": str(bid) in highlight,
            }
        )

    cfg_edges = []
    for u, v in g_cfg.edges():
        hint = _edge_branch_hint(graph, u, v)
        cfg_edges.append(
            {
                "source": str(u),
                "target": str(v),
                "branch": hint,
            }
        )

    dom_edges: list[dict[str, str]] = []
    idom_by_id: dict[str, str] = {}
    try:
        idom = nx.immediate_dominators(g_cfg, entry)
        for node, parent in idom.items():
            if node == entry:
                continue
            if parent == node:
                continue
            dom_edges.append({"source": str(parent), "target": str(node)})
            idom_by_id[str(node)] = str(parent)
    except (nx.NetworkXError, nx.NetworkXPointlessConcept):
        dom_edges = []

    for n in nodes_out:
        parent = idom_by_id.get(n["id"])
        if parent:
            pl = _block_label_for_id(graph, parent)
            pmeta = next((x for x in nodes_out if x["id"] == parent), None)
            n["idom_title"] = pmeta["title"] if pmeta else pl
        else:
            n["idom_title"] = None

    return {
        "name": func,
        "entry": str(entry),
        "blocks": nodes_out,
        "cfg_edges": cfg_edges,
        "dom_edges": dom_edges,
        "block_count": len(blocks),
    }


def build_flow_views(graph, *, highlight_nodes: set[str] | None = None) -> dict[str, Any]:
    """CFG + immediate-dominator data per function for live UI."""
    highlight_nodes = highlight_nodes or set()
    highlight = {str(x) for x in highlight_nodes}
    if graph is None:
        return {"functions": []}

    groups = blocks_by_function(graph)
    names = sorted(groups.keys())[:MAX_FUNCTIONS]
    functions = []
    for func in names:
        view = _function_cfg(graph, func, highlight)
        if view:
            functions.append(view)

    return {"functions": functions}