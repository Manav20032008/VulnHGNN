from __future__ import annotations

from collections import defaultdict


def blocks_by_function(graph) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = defaultdict(list)
    for node, data in graph.nodes(data=True):
        if data.get("node_type") != "block":
            continue
        groups[data.get("func") or "unknown"].append(node)
    return groups


def cfg_successors(graph, block_node: str) -> list[str]:
    out = []
    for _, dst, edge in graph.out_edges(block_node, data=True):
        if edge.get("edge_type") == "control_flow":
            out.append(dst)
    return out


def block_branch_instructions(graph, block_node: str) -> list[tuple[object, dict]]:
    items = []
    for _, inst, edge in graph.out_edges(block_node, data=True):
        if edge.get("edge_type") != "contains":
            continue
        data = graph.nodes[inst]
        if data.get("node_type") != "instruction":
            continue
        if data.get("opcode") in {"br", "switch"}:
            items.append((inst, data))
    return items


def block_has_return(graph, block_node: str) -> bool:
    for _, inst, edge in graph.out_edges(block_node, data=True):
        if edge.get("edge_type") != "contains":
            continue
        data = graph.nodes[inst]
        if data.get("opcode") == "ret":
            return True
    return False


def function_has_return(graph, func: str) -> bool:
    for node, data in graph.nodes(data=True):
        if data.get("node_type") != "block" or data.get("func") != func:
            continue
        if block_has_return(graph, node):
            return True
    return False
