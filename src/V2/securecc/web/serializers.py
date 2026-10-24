from __future__ import annotations

from typing import Any

from ..scan import build_report


def _to_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(x) for x in obj]
    return str(obj)


def serialize_graph(
    graph,
    *,
    highlight_nodes: set[str] | None = None,
    max_nodes: int = 400,
) -> dict[str, Any]:
    """Export a NetworkX graph for force-directed visualization."""
    highlight_nodes = highlight_nodes or set()
    nodes_out: list[dict[str, Any]] = []
    edges_out: list[dict[str, Any]] = []

    all_nodes = list(graph.nodes(data=True))
    if len(all_nodes) > max_nodes:
        keep: set[Any] = set(highlight_nodes)
        for node_id in highlight_nodes:
            if node_id not in graph:
                continue
            for neighbor in graph.predecessors(node_id):
                keep.add(neighbor)
            for neighbor in graph.successors(node_id):
                keep.add(neighbor)
            attrs = graph.nodes.get(node_id, {})
            for u, v, _ in graph.in_edges(node_id, data=True):
                if graph.nodes.get(u, {}).get("node_type") == "block":
                    keep.add(u)
            for u, v, _ in graph.out_edges(node_id, data=True):
                if graph.nodes.get(v, {}).get("node_type") == "block":
                    keep.add(v)
        filtered = [(n, a) for n, a in all_nodes if n in keep]
        if len(filtered) > max_nodes:
            filtered = sorted(
                filtered,
                key=lambda item: (0 if item[0] in highlight_nodes else 1, str(item[0])),
            )[:max_nodes]
        node_set = {n for n, _ in filtered}
    else:
        filtered = all_nodes
        node_set = {n for n, _ in filtered}

    for node_id, attrs in filtered:
        ntype = attrs.get("node_type", "unknown")
        label = str(node_id)
        if ntype == "instruction":
            opcode = attrs.get("opcode", "")
            text = (attrs.get("text") or "")[:72]
            label = f"{opcode}: {text}" if text else opcode
        elif ntype == "block":
            label = f"block {attrs.get('label', '')}"

        nodes_out.append(
            {
                "id": str(node_id),
                "type": ntype,
                "label": label,
                "opcode": attrs.get("opcode", ""),
                "text": attrs.get("text", ""),
                "function": attrs.get("func", ""),
                "highlight": str(node_id) in {str(x) for x in highlight_nodes},
            }
        )

    for u, v, attrs in graph.edges(data=True):
        if u not in node_set or v not in node_set:
            continue
        edge_type = attrs.get("edge_type") or attrs.get("type") or "unknown"
        edges_out.append(
            {
                "source": str(u),
                "target": str(v),
                "type": str(edge_type),
            }
        )

    return {
        "nodes": nodes_out,
        "edges": edges_out,
        "truncated": len(all_nodes) > len(filtered),
        "total_nodes": len(all_nodes),
        "shown_nodes": len(nodes_out),
    }


def analysis_bundle(analysis: dict) -> dict[str, Any]:
    """Turn analyze_source() output into API-friendly scan payload + graph."""
    report = build_report(analysis)
    highlight: set[str] = set()
    for finding in report.get("findings", []):
        node = finding.get("node_id")
        if node:
            highlight.add(str(node))
    for loc in report.get("localization", []):
        vn = loc.get("vulnerable_node")
        if vn:
            highlight.add(str(vn))
        for step in loc.get("evidence", []):
            nid = step.get("node_id")
            if nid:
                highlight.add(str(nid))

    graph = analysis.get("graph")
    graph_json = None
    if graph is not None:
        graph_json = serialize_graph(graph, highlight_nodes=highlight)

    return {
        "scan": report,
        "graph": graph_json,
        "source_path": analysis.get("source"),
    }
