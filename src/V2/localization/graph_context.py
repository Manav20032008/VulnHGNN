from collections import deque
from typing import Any, Iterable, Optional


class GraphContext:
    """Read-only helper around the existing NetworkX VulnHGNN graph."""

    def __init__(self, graph):
        if not hasattr(graph, "nodes") or not hasattr(graph, "edges"):
            raise TypeError("GraphContext requires a NetworkX graph")
        self.graph = graph

    def node_data(self, node):
        return self.graph.nodes[node]

    def instruction_nodes(self):
        return [
            node for node, data in self.graph.nodes(data=True)
            if data.get("node_type") == "instruction"
        ]

    def block_nodes(self):
        return [
            node for node, data in self.graph.nodes(data=True)
            if data.get("node_type") == "block"
        ]

    def instruction(self, node):
        data = self.node_data(node)
        return data.get("text", "")

    def opcode(self, node):
        return self.node_data(node).get("opcode", "")

    def function(self, node):
        data = self.node_data(node)
        return data.get("func")

    def containing_block(self, node):
        for block, data in self.graph.nodes(data=True):
            if data.get("node_type") != "block":
                continue
            if self.graph.has_edge(block, node):
                edge = self.graph.edges[block, node]
                if edge.get("edge_type") == "contains":
                    return block
        return None

    def predecessors(self, node, edge_types=None):
        result = []
        for pred in self.graph.predecessors(node):
            edge = self.graph.edges[pred, node]
            if edge_types is None or edge.get("edge_type") in edge_types:
                result.append(pred)
        return result

    def successors(self, node, edge_types=None):
        result = []
        for nxt in self.graph.successors(node):
            edge = self.graph.edges[node, nxt]
            if edge_types is None or edge.get("edge_type") in edge_types:
                result.append(nxt)
        return result

    def shortest_path(self, start, target, edge_types=None, max_depth=20):
        """BFS path using only the requested edge types."""
        if start == target:
            return [start]

        queue = deque([(start, [start])])
        visited = {start}

        while queue:
            current, path = queue.popleft()
            if len(path) - 1 >= max_depth:
                continue

            for nxt in self.successors(current, edge_types):
                if nxt in visited:
                    continue
                new_path = path + [nxt]
                if nxt == target:
                    return new_path
                visited.add(nxt)
                queue.append((nxt, new_path))

        return []

    def reverse_reachable(self, target, edge_types=None, max_depth=3):
        """Return nearby nodes that can reach target."""
        queue = deque([(target, 0)])
        visited = {target}

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for pred in self.predecessors(current, edge_types):
                if pred in visited:
                    continue
                visited.add(pred)
                queue.append((pred, depth + 1))

        visited.discard(target)
        return visited

    def forward_reachable(self, source, edge_types=None, max_depth=3):
        queue = deque([(source, 0)])
        visited = {source}

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for nxt in self.successors(current, edge_types):
                if nxt in visited:
                    continue
                visited.add(nxt)
                queue.append((nxt, depth + 1))

        visited.discard(source)
        return visited

    def edge_type(self, source, target):
        if not self.graph.has_edge(source, target):
            return None
        return self.graph.edges[source, target].get("edge_type")
