import re
from typing import Any

from .graph_context import GraphContext
from .models import EvidenceStep


class EvidenceBuilder:
    """Build deterministic, human-readable evidence for Phase-1 findings."""

    DATA_FLOW = {"data_flow"}
    CONTROL_FLOW = {"control_flow"}
    CONTAINS = {"contains"}

    @staticmethod
    def _tokens(text):
        return set(re.findall(r"%[-A-Za-z0-9._]+", text or ""))

    def __init__(self, graph):
        self.ctx = GraphContext(graph)

    def _step(self, node, role, relation=None, score=0.0):
        data = self.ctx.node_data(node)
        return EvidenceStep(
            node_id=node,
            role=role,
            instruction=data.get("text", ""),
            opcode=data.get("opcode", ""),
            function=data.get("func"),
            block=self.ctx.containing_block(node),
            relation=relation,
            score=float(score),
        )

    def _allocation_origin(self, target):
        """
        Recover a nearby allocator origin through graph data-flow and
        LLVM stack-slot semantics.
        """
        target_data = self.ctx.node_data(target)
        target_tokens = self._tokens(target_data.get("text", ""))

        allocators = {"malloc", "calloc", "realloc", "aligned_alloc"}

        candidates = []
        for node in self.ctx.instruction_nodes():
            data = self.ctx.node_data(node)
            if data.get("opcode") != "call":
                continue
            text = data.get("text", "")
            result = data.get("result", "")
            if result and any(f"@{name}" in text for name in allocators):
                candidates.append((node, result))

        # Direct data-flow path.
        for node, result in candidates:
            path = self.ctx.shortest_path(
                node, target, self.DATA_FLOW, max_depth=12
            )
            if path:
                return node, path

            # Stack-slot relationship:
            # alloc -> store ptr alloc, ptr slot -> load ptr slot -> target.
            if result not in target_tokens:
                continue

            for store in self.ctx.instruction_nodes():
                data = self.ctx.node_data(store)
                if data.get("opcode") != "store":
                    continue
                text = data.get("text", "")
                if result not in self._tokens(text):
                    continue

                parts = text.split(",", 1)
                if len(parts) != 2:
                    continue

                slots = self._tokens(parts[1])
                if not slots:
                    continue

                for load in self.ctx.instruction_nodes():
                    ld = self.ctx.node_data(load)
                    if ld.get("opcode") != "load":
                        continue
                    if "load ptr" not in ld.get("text", ""):
                        continue
                    if not (slots & self._tokens(ld.get("text", ""))):
                        continue

                    loaded = ld.get("result", "")
                    if not loaded:
                        continue

                    if loaded in target_tokens or loaded == result:
                        return node, [node, store, load, target]

        return None, []

    def _null_check_for(self, target):
        """Find a preceding/controlling NULL check on the same pointer."""
        target_block = self.ctx.containing_block(target)

        for node in self.ctx.instruction_nodes():
            data = self.ctx.node_data(node)
            if data.get("opcode") != "icmp":
                continue

            text = data.get("text", "")
            if "null" not in text or " ne " not in f" {text} ":
                continue

            check_block = self.ctx.containing_block(node)
            if check_block is None:
                continue

            # Same block: instruction order is approximated by graph order.
            if check_block == target_block:
                return node

            # A CFG path from check block to target block is evidence
            # that the check controls the later operation in this graph.
            if target_block is not None:
                path = self.ctx.shortest_path(
                    check_block,
                    target_block,
                    self.CONTROL_FLOW,
                    max_depth=20,
                )
                if path:
                    return node

        return None

    def build(self, finding):
        target = finding.node_id
        if target is None or target not in self.ctx.graph:
            return [], "Finding has no valid graph node."

        evidence = []
        target_data = self.ctx.node_data(target)

        evidence.append(
            self._step(
                target,
                "vulnerable_operation",
                relation="target",
                score=1.0,
            )
        )

        # Incoming data-flow evidence.
        incoming = self.ctx.predecessors(target, self.DATA_FLOW)
        for node in incoming[:4]:
            evidence.append(
                self._step(
                    node,
                    "data_flow_input",
                    relation="data_flow",
                    score=0.85,
                )
            )

        # Allocation origin, if recoverable.
        alloc_node, alloc_path = self._allocation_origin(target)
        if alloc_node is not None:
            evidence.append(
                self._step(
                    alloc_node,
                    "allocation_origin",
                    relation="allocation",
                    score=0.95,
                )
            )

            for node in alloc_path[1:-1]:
                if node not in {x.node_id for x in evidence}:
                    evidence.append(
                        self._step(
                            node,
                            "pointer_propagation",
                            relation="pointer_flow",
                            score=0.80,
                        )
                    )

        # NULL-check evidence.
        check = self._null_check_for(target)
        if check is not None:
            evidence.append(
                self._step(
                    check,
                    "null_check",
                    relation="control_flow",
                    score=0.90,
                )
            )

        # Small forward context.
        for node in list(self.ctx.successors(target, self.DATA_FLOW))[:3]:
            if node not in {x.node_id for x in evidence}:
                evidence.append(
                    self._step(
                        node,
                        "downstream_use",
                        relation="data_flow",
                        score=0.60,
                    )
                )

        # Stable order: strongest evidence first, then graph order.
        evidence.sort(key=lambda x: (-x.score, str(x.node_id)))

        roles = {x.role for x in evidence}
        if "allocation_origin" in roles and "pointer_propagation" in roles:
            rationale = (
                "The vulnerable operation is connected to an allocator result "
                "through the recovered pointer-flow/stack-slot chain."
            )
        elif "data_flow_input" in roles:
            rationale = (
                "The vulnerable operation has graph-level data-flow evidence "
                "from preceding instructions."
            )
        else:
            rationale = (
                "The detector identified the operation directly; additional "
                "graph evidence was not available."
            )

        return evidence, rationale
