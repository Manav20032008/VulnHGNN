from __future__ import annotations

from collections import defaultdict

from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from ..analysis.heap_ir import (
    is_dealloc_call_excluding_self_use,
    is_heap_alloc_call,
    ptr_arg_from_dealloc,
)
from .base import BaseDetector

_MEMORY_USE_OPS = {"load", "store", "call", "invoke"}


def _instructions_by_function(analyzer: DataFlowAnalyzer) -> dict[str, list]:
    groups: dict[str, list] = defaultdict(list)
    for info in analyzer.instructions:
        groups[info.function].append(info)
    return groups


class MemoryLifecycleDetector(BaseDetector):
    """CWE-401 leak, CWE-415 double free, CWE-416 use-after-free on LLVM IR."""

    cwe_id = "CWE-MEMORY"
    title = "Memory Lifecycle"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings: list[SecurityFinding] = []

        for _func, insts in _instructions_by_function(analyzer).items():
            freed_roots: set[str] = set()
            alloc_roots: list[tuple[str, object]] = []
            uaf_seen: set[tuple[str, str]] = set()

            for info in insts:
                text = info.attrs.get("text", "") or ""
                op = info.attrs.get("opcode", "")

                if op == "call" and is_heap_alloc_call(text):
                    result = info.attrs.get("result") or analyzer._result(text)
                    if result:
                        alloc_roots.append((result, info.node_id))

                if op == "call" and is_dealloc_call_excluding_self_use(text):
                    ptr = ptr_arg_from_dealloc(text)
                    if not ptr:
                        continue
                    root = analyzer._root(ptr)
                    if root in freed_roots:
                        findings.append(
                            SecurityFinding(
                                cwe_id="CWE-415",
                                title="Double Free",
                                severity="HIGH",
                                confidence=0.94,
                                message=(
                                    "The same heap pointer is released more than once "
                                    "(free or operator delete)."
                                ),
                                function=info.function,
                                instruction=text,
                                evidence=[f"pointer={ptr}", f"root={root}"],
                                detector="MemoryLifecycleDetector",
                                node_id=info.node_id,
                                compiler_stage=self.compiler_stage,
                            )
                        )
                    else:
                        freed_roots.add(root)

                if op in _MEMORY_USE_OPS and freed_roots:
                    if is_dealloc_call_excluding_self_use(text):
                        continue
                    # iostream and other library calls should not count as heap uses.
                    if op in {"call", "invoke"} and "_ZNSt3__" in text:
                        continue
                    operands = analyzer._tokens(text)
                    if not operands and op not in {"call", "invoke"}:
                        continue
                    for operand in operands:
                        root = analyzer._root(operand)
                        if root in freed_roots:
                            key = (info.function, root)
                            if key in uaf_seen:
                                break
                            uaf_seen.add(key)
                            findings.append(
                                SecurityFinding(
                                    cwe_id="CWE-416",
                                    title="Use After Free",
                                    severity="HIGH",
                                    confidence=0.91,
                                    message=(
                                        "Memory is used after it was freed or deleted "
                                        "in the same function."
                                    ),
                                    function=info.function,
                                    instruction=text,
                                    evidence=[f"use_operand={operand}", f"freed_root={root}"],
                                    detector="MemoryLifecycleDetector",
                                    node_id=info.node_id,
                                    compiler_stage=self.compiler_stage,
                                )
                            )
                            break

            for root, node_id in alloc_roots:
                if analyzer._root(root) not in freed_roots:
                    findings.append(
                        SecurityFinding(
                            cwe_id="CWE-401",
                            title="Memory Leak",
                            severity="MEDIUM",
                            confidence=0.80,
                            message=(
                                "Heap allocation (malloc or operator new) is not "
                                "released before leaving the function."
                            ),
                            function=insts[0].function if insts else "unknown",
                            instruction=f"alloc {root}",
                            evidence=[f"alloc={root}", "no matching free/delete in function"],
                            detector="MemoryLifecycleDetector",
                            node_id=node_id,
                            compiler_stage=self.compiler_stage,
                        )
                    )

        return findings
