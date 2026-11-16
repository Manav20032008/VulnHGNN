import re

from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from ..analysis.heap_ir import heap_alloc_size_operand, is_heap_alloc_call
from .base import BaseDetector

_OOM_THRESHOLD = 50_000_000


class CWE789Detector(BaseDetector):
    cwe_id = "CWE-789"
    title = "Memory Allocation with Excessive Size"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings = []

        for info in analyzer.instructions:
            if info.attrs.get("opcode") != "call":
                continue
            text = info.attrs.get("text", "") or ""
            if not is_heap_alloc_call(text):
                continue

            size_token = heap_alloc_size_operand(text)
            if not size_token:
                tokens = analyzer._tokens(text)
                size_token = tokens[-1] if tokens else None
            size_val = analyzer.value(size_token) if size_token else None

            risky = False
            reason = ""
            if size_val is not None and size_val >= _OOM_THRESHOLD:
                risky = True
                reason = f"constant_size={size_val}"
            elif size_token and size_token.startswith("%"):
                prev = analyzer.by_result.get(size_token.strip())
                if prev:
                    pdata = analyzer.arithmetic_info(prev)
                    if pdata and pdata["opcode"] in {"mul", "add"}:
                        risky = True
                        reason = f"size operand from {pdata['opcode']} (OOM/overflow risk)"

            if not risky:
                continue

            findings.append(
                SecurityFinding(
                    cwe_id=self.cwe_id,
                    title=self.title,
                    severity=self.severity,
                    confidence=0.86,
                    message="Allocation size may be excessive or derived from unchecked arithmetic (OOM risk).",
                    function=info.function,
                    instruction=text,
                    evidence=[reason or "unchecked allocation size"],
                    detector="CWE789Detector",
                    node_id=info.node_id,
                    compiler_stage=self.compiler_stage,
                )
            )
        return findings
