import re

from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from .base import BaseDetector

_HEAP_COPY = re.compile(r"@(?P<fn>strcpy|strcat|memcpy|sprintf)\s*\(")


class CWE122Detector(BaseDetector):
    cwe_id = "CWE-122"
    title = "Heap-based Buffer Overflow"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings = []
        heap_roots = {
            analyzer._root(result)
            for result, _ in analyzer.allocation_results()
        }

        for info in analyzer.instructions:
            if info.attrs.get("opcode") != "call":
                continue
            text = info.attrs.get("text", "") or ""
            if not _HEAP_COPY.search(text):
                continue
            tokens = analyzer._tokens(text)
            if not tokens:
                continue
            dest = tokens[0]
            if analyzer._root(dest) not in heap_roots:
                continue
            findings.append(
                SecurityFinding(
                    cwe_id=self.cwe_id,
                    title=self.title,
                    severity=self.severity,
                    confidence=0.93,
                    message="Unbounded copy into a heap buffer may overflow the allocation.",
                    function=info.function,
                    instruction=text,
                    evidence=["destination aliases heap allocation (malloc or operator new)"],
                    detector="CWE122Detector",
                    node_id=info.node_id,
                    compiler_stage=self.compiler_stage,
                )
            )
        return findings
