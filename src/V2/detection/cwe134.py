import re

from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from .base import BaseDetector

_FORMAT_FUNCS = ("printf", "fprintf", "dprintf", "vprintf")
# Literal format in IR usually appears as @.str or constant global
_LITERAL_FORMAT_RE = re.compile(r"@\.str")


class CWE134Detector(BaseDetector):
    cwe_id = "CWE-134"
    title = "Use of Externally-Controlled Format String"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings = []

        for info in analyzer.instructions:
            if info.attrs.get("opcode") != "call":
                continue
            text = info.attrs.get("text", "") or ""
            if not any(f"@{fn}" in text or f" {fn}(" in text for fn in _FORMAT_FUNCS):
                continue
            if _LITERAL_FORMAT_RE.search(text):
                continue
            findings.append(
                SecurityFinding(
                    cwe_id=self.cwe_id,
                    title=self.title,
                    severity=self.severity,
                    confidence=0.88,
                    message="printf-family call uses a non-literal format string in LLVM IR.",
                    function=info.function,
                    instruction=text,
                    evidence=["format argument is not an @.str literal"],
                    detector="CWE134Detector",
                    node_id=info.node_id,
                    compiler_stage=self.compiler_stage,
                )
            )
        return findings
