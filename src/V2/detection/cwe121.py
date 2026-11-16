from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from .base import BaseDetector

_UNBOUNDED_LIBC = (
    "strcpy",
    "strcat",
    "gets",
    "sprintf",
    "vsprintf",
    "scanf",
    "sscanf",
)


class CWE121Detector(BaseDetector):
    cwe_id = "CWE-121"
    title = "Stack-based Buffer Overflow"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings = []

        for info in analyzer.instructions:
            if info.attrs.get("opcode") != "call":
                continue
            text = info.attrs.get("text", "") or ""
            hit = next((name for name in _UNBOUNDED_LIBC if f"@{name}" in text or f" {name}(" in text), None)
            if not hit:
                continue
            findings.append(
                SecurityFinding(
                    cwe_id=self.cwe_id,
                    title=self.title,
                    severity=self.severity,
                    confidence=0.92,
                    message=f"Unbounded libc routine @{hit} may overflow stack or heap buffers.",
                    function=info.function,
                    instruction=text,
                    evidence=[f"call={hit}", "no bounded-length API detected in IR"],
                    detector="CWE121Detector",
                    node_id=info.node_id,
                    compiler_stage=self.compiler_stage,
                )
            )
        return findings
