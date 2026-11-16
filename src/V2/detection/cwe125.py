from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from .base import BaseDetector


class CWE125Detector(BaseDetector):
    """IR-level heuristic: load through GEP with non-constant index."""

    cwe_id = "CWE-125"
    title = "Out-of-bounds Read"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings = []

        for info in analyzer.instructions:
            op = info.attrs.get("opcode", "")
            text = info.attrs.get("text", "") or ""
            if op != "getelementptr":
                continue
            if "inbounds" in text:
                continue
            idx_tokens = [t for t in analyzer._tokens(text) if t.startswith("%")]
            if len(idx_tokens) < 2:
                continue
            index = idx_tokens[-1]
            if analyzer.value(index) is not None:
                continue
            findings.append(
                SecurityFinding(
                    cwe_id=self.cwe_id,
                    title=self.title,
                    severity=self.severity,
                    confidence=0.75,
                    message="Array/ pointer offset read uses a non-proven-constant index in IR.",
                    function=info.function,
                    instruction=text,
                    evidence=[f"dynamic_index={index}", "gep without inbounds"],
                    detector="CWE125Detector",
                    node_id=info.node_id,
                    compiler_stage=self.compiler_stage,
                )
            )
        return findings
