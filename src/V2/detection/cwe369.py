from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from .base import BaseDetector

class CWE369Detector(BaseDetector):
    cwe_id = "CWE-369"
    title = "Divide by Zero"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings = []

        for info in analyzer.instructions:
            data = analyzer.division_info(info)
            if not data:
                continue

            divisor_value = data["divisor_value"]

            # Proven non-zero => safe.
            if divisor_value is not None and divisor_value != 0:
                continue

            findings.append(SecurityFinding(
                cwe_id=self.cwe_id,
                title=self.title,
                severity=self.severity,
                confidence=0.99 if divisor_value == 0 else 0.90,
                message="Integer division or remainder uses a divisor that is zero or not proven non-zero.",
                function=info.function,
                instruction=info.attrs.get("text", ""),
                evidence=[
                    f"opcode={data['opcode']}",
                    f"divisor={data['divisor']}",
                    f"known_value={divisor_value}",
                ],
                detector=self.cwe_id,
                node_id=info.node_id,
            ))
        return findings
