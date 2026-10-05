from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from .base import BaseDetector

class CWE191Detector(BaseDetector):
    cwe_id = "CWE-191"
    title = "Integer Underflow"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings = []

        for info in analyzer.instructions:
            data = analyzer.arithmetic_info(info)
            if not data or data["opcode"] != "sub":
                continue

            av, bv = data["a_value"], data["b_value"]

            if av is not None and bv is not None:
                value = av - bv
                if -(2**31) <= value <= 2**31 - 1:
                    continue

            if not data["nsw"]:
                continue

            findings.append(SecurityFinding(
                cwe_id=self.cwe_id,
                title=self.title,
                severity=self.severity,
                confidence=0.97,
                message="Signed integer subtraction may fall below the representable range.",
                function=info.function,
                instruction=info.attrs.get("text", ""),
                evidence=[
                    "opcode=sub",
                    "LLVM IR contains 'nsw'",
                    f"operands={data['a']}, {data['b']}",
                ],
                detector=self.cwe_id,
                node_id=info.node_id,
            ))
        return findings
