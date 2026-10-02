from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from .base import BaseDetector

class CWE190Detector(BaseDetector):
    cwe_id = "CWE-190"
    title = "Integer Overflow"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings = []

        for info in analyzer.instructions:
            data = analyzer.arithmetic_info(info)
            if not data or data["opcode"] not in {"add", "mul"}:
                continue

            av, bv = data["a_value"], data["b_value"]

            # Fully constant expression: prove safety instead of flagging it.
            if av is not None and bv is not None:
                value = av + bv if data["opcode"] == "add" else av * bv
                if -(2**31) <= value <= 2**31 - 1:
                    continue

            # LLVM's nsw is the important signal here: the operation is signed
            # and LLVM assumes it does not overflow. If operands are not
            # statically safe, this is a meaningful vulnerability candidate.
            if not data["nsw"]:
                continue

            findings.append(SecurityFinding(
                cwe_id=self.cwe_id,
                title=self.title,
                severity=self.severity,
                confidence=0.97,
                message="Signed integer arithmetic may exceed the representable range.",
                function=info.function,
                instruction=info.attrs.get("text", ""),
                evidence=[
                    f"opcode={data['opcode']}",
                    "LLVM IR contains 'nsw'",
                    f"operands={data['a']}, {data['b']}",
                ],
                detector=self.cwe_id,
                node_id=info.node_id,
            ))
        return findings
