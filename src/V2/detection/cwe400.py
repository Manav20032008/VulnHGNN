from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from ..analysis.heap_ir import heap_alloc_size_operand, is_heap_alloc_call
from .base import BaseDetector


class CWE400Detector(BaseDetector):
    """Uncontrolled resource consumption: unbounded calloc/malloc loop input."""

    cwe_id = "CWE-400"
    title = "Uncontrolled Resource Consumption"
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
            size = heap_alloc_size_operand(text)
            if not size:
                tokens = analyzer._tokens(text)
                size = tokens[-1] if tokens else None
            if size and size.startswith("%") and analyzer.value(size) is None:
                findings.append(
                    SecurityFinding(
                        cwe_id=self.cwe_id,
                        title=self.title,
                        severity=self.severity,
                        confidence=0.82,
                        message="Allocation size depends on non-constant input (potential OOM / exhaustion).",
                        function=info.function,
                        instruction=text,
                        evidence=[f"dynamic_size={size}"],
                        detector="CWE400Detector",
                        node_id=info.node_id,
                        compiler_stage=self.compiler_stage,
                    )
                )
        return findings
