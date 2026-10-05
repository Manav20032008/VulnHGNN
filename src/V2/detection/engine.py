from .registry import get_detectors
from ..analysis.graph_adapter import GraphAdapter

class DetectionEngine:
    def __init__(self):
        self.detectors = get_detectors()

    def analyze(self, sample, context=None):
        graph = GraphAdapter.graph(sample)
        context = dict(context or {})
        findings = []

        for detector in self.detectors:
            results = detector.detect(graph, context)
            findings.extend(results)

        return findings
