from typing import Optional

from ..analysis.graph_adapter import GraphAdapter
from .evidence import EvidenceBuilder
from .models import LocalizedFinding


class VulnerabilityLocalizer:
    """
    Convert Phase-1 SecurityFinding objects into precise Phase-2
    localized findings.

    Localization is deterministic and evidence-first. It does not replace
    the Phase-1 detector and does not invent source lines.
    """

    def __init__(self):
        pass

    @staticmethod
    def _source_metadata(sample, node_data):
        source_file = node_data.get("file")
        source_line = node_data.get("line")
        source_column = node_data.get("column")

        if isinstance(sample, dict):
            source_file = source_file or sample.get("source_file")
            source_line = source_line if source_line is not None else sample.get("source_line")
            source_column = source_column if source_column is not None else sample.get("source_column")

        return source_file, source_line, source_column

    def localize_one(self, sample, finding):
        graph = GraphAdapter.graph(sample)
        if finding.node_id not in graph:
            raise ValueError(
                f"Finding node {finding.node_id!r} does not exist in graph"
            )

        node_data = graph.nodes[finding.node_id]
        block = None

        for candidate, data in graph.nodes(data=True):
            if data.get("node_type") != "block":
                continue
            if graph.has_edge(candidate, finding.node_id):
                edge = graph.edges[candidate, finding.node_id]
                if edge.get("edge_type") == "contains":
                    block = candidate
                    break

        evidence_builder = EvidenceBuilder(graph)
        evidence, rationale = evidence_builder.build(finding)

        # Localization confidence is based on concrete evidence, not the
        # detector's classification confidence.
        roles = {x.role for x in evidence}
        score = 0.50
        if "vulnerable_operation" in roles:
            score += 0.20
        if "allocation_origin" in roles:
            score += 0.15
        if "pointer_propagation" in roles:
            score += 0.10
        if "data_flow_input" in roles:
            score += 0.05
        score = min(score, 1.0)

        source_file, source_line, source_column = self._source_metadata(
            sample, node_data
        )

        related = []
        for step in evidence:
            if step.node_id != finding.node_id and step.node_id not in related:
                related.append(step.node_id)

        return LocalizedFinding(
            cwe_id=finding.cwe_id,
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            function=finding.function or node_data.get("func"),
            vulnerable_node=finding.node_id,
            vulnerable_instruction=finding.instruction or node_data.get("text", ""),
            vulnerable_block=block,
            evidence=evidence,
            related_nodes=related,
            source_file=source_file,
            source_line=source_line,
            source_column=source_column,
            localization_confidence=score,
            rationale=rationale,
        )

    def localize(self, sample, findings):
        return [self.localize_one(sample, finding) for finding in findings]
