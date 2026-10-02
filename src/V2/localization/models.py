from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class EvidenceStep:
    node_id: Any
    role: str
    instruction: str
    opcode: str = ""
    function: Optional[str] = None
    block: Optional[Any] = None
    relation: Optional[str] = None
    score: float = 0.0

    def to_dict(self):
        return {
            "node_id": self.node_id,
            "role": self.role,
            "instruction": self.instruction,
            "opcode": self.opcode,
            "function": self.function,
            "block": self.block,
            "relation": self.relation,
            "score": self.score,
        }


@dataclass
class LocalizedFinding:
    cwe_id: str
    title: str
    severity: str
    confidence: float
    function: Optional[str]
    vulnerable_node: Any
    vulnerable_instruction: str
    vulnerable_block: Optional[Any]
    evidence: list[EvidenceStep] = field(default_factory=list)
    related_nodes: list[Any] = field(default_factory=list)
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    source_column: Optional[int] = None
    localization_confidence: float = 0.0
    rationale: str = ""

    @property
    def evidence_path(self):
        return [step.node_id for step in self.evidence]

    def to_dict(self):
        return {
            "cwe_id": self.cwe_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "function": self.function,
            "vulnerable_node": self.vulnerable_node,
            "vulnerable_instruction": self.vulnerable_instruction,
            "vulnerable_block": self.vulnerable_block,
            "evidence": [x.to_dict() for x in self.evidence],
            "related_nodes": list(self.related_nodes),
            "source_file": self.source_file,
            "source_line": self.source_line,
            "source_column": self.source_column,
            "localization_confidence": self.localization_confidence,
            "rationale": self.rationale,
        }


@dataclass
class ValidationResult:
    passed: bool
    original_cwes: list[str]
    remaining_cwes: list[str]
    new_cwes: list[str]
    original_finding_count: int
    patched_finding_count: int
    removed_target_findings: int
    message: str
    original_findings: list[dict] = field(default_factory=list)
    patched_findings: list[dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "passed": self.passed,
            "original_cwes": self.original_cwes,
            "remaining_cwes": self.remaining_cwes,
            "new_cwes": self.new_cwes,
            "original_finding_count": self.original_finding_count,
            "patched_finding_count": self.patched_finding_count,
            "removed_target_findings": self.removed_target_findings,
            "message": self.message,
            "original_findings": list(self.original_findings),
            "patched_findings": list(self.patched_findings),
        }
