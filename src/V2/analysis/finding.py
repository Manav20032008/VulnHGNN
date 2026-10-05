from dataclasses import dataclass, field
from typing import Optional

@dataclass
class SourceLocation:
    file: str
    line: Optional[int] = None
    column: Optional[int] = None

@dataclass
class SecurityFinding:
    cwe_id: str
    title: str
    severity: str
    confidence: float
    message: str
    location: Optional[SourceLocation] = None
    function: Optional[str] = None
    instruction: Optional[str] = None
    evidence: list[str] = field(default_factory=list)
    detector: str = "unknown"
    node_id: object = None

    def to_dict(self):
        return {
            "cwe_id": self.cwe_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "location": None if self.location is None else {
                "file": self.location.file,
                "line": self.location.line,
                "column": self.location.column,
            },
            "function": self.function,
            "instruction": self.instruction,
            "evidence": list(self.evidence),
            "detector": self.detector,
            "node_id": self.node_id,
        }
