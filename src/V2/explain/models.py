from dataclasses import dataclass, field

@dataclass
class EvidenceItem:
    role: str
    node_id: str
    instruction: str
    function: str
    block: str
    reason: str

@dataclass
class Explanation:
    cwe_id: str
    title: str
    severity: str
    root_cause: str
    security_impact: str
    vulnerable_operation: str
    function: str
    block: str
    node_id: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    repair_strategy: str = ""
    verification: str = ""
    confidence_basis: str = ""

    def to_dict(self):
        return {
            "cwe_id": self.cwe_id, "title": self.title,
            "severity": self.severity, "root_cause": self.root_cause,
            "security_impact": self.security_impact,
            "vulnerable_operation": self.vulnerable_operation,
            "function": self.function, "block": self.block,
            "node_id": self.node_id,
            "evidence": [e.__dict__ for e in self.evidence],
            "repair_strategy": self.repair_strategy,
            "verification": self.verification,
            "confidence_basis": self.confidence_basis,
        }
