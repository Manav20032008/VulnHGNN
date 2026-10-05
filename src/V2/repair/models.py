from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class RepairAction:
    cwe_id: str
    node_id: Any
    instruction: str
    strategy: str
    description: str
    safe: bool = True
    target_function: Optional[str] = None
    target_block: Optional[Any] = None
    evidence_nodes: list[Any] = field(default_factory=list)

    def to_dict(self):
        return {
            "cwe_id": self.cwe_id,
            "node_id": self.node_id,
            "instruction": self.instruction,
            "strategy": self.strategy,
            "description": self.description,
            "safe": self.safe,
            "target_function": self.target_function,
            "target_block": self.target_block,
            "evidence_nodes": list(self.evidence_nodes),
        }


@dataclass
class RepairPlan:
    actions: list[RepairAction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def cwes(self):
        return sorted({x.cwe_id for x in self.actions})

    def to_dict(self):
        return {
            "action_count": len(self.actions),
            "cwes": self.cwes,
            "warnings": list(self.warnings),
            "actions": [x.to_dict() for x in self.actions],
        }


@dataclass
class RepairResult:
    success: bool
    patched_ir: str
    plan: RepairPlan
    patches: list[dict] = field(default_factory=list)
    syntax_valid: bool = False
    syntax_issues: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self):
        return {
            "success": self.success,
            "patched_ir": self.patched_ir,
            "plan": self.plan.to_dict(),
            "patches": list(self.patches),
            "syntax_valid": self.syntax_valid,
            "syntax_issues": list(self.syntax_issues),
            "message": self.message,
        }
