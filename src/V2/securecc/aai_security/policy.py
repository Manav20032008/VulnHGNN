from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


FORBIDDEN_TOOLS = frozenset(
    {
        "mark_safe",
        "skip_verify",
        "disable_policy",
        "override_verdict",
        "shell",
        "exec_command",
    }
)

TOOLS_REQUIRING_PRIOR_VERIFY = frozenset({"complete", "deploy", "approve_patch"})


@dataclass(frozen=True)
class AgentSecurityPolicy:
    """Non-overridable rules for the agent orchestrator."""

    name: str = "vulnhgnn-aai-secure"
    version: int = 1
    block_on_prompt_injection: bool = True
    block_on_code_poisoning: bool = True
    require_verify_before_complete: bool = True
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "scan",
                "explain",
                "diagnose",
                "learn",
                "fix",
                "catalog_heal",
                "ai_source_review",
                "verify",
                "benchmark",
                "rescan",
            }
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.name,
            "version": self.version,
            "block_on_prompt_injection": self.block_on_prompt_injection,
            "block_on_code_poisoning": self.block_on_code_poisoning,
            "require_verify_before_complete": self.require_verify_before_complete,
            "allowed_tools": sorted(self.allowed_tools),
            "forbidden_tools": sorted(FORBIDDEN_TOOLS),
        }


DEFAULT_AAI_POLICY = AgentSecurityPolicy()


def evaluate_tool_call(
    tool: str,
    *,
    policy: AgentSecurityPolicy = DEFAULT_AAI_POLICY,
    prompt_blocked: bool = False,
    verify_passed: bool | None = None,
) -> dict[str, Any]:
    tool = tool.strip().lower()

    if prompt_blocked:
        return {
            "allowed": False,
            "reason": "blocked_by_input_guard",
            "risk": 1.0,
        }

    if tool in FORBIDDEN_TOOLS:
        return {
            "allowed": False,
            "reason": "forbidden_tool",
            "risk": 0.95,
        }

    if tool not in policy.allowed_tools:
        return {
            "allowed": False,
            "reason": "tool_not_in_allowlist",
            "risk": 0.8,
        }

    if (
        policy.require_verify_before_complete
        and tool in TOOLS_REQUIRING_PRIOR_VERIFY
        and verify_passed is not True
    ):
        return {
            "allowed": False,
            "reason": "verify_required",
            "risk": 0.9,
        }

    return {"allowed": True, "reason": "ok", "risk": 0.0}
