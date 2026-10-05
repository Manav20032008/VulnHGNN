from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VerificationGateResult:
    compile_passed: bool
    hardening_passed: bool
    runtime_passed: bool
    security_rescan_passed: bool
    behavior_passed: bool
    accepted: bool
    reasons: list[str] = field(default_factory=list)


class VerificationGate:
    """Deterministic final gate for a repaired/build artifact."""

    def evaluate(
        self,
        *,
        compile_passed: bool,
        hardening_passed: bool,
        runtime_passed: bool,
        security_rescan_passed: bool,
        behavior_passed: bool,
        allow_unverified_behavior: bool = False,
    ) -> VerificationGateResult:
        reasons = []

        checks = {
            "compilation": compile_passed,
            "binary hardening": hardening_passed,
            "runtime verification": runtime_passed,
            "security re-analysis": security_rescan_passed,
        }

        for name, passed in checks.items():
            if not passed:
                reasons.append(f"{name} failed")

        behavior_ok = behavior_passed or allow_unverified_behavior
        if not behavior_ok:
            reasons.append("behavioral verification failed or is unavailable")

        accepted = not reasons

        return VerificationGateResult(
            compile_passed=compile_passed,
            hardening_passed=hardening_passed,
            runtime_passed=runtime_passed,
            security_rescan_passed=security_rescan_passed,
            behavior_passed=behavior_passed,
            accepted=accepted,
            reasons=reasons,
        )
