from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


POLICY_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class HardeningPolicy:
    require_elf: bool = True
    require_pie: bool = True
    require_relro: bool = True
    require_bind_now: bool = True
    require_nx_stack: bool = True
    require_stack_protector: bool = True
    require_fortify: bool = True


@dataclass(frozen=True)
class VerificationPolicy:
    require_security_rescan: bool = True
    require_runtime_verification: bool = True
    require_behavior_verification: bool = True
    require_provenance: bool = True


@dataclass(frozen=True)
class SecureCCPolicy:
    name: str = "vulnhgnn-secure"
    version: int = POLICY_SCHEMA_VERSION

    reject_findings: bool = True

    hardening: HardeningPolicy = field(
        default_factory=HardeningPolicy
    )

    verification: VerificationPolicy = field(
        default_factory=VerificationPolicy
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_schema_version": self.version,
            "policy": self.name,
            "reject_findings": self.reject_findings,
            "hardening": {
                "require_elf": self.hardening.require_elf,
                "require_pie": self.hardening.require_pie,
                "require_relro": self.hardening.require_relro,
                "require_bind_now": self.hardening.require_bind_now,
                "require_nx_stack": self.hardening.require_nx_stack,
                "require_stack_protector":
                    self.hardening.require_stack_protector,
                "require_fortify":
                    self.hardening.require_fortify,
            },
            "verification": {
                "require_security_rescan":
                    self.verification.require_security_rescan,
                "require_runtime_verification":
                    self.verification.require_runtime_verification,
                "require_behavior_verification":
                    self.verification.require_behavior_verification,
                "require_provenance":
                    self.verification.require_provenance,
            },
        }


DEFAULT_POLICY = SecureCCPolicy()


def evaluate_hardening(
    audit: Any,
    policy: SecureCCPolicy = DEFAULT_POLICY,
) -> dict[str, Any]:
    checks = {
        "elf": audit.is_elf,
        "pie": audit.is_pie,
        "relro": audit.relro,
        "bind_now": audit.bind_now,
        "nx_stack": audit.nx_stack,
        "stack_protector":
            audit.stack_canary_reference,
        "fortify":
            getattr(audit, "fortify_reference", False),
    }

    required = {
        "elf": policy.hardening.require_elf,
        "pie": policy.hardening.require_pie,
        "relro": policy.hardening.require_relro,
        "bind_now": policy.hardening.require_bind_now,
        "nx_stack": policy.hardening.require_nx_stack,
        "stack_protector":
            policy.hardening.require_stack_protector,
        "fortify":
            policy.hardening.require_fortify,
    }

    failures = [
        name
        for name, required_value in required.items()
        if required_value and not checks[name]
    ]

    return {
        "passed": not failures,
        "checks": checks,
        "required": required,
        "failures": failures,
    }


def evaluate_verification(
    verification: dict[str, Any],
    policy: SecureCCPolicy = DEFAULT_POLICY,
) -> dict[str, Any]:
    runtime = verification.get("runtime")
    gate = verification.get("gate")

    runtime_passed = bool(
        getattr(runtime, "passed", False)
    )

    behavior_passed = bool(
        getattr(gate, "behavior_passed", False)
    )

    provenance_passed = bool(
        verification.get(
            "binary_integrity_passed",
            False,
        )
        and verification.get(
            "source_integrity_passed",
            False,
        )
        and verification.get(
            "manifest_validation",
            {
                "valid": True,
            },
        ).get("valid", True)
    )

    security_rescan_passed = bool(
        verification.get(
            "security_rescan_passed",
            False,
        )
    )

    checks = {
        "security_rescan": security_rescan_passed,
        "runtime": runtime_passed,
        "behavior": behavior_passed,
        "provenance": provenance_passed,
    }

    required = {
        "security_rescan":
            policy.verification.require_security_rescan,
        "runtime":
            policy.verification.require_runtime_verification,
        "behavior":
            policy.verification.require_behavior_verification,
        "provenance":
            policy.verification.require_provenance,
    }

    failures = [
        name
        for name, required_value in required.items()
        if required_value and not checks[name]
    ]

    return {
        "passed": not failures,
        "checks": checks,
        "required": required,
        "failures": failures,
    }

def evaluate_findings(
    findings: list[Any],
    policy: SecureCCPolicy = DEFAULT_POLICY,
) -> dict[str, Any]:
    count = len(findings)

    passed = (
        count == 0
        if policy.reject_findings
        else True
    )

    return {
        "passed": passed,
        "finding_count": count,
        "reject_findings": policy.reject_findings,
    }
