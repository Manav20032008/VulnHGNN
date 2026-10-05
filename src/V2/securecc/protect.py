from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..hardening.audit import audit_binary
from ..sandbox.runner import SandboxRunner


PROTECTION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ProtectionProfile:
    name: str
    operation: str
    description: str


PROTECTION_PROFILES = {
    "strip-unneeded": ProtectionProfile(
        name="strip-unneeded",
        operation="strip-unneeded",
        description="Remove unnecessary ELF sections and symbols.",
    ),
    "strip-debug": ProtectionProfile(
        name="strip-debug",
        operation="strip-debug",
        description="Remove debugging information from the ELF binary.",
    ),
}


def get_profile(name: str) -> ProtectionProfile:
    try:
        return PROTECTION_PROFILES[name]
    except KeyError as exc:
        available = ", ".join(sorted(PROTECTION_PROFILES))
        raise ValueError(
            f"Unknown protection profile '{name}'. Available: {available}"
        ) from exc


def _tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"{name} was not found on PATH")
    return path


def _audit_dict(audit: Any) -> dict[str, Any]:
    return {
        "path": str(audit.path),
        "elf": bool(audit.is_elf),
        "pie": bool(audit.is_pie),
        "relro": bool(audit.relro),
        "bind_now": bool(audit.bind_now),
        "nx_stack": bool(audit.nx_stack),
        "stack_protector": bool(audit.stack_canary_reference),
        "fortify": bool(audit.fortify_reference),
        "passed": bool(audit.passed),
    }


def _run_transformation(
    profile: ProtectionProfile,
    output: Path,
) -> tuple[list[str], subprocess.CompletedProcess[str]]:
    strip = _tool("strip")

    if profile.operation == "strip-unneeded":
        command = [strip, "--strip-unneeded", str(output)]
    elif profile.operation == "strip-debug":
        command = [strip, "--strip-debug", str(output)]
    else:
        raise ValueError(f"Unsupported protection operation: {profile.operation}")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    return command, result


def _hardening_preserved(before: dict[str, Any], after: dict[str, Any]) -> bool:
    properties = (
        "pie",
        "relro",
        "bind_now",
        "nx_stack",
        "stack_protector",
        "fortify",
    )

    return all(
        before.get(property_name) == after.get(property_name)
        for property_name in properties
    )


def _runtime_dict(result: Any) -> dict[str, Any]:
    return {
        "command": list(result.command),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": bool(result.timed_out),
        "memory_limited": bool(result.memory_limited),
        "isolation_mode": result.isolation_mode,
        "duration_seconds": result.duration_seconds,
        "notes": list(result.notes),
        "passed": bool(result.passed),
    }


def _behavior_compare(
    original: Any,
    protected: Any,
) -> dict[str, Any]:
    comparable = (
        not original.timed_out
        and not protected.timed_out
        and not original.memory_limited
        and not protected.memory_limited
        and original.returncode is not None
        and protected.returncode is not None
    )

    exit_code_match = (
        original.returncode == protected.returncode
        if comparable
        else False
    )
    stdout_match = (
        original.stdout == protected.stdout
        if comparable
        else False
    )
    stderr_match = (
        original.stderr == protected.stderr
        if comparable
        else False
    )

    behavior_preserved = (
        comparable
        and exit_code_match
        and stdout_match
        and stderr_match
    )

    return {
        "verified": comparable,
        "preserved": behavior_preserved,
        "exit_code_match": exit_code_match,
        "stdout_match": stdout_match,
        "stderr_match": stderr_match,
        "original": _runtime_dict(original),
        "protected": _runtime_dict(protected),
    }


def protect_binary(
    source: Path,
    output: Path,
    profile: str = "strip-unneeded",
) -> dict[str, Any]:
    source = Path(source).resolve()
    output = Path(output).resolve()

    if not source.exists():
        raise FileNotFoundError(f"Binary does not exist: {source}")

    if not source.is_file():
        raise ValueError(f"Binary is not a regular file: {source}")

    if not source.stat().st_mode & 0o111:
        raise ValueError(f"Binary is not executable: {source}")

    before_audit = audit_binary(source)

    if not before_audit.is_elf:
        raise ValueError("protect currently supports ELF executables only")

    selected_profile = get_profile(profile)

    output.parent.mkdir(parents=True, exist_ok=True)

    if source == output:
        raise ValueError(
            "Protected output must be different from the source binary"
        )

    shutil.copy2(source, output)
    output.chmod(output.stat().st_mode | 0o111)

    size_before = source.stat().st_size

    # ------------------------------------------------------------------
    # Protection transformation
    # ------------------------------------------------------------------
    try:
        command, process = _run_transformation(
            selected_profile,
            output,
        )
    except Exception as exc:
        return {
            "schema_version": PROTECTION_SCHEMA_VERSION,
            "status": "PROTECTION_FAILED",
            "source": str(source),
            "output": str(output),
            "profile": {
                "name": selected_profile.name,
                "operation": selected_profile.operation,
                "description": selected_profile.description,
            },
            "operation": selected_profile.operation,
            "command": [],
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "before": _audit_dict(before_audit),
            "after": None,
            "hardening_preserved": False,
            "behavior": None,
            "size_before": size_before,
            "size_after": None,
            "size_reduction_bytes": None,
            "size_reduction_percent": None,
        }

    if process.returncode != 0:
        return {
            "schema_version": PROTECTION_SCHEMA_VERSION,
            "status": "PROTECTION_FAILED",
            "source": str(source),
            "output": str(output),
            "profile": {
                "name": selected_profile.name,
                "operation": selected_profile.operation,
                "description": selected_profile.description,
            },
            "operation": selected_profile.operation,
            "command": command,
            "returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
            "before": _audit_dict(before_audit),
            "after": None,
            "hardening_preserved": False,
            "behavior": None,
            "size_before": size_before,
            "size_after": None,
            "size_reduction_bytes": None,
            "size_reduction_percent": None,
        }

    size_after = output.stat().st_size

    # ------------------------------------------------------------------
    # Protected binary audit
    # ------------------------------------------------------------------
    after_audit = audit_binary(output)

    before = _audit_dict(before_audit)
    after = _audit_dict(after_audit)

    hardening_preserved = _hardening_preserved(
        before,
        after,
    )

    # ------------------------------------------------------------------
    # Phase 10.3: behavioral verification
    #
    # Both binaries execute under the same SandboxRunner policy.
    # stdin, environment, limits and isolation are therefore controlled
    # consistently for both executions.
    # ------------------------------------------------------------------
    runner = SandboxRunner()

    original_runtime = runner.run([str(source)])
    protected_runtime = runner.run([str(output)])

    behavior = _behavior_compare(
        original_runtime,
        protected_runtime,
    )

    protected = (
        after["passed"]
        and hardening_preserved
        and behavior["verified"]
        and behavior["preserved"]
    )

    size_reduction_bytes = size_before - size_after

    if size_before:
        size_reduction_percent = (
            size_reduction_bytes / size_before
        ) * 100.0
    else:
        size_reduction_percent = 0.0

    status = "PROTECTED" if protected else "PROTECTION_FAILED"

    return {
        "schema_version": PROTECTION_SCHEMA_VERSION,
        "status": status,
        "source": str(source),
        "output": str(output),
        "profile": {
            "name": selected_profile.name,
            "operation": selected_profile.operation,
            "description": selected_profile.description,
        },
        "operation": selected_profile.operation,
        "command": command,
        "returncode": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
        "before": before,
        "after": after,
        "hardening_preserved": hardening_preserved,
        "behavior": behavior,
        "size_before": size_before,
        "size_after": size_after,
        "size_reduction_bytes": size_reduction_bytes,
        "size_reduction_percent": size_reduction_percent,
    }


def text_report(result: dict[str, Any]) -> str:
    before = result["before"]
    after = result.get("after")
    behavior = result.get("behavior")

    lines = [
        "=" * 88,
        "VULNHGNN 2.0 — SECURECC PROTECT",
        "=" * 88,
        f"Source        : {result['source']}",
        f"Output        : {result['output']}",
        f"Profile       : {result['profile']['name']}",
        f"Operation     : {result['profile']['operation']}",
        "",
        "[1/5] Original binary audit",
        f"      ELF              : {'PASS' if before['elf'] else 'FAIL'}",
        f"      PIE              : {'PASS' if before['pie'] else 'FAIL'}",
        f"      RELRO            : {'PASS' if before['relro'] else 'FAIL'}",
        f"      BIND_NOW         : {'PASS' if before['bind_now'] else 'FAIL'}",
        f"      NX stack         : {'PASS' if before['nx_stack'] else 'FAIL'}",
        f"      Stack protector  : {'PASS' if before['stack_protector'] else 'FAIL'}",
        f"      FORTIFY          : {'PASS' if before['fortify'] else 'FAIL'}",
        "",
        "[2/5] Protection transformation",
        f"      Operation        : {result['profile']['operation']}",
        f"      Return code      : {result['returncode']}",
        f"      STATUS           : {'PASS' if result['returncode'] == 0 else 'FAIL'}",
        "",
    ]

    if after is not None:
        lines.extend(
            [
                "[3/5] Protected binary audit",
                f"      ELF              : {'PASS' if after['elf'] else 'FAIL'}",
                f"      PIE              : {'PASS' if after['pie'] else 'FAIL'}",
                f"      RELRO            : {'PASS' if after['relro'] else 'FAIL'}",
                f"      BIND_NOW         : {'PASS' if after['bind_now'] else 'FAIL'}",
                f"      NX stack         : {'PASS' if after['nx_stack'] else 'FAIL'}",
                f"      Stack protector  : {'PASS' if after['stack_protector'] else 'FAIL'}",
                f"      FORTIFY          : {'PASS' if after['fortify'] else 'FAIL'}",
                f"      Hardening kept   : {'PASS' if result['hardening_preserved'] else 'FAIL'}",
                "",
                f"      Size before      : {result['size_before']} bytes",
                f"      Size after       : {result['size_after']} bytes",
                f"      Size reduction   : {result['size_reduction_bytes']} bytes",
                f"      Reduction        : {result['size_reduction_percent']:.2f}%",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "[3/5] Protected binary audit",
                "      STATUS           : NOT AVAILABLE",
                "",
            ]
        )

    if behavior is not None:
        lines.extend(
            [
                "[4/5] Behavioral verification",
                f"      Execution compare: {'PASS' if behavior['verified'] else 'FAIL'}",
                f"      Exit code        : {'MATCH' if behavior['exit_code_match'] else 'MISMATCH'}",
                f"      stdout           : {'MATCH' if behavior['stdout_match'] else 'MISMATCH'}",
                f"      stderr           : {'MATCH' if behavior['stderr_match'] else 'MISMATCH'}",
                f"      Behavior kept    : {'PASS' if behavior['preserved'] else 'FAIL'}",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "[4/5] Behavioral verification",
                "      STATUS           : NOT AVAILABLE",
                "",
            ]
        )

    lines.extend(
        [
            "[5/5] Protection result",
            f"      STATUS           : {result['status']}",
            "",
            f"FINAL STATUS : {result['status']}",
            "=" * 88,
        ]
    )

    return "\n".join(lines)


def json_report(result: dict[str, Any]) -> str:
    import json

    return json.dumps(
        result,
        indent=2,
        sort_keys=True,
    )
