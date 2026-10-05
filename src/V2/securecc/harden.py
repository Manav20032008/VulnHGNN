from __future__ import annotations

from pathlib import Path

from ..hardening.audit import audit_binary
from ..hardening.compiler import SecureCompiler
from ..hardening.profile import HardeningProfile


def harden_source(source: Path, output: Path) -> dict:
    source = Path(source)
    output = Path(output)

    if not source.exists():
        raise FileNotFoundError(f"source file not found: {source}")

    if source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
        raise ValueError("SecureCC harden supports C/C++ source files only.")

    compiler = SecureCompiler(profile=HardeningProfile())

    build_result = compiler.build(source, output)

    if not build_result["success"]:
        return {
            "status": "BUILD_FAILED",
            "source": str(source.resolve()),
            "output": str(output.resolve()),
            "build": build_result,
            "audit": None,
        }

    audit = audit_binary(output)

    status = "HARDENED" if audit.passed else "HARDENING_FAILED"

    return {
        "status": status,
        "source": str(source.resolve()),
        "output": str(output.resolve()),
        "profile": compiler.profile.name,
        "compiler": build_result["command"][0],
        "build": build_result,
        "audit": {
            "elf": audit.is_elf,
            "pie": audit.is_pie,
            "relro": audit.relro,
            "bind_now": audit.bind_now,
            "nx_stack": audit.nx_stack,
            "stack_protector": audit.stack_canary_reference,
            "fortify": audit.fortify_reference,
            "passed": audit.passed,
        },
    }


def text_report(result: dict) -> str:
    audit = result.get("audit")

    lines = [
        "=" * 88,
        "VULNHGNN 2.0 — SECURECC HARDEN",
        "=" * 88,
        f"Source        : {result['source']}",
        f"Output        : {result['output']}",
        f"Profile       : {result.get('profile', 'unknown')}",
        f"Compiler      : {result.get('compiler', 'unknown')}",
        "",
        "[1/2] Hardened compilation",
    ]

    build = result.get("build", {})
    lines.append(
        "      STATUS   : "
        + ("PASS" if build.get("success") else "FAIL")
    )

    if not build.get("success") and build.get("stderr"):
        lines.append("")
        lines.append(build["stderr"].rstrip())

    if audit is not None:
        lines.extend(
            [
                "",
                "[2/2] Binary security audit",
                f"      ELF              : {'PASS' if audit['elf'] else 'FAIL'}",
                f"      PIE              : {'PASS' if audit['pie'] else 'FAIL'}",
                f"      RELRO            : {'PASS' if audit['relro'] else 'FAIL'}",
                f"      BIND_NOW         : {'PASS' if audit['bind_now'] else 'FAIL'}",
                f"      NX stack         : {'PASS' if audit['nx_stack'] else 'FAIL'}",
                f"      Stack protector  : {'PASS' if audit['stack_protector'] else 'FAIL'}",
                f"      FORTIFY          : {'PASS' if audit['fortify'] else 'FAIL'}",
                "",
                "      STATUS   : "
                + ("PASS" if audit["passed"] else "FAIL"),
            ]
        )

    lines.extend(
        [
            "",
            f"FINAL STATUS : {result['status']}",
            "=" * 88,
        ]
    )

    return "\n".join(lines)


def json_report(result: dict) -> str:
    import json

    return json.dumps(result, indent=2)
