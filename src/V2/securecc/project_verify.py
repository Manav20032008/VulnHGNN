from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .project_scan import discover_sources
from .fix import fix_source
from ..hardening.compiler import SecureCompiler
from ..verification.behavior import BehaviorExpectation, BehaviorOracle


@dataclass
class ProjectVerifyResult:
    source: str
    status: str
    cwes: list[str]
    compile_passed: bool
    hardening_passed: bool
    runtime_passed: bool
    security_rescan_passed: bool
    behavior_passed: bool
    repair_passed: bool
    behavior_verified: bool
    message: str = ""


def _run(
    command: list[str],
    timeout: int = 10,
) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as exc:
        return False, str(exc)


def _binary_audit(binary: Path) -> tuple[bool, str]:
    checks: list[tuple[str, bool]] = []

    ok, out = _run(["file", str(binary)])
    checks.append(("ELF", ok and "ELF" in out))

    ok, out = _run(["readelf", "-h", str(binary)])
    checks.append(("PIE", ok and "DYN" in out))

    ok, out = _run(["readelf", "-l", str(binary)])
    checks.append(
        ("NX", ok and "GNU_STACK" in out and "RWE" not in out)
    )

    ok, out = _run(["readelf", "-l", str(binary)])
    checks.append(("RELRO", ok and "GNU_RELRO" in out))

    ok, out = _run(["readelf", "-d", str(binary)])
    checks.append(("BIND_NOW", ok and "BIND_NOW" in out))

    ok, out = _run(["readelf", "-s", str(binary)])
    checks.append(
        ("STACK_CANARY", ok and "__stack_chk_fail" in out)
    )

    passed = all(value for _, value in checks)

    report = "\n".join(
        f"{name}: {'PASS' if value else 'FAIL'}"
        for name, value in checks
    )

    return passed, report

def _compile_hardened(
    patched_ir: Path,
    output: Path,
) -> tuple[bool, str]:
    """
    Compile patched IR using the authoritative SecureCC hardening
    compiler rather than duplicating compiler flags here.
    """
    compiler = SecureCompiler()

    try:
        result = compiler.build(
            patched_ir,
            output,
        )
    except Exception as exc:
        return False, str(exc)

    output_text = "\n".join(
        part
        for part in (
            result.get("stdout", ""),
            result.get("stderr", ""),
        )
        if part
    ).strip()

    return (
        bool(result.get("success"))
        and output.exists(),
        output_text,
    )
    
    
def _find_patched_ir(
    repair: dict[str, Any],
    file_root: Path,
) -> Path | None:
    patched_ir = repair.get("patched_ir")

    if patched_ir:
        candidate = Path(patched_ir)
        if candidate.exists():
            return candidate

    candidates = sorted(file_root.rglob("*.patched.ll"))

    return candidates[0] if candidates else None



def _execute_behavior(
    binary: Path,
    expectation: BehaviorExpectation,
) -> tuple[bool, bool, bool, str]:
    """
    Execute a verified binary against an explicit behavioral oracle.

    Returns:
        runtime_passed
        behavior_passed
        behavior_verified
        evidence
    """
    try:
        result = subprocess.run(
            [str(binary)],
            input=expectation.stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2,
        )

        actual_stdout = result.stdout
        actual_stderr = result.stderr
        actual_exit_code = result.returncode

        runtime_passed = actual_exit_code == expectation.exit_code

        behavior_passed = (
            actual_exit_code == expectation.exit_code
            and actual_stdout == expectation.stdout
            and actual_stderr == expectation.stderr
        )

        evidence = (
            f"returncode_expected={expectation.exit_code!r}\n"
            f"returncode_actual={actual_exit_code!r}\n"
            f"stdout_expected={expectation.stdout!r}\n"
            f"stdout_actual={actual_stdout!r}\n"
            f"stderr_expected={expectation.stderr!r}\n"
            f"stderr_actual={actual_stderr!r}"
        )

        return (
            runtime_passed,
            behavior_passed,
            True,
            evidence,
        )

    except subprocess.TimeoutExpired:
        return (
            False,
            False,
            False,
            "runtime timeout",
        )

    except Exception as exc:
        return (
            False,
            False,
            False,
            f"runtime exception: {exc}",
        )


def verify_file(
    source: Path,
    output_root: Path,
    expected_output: str | None = None,
    behavior: BehaviorExpectation | None = None,
) -> ProjectVerifyResult:

    file_root = output_root / source.stem
    file_root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------
    # 1. Repair / deterministic security verification
    # ------------------------------------------------------------
    try:
        repair = fix_source(
            source,
            output_dir=file_root,
            keep_ir=True,
            build_artifact=True,
        )
    except Exception as exc:
        return ProjectVerifyResult(
            source=str(source),
            status="FAILED",
            cwes=[],
            compile_passed=False,
            hardening_passed=False,
            runtime_passed=False,
            security_rescan_passed=False,
            behavior_passed=False,
            repair_passed=False,
            behavior_verified=False,
            message=f"repair exception: {exc}",
        )

    if isinstance(repair, dict):
        repair_status = repair.get("status", "")
        cwes = repair.get("detected_cwes", []) or []
        verification = repair.get("verification") or {}
        detector = repair.get("detector_verification") or {}

        repair_passed = (
            repair_status in {"CLEAN", "VERIFIED"}
            and verification.get(
                "passed",
                repair_status == "CLEAN",
            )
        )

        security_rescan_passed = (
            repair_status == "CLEAN"
            or detector.get("passed", False)
        )
    else:
        repair_status = getattr(repair, "status", "")
        cwes = getattr(repair, "detected_cwes", []) or []
        repair_passed = repair_status in {"CLEAN", "VERIFIED"}
        security_rescan_passed = repair_passed

    # ------------------------------------------------------------
    # 2. Clean source
    # ------------------------------------------------------------
    #
    # A clean source file still needs to execute against an explicit
    # behavior oracle when one exists. Otherwise it remains CLEAN.
    #
    if repair_status == "CLEAN" and behavior is None and expected_output is None:
        return ProjectVerifyResult(
            source=str(source),
            status="CLEAN",
            cwes=[],
            compile_passed=True,
            hardening_passed=True,
            runtime_passed=False,
            security_rescan_passed=True,
            behavior_passed=False,
            repair_passed=True,
            behavior_verified=False,
            message="Source is clean; static verification passed.",
        )

    # ------------------------------------------------------------
    # 3. Repair failed
    # ------------------------------------------------------------
    if not repair_passed:
        return ProjectVerifyResult(
            source=str(source),
            status="REJECTED",
            cwes=cwes,
            compile_passed=False,
            hardening_passed=False,
            runtime_passed=False,
            security_rescan_passed=security_rescan_passed,
            behavior_passed=False,
            repair_passed=False,
            behavior_verified=False,
            message="Repair verification failed.",
        )

    # ------------------------------------------------------------
    # 4. Select compilation input
    # ------------------------------------------------------------
    #
    # Vulnerable files compile from their verified patched IR.
    # Clean files compile directly from their original source.
    #
    if repair_status == "CLEAN":
        compile_input = source
    else:
        compile_input = _find_patched_ir(repair, file_root)

        if compile_input is None:
            return ProjectVerifyResult(
                source=str(source),
                status="FAILED",
                cwes=cwes,
                compile_passed=False,
                hardening_passed=False,
                runtime_passed=False,
                security_rescan_passed=security_rescan_passed,
                behavior_passed=False,
                repair_passed=repair_passed,
                behavior_verified=False,
                message="Patched IR not found.",
            )

    # ------------------------------------------------------------
    # 5. Hardened compilation
    # ------------------------------------------------------------
    binary = file_root / f"{source.stem}.verified"

    compile_passed, compile_output = _compile_hardened(
        compile_input,
        binary,
    )

    if not compile_passed:
        return ProjectVerifyResult(
            source=str(source),
            status="REJECTED",
            cwes=cwes,
            compile_passed=False,
            hardening_passed=False,
            runtime_passed=False,
            security_rescan_passed=security_rescan_passed,
            behavior_passed=False,
            repair_passed=repair_passed,
            behavior_verified=False,
            message=f"Hardened compilation failed: {compile_output}",
        )

    # ------------------------------------------------------------
    # 6. Binary hardening audit
    # ------------------------------------------------------------
    hardening_passed, hardening_output = _binary_audit(binary)

    if not hardening_passed:
        return ProjectVerifyResult(
            source=str(source),
            status="REJECTED",
            cwes=cwes,
            compile_passed=True,
            hardening_passed=False,
            runtime_passed=False,
            security_rescan_passed=security_rescan_passed,
            behavior_passed=False,
            repair_passed=repair_passed,
            behavior_verified=False,
            message=f"Binary hardening audit failed:\n{hardening_output}",
        )

    # ------------------------------------------------------------
    # 7. Behavioral verification
    #
    # Structured BehaviorOracle is authoritative for project tests.
    # Legacy expected_output remains supported for compatibility.
    # ------------------------------------------------------------
    runtime_passed = False
    behavior_passed = False
    behavior_verified = False

    runtime_output = "not executed: no expected behavior oracle"

    if behavior is not None:
        (
            runtime_passed,
            behavior_passed,
            behavior_verified,
            runtime_output,
        ) = _execute_behavior(binary, behavior)

    elif expected_output is not None:
        try:
            result = subprocess.run(
                [str(binary)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
            )

            actual = result.stdout

            runtime_passed = result.returncode == 0
            behavior_passed = (
                runtime_passed
                and actual == expected_output
            )
            behavior_verified = True

            runtime_output = (
                f"returncode={result.returncode}\n"
                f"expected_stdout={expected_output!r}\n"
                f"actual_stdout={actual!r}"
            )

        except subprocess.TimeoutExpired:
            runtime_output = "runtime timeout"

        except Exception as exc:
            runtime_output = f"runtime exception: {exc}"

    # ------------------------------------------------------------
    # 8. Final project verification
    #
    # Security verification does NOT depend on an absent behavior
    # oracle. If no oracle exists, explicitly report UNVERIFIED.
    # ------------------------------------------------------------
    security_verified = (
        repair_passed
        and compile_passed
        and hardening_passed
        and security_rescan_passed
    )

    behavior_supplied = (
        behavior is not None
        or expected_output is not None
    )

    if not security_verified:
        final_status = "PROJECT_VERIFY_FAILED"
        message = "Security verification gate failed."

    elif behavior_supplied and not behavior_passed:
        final_status = "PROJECT_VERIFY_FAILED"
        message = (
            "Security verification passed, but behavioral verification failed."
        )

    elif not behavior_supplied:
        final_status = (
            "CLEAN"
            if repair_status == "CLEAN"
            else "PROJECT_VERIFY_UNVERIFIED"
        )
        message = (
            "Source is clean; static verification passed."
            if repair_status == "CLEAN"
            else
            "Security verification passed; behavioral verification "
            "is unavailable because no behavior oracle was supplied."
        )

    else:
        final_status = "PROJECT_VERIFY_VERIFIED"
        message = "Security and behavioral verification passed."

    # ------------------------------------------------------------
    # 9. Persist evidence
    # ------------------------------------------------------------
    report = {
        "source": str(source),
        "status": final_status,
        "cwes": cwes,
        "repair_passed": repair_passed,
        "compile_passed": compile_passed,
        "hardening_passed": hardening_passed,
        "runtime_passed": runtime_passed,
        "security_rescan_passed": security_rescan_passed,
        "behavior_passed": behavior_passed,
        "behavior_verified": behavior_verified,
        "behavior_oracle_supplied": behavior is not None,
        "legacy_expected_output_supplied": expected_output is not None,
        "behavior_expectation": (
            {
                "stdin": behavior.stdin,
                "stdout": behavior.stdout,
                "stderr": behavior.stderr,
                "exit_code": behavior.exit_code,
            }
            if behavior is not None
            else None
        ),
        "hardening_output": hardening_output,
        "runtime_output": runtime_output,
    }

    (file_root / "verification.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return ProjectVerifyResult(
        source=str(source),
        status=final_status,
        cwes=cwes,
        compile_passed=compile_passed,
        hardening_passed=hardening_passed,
        runtime_passed=runtime_passed,
        security_rescan_passed=security_rescan_passed,
        behavior_passed=behavior_passed,
        repair_passed=repair_passed,
        behavior_verified=behavior_verified,
        message=message,
    )


def verify_project(
    root: Path,
    output_dir: Path,
    expected_outputs: dict[str, str] | None = None,
    behavior_oracle: BehaviorOracle | None = None,
) -> dict[str, Any]:

    root = Path(root).resolve()

    if output_dir is None:
        output_root = Path("build/verify").resolve()
    else:
        output_root = Path(output_dir).resolve()
        
    expected_outputs = expected_outputs or {}

    sources = discover_sources(root)

    results: list[ProjectVerifyResult] = []

    for source in sources:
        relative = source.relative_to(root)

        expected = expected_outputs.get(str(relative))

        behavior = (
            behavior_oracle.get(relative)
            if behavior_oracle is not None
            else None
        )

        # Also allow basename-based oracle entries.
        if behavior is None and behavior_oracle is not None:
            behavior = behavior_oracle.get(source.name)

        result = verify_file(
            source,
            output_root / root.name,
            expected_output=expected,
            behavior=behavior,
        )

        results.append(result)

    security_verified = all(
        result.status in {
            "CLEAN",
            "PROJECT_VERIFY_VERIFIED",
            "PROJECT_VERIFY_UNVERIFIED",
        }
        for result in results
    )

    behavior_unverified = any(
        result.status == "PROJECT_VERIFY_UNVERIFIED"
        for result in results
    )

    behavior_failed = any(
        result.status == "PROJECT_VERIFY_FAILED"
        and result.repair_passed
        and result.compile_passed
        and result.hardening_passed
        and result.security_rescan_passed
        for result in results
    )

    if not security_verified or behavior_failed:
        final_status = "PROJECT_VERIFY_FAILED"
    elif behavior_unverified:
        final_status = "PROJECT_VERIFY_UNVERIFIED"
    else:
        final_status = "PROJECT_VERIFY_VERIFIED"

    summary = {
        "root": str(root),
        "output_root": str(output_root / root.name),
        "behavior_oracle": (
            str(behavior_oracle.path)
            if behavior_oracle is not None
            else None
        ),
        "behavior_tests_registered": (
            behavior_oracle.names()
            if behavior_oracle is not None
            else []
        ),
        "files_scanned": len(results),
        "files_clean": sum(
            result.status == "CLEAN"
            for result in results
        ),
        "files_verified": sum(
            result.status == "PROJECT_VERIFY_VERIFIED"
            for result in results
        ),
        "files_unverified": sum(
            result.status == "PROJECT_VERIFY_UNVERIFIED"
            for result in results
        ),
        "files_failed": sum(
            result.status == "PROJECT_VERIFY_FAILED"
            for result in results
        ),
        "findings": sum(
            len(result.cwes)
            for result in results
        ),
        "status": final_status,
        "results": [asdict(result) for result in results],
    }

    output_dir = output_root / root.name
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "project_verification.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    return summary


def print_project_verify(
    summary: dict[str, Any],
    output_format: str = "text",
) -> None:
    """Render project verification results for the SecureCC CLI."""

    if output_format == "json":
        print(json.dumps(summary, indent=2))
        return

    print("=" * 88)
    print("VULNHGNN 2.0 — SECURECC PROJECT VERIFY")
    print("=" * 88)

    print(f"Root           : {summary['root']}")
    print(f"Output root    : {summary['output_root']}")
    print(f"Files scanned  : {summary['files_scanned']}")
    print(f"Files clean    : {summary['files_clean']}")
    print(f"Files verified : {summary['files_verified']}")
    print(f"Files unverified: {summary['files_unverified']}")
    print(f"Files failed   : {summary['files_failed']}")
    print(f"Findings       : {summary['findings']}")

    print()
    print("FILES")

    for result in summary["results"]:
        source = Path(result["source"]).name
        status = result["status"]
        cwes = ", ".join(result["cwes"])

        if cwes:
            print(f"{source:<40} {status:<28} {cwes}")
        else:
            print(f"{source:<40} {status}")

    print()
    print(f"FINAL STATUS : {summary['status']}")
    print("=" * 88)


def print_project_verify(
    summary: dict[str, Any],
    output_format: str = "text",
) -> None:
    """Render project verification results for the SecureCC CLI."""

    if output_format == "json":
        print(json.dumps(summary, indent=2))
        return

    print("=" * 88)
    print("VULNHGNN 2.0 — SECURECC PROJECT VERIFY")
    print("=" * 88)

    print(f"Root           : {summary['root']}")
    print(f"Output root    : {summary['output_root']}")
    print(f"Files scanned  : {summary['files_scanned']}")
    print(f"Files clean    : {summary['files_clean']}")
    print(f"Files verified : {summary['files_verified']}")
    print(f"Files unverified: {summary['files_unverified']}")
    print(f"Files failed   : {summary['files_failed']}")
    print(f"Findings       : {summary['findings']}")

    print()
    print("FILES")

    for result in summary["results"]:
        source = Path(result["source"]).name
        status = result["status"]
        cwes = ", ".join(result["cwes"])

        if cwes:
            print(f"{source:<40} {status:<28} {cwes}")
        else:
            print(f"{source:<40} {status}")

    print()
    print(f"FINAL STATUS : {summary['status']}")
    print("=" * 88)
