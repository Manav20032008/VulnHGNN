from __future__ import annotations

from pathlib import Path

from ..hardening.audit import audit_binary
from ..sandbox.models import SandboxPolicy
from ..sandbox.verifier import RuntimeVerifier
from ..verification.models import VerificationGate

from .analysis import analyze_source
from .provenance import (
    read_manifest,
    sha256_file,
    validate_manifest,
)


def verify_binary(
    binary: Path,
    expected_output: str | None = None,
) -> dict:

    binary = Path(binary).resolve()

    if not binary.exists():
        raise FileNotFoundError(f"binary not found: {binary}")

    if not binary.is_file():
        raise ValueError(f"not a regular file: {binary}")

    if not binary.stat().st_mode & 0o111:
        raise ValueError(f"binary is not executable: {binary}")

    # ------------------------------------------------------------
    # 1. Load provenance
    # ------------------------------------------------------------

    manifest = read_manifest(binary)

    manifest_validation = validate_manifest(manifest)

    if not manifest_validation["valid"]:
        raise RuntimeError(
            "invalid SecureCC provenance manifest: "
            + str(manifest_validation)
        )
        
        
    manifest_binary_hash = manifest.get("binary_sha256")
    actual_binary_hash = sha256_file(binary)

    binary_integrity_passed = (
        manifest_binary_hash == actual_binary_hash
    )

    if not binary_integrity_passed:
        raise RuntimeError(
            "binary integrity check failed: "
            "binary hash does not match SecureCC manifest"
        )

    # ------------------------------------------------------------
    # 2. Verify source provenance
    # ------------------------------------------------------------

    source = Path(manifest["source"]).resolve()

    if not source.exists():
        raise FileNotFoundError(
            f"source recorded in manifest no longer exists: {source}"
        )

    expected_source_hash = manifest.get("source_sha256")
    actual_source_hash = sha256_file(source)

    source_integrity_passed = (
        expected_source_hash == actual_source_hash
    )

    # ------------------------------------------------------------
    # 3. Re-run deterministic security analysis
    # ------------------------------------------------------------

    analysis = analyze_source(source)

    findings = analysis.get("findings", [])
    cwes = analysis.get("cwes", [])

    security_rescan_passed = len(findings) == 0

    # ------------------------------------------------------------
    # 4. Binary hardening audit
    # ------------------------------------------------------------

    audit = audit_binary(binary)
    hardening_passed = audit.passed

    # ------------------------------------------------------------
    # 5. Runtime verification
    # ------------------------------------------------------------

    runtime_report = None

    if expected_output is not None:
        runtime_verifier = RuntimeVerifier(
            SandboxPolicy()
        )

        runtime_report = runtime_verifier.run_expected_success(
            name="securecc_verify",
            executable=binary,
            expected_output=expected_output,
        )

        runtime_passed = runtime_report.passed
        behavior_passed = runtime_report.passed
    else:
        runtime_passed = False
        behavior_passed = False

    # ------------------------------------------------------------
    # 6. Final gate
    # ------------------------------------------------------------

    compile_passed = (
        manifest.get("build", {}).get("passed", False)
        and binary_integrity_passed
        and source_integrity_passed
    )

    gate = VerificationGate().evaluate(
        compile_passed=compile_passed,
        hardening_passed=hardening_passed,
        runtime_passed=runtime_passed,
        security_rescan_passed=security_rescan_passed,
        behavior_passed=behavior_passed,
        allow_unverified_behavior=False,
    )

    return {
        "binary": str(binary),
        "source": str(source),
        "manifest": manifest,
        "binary_integrity_passed": binary_integrity_passed,
        "source_integrity_passed": source_integrity_passed,
        "security_rescan_passed": security_rescan_passed,
        "cwes": cwes,
        "finding_count": len(findings),
        "hardening": audit,
        "runtime": runtime_report,
        "compile_passed": compile_passed,
        "gate": gate,
    }
