import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from .project_verify import verify_project, print_project_verify
from ..verification.behavior import BehaviorOracle
from .project_benchmark import benchmark_project
from .metadata import METADATA, version_report


def clang_path():
    path = shutil.which("clang")
    if not path:
        raise RuntimeError("clang was not found on PATH")
    return path


def build(source: Path, output: Path, secure: bool) -> int:
    if not source.exists():
        raise FileNotFoundError(f"source file not found: {source}")

    if source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
        raise ValueError("SecureCC build supports C/C++ source files only.")

    output.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------
    # Normal build
    # ------------------------------------------------------------
    if not secure:
        compiler = clang_path()

        cmd = [
            compiler,
            "-O2",
            str(source),
            "-o",
            str(output),
        ]

        result = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
        )

        if result.returncode != 0:
            print(result.stderr, file=sys.stderr, end="")
            return result.returncode

        print(f"compiler : {compiler}")
        print(f"source   : {source}")
        print(f"output   : {output}")
        print("profile  : default")
        print("status   : BUILD_OK")

        return 0

    # ------------------------------------------------------------
    # Secure build
    #
    # source
    #   ↓
    # security analysis
    #   ↓
    # hardened compilation
    #   ↓
    # binary audit
    #   ↓
    # provenance manifest
    #   ↓
    # SECURE_BUILD_VERIFIED
    # ------------------------------------------------------------

    print("=" * 88)
    print("VULNHGNN 2.0 — SECURECC SECURE BUILD")
    print("=" * 88)
    print(f"Source        : {source}")
    print(f"Output        : {output}")
    print()

    # ------------------------------------------------------------
    # Step 1 — security analysis
    # ------------------------------------------------------------

    print("[1/4] Security analysis")

    from .analysis import analyze_source

    analysis = analyze_source(source)

    findings = analysis.get("findings", [])
    cwes = analysis.get("cwes", [])

    print(f"      Findings : {len(findings)}")
    print(
        "      CWEs     : "
        + (", ".join(cwes) if cwes else "none")
    )

    if findings:
        print("      STATUS   : REJECTED")
        print()
        print("Secure build rejected because security findings remain.")
        print("Use:")
        print(f"  ./securecc scan {source}")
        print(f"  ./securecc fix {source}")
        print("=" * 88)
        return 2

    print("      STATUS   : PASS")
    print()

    # ------------------------------------------------------------
    # Step 2 — hardened compilation
    # ------------------------------------------------------------

    print("[2/4] Hardened compilation")

    from ..hardening.compiler import SecureCompiler
    from ..hardening.profile import HardeningProfile

    compiler = SecureCompiler(
        profile=HardeningProfile()
    )

    build_result = compiler.build(
        source,
        output,
    )

    if not build_result["success"]:
        print("      STATUS   : FAIL")

        if build_result.get("stderr"):
            print(
                build_result["stderr"],
                file=sys.stderr,
                end=""
            )

        print("=" * 88)
        return build_result.get("returncode", 1) or 1

    print("      STATUS   : PASS")
    print()

    # ------------------------------------------------------------
    # Step 3 — binary security audit
    # ------------------------------------------------------------

    print("[3/4] Binary security audit")

    from ..hardening.audit import audit_binary

    audit = audit_binary(output)

    print(
        "      ELF              : "
        + ("PASS" if audit.is_elf else "FAIL")
    )
    print(
        "      PIE              : "
        + ("PASS" if audit.is_pie else "FAIL")
    )
    print(
        "      RELRO            : "
        + ("PASS" if audit.relro else "FAIL")
    )
    print(
        "      BIND_NOW         : "
        + ("PASS" if audit.bind_now else "FAIL")
    )
    print(
        "      NX stack         : "
        + ("PASS" if audit.nx_stack else "FAIL")
    )
    print(
        "      Stack protector  : "
        + ("PASS" if audit.stack_canary_reference else "FAIL")
    )

    if not audit.passed:
        print()
        print("      STATUS   : REJECTED")
        print("Secure build failed binary hardening audit.")
        print("=" * 88)
        return 2

    print()
    print("      STATUS   : PASS")
    print()

    # ------------------------------------------------------------
    # Step 4 — provenance manifest
    # ------------------------------------------------------------

    print("[4/4] Provenance manifest")

    from .provenance import sha256_file, write_manifest

    source_hash = sha256_file(source)

    manifest = write_manifest(
        output,
        {
            "tool": "VulnHGNN 2.0 SecureCC",
            "command": "build",

            "source": str(source.resolve()),
            "source_sha256": source_hash,

            "compiler": build_result["command"][0],
            "compiler_command": build_result["command"],
            "profile": "vulnhgnn-secure",

            "security_analysis": {
                "findings": len(findings),
                "cwes": cwes,
                "passed": True,
            },

            "hardening": {
                "elf": audit.is_elf,
                "pie": audit.is_pie,
                "relro": audit.relro,
                "bind_now": audit.bind_now,
                "nx_stack": audit.nx_stack,
                "stack_protector": audit.stack_canary_reference,
                "passed": audit.passed,
            },

            "build": {
                "passed": True,
                "status": "SECURE_BUILD_VERIFIED",
            },

            "verification": {
                "required": True,
                "status": "SECURE_BUILD_VERIFIED",
            },
        },
    )

    print(f"      Manifest         : {manifest}")
    print()
    print("FINAL STATUS : SECURE_BUILD_VERIFIED")
    print("=" * 88)

    return 0


def version():
    result = subprocess.run(
        [clang_path(), "--version"],
        text=True,
        capture_output=True,
    )

    clang_version = (
        result.stdout.splitlines()[0]
        if result.stdout.splitlines()
        else "clang: unavailable"
    )

    print(f"{METADATA.name} {METADATA.version}")
    print(f"release : {METADATA.release}")
    print(clang_version)

    return result.returncode

def report(source: Path, output: Path, secure: bool):
    data = {
        "tool": "VulnHGNN 2.0 SecureCC",
        "command": "build",
        "source": str(source),
        "output": str(output),
        "profile": "secure" if secure else "default",
        "compiler": clang_path(),
    }
    print(json.dumps(data, indent=2))
    return 0


def scan(source: Path, output_format: str):
    if not source.exists():
        raise FileNotFoundError(f"path not found: {source}")

    if source.is_dir():
        from .project_scan import scan_project
        from .project_scan import json_report as project_json_report
        from .project_scan import text_report as project_text_report

        result = scan_project(source)

        if output_format == "json":
            print(project_json_report(result))
        else:
            print(project_text_report(result))

        return 0 if result["status"] != "ANALYSIS_FAILED" else 2

    from .analysis import analyze_source
    from .scan import print_json, print_report

    result = analyze_source(source)

    if output_format == "json":
        print_json(result)
    else:
        print_report(result)

    return 0


def fix(source: Path, output_dir: Path, output_format: str, no_build: bool):
    """
    SecureCC fix dispatcher.

    File:
        Uses the existing deterministic single-file repair pipeline.

    Directory:
        Uses project-wide orchestration while keeping every original
        source file untouched.
    """
    source = Path(source)

    if not source.exists():
        raise FileNotFoundError(f"path not found: {source}")

    # ------------------------------------------------------------
    # Project-wide fix
    # ------------------------------------------------------------
    if source.is_dir():
        from .project_fix import (
            fix_project,
            json_report,
            text_report,
        )

        result = fix_project(
            root=source,
            output_root=output_dir,
            build_artifact=not no_build,
        )

        if output_format == "json":
            print(json_report(result))
        else:
            print(text_report(result))

        return (
            0
            if result["status"] == "PROJECT_FIX_VERIFIED"
            else 2
        )

    # ------------------------------------------------------------
    # Existing single-file fix
    # ------------------------------------------------------------
    from .fix import fix_source, json_report

    result = fix_source(
        source,
        output_dir=output_dir,
        keep_ir=True,
        build_artifact=not no_build,
    )

    if output_format == "json":
        print(json_report(result))
        return 0 if result["status"] in {"CLEAN", "VERIFIED"} else 2

    print("=" * 88)
    print("VULNHGNN 2.0 — SECURECC FIX")
    print("=" * 88)
    print(f"Source        : {result['source']}")
    print(f"Output dir    : {result['output_dir']}")
    print(f"Findings      : {result['finding_count']}")
    print(
        "CWEs          : "
        + (
            ", ".join(result["detected_cwes"])
            if result["detected_cwes"]
            else "none"
        )
    )

    plan = result.get("plan") or {}
    print(f"Repair actions: {plan.get('action_count', 0)}")

    verification = result.get("verification")
    if verification:
        print(
            f"IR verification : "
            f"{'PASS' if verification.get('passed') else 'FAIL'}"
        )

    detector = result.get("detector_verification")
    if detector:
        print(
            "Security re-scan: "
            + ("PASS" if detector.get("passed") else "FAIL")
        )
        print(
            f"Original CWEs   : "
            f"{', '.join(detector.get('original_cwes', [])) or 'none'}"
        )
        print(
            f"Patched CWEs    : "
            f"{', '.join(detector.get('patched_cwes', [])) or 'none'}"
        )

    build_check = result.get("build_check")
    if build_check:
        print(
            f"Compile check   : "
            f"{'PASS' if build_check.get('passed') else 'FAIL'}"
        )

    if result.get("patched_ir"):
        print(f"Patched IR      : {result['patched_ir']}")

    print(f"STATUS          : {result['status']}")
    print(f"Message         : {result.get('message', '')}")
    print("=" * 88)

    return 0 if result["status"] in {"CLEAN", "VERIFIED"} else 2
def verify(
    target: Path,
    expected_output: str | None,
    output_dir: Path | None = None,
    output_format: str = "text",
    behavior_config: Path | None = None,
):
    target = Path(target)

    if not target.exists():
        raise FileNotFoundError(f"path not found: {target}")

    # ------------------------------------------------------------
    # Project-wide verification
    # ------------------------------------------------------------
    if target.is_dir():
        # Automatically load the project behavior oracle when present.
        oracle_path = (
            behavior_config
            if behavior_config is not None
            else Path("configs/behavior.json")
        )

        behavior_oracle = None

        if oracle_path.exists():
            behavior_oracle = BehaviorOracle(oracle_path)
        elif behavior_config is not None:
            raise FileNotFoundError(
                f"behavior configuration not found: {oracle_path}"
            )

        result = verify_project(
            root=target,
            output_dir=output_dir,
            behavior_oracle=behavior_oracle,
        )

        if output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            print_project_verify(result)

        from .exit_codes import ExitCode

        if result["status"] == "PROJECT_VERIFY_VERIFIED":
            return int(ExitCode.SUCCESS)

        if result["status"] == "PROJECT_VERIFY_UNVERIFIED":
            return int(ExitCode.VERIFICATION_UNVERIFIED)

        return int(ExitCode.VERIFICATION_FAILED)

    # ------------------------------------------------------------
    # Existing single-binary verification
    # ------------------------------------------------------------
    from .verify import verify_binary

    result = verify_binary(
        target,
        expected_output=expected_output,
    )

    # ------------------------------------------------------------
    # Phase 8E — Unified security evidence
    #
    # Verification remains authoritative. This only packages the
    # already-observed explanation, verification, and provenance data.
    # ------------------------------------------------------------
    from ..explain.unified_evidence import (
        build_unified_evidence,
        save_unified_evidence,
    )
    from .explain import explain_source

    source_path = Path(result["source"])

    explanation_result = explain_source(source_path)

    provenance = result.get("manifest")

    unified_evidence = build_unified_evidence(
        explanation_result,
        verification=result,
        provenance=provenance,
    )

    evidence_dir = Path("build/evidence")
    evidence_dir.mkdir(parents=True, exist_ok=True)

    unified_path = evidence_dir / (
        source_path.stem + ".unified.evidence.json"
    )

    save_unified_evidence(
        unified_evidence,
        unified_path,
    )

    result["unified_evidence"] = unified_evidence
    result["unified_evidence_artifact"] = str(
        unified_path.resolve()
    )

    audit = result["hardening"]
    gate = result["gate"]
    runtime = result["runtime"]

    print("=" * 88)
    print("VULNHGNN 2.0 — SECURECC VERIFY")
    print("=" * 88)
    print(f"Binary        : {result['binary']}")
    print(f"Source        : {result['source']}")
    print()

    print("[1/5] Provenance integrity")

    print(
        f"      Binary hash       : "
        f"{'PASS' if result['binary_integrity_passed'] else 'FAIL'}"
    )

    print(
        f"      Source hash       : "
        f"{'PASS' if result['source_integrity_passed'] else 'FAIL'}"
    )

    print()

    print("[2/5] Security re-analysis")

    print(
        f"      Findings          : "
        f"{result['finding_count']}"
    )

    print(
        f"      CWEs              : "
        f"{', '.join(result['cwes']) if result['cwes'] else 'none'}"
    )

    print(
        f"      STATUS            : "
        f"{'PASS' if result['security_rescan_passed'] else 'FAIL'}"
    )

    print()

    print("[3/5] Binary security audit")

    print(
        f"      ELF              : "
        f"{'PASS' if audit.is_elf else 'FAIL'}"
    )

    print(
        f"      PIE              : "
        f"{'PASS' if audit.is_pie else 'FAIL'}"
    )

    print(
        f"      RELRO            : "
        f"{'PASS' if audit.relro else 'FAIL'}"
    )

    print(
        f"      BIND_NOW         : "
        f"{'PASS' if audit.bind_now else 'FAIL'}"
    )

    print(
        f"      NX stack         : "
        f"{'PASS' if audit.nx_stack else 'FAIL'}"
    )

    print(
        f"      Stack protector  : "
        f"{'PASS' if audit.stack_canary_reference else 'FAIL'}"
    )

    print(
        f"      STATUS           : "
        f"{'PASS' if audit.passed else 'FAIL'}"
    )

    print()

    print("[4/5] Runtime verification")

    if runtime is None:
        print("      STATUS           : UNVERIFIED")
        print("      Reason           : expected output was not supplied")
    else:
        print(
            f"      STATUS           : "
            f"{'PASS' if runtime.passed else 'FAIL'}"
        )

        print(f"      Expected         : {runtime.expected}")

        print(
            f"      Return code      : "
            f"{runtime.result.returncode}"
        )

        print(
            f"      Isolation        : "
            f"{runtime.result.isolation_mode}"
        )

    print()

    print("[5/5] Verification gate")

    print(
        f"      Compilation      : "
        f"{'PASS' if gate.compile_passed else 'FAIL'}"
    )

    print(
        f"      Hardening        : "
        f"{'PASS' if gate.hardening_passed else 'FAIL'}"
    )

    print(
        f"      Runtime          : "
        f"{'PASS' if gate.runtime_passed else 'FAIL'}"
    )

    print(
        f"      Security rescan  : "
        f"{'PASS' if gate.security_rescan_passed else 'FAIL'}"
    )

    print(
        f"      Behavior         : "
        f"{'PASS' if gate.behavior_passed else 'FAIL'}"
    )

    if gate.reasons:
        print()
        print("      Reasons:")

        for reason in gate.reasons:
            print(f"        - {reason}")

    print()

    print(
        "FINAL STATUS : "
        + ("VERIFIED" if gate.accepted else "REJECTED")
    )

    print("=" * 88)

    return 0 if gate.accepted else 2



def explain(source: Path, output_format: str):
    from .explain import (
        explain_source,
        json_report,
        text_report,
    )
    from ..explain.evidence_report import save_evidence_report

    result = explain_source(source)

    # Persist the deterministic Phase 8 evidence artifact.
    evidence = result.get("evidence_report")

    if evidence is not None:
        evidence_dir = Path("build/evidence")
        evidence_dir.mkdir(parents=True, exist_ok=True)

        artifact = evidence_dir / (
            source.stem + ".evidence.json"
        )

        save_evidence_report(evidence, artifact)

        result["evidence_artifact"] = str(artifact.resolve())

    if output_format == "json":
        print(json_report(result))
    else:
        print(text_report(result))

    return 0


def diagnose(source: Path, output_format: str):
    from .diagnostics import (
        diagnose_source,
        json_report,
        save_diagnostics,
        text_report,
    )

    result = diagnose_source(source)

    evidence_dir = Path("build/evidence")
    evidence_dir.mkdir(parents=True, exist_ok=True)

    artifact = evidence_dir / (
        source.stem + ".diagnostics.json"
    )

    save_diagnostics(result, artifact)

    result["artifact"] = str(artifact.resolve())

    if output_format == "json":
        print(json_report(result))
    else:
        print(text_report(result))
        print(f"Artifact      : {artifact.resolve()}")

    return 0


def harden(source: Path, output: Path, output_format: str):
    from .harden import harden_source, json_report, text_report

    result = harden_source(source, output)

    if output_format == "json":
        print(json_report(result))
    else:
        print(text_report(result))

    return 0 if result["status"] == "HARDENED" else 2


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="securecc",
description=(
    "VulnHGNN 2.0 local-first secure C/C++ compiler "
    "and verification interface"
),    )
    parser.add_argument("--version", action="store_true")

    sub = parser.add_subparsers(dest="command")

    p_build = sub.add_parser("build", help="compile a C/C++ source file")
    p_build.add_argument("source", type=Path)
    p_build.add_argument("-o", "--output", type=Path)
    p_build.add_argument("--secure", action="store_true")

    p_report = sub.add_parser(
        "report",
        help="show machine-readable build configuration",
    )
    p_report.add_argument("source", type=Path)
    p_report.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("build/app"),
    )
    p_report.add_argument("--secure", action="store_true")

    p_scan = sub.add_parser(
        "scan",
        help="run V2 security analysis on a C/C++ source file",
    )
    p_scan.add_argument("source", type=Path)
    p_scan.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="scan output format",
    )

    p_fix = sub.add_parser(
        "fix",
        help="generate and verify deterministic security patches for a file or project",
    )
    p_fix.add_argument("source", type=Path)
    p_fix.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="directory for the verified patch candidate and build artifact",
    )
    p_fix.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="fix output format",
    )
    p_fix.add_argument(
        "--no-build",
        action="store_true",
        help="skip compiling the patched LLVM IR; security re-analysis still runs",
    )

    p_verify = sub.add_parser(
        "verify",
        help="verify an executable or an entire C/C++ project",
    )

    p_verify.add_argument(
        "target",
        type=Path,
        help="executable or C/C++ project directory",
    )

    p_verify.add_argument(
        "--expect",
        default=None,
        help="expected stdout for single-binary runtime verification",
    )

    p_verify.add_argument(
        "--behavior-config",
        type=Path,
        default=None,
        help=(
            "project behavior oracle JSON; defaults to "
            "configs/behavior.json when present"
        ),
    )

    p_verify.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="directory for project verification artifacts",
    )

    p_verify.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="verification output format",
    )
    p_explain = sub.add_parser(
        "explain",
        help="explain detected security findings",
    )
    p_explain.add_argument(
        "source",
        type=Path,
    )
    p_explain.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="explanation output format",
    )
    p_diagnose = sub.add_parser(
        "diagnose",
        help="show developer-facing security diagnostics",
    )
    p_diagnose.add_argument(
        "source",
        type=Path,
    )
    p_diagnose.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="diagnostic output format",
    )

    p_harden = sub.add_parser(
        "harden",
        help="compile a C/C++ source file with security hardening",
    )
    p_harden.add_argument(
        "source",
        type=Path,
    )
    p_harden.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="output executable path",
    )
    p_harden.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="hardening output format",
    )
    p_protect = sub.add_parser(
        "protect",
        help="apply validated binary-level protection",
    )
    p_protect.add_argument(
        "binary",
        type=Path,
    )
    p_protect.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="protected executable path",
    )
    p_protect.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="protection output format",
    )
    p_protect.add_argument(
        "--profile",
        choices=("strip-unneeded", "strip-debug"),
        default="strip-unneeded",
        help="binary protection profile",
    )
    p_learn = sub.add_parser(
        "learn",
        help="teach secure coding concepts from detected findings",
    )
    p_learn.add_argument(
        "source",
        type=Path,
    )
    p_learn.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="learning output format",
    )
    p_benchmark = sub.add_parser(
        "benchmark",
        help="run the complete VulnHGNN 2.0 project benchmark",
    )

    p_benchmark.add_argument(
        "target",
        type=Path,
        help="C/C++ project directory to benchmark",
    )

    p_benchmark.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="directory for benchmark artifacts",
    )

    p_benchmark.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="benchmark output format",
    )
    args = parser.parse_args(argv)

    try:
        if args.version:
            return version()

        if args.command == "build":
            output = args.output or Path("build") / args.source.stem
            return build(args.source, output, args.secure)

        if args.command == "report":
            return report(args.source, args.output, args.secure)

        if args.command == "scan":
            return scan(args.source, args.format)

        if args.command == "fix":
            return fix(
                args.source,
                args.output_dir,
                args.format,
                args.no_build,
            )

        if args.command == "verify":
            return verify(
                args.target,
                args.expect,
                args.output_dir,
                args.format,
                args.behavior_config,
            )
        if args.command == "explain":
            return explain(
                args.source,
                args.format,
            )      
        if args.command == "diagnose":
            return diagnose(
                args.source,
                args.format,
            )

        if args.command == "harden":
            output = args.output or Path("build") / "hardened" / args.source.stem
            return harden(
                args.source,
                output,
                args.format,
            )      
        if args.command == "protect":
            from .protect import protect_binary, json_report, text_report

            output = (
                args.output
                or Path("build") / "protected" / args.binary.name
            )

            result = protect_binary(
                args.binary,
                output,
                profile=args.profile,
            )

            from .protection.evidence import (
                build_protection_evidence,
                save_protection_evidence,
            )

            evidence = build_protection_evidence(result)

            evidence_dir = Path("build/protection")
            evidence_dir.mkdir(parents=True, exist_ok=True)

            evidence_path = (
                evidence_dir
                / f"{args.binary.stem}.{args.profile}.protection.json"
            )

            save_protection_evidence(
                evidence,
                evidence_path,
            )

            result["protection_evidence"] = evidence
            result["protection_evidence_artifact"] = str(
                evidence_path.resolve()
            )

            if args.format == "json":
                print(json_report(result))
            else:
                print(text_report(result))

            return 0 if result["status"] == "PROTECTED" else 2
        if args.command == "learn":
            from .learn import learn_source, json_report, text_report

            result = learn_source(args.source)

            if args.format == "json":
                print(json_report(result))
            else:
                print(text_report(result))
        if args.command == "benchmark":
            return benchmark_project(
                root=args.target,
                output_dir=args.output_dir,
                output_format=args.format,
            )
            return 0 
        parser.print_help()
        return 0

    except Exception as exc:
        print(f"securecc: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
