from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .measurement import measure_protection, save_measurement


@dataclass
class BenchmarkStage:
    name: str
    passed: bool
    details: dict[str, Any]


@dataclass
class BenchmarkResult:
    root: str
    status: str
    stages: list[BenchmarkStage]
    summary: dict[str, Any]


def _run(repo_root: Path, *args: str) -> tuple[int, str, str]:
    result = subprocess.run(
        [sys.executable, "-m", "src.V2.securecc", *args],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    return result.returncode, result.stdout, result.stderr

def _run_json(
    root: Path,
    *args: str,
) -> tuple[int, dict[str, Any] | None, str]:
    code, stdout, stderr = _run(root, *args)

    if not stdout.strip():
        return code, None, stderr.strip() or "no JSON output"

    try:
        return code, json.loads(stdout), stderr.strip()
    except json.JSONDecodeError as exc:
        return code, None, (
            f"invalid JSON: {exc}\n"
            f"stdout:\n{stdout[:2000]}\n"
            f"stderr:\n{stderr[:2000]}"
        )


def _lookup(data: dict[str, Any] | None, key: str, default=None):
    """
    Read a field from the existing SecureCC JSON reports.

    The project reports intentionally use different names for some
    counters, so aliases are handled here rather than changing the
    authoritative scan/fix/verify implementations.
    """
    if not isinstance(data, dict):
        return default

    aliases = {
        "files_findings": "files_with_findings",
        "findings": "total_findings",
    }

    candidates = [key]

    if key in aliases:
        candidates.append(aliases[key])

    for candidate in candidates:
        if candidate in data:
            return data[candidate]

    for nested_key in ("summary", "project", "result", "report", "data"):
        nested = data.get(nested_key)

        if isinstance(nested, dict):
            for candidate in candidates:
                if candidate in nested:
                    return nested[candidate]

    return default

def _results(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []

    candidates = [
        data.get("results"),
        data.get("files"),
    ]

    for nested_key in ("summary", "project", "result", "report", "data"):
        nested = data.get(nested_key)
        if isinstance(nested, dict):
            candidates.extend(
                [
                    nested.get("results"),
                    nested.get("files"),
                ]
            )

    for candidate in candidates:
        if isinstance(candidate, list):
            return [
                item for item in candidate
                if isinstance(item, dict)
            ]

    return []


def _stage(
    name: str,
    passed: bool,
    details: dict[str, Any],
) -> BenchmarkStage:
    return BenchmarkStage(
        name=name,
        passed=passed,
        details=details,
    )


def run_project_benchmark(
    root: Path,
    output_dir: Path | None = None,
) -> BenchmarkResult:

    root = root.resolve()
    target_root = root
    repo_root =    Path(__file__).resolve().parents[3]

    if output_dir is None:
        output_dir = repo_root / "build" / "benchmark" / root.name
    output_dir.mkdir(parents=True, exist_ok=True)

    stages: list[BenchmarkStage] = []

    # ============================================================
    # 1. DETECTION
    # ============================================================

    scan_code, scan, scan_error = _run_json(
        repo_root, "scan", str(target_root), "--format", "json"
    )

    scan_status = _lookup(scan, "status")
    scan_files = _lookup(scan, "files_scanned", 0)
    scan_findings = _lookup(scan, "findings", 0)
    scan_failed = _lookup(scan, "files_failed", 0)

    scan_passed = (
        scan_code == 0
        and scan is not None
        and scan_files == 10
        and scan_findings == 18
        and scan_failed == 0
    )

    scan_details = {
        "returncode": scan_code,
        "status": scan_status,
        "files_scanned": scan_files,
        "findings": scan_findings,
        "files_with_findings": _lookup(scan, "files_findings", 0),
        "files_failed": scan_failed,
    }

    if scan_error:
        scan_details["stderr"] = scan_error

    stages.append(
        _stage("detection", scan_passed, scan_details)
    )

    # ============================================================
    # 2. REPAIR
    # ============================================================

    fix_code, fix, fix_error = _run_json(
        repo_root, "fix", str(target_root), "--format", "json"
    )

    fix_status = _lookup(fix, "status")
    fix_files = _lookup(fix, "files_scanned", 0)
    fix_clean = _lookup(fix, "files_clean", 0)
    fix_verified = _lookup(fix, "files_verified", 0)
    fix_rejected = _lookup(fix, "files_rejected", 0)
    fix_failed = _lookup(fix, "files_failed", 0)
    fix_findings = _lookup(fix, "findings", 0)

    # Project fix JSON has no root-level status.
    # The authoritative project result is the aggregate counters.
    fix_passed = (
        fix_code == 0
        and fix is not None
        and fix_files == 10
        and fix_clean == 1
        and fix_verified == 9
        and fix_rejected == 0
        and fix_failed == 0
        and fix_findings == 18
    )

    fix_details = {
        "returncode": fix_code,
        "status": fix_status,
        "files_scanned": fix_files,
        "files_clean": fix_clean,
        "files_verified": fix_verified,
        "files_rejected": fix_rejected,
        "files_failed": fix_failed,
        "findings": fix_findings,
    }

    if fix_error:
        fix_details["stderr"] = fix_error

    stages.append(
        _stage("repair", fix_passed, fix_details)
    )

    # ============================================================
    # 3. PROJECT VERIFICATION
    # ============================================================

    verify_code, verify, verify_error = _run_json(
        repo_root, "verify", str(target_root), "--format", "json"
    )

    verify_status = _lookup(verify, "status")
    verify_files = _lookup(verify, "files_scanned", 0)
    verify_clean = _lookup(verify, "files_clean", 0)
    verify_verified = _lookup(verify, "files_verified", 0)
    verify_unverified = _lookup(verify, "files_unverified", 0)
    verify_failed = _lookup(verify, "files_failed", 0)
    verify_findings = _lookup(verify, "findings", 0)

    verify_passed = (
        verify_code == 0
        and verify is not None
        and verify_status == "PROJECT_VERIFY_VERIFIED"
        and verify_files == 10
        and verify_verified == 10
        and verify_unverified == 0
        and verify_failed == 0
        and verify_findings == 18
    )

    verify_details = {
        "returncode": verify_code,
        "status": verify_status,
        "files_scanned": verify_files,
        "files_clean": verify_clean,
        "files_verified": verify_verified,
        "files_unverified": verify_unverified,
        "files_failed": verify_failed,
        "findings": verify_findings,
    }

    if verify_error:
        verify_details["stderr"] = verify_error

    stages.append(
        _stage("verification", verify_passed, verify_details)
    )

    # ============================================================
    # 4. MACHINE-READABLE EVIDENCE
    # ============================================================

    verify_report = (
repo_root / "build" / "verify" / target_root.name / "project_verification.json"
    )

    fixture_results: list[dict[str, Any]] = []

    if verify_report.exists():
        try:
            payload = json.loads(
                verify_report.read_text(encoding="utf-8")
            )
            fixture_results = payload.get("results", [])
        except (OSError, json.JSONDecodeError):
            fixture_results = []

    fixture_total = len(fixture_results)

    fixture_verified = sum(
        item.get("status") == "PROJECT_VERIFY_VERIFIED"
        for item in fixture_results
    )

    evidence_passed = (
        verify_passed
        and fixture_total == 10
        and fixture_verified == 10
    )

    stages.append(
        _stage(
            "evidence",
            evidence_passed,
            {
                "report": str(verify_report),
                "fixtures": fixture_total,
                "verified": fixture_verified,
                "expected": 10,
            },
        )
    )

    # ============================================================
    # 5. REGRESSION
    # ============================================================

    regression = repo_root / "tests" / "regression_project_verify.sh"

    if regression.exists():
        completed = subprocess.run(
            [str(regression)],
            cwd=root,
            text=True,
            capture_output=True,
        )

        regression_passed = completed.returncode == 0

        regression_details = {
            "returncode": completed.returncode,
            "script": str(regression),
        }

        if not regression_passed:
            regression_details["stdout"] = completed.stdout[-3000:]
            regression_details["stderr"] = completed.stderr[-3000:]
    else:
        regression_passed = False
        regression_details = {
            "script": str(regression),
            "error": "regression harness not found",
        }

    stages.append(
        _stage(
            "regression",
            regression_passed,
            regression_details,
        )
    )

    # ============================================================
    # 6. PROTECTION / PERFORMANCE MEASUREMENT
    # ============================================================

    measurement_source = repo_root / "build" / "test_01_clean"

    measurement_dir = (
        output_dir / "protection"
    )

    measurement_report_path = (
        output_dir / "measurement.json"
    )

    try:
        if not measurement_source.exists():
            measurement_passed = False
            measurement_details = {
                "status": "MEASUREMENT_FAILED",
                "error": (
                    f"measurement source does not exist: "
                    f"{measurement_source}"
                ),
            }
        else:
            measurement = measure_protection(
                measurement_source,
                measurement_dir,
            )

            save_measurement(
                measurement,
                measurement_report_path,
            )

            measurement_passed = (
                measurement["status"]
                == "MEASUREMENT_VERIFIED"
            )

            measurement_details = {
                "status": measurement["status"],
                "report": str(
                    measurement_report_path
                ),
                "profiles": (
                    measurement["summary"]
                ),
            }

    except Exception as exc:
        measurement_passed = False
        measurement_details = {
            "status": "MEASUREMENT_FAILED",
            "error": str(exc),
        }

    stages.append(
        _stage(
            "measurement",
            measurement_passed,
            measurement_details,
        )
    )
    
    
    # ============================================================
    # FINAL
    # ============================================================

    overall_passed = all(stage.passed for stage in stages)

    status = (
        "VULNHGNN_2.0_VERIFIED"
        if overall_passed
        else "VULNHGNN_2.0_BENCHMARK_FAILED"
    )

    summary = {
        "files_scanned": scan_files,
        "findings": scan_findings,
        "files_repaired": fix_verified,
        "files_verified": verify_verified,
        "files_unverified": verify_unverified,
        "files_failed": verify_failed,
        "fixtures_verified": fixture_verified,
        "fixture_total": fixture_total,
        "stages_passed": sum(
            stage.passed for stage in stages
        ),
        "stages_total": len(stages),
        "measurement": measurement_details,
    }

    result = BenchmarkResult(
        root=str(root),
        status=status,
        stages=stages,
        summary=summary,
    )

    report = {
        "tool": "VulnHGNN 2.0 SecureCC",
        "benchmark": "VulnHGNN 2.0 End-to-End Security + Measurement Benchmark",        "root": str(root),
        "status": status,
        "summary": summary,
        "stages": [asdict(stage) for stage in stages],
    }

    (output_dir / "benchmark.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    return result


def print_benchmark(result: BenchmarkResult) -> None:
    print("=" * 88)
    print("VULNHGNN 2.0 — END-TO-END SECURITY BENCHMARK")
    print("=" * 88)
    print(f"Root : {result.root}")
    print()

    s = result.summary

    print("PIPELINE")
    print(f"  Detection findings       : {s['findings']}")
    print(f"  Files scanned            : {s['files_scanned']}")
    print(f"  Files repaired           : {s['files_repaired']}")
    print(f"  Files verified           : {s['files_verified']}")
    print(f"  Files unverified         : {s['files_unverified']}")
    print(f"  Files failed             : {s['files_failed']}")
    print(
        f"  Behavioral fixtures      : "
        f"{s['fixtures_verified']}/{s['fixture_total']}"
    )
    print()

    print("STAGES")
    for stage in result.stages:
        print(
            f"  [{'PASS' if stage.passed else 'FAIL'}] "
            f"{stage.name}"
        )

    print()
    print(
        f"  Stages passed            : "
        f"{s['stages_passed']}/{s['stages_total']}"
    )
    print()
    print(f"FINAL STATUS : {result.status}")
    print("=" * 88)


def benchmark_project(
    root: Path,
    output_dir: Path | None = None,
    output_format: str = "text",
) -> int:

    result = run_project_benchmark(
        root=root,
        output_dir=output_dir,
    )

    if output_format == "json":
        print(
            json.dumps(
                {
                    "root": result.root,
                    "status": result.status,
                    "summary": result.summary,
                    "stages": [
                        asdict(stage)
                        for stage in result.stages
                    ],
                },
                indent=2,
            )
        )
    else:
        print_benchmark(result)

    return (
        0
        if result.status == "VULNHGNN_2.0_VERIFIED"
        else 1
    )
