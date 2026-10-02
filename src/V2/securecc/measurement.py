from __future__ import annotations

import hashlib
import json
import statistics
import time
from pathlib import Path
from typing import Any

from .protect import protect_binary
from ..sandbox.models import SandboxPolicy
from ..sandbox.runner import SandboxRunner


MEASUREMENT_SCHEMA_VERSION = 2
RUNTIME_MEASUREMENT_RUNS = 10


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def _run_sandbox(binary: Path) -> dict[str, Any]:
    policy = SandboxPolicy(
        timeout_seconds=2.0,
        memory_limit_mb=256,
        cpu_seconds=2,
        network=False,
        inherit_environment=False,
    )

    runner = SandboxRunner(policy)

    start = time.perf_counter()
    result = runner.run([str(binary)])
    wall_time = time.perf_counter() - start

    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "memory_limited": result.memory_limited,
        "isolation_mode": result.isolation_mode,
        "duration_seconds": result.duration_seconds,
        "wall_time_seconds": wall_time,
        "passed": result.passed,
    }


def _runtime_statistics(
    samples: list[float],
) -> dict[str, Any]:
    if not samples:
        return {
            "runs": 0,
            "minimum_seconds": None,
            "median_seconds": None,
            "mean_seconds": None,
            "maximum_seconds": None,
            "stddev_seconds": None,
        }

    return {
        "runs": len(samples),
        "minimum_seconds": min(samples),
        "median_seconds": statistics.median(samples),
        "mean_seconds": statistics.mean(samples),
        "maximum_seconds": max(samples),
        "stddev_seconds": (
            statistics.stdev(samples)
            if len(samples) >= 2
            else 0.0
        ),
    }


def _measure_runtime(
    binary: Path,
    runs: int = RUNTIME_MEASUREMENT_RUNS,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    for _ in range(runs):
        results.append(
            _run_sandbox(binary)
        )

    samples = [
        float(item["duration_seconds"])
        for item in results
        if (
            not item["timed_out"]
            and not item["memory_limited"]
            and item["duration_seconds"] is not None
        )
    ]

    first = results[0] if results else None

    return {
        "statistics": _runtime_statistics(samples),
        "runs": results,
        "all_runs_completed": (
            len(samples) == runs
        ),
        "all_runs_passed": (
            len(results) == runs
            and all(item["passed"] for item in results)
        ),
        "reference_output": {
            "returncode": (
                first["returncode"]
                if first is not None
                else None
            ),
            "stdout": (
                first["stdout"]
                if first is not None
                else ""
            ),
            "stderr": (
                first["stderr"]
                if first is not None
                else ""
            ),
        },
    }


def _measure_profile(
    source: Path,
    profile: str,
    output_dir: Path,
) -> dict[str, Any]:
    output = output_dir / f"{source.stem}_{profile}"

    if output.exists():
        output.unlink()

    before_size = source.stat().st_size

    baseline = _measure_runtime(source)

    start = time.perf_counter()

    protection = protect_binary(
        source,
        output,
        profile=profile,
    )

    transformation_time = (
        time.perf_counter() - start
    )

    if not output.exists():
        return {
            "profile": profile,
            "status": protection["status"],
            "transformation_time_seconds": (
                transformation_time
            ),
            "protection": protection,
            "baseline_runtime": baseline,
            "protected_runtime": None,
            "runtime_delta_seconds": None,
            "runtime_delta_percent": None,
            "behavior_preserved": False,
            "hardening_preserved": False,
        }

    protected = _measure_runtime(output)

    baseline_reference = baseline["reference_output"]
    protected_reference = protected["reference_output"]

    behavior_preserved = (
        baseline["all_runs_completed"]
        and protected["all_runs_completed"]
        and baseline_reference["returncode"]
        == protected_reference["returncode"]
        and baseline_reference["stdout"]
        == protected_reference["stdout"]
        and baseline_reference["stderr"]
        == protected_reference["stderr"]
    )

    baseline_median = (
        baseline["statistics"]["median_seconds"]
    )
    protected_median = (
        protected["statistics"]["median_seconds"]
    )

    if (
        baseline_median is not None
        and protected_median is not None
    ):
        runtime_delta = (
            protected_median
            - baseline_median
        )

        runtime_delta_percent = (
            runtime_delta
            / baseline_median
            * 100.0
            if baseline_median > 0
            else 0.0
        )
    else:
        runtime_delta = None
        runtime_delta_percent = None

    after_size = output.stat().st_size

    return {
        "profile": profile,
        "status": protection["status"],

        "source": str(source),
        "source_sha256": sha256_file(source),

        "protected_binary": str(output),
        "protected_sha256": sha256_file(output),

        "size": {
            "before_bytes": before_size,
            "after_bytes": after_size,
            "delta_bytes": after_size - before_size,
            "reduction_bytes": (
                before_size - after_size
            ),
            "reduction_percent": (
                (
                    (before_size - after_size)
                    / before_size
                ) * 100.0
                if before_size
                else 0.0
            ),
        },

        "transformation_time_seconds": (
            transformation_time
        ),

        "baseline_runtime": baseline,
        "protected_runtime": protected,

        "runtime_delta_seconds": runtime_delta,
        "runtime_delta_percent": (
            runtime_delta_percent
        ),

        "behavior_preserved": behavior_preserved,

        "hardening_preserved": protection.get(
            "hardening_preserved",
            False,
        ),

        "protection": protection,
    }


def measure_protection(
    source: Path,
    output_dir: Path,
) -> dict[str, Any]:
    source = Path(source).resolve()
    output_dir = Path(output_dir).resolve()

    if not source.exists():
        raise FileNotFoundError(
            f"measurement source does not exist: {source}"
        )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    profiles = (
        "strip-unneeded",
        "strip-debug",
    )

    measurements = [
        _measure_profile(
            source,
            profile,
            output_dir,
        )
        for profile in profiles
    ]

    passed = all(
        item["status"] == "PROTECTED"
        and item["behavior_preserved"]
        and item["hardening_preserved"]
        and item["baseline_runtime"]["all_runs_completed"]
        and item["protected_runtime"]["all_runs_completed"]
        for item in measurements
    )

    report = {
        "measurement_schema_version": (
            MEASUREMENT_SCHEMA_VERSION
        ),
        "measurement_format": (
            "vulnhgnn-protection-measurement"
        ),
        "tool": "VulnHGNN 2.0 SecureCC",

        "runtime_runs_per_binary": (
            RUNTIME_MEASUREMENT_RUNS
        ),

        "source": str(source),
        "source_sha256": sha256_file(source),

        "profiles": measurements,

        "summary": {
            "profiles_total": len(measurements),
            "profiles_passed": sum(
                item["status"] == "PROTECTED"
                for item in measurements
            ),
            "behavior_preserved": all(
                item["behavior_preserved"]
                for item in measurements
            ),
            "hardening_preserved": all(
                item["hardening_preserved"]
                for item in measurements
            ),
            "runtime_measurements_completed": all(
                item["baseline_runtime"][
                    "all_runs_completed"
                ]
                and item["protected_runtime"][
                    "all_runs_completed"
                ]
                for item in measurements
            ),
        },

        "status": (
            "MEASUREMENT_VERIFIED"
            if passed
            else "MEASUREMENT_FAILED"
        ),
    }

    return report


def save_measurement(
    report: dict[str, Any],
    path: Path,
) -> Path:
    path = Path(path).resolve()
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )

    return path