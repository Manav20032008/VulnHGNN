from __future__ import annotations

import json
from pathlib import Path
from typing import Any


EVALUATION_SCHEMA_VERSION = 1


def build_evaluation_report(
    benchmark: dict[str, Any],
    measurement: dict[str, Any],
) -> dict[str, Any]:

    summary = benchmark.get("summary", {})

    stages = benchmark.get("stages", [])

    pipeline = {
        "stages_total": len(stages),
        "stages_passed": sum(
            stage.get("passed", False)
            for stage in stages
        ),
        "stages": stages,
        "status": benchmark.get("status"),
    }

    security = {
        "files_scanned": summary.get(
            "files_scanned",
            0,
        ),
        "findings": summary.get(
            "findings",
            0,
        ),
        "files_repaired": summary.get(
            "files_repaired",
            0,
        ),
        "files_verified": summary.get(
            "files_verified",
            0,
        ),
        "files_unverified": summary.get(
            "files_unverified",
            0,
        ),
        "files_failed": summary.get(
            "files_failed",
            0,
        ),
        "fixtures_verified": summary.get(
            "fixtures_verified",
            0,
        ),
        "fixture_total": summary.get(
            "fixture_total",
            0,
        ),
    }

    protection = []

    for profile in measurement.get("profiles", []):
        protection.append(
            {
                "profile": profile.get("profile"),
                "status": profile.get("status"),
                "size": profile.get("size"),
                "hardening_preserved": profile.get(
                    "hardening_preserved"
                ),
                "behavior_preserved": profile.get(
                    "behavior_preserved"
                ),
                "source_sha256": profile.get(
                    "source_sha256"
                ),
                "protected_sha256": profile.get(
                    "protected_sha256"
                ),
            }
        )

    performance = []

    for profile in measurement.get("profiles", []):
        baseline = profile.get(
            "baseline_runtime",
            {},
        )

        protected = profile.get(
            "protected_runtime",
            {},
        )

        performance.append(
            {
                "profile": profile.get("profile"),

                "baseline": baseline.get(
                    "statistics",
                    {},
                ),

                "protected": protected.get(
                    "statistics",
                    {},
                ),

                "runtime_delta_seconds": profile.get(
                    "runtime_delta_seconds"
                ),

                "runtime_delta_percent": profile.get(
                    "runtime_delta_percent"
                ),
            }
        )

    measurement_summary = measurement.get(
        "summary",
        {},
    )

    verified = (
        benchmark.get("status")
        == "VULNHGNN_2.0_VERIFIED"
        and measurement.get("status")
        == "MEASUREMENT_VERIFIED"
        and security["files_verified"]
        == security["files_scanned"]
        and security["files_unverified"] == 0
        and security["files_failed"] == 0
        and measurement_summary.get(
            "behavior_preserved"
        ) is True
        and measurement_summary.get(
            "hardening_preserved"
        ) is True
        and measurement_summary.get(
            "runtime_measurements_completed"
        ) is True
    )

    return {
        "evaluation_schema_version":
            EVALUATION_SCHEMA_VERSION,

        "evaluation_format":
            "vulnhgnn-evaluation",

        "tool":
            "VulnHGNN 2.0 SecureCC",

        "pipeline":
            pipeline,

        "security":
            security,

        "protection":
            protection,

        "performance":
            performance,

        "measurement":
            measurement_summary,

        "status": (
            "EVALUATION_VERIFIED"
            if verified
            else "EVALUATION_FAILED"
        ),
    }


def save_evaluation(
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
