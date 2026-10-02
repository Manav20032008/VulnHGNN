from __future__ import annotations

import json
from pathlib import Path

from .fix import fix_source
from .project_scan import discover_sources


def fix_project(
    root: Path,
    output_root: Path | None = None,
    build_artifact: bool = True,
) -> dict:
    """
    Apply the existing deterministic SecureCC single-file repair pipeline
    to every supported C/C++ source in a project.

    Original source files are never overwritten.

    Output structure mirrors the project source tree under output_root.
    """

    root = Path(root).resolve()

    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")

    if not root.is_dir():
        raise ValueError(f"project fix requires a directory: {root}")

    if output_root is None:
        output_root = root.parent / "build" / "fixes" / root.name
    else:
        output_root = Path(output_root).resolve()

    output_root.mkdir(parents=True, exist_ok=True)

    sources = discover_sources(root)

    files = []
    files_clean = 0
    files_verified = 0
    files_rejected = 0
    files_failed = 0
    total_findings = 0

    for source in sources:
        relative = source.relative_to(root)

        # Each source gets its own isolated output directory.
        file_output = output_root / relative.parent / source.stem

        try:
            result = fix_source(
                source=source,
                output_dir=file_output,
                build_artifact=build_artifact,
            )

            detected_cwes = result.get("detected_cwes", [])
            finding_count = int(result.get("finding_count", 0))

            total_findings += finding_count

            status = result.get("status", "UNKNOWN")

            if status == "CLEAN":
                files_clean += 1
            elif status == "VERIFIED":
                files_verified += 1
            elif status == "REJECTED":
                files_rejected += 1
            else:
                files_failed += 1

            files.append(
                {
                    "source": str(source),
                    "relative_source": str(relative),
                    "output_dir": str(file_output),
                    "status": status,
                    "finding_count": finding_count,
                    "cwes": detected_cwes,
                    "message": result.get("message"),
                    "verification": result.get("verification"),
                    "detector_verification": result.get(
                        "detector_verification"
                    ),
                    "build_check": result.get("build_check"),
                    "patched_ir": result.get("patched_ir"),
                }
            )

        except Exception as exc:
            files_failed += 1

            files.append(
                {
                    "source": str(source),
                    "relative_source": str(relative),
                    "output_dir": str(file_output),
                    "status": "FIX_FAILED",
                    "finding_count": 0,
                    "cwes": [],
                    "error": str(exc),
                }
            )

    # A project is accepted only when every source was either:
    #   - already clean, or
    #   - successfully repaired and verified.
    project_passed = (
        files_failed == 0
        and files_rejected == 0
    )

    status = (
        "PROJECT_FIX_VERIFIED"
        if project_passed
        else "PROJECT_FIX_FAILED"
    )

    return {
        "tool": "VulnHGNN 2.0 SecureCC",
        "command": "fix",
        "scope": "project",
        "root": str(root),
        "output_root": str(output_root),
        "build_artifact": build_artifact,
        "files_scanned": len(sources),
        "files_clean": files_clean,
        "files_verified": files_verified,
        "files_rejected": files_rejected,
        "files_failed": files_failed,
        "total_findings": total_findings,
        "files": files,
        "status": status,
    }


def text_report(result: dict) -> str:
    lines = [
        "VULNHGNN 2.0 — SECURECC PROJECT FIX",
        f"Root           : {result['root']}",
        f"Output root    : {result['output_root']}",
        f"Files scanned  : {result['files_scanned']}",
        f"Files clean    : {result['files_clean']}",
        f"Files verified : {result['files_verified']}",
        f"Files rejected : {result['files_rejected']}",
        f"Files failed   : {result['files_failed']}",
        f"Findings       : {result['total_findings']}",
        "",
        "FILES",
    ]

    for item in result["files"]:
        cwes = ", ".join(item.get("cwes", []))
        suffix = f" {cwes}" if cwes else ""

        lines.append(
            f"{item['relative_source']:<40} "
            f"{item['status']}{suffix}"
        )

    lines.extend(
        [
            "",
            f"FINAL STATUS : {result['status']}",
        ]
    )

    return "\n".join(lines)


def json_report(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)
