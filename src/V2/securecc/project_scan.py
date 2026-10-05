from __future__ import annotations

import json
from pathlib import Path

from .analysis import analyze_source


SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "build",
    "dist",
    ".securecc",
}


def discover_sources(root: Path) -> list[Path]:
    root = Path(root).resolve()

    if root.is_file():
        if root.suffix.lower() not in SOURCE_EXTENSIONS:
            raise ValueError(
                f"unsupported source file: {root}"
            )
        return [root]

    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")

    sources = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue

        if any(part in DEFAULT_EXCLUDED_DIRS for part in path.parts):
            continue

        sources.append(path)

    return sorted(sources)


def scan_project(root: Path) -> dict:
    root = Path(root).resolve()

    sources = discover_sources(root)

    files = []
    total_findings = 0
    cwe_counts = {}

    for source in sources:
        try:
            result = analyze_source(source)

            findings = result.get("findings", [])
            cwes = result.get("cwes", [])

            finding_records = []

            for finding in findings:
                finding_records.append(
                    {
                        "cwe_id": finding.cwe_id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "message": finding.message,
                        "function": finding.function,
                        "instruction": finding.instruction,
                        "node_id": finding.node_id,
                    }
                )

                total_findings += 1
                cwe_counts[finding.cwe_id] = (
                    cwe_counts.get(finding.cwe_id, 0) + 1
                )

            files.append(
                {
                    "source": str(source),
                    "relative_source": str(
                        source.relative_to(root)
                    )
                    if root.is_dir()
                    else source.name,
                    "findings": finding_records,
                    "finding_count": len(finding_records),
                    "cwes": cwes,
                    "status": (
                        "FINDINGS_PRESENT"
                        if finding_records
                        else "CLEAN"
                    ),
                }
            )

        except Exception as exc:
            files.append(
                {
                    "source": str(source),
                    "relative_source": (
                        str(source.relative_to(root))
                        if root.is_dir()
                        else source.name
                    ),
                    "findings": [],
                    "finding_count": 0,
                    "cwes": [],
                    "status": "ANALYSIS_FAILED",
                    "error": str(exc),
                }
            )

    failed_files = [
        item for item in files
        if item["status"] == "ANALYSIS_FAILED"
    ]

    return {
        "tool": "VulnHGNN 2.0 SecureCC",
        "command": "scan",
        "scope": "project",
        "root": str(root),
        "files_scanned": len(files),
        "files_with_findings": sum(
            1 for item in files
            if item["finding_count"] > 0
        ),
        "files_failed": len(failed_files),
        "total_findings": total_findings,
        "cwe_counts": dict(sorted(cwe_counts.items())),
        "files": files,
        "status": (
            "ANALYSIS_FAILED"
            if failed_files
            else "FINDINGS_PRESENT"
            if total_findings
            else "CLEAN"
        ),
    }


def text_report(result: dict) -> str:
    lines = [
        "=" * 88,
        "VULNHGNN 2.0 — SECURECC PROJECT SCAN",
        "=" * 88,
        f"Root          : {result['root']}",
        f"Files scanned : {result['files_scanned']}",
        f"Files findings: {result['files_with_findings']}",
        f"Files failed  : {result['files_failed']}",
        f"Findings      : {result['total_findings']}",
        "",
        "CWE SUMMARY",
    ]

    if result["cwe_counts"]:
        for cwe, count in result["cwe_counts"].items():
            lines.append(f"  {cwe:<12}: {count}")
    else:
        lines.append("  none")

    lines.extend([
        "",
        "-" * 88,
        "FILES",
    ])

    for item in result["files"]:
        lines.append(
            f"  {item['relative_source']} "
            f"— {item['status']}"
        )

        for finding in item["findings"]:
            lines.append(
                f"      {finding['cwe_id']} — "
                f"{finding['title']} "
                f"[{finding['severity']}]"
            )

    lines.extend([
        "",
        f"FINAL STATUS : {result['status']}",
        "=" * 88,
    ])

    return "\n".join(lines)


def json_report(result: dict) -> str:
    return json.dumps(result, indent=2)
