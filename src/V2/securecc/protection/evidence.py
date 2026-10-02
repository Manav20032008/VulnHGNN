from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


PROTECTION_EVIDENCE_VERSION = 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def build_protection_evidence(
    result: dict[str, Any],
) -> dict[str, Any]:
    source = Path(result["source"]).resolve()
    output = Path(result["output"]).resolve()

    source_sha256 = (
        sha256_file(source)
        if source.exists()
        else None
    )

    output_sha256 = (
        sha256_file(output)
        if output.exists()
        else None
    )

    behavior = result.get("behavior")

    return {
        "evidence_version": PROTECTION_EVIDENCE_VERSION,
        "evidence_format": "vulnhgnn-protection-evidence",
        "tool": "VulnHGNN 2.0 SecureCC",

        "source": str(source),
        "source_sha256": source_sha256,

        "output": str(output),
        "output_sha256": output_sha256,

        "profile": result.get("profile"),
        "operation": result.get("operation"),

        "transformation": {
            "command": result.get("command", []),
            "returncode": result.get("returncode"),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
        },

        "security": {
            "before": result.get("before"),
            "after": result.get("after"),
            "hardening_preserved": result.get(
                "hardening_preserved",
                False,
            ),
        },

        "behavior": behavior,

        "measurement": {
            "size_before": result.get("size_before"),
            "size_after": result.get("size_after"),
            "size_reduction_bytes": result.get(
                "size_reduction_bytes"
            ),
            "size_reduction_percent": result.get(
                "size_reduction_percent"
            ),
        },

        "status": result.get("status"),
    }


def save_protection_evidence(
    evidence: dict[str, Any],
    path: Path,
) -> Path:
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            evidence,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return path
