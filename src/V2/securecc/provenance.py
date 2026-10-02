from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any


MANIFEST_SUFFIX = ".securecc.json"
CURRENT_MANIFEST_VERSION = 2


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def manifest_path(binary: Path) -> Path:
    return Path(str(binary) + MANIFEST_SUFFIX)


def _environment() -> dict[str, str]:
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
    }


def build_manifest_payload(
    binary: Path,
    data: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a deterministic SecureCC provenance manifest.

    Existing manifest fields are preserved. Phase-7 provenance metadata
    is added without changing the meaning of existing fields.
    """

    binary = Path(binary).resolve()

    payload = dict(data)

    payload["manifest_version"] = CURRENT_MANIFEST_VERSION
    payload["manifest_format"] = "securecc-provenance"
    payload["binary"] = str(binary)
    payload["binary_sha256"] = sha256_file(binary)

    if "environment" not in payload:
        payload["environment"] = _environment()

    return payload


def write_manifest(
    binary: Path,
    data: dict[str, Any],
) -> Path:
    binary = Path(binary).resolve()

    path = manifest_path(binary)
    payload = build_manifest_payload(binary, data)

    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return path


def read_manifest(binary: Path) -> dict[str, Any]:
    path = manifest_path(Path(binary))

    if not path.exists():
        raise FileNotFoundError(
            f"SecureCC provenance manifest not found: {path}"
        )

    payload = json.loads(
        path.read_text(encoding="utf-8")
    )

    if not isinstance(payload, dict):
        raise ValueError(
            f"Invalid SecureCC provenance manifest: {path}"
        )

    return payload


def validate_manifest(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate the structural integrity of a provenance manifest.

    This function does not make a security decision.
    It only checks that required provenance fields exist.
    """

    required = {
        "manifest_version",
        "binary",
        "binary_sha256",
        "source",
        "source_sha256",
        "build",
        "security_analysis",
        "hardening",
    }

    missing = sorted(
        field
        for field in required
        if field not in manifest
    )

    version = manifest.get(
        "manifest_version"
    )

    supported_version = (
        version in {1, CURRENT_MANIFEST_VERSION}
    )

    return {
        "valid": not missing and supported_version,
        "manifest_version": version,
        "supported_version": supported_version,
        "missing_fields": missing,
    }
