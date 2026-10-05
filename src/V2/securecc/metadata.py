from __future__ import annotations

from dataclasses import dataclass


TOOL_NAME = "VulnHGNN 2.0 SecureCC"
VERSION = "2.0.0"
RELEASE = "development"


@dataclass(frozen=True)
class ToolMetadata:
    name: str
    version: str
    release: str


METADATA = ToolMetadata(
    name=TOOL_NAME,
    version=VERSION,
    release=RELEASE,
)


def version_string() -> str:
    return f"{METADATA.name} {METADATA.version}"


def version_report() -> dict[str, str]:
    return {
        "tool": METADATA.name,
        "version": METADATA.version,
        "release": METADATA.release,
    }
