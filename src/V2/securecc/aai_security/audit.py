from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def default_log_path(project_root: Path | None = None) -> Path:
    root = project_root or Path.cwd()
    path = root / "build" / "aai_security" / "attack_log.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def append_audit_event(path: Path, event: dict[str, Any]) -> None:
    row = dict(event)
    row["timestamp"] = datetime.now(timezone.utc).isoformat()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, default=str) + "\n")
