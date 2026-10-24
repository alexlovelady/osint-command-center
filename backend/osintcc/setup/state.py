"""Record of tools installed by first-run setup (kept dependency-free so adapters can read it without importing the installer)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf8"))
    except (OSError, ValueError):
        return {}


def managed_path(path: Path | None, tool_id: str) -> str | None:
    """Binary path recorded by setup for `tool_id`, if the file still exists."""
    if path is None:
        return None
    p = (load_state(path).get(tool_id) or {}).get("path")
    return p if p and Path(p).is_file() else None
