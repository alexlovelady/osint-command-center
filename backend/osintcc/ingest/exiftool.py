"""Optional metadata enrichment with ExifTool (installed by first-run setup or found on PATH).

The file is copied to a private scratch directory under a neutral name and read by ExifTool with a fixed argument list, a
timeout, an output cap and a minimal environment. Everything it reports is a claim made by the file (trivially editable) and
is stored as an observation with that caveat; nothing is ever written back to the file or the vault.
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from ..adapters.cli import run_argv
from .parsers import Obs

KINDS = {"jpeg_exif", "geotiff", "pdf", "docx"}
MAX_TAGS = 400
MAX_VALUE = 400
_SKIP = re.compile(r"(Thumbnail|Preview|Data$|^System:|SourceFile|Directory|FileName|FilePermissions|FileAccess|FileInode)", re.IGNORECASE)
_GPS = re.compile(r"GPS(Latitude|Longitude|Position)", re.IGNORECASE)


async def read_tags(exe: str, data: bytes, filename: str, timeout: float = 30) -> Obs | None:
    ext = re.sub(r"[^A-Za-z0-9]", "", Path(filename).suffix)[:6]
    with tempfile.TemporaryDirectory(prefix="osintcc-exif-") as td:
        f = Path(td) / f"input.{ext or 'bin'}"
        f.write_bytes(data)
        res = await run_argv([exe, "-json", "-G1", "-n", "-q", "-fast2", "--", str(f)], timeout, 2 * 1024 * 1024, cwd=td)
    if res.timed_out or res.returncode not in (0, None):
        return None
    try:
        raw = json.loads(res.stdout)[0]
    except (ValueError, IndexError, TypeError):
        return None
    tags: dict[str, Any] = {}
    for k, v in raw.items():
        if _SKIP.search(k) or len(tags) >= MAX_TAGS:
            continue
        tags[k] = v[:MAX_VALUE] if isinstance(v, str) else (v if isinstance(v, int | float | bool) else str(v)[:MAX_VALUE])
    if not tags:
        return None
    has_gps = any(_GPS.search(k) for k in tags)
    return Obs("GEOINT" if has_gps else "OSINT", "exiftool.metadata", {
        "tags": tags, "tag_count": len(tags), "contains_position": has_gps,
        "note": "Tags are claims made by the file; authors, dates and positions are easily edited. Read-only inspection of a scratch copy."},
        confidence="low", sensitivity="RESTRICTED" if has_gps else "INTERNAL")
