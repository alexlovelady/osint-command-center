"""Copy the user-facing docs the Copilot may cite into backend/osintcc/copilot/kb/docs (so they ship inside the app).

    uv run python scripts/sync_copilot_docs.py [--check]
--check exits 1 when the copies differ from docs/ (the test suite runs the same comparison).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ["troubleshooting.md", "operator-runbook.md", "privacy.md", "recovery.md", "integration-matrix.md", "install-matrix.md", "tool-contracts.md"]
DEST = ROOT / "backend" / "osintcc" / "copilot" / "kb" / "docs"


def main(check: bool) -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    stale = []
    for n in DOCS:
        src, dst = ROOT / "docs" / n, DEST / n
        data = src.read_bytes()
        if not dst.exists() or dst.read_bytes() != data:
            stale.append(n)
            if not check:
                dst.write_bytes(data)
    print(("stale: " if check else "synced: ") + (", ".join(stale) or "none"))
    return 1 if (check and stale) else 0


if __name__ == "__main__":
    raise SystemExit(main("--check" in sys.argv))
