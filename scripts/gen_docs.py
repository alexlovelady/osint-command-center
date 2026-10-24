"""Generate reference docs from the running code so they cannot drift: docs/api.md, docs/openapi.json, docs/data-model.md.

    uv run python scripts/gen_docs.py            (add --check to fail if the committed docs are out of date)
"""
from __future__ import annotations

import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from osintcc.config import Settings
from osintcc.db import models
from osintcc.db.base import Base
from osintcc.main import create_app

DOCS = ROOT / "docs"


def api_md(spec: dict) -> str:
    groups: dict[str, list[tuple[str, str, dict]]] = defaultdict(list)
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            seg = path.removeprefix("/api/v1").strip("/").split("/")
            key = seg[0] if seg and seg[0] else "root"
            if key == "cases" and len(seg) > 2:
                key = f"cases/{{id}}/{seg[2]}".split("/")[0] + " (case-scoped)"
            groups[key].append((method.upper(), path, op))
    lines = ["# HTTP API reference", "",
             "Generated from the application's OpenAPI document by `scripts/gen_docs.py` (the full machine-readable file is `docs/openapi.json`; "
             "a running backend also serves it at `/api/openapi.json` and interactive docs at `/api/docs`).", "",
             "**Conventions**", "",
             "- Loopback only (`127.0.0.1`). Every request needs `Authorization: Bearer <per-launch token>`; the desktop shell receives the token over a "
             "private stdout handshake. A browser origin must be on the allow-list.",
             "- Errors use one envelope: `{code, message, request_id, retryable, details_safe}`.",
             "- Case-scoped routes check case membership; global routes (settings, plugins, AI profiles, vault, updates, backup) need the admin role.",
             "- Time values are ISO-8601 UTC. Nothing returned is a conclusion: findings, claims and suggestions carry confidence labels and evidence ids.", "",
             f"{sum(len(v) for v in groups.values())} operations in {len(groups)} groups.", ""]
    for key in sorted(groups):
        lines += [f"## {key}", "", "| Method | Path | Summary |", "|---|---|---|"]
        for m, p, op in sorted(groups[key], key=lambda x: (x[1], x[0])):
            summ = (op.get("summary") or op.get("operationId", "")).replace("|", "/")
            doc = (op.get("description") or "").strip().splitlines()
            if doc:
                summ = doc[0].replace("|", "/")[:140]
            lines.append(f"| {m} | `{p}` | {summ} |")
        lines.append("")
    return "\n".join(lines)


def model_md() -> str:
    lines = ["# Data model", "",
             "Generated from the SQLAlchemy models by `scripts/gen_docs.py`. SQLite in WAL mode with foreign keys on; schema changes only through "
             "Alembic migrations (`backend/osintcc/db/migrations`). FTS5 `search_index` is maintained by triggers and is not an ORM table.", "",
             f"{len(Base.metadata.tables)} tables.", ""]
    for name in sorted(Base.metadata.tables):
        t = Base.metadata.tables[name]
        doc = (next((m.class_.__doc__ for m in Base.registry.mappers if m.local_table is t), "") or "").strip().splitlines()
        lines += [f"## {name}", ""] + ([doc[0], ""] if doc else [])
        lines += ["| Column | Type | Null | Key |", "|---|---|---|---|"]
        for c in t.columns:
            key = "PK" if c.primary_key else (f"FK → {next(iter(c.foreign_keys)).column.table.name}" if c.foreign_keys else "")
            lines.append(f"| {c.name} | {str(c.type)[:30]} | {'yes' if c.nullable else 'no'} | {key} |")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    s = Settings(data_dir=Path(tempfile.mkdtemp(prefix="osintcc-docs-")), vault_encryption="off", run_scheduler=False)
    s.ensure_dirs()
    spec = create_app(s).openapi()
    outputs = {DOCS / "openapi.json": json.dumps(spec, indent=1, sort_keys=True) + "\n", DOCS / "api.md": api_md(spec) + "\n", DOCS / "data-model.md": model_md() + "\n"}
    _ = models
    stale = []
    for p, text in outputs.items():
        if "--check" in sys.argv:
            if not p.exists() or p.read_text(encoding="utf8") != text:
                stale.append(p.name)
        else:
            p.write_text(text, encoding="utf8")
    if stale:
        print("stale generated docs:", ", ".join(stale))
        return 1
    print("ok", {p.name: len(t) for p, t in outputs.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
