"""Content-addressed comparison of datasets between runs: new / removed / changed / uncertain, with stable ids and provenance pointers.

A dataset is a list of finding items. Items are grouped by (entity, predicate); a group holds a set of value digests. Comparing two snapshots:
  added     group not seen before                      removed   group no longer observed
  changed   group present in both, value set differs   uncertain removals when the current dataset is PARTIAL (a source failed), plus low-confidence changes
"No longer observed" is never "does not exist": the wording and the `uncertain` bucket exist so a flaky source cannot raise a false alarm."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AutomationSnapshot

LOW = ("low", "unknown")


def _h(*parts: Any) -> str:
    return hashlib.sha256("|".join(json.dumps(p, sort_keys=True, default=str) for p in parts).encode()).hexdigest()


def group_id(it: dict[str, Any]) -> str:
    return _h(it.get("entity_type"), it.get("entity"), it.get("predicate"))[:20]


def value_digest(it: dict[str, Any]) -> str:
    return _h(it.get("value"))[:16]


def to_snapshot(items: list[dict[str, Any]], ignore: list[str] | None = None) -> dict[str, Any]:
    ignore_set = set(ignore or [])
    groups: dict[str, dict[str, Any]] = {}
    for it in items:
        if it.get("predicate") in ignore_set:
            continue
        g = groups.setdefault(group_id(it), {"entity": it.get("entity"), "predicate": it.get("predicate"), "values": {}, "evidence": [], "low": True})
        g["values"][value_digest(it)] = it.get("value")
        if it.get("evidence_id") and it["evidence_id"] not in g["evidence"]:
            g["evidence"].append(it["evidence_id"])
        if it.get("confidence") not in LOW:
            g["low"] = False
    return groups


def snapshot_hash(groups: dict[str, Any]) -> str:
    return _h({k: sorted(v["values"]) for k, v in sorted(groups.items())})


def compare(prev: dict[str, Any] | None, cur: dict[str, Any], *, partial: bool = False, ignore: list[str] | None = None) -> dict[str, Any]:
    if ignore:                                           # an ignore list applies to BOTH sides, so changing it never fakes a removal
        prev = {k: v for k, v in prev.items() if v["predicate"] not in ignore} if prev is not None else None
        cur = {k: v for k, v in cur.items() if v["predicate"] not in ignore}
    if prev is None:
        return {"baseline": True, "changed": False, "added": [], "removed": [], "changed_items": [], "uncertain": [], "added_count": 0, "removed_count": 0,
                "changed_count": 0, "count": 0, "note": "first run: this snapshot is now the baseline; nothing to compare with"}
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    uncertain: list[dict[str, Any]] = []

    def desc(g: dict[str, Any], vals: list[Any] | None = None) -> dict[str, Any]:
        return {"entity": g["entity"], "predicate": g["predicate"], "values": [v if isinstance(v, str | int | float | bool) or v is None else json.dumps(v, default=str)
                                                                          for v in (vals if vals is not None else list(g["values"].values()))][:10], "evidence": g["evidence"][:5]}
    for gid, g in cur.items():
        if gid not in prev:
            (uncertain if g["low"] else added).append(desc(g) | ({"why": "low-confidence source"} if g["low"] else {}))
        elif set(g["values"]) != set(prev[gid]["values"]):
            new_vals = [v for k, v in g["values"].items() if k not in prev[gid]["values"]]
            gone_vals = [v for k, v in prev[gid]["values"].items() if k not in g["values"]]
            item = desc(g, new_vals) | {"no_longer_observed": gone_vals[:10]}
            (uncertain if (g["low"] or partial) and gone_vals and not new_vals else changed).append(item)
    for gid, g in prev.items():
        if gid not in cur:
            item = desc(g)
            if partial:
                uncertain.append(item | {"why": "the dataset is partial (a source failed), so absence proves nothing"})
            else:
                removed.append(item)
    return {"baseline": False, "changed": bool(added or removed or changed), "added": added, "removed": removed, "changed_items": changed, "uncertain": uncertain,
            "added_count": len(added), "removed_count": len(removed), "changed_count": len(changed), "count": len(added) + len(removed) + len(changed),
            "note": "'removed' means no longer observed, not proven non-existent"}


def latest(db: Session, workflow_id: str, case_id: str | None, node_id: str) -> AutomationSnapshot | None:
    q = select(AutomationSnapshot).where(AutomationSnapshot.workflow_id == workflow_id, AutomationSnapshot.node_id == node_id)
    q = q.where(AutomationSnapshot.case_id == case_id) if case_id else q
    return db.scalars(q.order_by(AutomationSnapshot.taken_at.desc())).first()


SOURCES_KEY = "__sources__"


def save(db: Session, workflow_id: str, case_id: str | None, node_id: str, groups: dict[str, Any], run_id: str, sources: list[str] | None = None) -> AutomationSnapshot:
    s = AutomationSnapshot(workflow_id=workflow_id, case_id=case_id, node_id=node_id, content_hash=snapshot_hash(groups), items_json=groups | {SOURCES_KEY: sources or []},
                           source_run_id=run_id, taken_at=datetime.now(UTC))
    db.add(s)
    return s
