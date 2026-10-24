"""Tamper-evident audit chain (spec 12.1). Metadata is redacted: secrets/long free text never stored."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import AuditEvent

GENESIS = "0" * 64
_SECRET_KEYS = ("token", "secret", "password", "api_key", "authorization")


def redact(meta: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (meta or {}).items():
        if any(s in k.lower() for s in _SECRET_KEYS):
            out[k] = "[redacted]"
        elif isinstance(v, str) and len(v) > 200:
            out[k] = v[:200] + "…"
        else:
            out[k] = v
    return out


def _hash(prev: str, seq: int, actor: str, action: str, case_id, rtype, rid, decision, meta, ts: str) -> str:
    body = json.dumps([prev, seq, actor, action, case_id, rtype, rid, decision, meta, ts], sort_keys=True,
                      separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def record(db: Session, action: str, *, actor: str = "local", case_id: str | None = None,
           resource_type: str | None = None, resource_id: str | None = None, decision: str = "allow",
           metadata: dict[str, Any] | None = None) -> AuditEvent:
    last = db.scalars(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)).first()
    seq = (last.seq + 1) if last else 1
    prev = last.event_hash if last else GENESIS
    now = datetime.now(UTC)
    meta = redact(metadata)
    ev = AuditEvent(seq=seq, actor_id=actor, case_id=case_id, action=action, resource_type=resource_type,
                    resource_id=resource_id, decision=decision, metadata_json=meta, ts=now, prev_hash=prev,
                    event_hash=_hash(prev, seq, actor, action, case_id, resource_type, resource_id, decision, meta,
                                     now.isoformat()))
    db.add(ev)
    db.flush()
    return ev


def verify_chain(db: Session) -> tuple[bool, int, int | None]:
    """Returns (ok, events_checked, first_bad_seq)."""
    prev, n = GENESIS, 0
    for ev in db.scalars(select(AuditEvent).order_by(AuditEvent.seq)):
        ts = ev.ts if ev.ts.tzinfo else ev.ts.replace(tzinfo=UTC)
        exp = _hash(prev, ev.seq, ev.actor_id, ev.action, ev.case_id, ev.resource_type, ev.resource_id,
                    ev.decision, ev.metadata_json, ts.isoformat())
        if ev.prev_hash != prev or ev.event_hash != exp:
            return False, n, ev.seq
        prev, n = ev.event_hash, n + 1
    return True, n, None


def count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(AuditEvent)) or 0
