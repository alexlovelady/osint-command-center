"""Conversation persistence. Reads are defensive: a damaged row is skipped and counted, never a crash and never shown as if it were valid."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ..db.models import CopilotConversation, CopilotMessage

MODES = ("general", "investigation", "tutor")
ROLES = ("user", "assistant", "note")


def _now() -> datetime:
    return datetime.now(UTC)


def get_conversation(db: Session, user_id: str, case_id: str | None, conversation_id: str | None = None, create: bool = True) -> CopilotConversation | None:
    """The user's conversation for this investigation (or the general one when case_id is None). Per-investigation history lives here."""
    if conversation_id:
        c = db.get(CopilotConversation, conversation_id)
        if c and c.user_id == user_id:
            return c
        return None
    q = select(CopilotConversation).where(CopilotConversation.user_id == user_id, CopilotConversation.case_id.is_(None) if case_id is None else CopilotConversation.case_id == case_id)
    c = db.scalars(q.order_by(CopilotConversation.updated_at.desc()).limit(1)).first()
    if c or not create:
        return c
    c = CopilotConversation(user_id=user_id, case_id=case_id, mode="investigation" if case_id else "general")
    db.add(c)
    db.flush()
    return c


def new_conversation(db: Session, user_id: str, case_id: str | None, mode: str = "general") -> CopilotConversation:
    c = CopilotConversation(user_id=user_id, case_id=case_id, mode=mode if mode in MODES else "general")
    db.add(c)
    db.flush()
    return c


def add_message(db: Session, conv: CopilotConversation, role: str, content: str, mode: str, meta: dict[str, Any] | None = None) -> CopilotMessage:
    seq = (db.scalar(select(func.max(CopilotMessage.seq)).where(CopilotMessage.conversation_id == conv.id)) or 0) + 1
    m = CopilotMessage(conversation_id=conv.id, seq=seq, role=role, mode=mode if mode in MODES else "general", content=content, meta_json=meta or {})
    db.add(m)
    conv.updated_at = _now()
    conv.mode = m.mode
    if role == "user" and conv.title in ("New conversation", ""):
        conv.title = " ".join(content.split())[:80] or "New conversation"
    db.flush()
    return m


def load_messages(db: Session, conversation_id: str, limit: int | None = None) -> tuple[list[dict[str, Any]], int]:
    """Returns (valid messages oldest-first, number of damaged rows skipped). JSON columns are parsed by hand so invalid JSON cannot raise."""
    sql = "SELECT id, seq, role, mode, content, meta_json, created_at FROM copilot_messages WHERE conversation_id = :c ORDER BY seq"
    try:
        rows = list(db.execute(text(sql), {"c": conversation_id}))
    except Exception:
        return [], 1
    out: list[dict[str, Any]] = []
    skipped = 0
    for mid, seq, role, mode, content, meta_raw, created in rows:
        try:
            if role not in ROLES or not isinstance(content, str):
                raise ValueError("bad row")
            meta = json.loads(meta_raw) if isinstance(meta_raw, str) else (meta_raw or {})
            if not isinstance(meta, dict):
                raise TypeError("bad meta")
        except (ValueError, TypeError):
            skipped += 1
            continue
        out.append({"id": mid, "seq": seq, "role": role, "mode": mode if mode in MODES else "general", "content": content, "meta": meta, "created_at": str(created)})
    if limit:
        out = out[-limit:]
    return out, skipped


def conversation_dict(c: CopilotConversation) -> dict[str, Any]:
    return {"id": c.id, "case_id": c.case_id, "title": c.title, "mode": c.mode if c.mode in MODES else "general",
            "created_at": c.created_at.isoformat() if c.created_at else None, "updated_at": c.updated_at.isoformat() if c.updated_at else None}


def list_conversations(db: Session, user_id: str, case_id: str | None | bool = False) -> list[dict[str, Any]]:
    q = select(CopilotConversation).where(CopilotConversation.user_id == user_id)
    if case_id is not False:
        q = q.where(CopilotConversation.case_id.is_(None) if case_id is None else CopilotConversation.case_id == case_id)
    return [conversation_dict(c) for c in db.scalars(q.order_by(CopilotConversation.updated_at.desc()).limit(100))]
