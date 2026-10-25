"""Glue between subject authorization and the other engines (job runner, automations). Imported for its side effect of registering the revoke hook."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AutomationWorkflow, Subject
from . import consent
from .registry import SOURCES

TAG_PREFIX = "subject:"


def bound_subject_id(wf: AutomationWorkflow) -> str | None:
    for t in (wf.draft_json or {}).get("tags", []):
        if isinstance(t, str) and t.startswith(TAG_PREFIX):
            return t[len(TAG_PREFIX):]
    return None


def deactivate_bound_workflows(db: Session, subject: Subject, why: str) -> int:
    from ..automations import service as auto
    n = 0
    for wf in db.scalars(select(AutomationWorkflow).where(AutomationWorkflow.case_id == subject.case_id, AutomationWorkflow.deleted_at.is_(None))):
        if bound_subject_id(wf) == subject.id and (wf.state == "active" or wf.active_version_id):
            auto.deactivate(db, wf, by="authorization", reason=why)
            n += 1
    return n


def workflow_gate(db: Session, wf: AutomationWorkflow, now: datetime | None = None) -> None:
    """Raises NodeError when a workflow bound to a subject would run without live authorization for every source class it uses."""
    sid = bound_subject_id(wf)
    if sid is None:
        return
    from ..automations.registry import NodeError
    subject = db.get(Subject, sid)
    if subject is None:
        raise NodeError("SCOPE_DENIED", "the subject this automation is bound to no longer exists")
    adapters = {n.get("config", {}).get("adapter") for n in (wf.draft_json or {}).get("nodes", []) if n.get("type") in ("adapter_query", "enrich")}
    classes = {SOURCES[a].source_class for a in adapters if a in SOURCES} or {"public_passive"}
    for cls in sorted(classes):
        d = consent.check(db, subject, cls, now=now)
        if not d.allowed:
            raise NodeError("SCOPE_DENIED", f"subject authorization: {d.reason}")


consent.REVOKE_HOOKS.append(deactivate_bound_workflows)
