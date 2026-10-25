"""Remediation tasks, subject correction requests, and retention (purge preview, purge). Everything is attributable and audited."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    Evidence,
    ExposureIndicator,
    ImageAsset,
    ImageMatch,
    ProfileCandidateLink,
    ProfileClaim,
    ProfileReviewEvent,
    RemediationTask,
    ResearchTask,
    RetentionAction,
    Subject,
    SubjectConsent,
    SubjectCorrection,
    SubjectIdentifier,
)
from ..telemetry import audit
from . import candidates, consent, service
from .exposure import CLASSES
from .service import ProfileError

PRIORITIES = ("low", "medium", "high")
STATES = ("open", "in_progress", "resolved", "wont_fix")
CORRECTION_TARGETS = ("claim", "candidate", "exposure", "image_match", "identifier", "other")


def _now() -> datetime:
    return datetime.now(UTC)


# ---- remediation ---------------------------------------------------------------------------------------------------------------------------
def create_remediation(db: Session, subject: Subject, *, issue: str, priority: str, guidance: str, owner: str | None, due_in_days: int | None,
                       indicator_id: str | None, actor: str) -> RemediationTask:
    if priority not in PRIORITIES:
        raise ProfileError("invalid_priority", "priority must be low, medium or high")
    if not issue.strip():
        raise ProfileError("issue_required", "describe the issue")
    if indicator_id:
        x = db.get(ExposureIndicator, indicator_id)
        if not x or x.subject_id != subject.id:
            raise ProfileError("not_found", "exposure indicator not found")
        if not guidance.strip():
            guidance = " ".join(f"{i + 1}. {g}" for i, g in enumerate(CLASSES.get(x.cls, {}).get("guidance", [])))
        if x.remediation_state in ("not_applicable", "resolved"):
            x.remediation_state = "open"
    due = _now() + timedelta(days=due_in_days) if due_in_days else None
    t = RemediationTask(subject_id=subject.id, case_id=subject.case_id, indicator_id=indicator_id, issue=issue.strip()[:2000], priority=priority, guidance=guidance.strip()[:4000],
                        owner=owner or actor, due_at=due, recheck_at=due)
    db.add(t)
    db.flush()
    audit.record(db, "remediation.create", actor=actor, case_id=subject.case_id, resource_type="remediation_task", resource_id=t.id)
    return t


def update_remediation(db: Session, subject: Subject, task_id: str, *, state: str | None, resolution_evidence_id: str | None, owner: str | None,
                       recheck_in_days: int | None, actor: str) -> RemediationTask:
    t = db.get(RemediationTask, task_id)
    if not t or t.subject_id != subject.id:
        raise ProfileError("not_found", "remediation task not found")
    if state is not None:
        if state not in STATES:
            raise ProfileError("invalid_state", f"state must be one of {', '.join(STATES)}")
        if state == "resolved":
            ev = db.get(Evidence, resolution_evidence_id) if resolution_evidence_id else None
            if ev is None or ev.case_id != subject.case_id:
                raise ProfileError("resolution_evidence_required", "attach case evidence of the fix or of the retest before marking a task resolved")
            t.resolution_evidence_id = ev.id
        t.state = state
        if t.indicator_id and (x := db.get(ExposureIndicator, t.indicator_id)):
            x.remediation_state = {"open": "open", "in_progress": "in_progress", "resolved": "resolved", "wont_fix": "accepted_risk"}[state]
    if owner is not None:
        t.owner = owner
    if recheck_in_days is not None:
        t.recheck_at = _now() + timedelta(days=recheck_in_days)
    t.updated_at = _now()
    audit.record(db, "remediation.update", actor=actor, case_id=subject.case_id, resource_type="remediation_task", resource_id=t.id, metadata={"state": t.state})
    return t


def remediation_dict(t: RemediationTask) -> dict[str, Any]:
    now = _now()
    rc = t.recheck_at if t.recheck_at is None or t.recheck_at.tzinfo else t.recheck_at.replace(tzinfo=UTC)
    return {"id": t.id, "issue": t.issue, "priority": t.priority, "guidance": t.guidance, "owner": t.owner, "state": t.state, "due_at": t.due_at, "recheck_at": t.recheck_at,
            "recheck_due": bool(rc and rc <= now and t.state != "resolved"), "indicator_id": t.indicator_id, "resolution_evidence_id": t.resolution_evidence_id, "created_at": t.created_at}


# ---- corrections ---------------------------------------------------------------------------------------------------------------------------
def request_correction(db: Session, subject: Subject, *, target_type: str, target_id: str | None, request_text: str, justification: str, requested_by: str, actor: str) -> SubjectCorrection:
    if target_type not in CORRECTION_TARGETS:
        raise ProfileError("invalid_target", f"target_type must be one of {', '.join(CORRECTION_TARGETS)}")
    if not request_text.strip():
        raise ProfileError("request_required", "say what should be corrected")
    ev = audit.record(db, "correction.request", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id, metadata={"target_type": target_type})
    c = SubjectCorrection(subject_id=subject.id, case_id=subject.case_id, target_type=target_type, target_id=target_id, request_text=request_text.strip()[:4000],
                          justification=justification.strip()[:4000], requested_by=requested_by.strip()[:200] or "subject", audit_seq=ev.seq)
    db.add(c)
    db.flush()
    return c


def resolve_correction(db: Session, subject: Subject, correction_id: str, *, decision: str, resolution: str, actor: str) -> SubjectCorrection:
    c = db.get(SubjectCorrection, correction_id)
    if not c or c.subject_id != subject.id:
        raise ProfileError("not_found", "correction request not found")
    if decision not in ("accepted", "declined", "applied"):
        raise ProfileError("invalid_decision", "decision must be accepted, declined or applied")
    if not resolution.strip():
        raise ProfileError("resolution_required", "record why")
    if decision == "applied":
        _apply(db, subject, c, actor)
    c.status, c.resolution = decision, resolution.strip()[:4000]
    ev = audit.record(db, f"correction.{decision}", actor=actor, case_id=subject.case_id, resource_type="subject_correction", resource_id=c.id)
    c.audit_seq = ev.seq
    return c


def _apply(db: Session, subject: Subject, c: SubjectCorrection, actor: str) -> None:
    """Applying a correction changes only the disputed record, through the same attributable paths a reviewer would use."""
    if c.target_type == "claim" and c.target_id:
        service.review_claim(db, subject, c.target_id, to_state="conflicting", reviewer=actor, basis=f"subject correction request {c.id}: {c.request_text[:200]}")
    elif c.target_type == "candidate" and c.target_id:
        candidates.review(db, subject, [c.target_id], to_state="rejected", reviewer=actor, basis=f"subject correction request {c.id}: not the subject's account")
    elif c.target_type == "identifier" and c.target_id:
        service.remove_identifier(db, subject, c.target_id, actor)
    elif c.target_type == "image_match" and c.target_id:
        m = db.get(ImageMatch, c.target_id)
        if m and m.subject_id == subject.id:
            m.review_state, m.reviewer, m.note = "rejected", actor, f"subject correction request {c.id}"
    else:
        raise ProfileError("cannot_apply", "this kind of correction is recorded and resolved by hand; use 'accepted' and make the change yourself")


def correction_dict(c: SubjectCorrection) -> dict[str, Any]:
    return {"id": c.id, "target_type": c.target_type, "target_id": c.target_id, "request": c.request_text, "justification": c.justification, "requested_by": c.requested_by,
            "status": c.status, "resolution": c.resolution, "event_time": c.event_time, "audit_seq": c.audit_seq}


# ---- retention ---------------------------------------------------------------------------------------------------------------------------
def _counts(db: Session, subject: Subject) -> dict[str, int]:
    out = {}
    for name, model in (("identifiers", SubjectIdentifier), ("claims", ProfileClaim), ("candidate_accounts", ProfileCandidateLink), ("review_events", ProfileReviewEvent),
                        ("authorizations", SubjectConsent), ("research_tasks", ResearchTask), ("images", ImageAsset), ("image_matches", ImageMatch),
                        ("exposure_indicators", ExposureIndicator), ("remediation_tasks", RemediationTask), ("correction_requests", SubjectCorrection)):
        out[name] = db.scalar(select(func.count()).select_from(model).where(model.subject_id == subject.id)) or 0
    return out


def _evidence_ids(db: Session, subject: Subject) -> set[str]:
    ids = {a.evidence_id for a in db.scalars(select(ImageAsset).where(ImageAsset.subject_id == subject.id))}
    ids |= {c.proof_evidence_id for c in db.scalars(select(SubjectConsent).where(SubjectConsent.subject_id == subject.id)) if c.proof_evidence_id}
    ids |= {x.evidence_id for x in db.scalars(select(ExposureIndicator).where(ExposureIndicator.subject_id == subject.id)) if x.evidence_id}
    return ids


def purge_preview(db: Session, subject: Subject, actor: str) -> dict[str, Any]:
    ev_ids = _evidence_ids(db, subject)
    ev = [db.get(Evidence, i) for i in ev_ids]
    other_case_refs = 0
    out = {"subject": subject.display_name, "will_delete": _counts(db, subject), "evidence_objects_redacted": len([e for e in ev if e]), "evidence_shared_elsewhere": other_case_refs,
           "kept": ["The tamper-evident audit log (it never contains identifier values) and a record that this purge happened.",
                    "Case evidence you imported yourself, which the case still owns; delete it from the Evidence tab if needed.",
                    "Encrypted backups made earlier: they still contain this subject until you delete them."],
           "irreversible": True,
           "confirm_with": f"PURGE {subject.display_name}",
           "note": "SSD wear-levelling means deletion is not guaranteed secure erasure; use full-disk encryption."}
    db.add(RetentionAction(subject_id=subject.id, case_id=subject.case_id, action="purge_preview", summary_json={"counts": out["will_delete"]}, performed_by=actor))
    audit.record(db, "retention.purge_preview", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id)
    return out


def purge(db: Session, vault_root: Any, subject: Subject, confirm: str, actor: str) -> dict[str, Any]:
    """Deletes the profile records of one subject, stops dependent work, redacts and removes the evidence objects only this subject referenced."""
    if confirm != f"PURGE {subject.display_name}":
        raise ProfileError("confirmation_required", f'type "PURGE {subject.display_name}" to confirm')
    consent.stop_dependents(db, subject, "subject purged")
    counts = _counts(db, subject)
    ev_ids = _evidence_ids(db, subject)
    removed_objects = 0
    redacted = 0
    for eid in ev_ids:
        ev = db.get(Evidence, eid)
        if not ev:
            continue
        still_used = db.scalar(select(func.count()).select_from(ImageAsset).where(ImageAsset.evidence_id == eid, ImageAsset.subject_id != subject.id)) or 0
        still_used += db.scalar(select(func.count()).select_from(SubjectConsent).where(SubjectConsent.proof_evidence_id == eid, SubjectConsent.subject_id != subject.id)) or 0
        if still_used:
            continue
        rel, sha = ev.vault_relpath, ev.sha256
        same_object = db.scalar(select(func.count()).select_from(Evidence).where(Evidence.sha256 == sha, Evidence.id != eid, Evidence.vault_relpath.is_not(None))) or 0
        ev.title, ev.description, ev.redacted, ev.original_url = "[purged]", "Content removed by a subject purge; hashes retained for chain of custody.", True, None
        redacted += 1
        if rel and not same_object:
            p = vault_root / rel
            if p.is_file():
                p.unlink()
                removed_objects += 1
            ev.vault_relpath = None
    sid, name = subject.id, subject.display_name
    # children go with the subject (cascade); the subject row stays as a tombstone so the audit trail still points at something
    for model in (SubjectIdentifier, ProfileClaim, ProfileCandidateLink, ProfileReviewEvent, SubjectConsent, ResearchTask, ImageMatch, ImageAsset, RemediationTask, ExposureIndicator, SubjectCorrection):
        for row in db.scalars(select(model).where(model.subject_id == sid)):
            db.delete(row)
        db.flush()
    subject.display_name, subject.purpose, subject.status = "[purged]", "", "purged"
    ev_row = audit.record(db, "retention.purge", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=sid, metadata={"deleted": counts})
    db.add(RetentionAction(subject_id=sid, case_id=subject.case_id, action="purge", summary_json={"deleted": counts, "evidence_redacted": redacted, "vault_objects_removed": removed_objects},
                           performed_by=actor, audit_seq=ev_row.seq))
    del name
    return {"purged": counts, "evidence_redacted": redacted, "vault_objects_removed": removed_objects}


def due_for_expiry(db: Session, now: datetime | None = None) -> list[dict[str, Any]]:
    """Subjects past their retention period. Nothing is deleted automatically; the list is shown to the owner."""
    now = now or _now()
    out = []
    for s in db.scalars(select(Subject).where(Subject.retention_days.is_not(None), Subject.status != "purged")):
        created = s.created_at if s.created_at.tzinfo else s.created_at.replace(tzinfo=UTC)
        if created + timedelta(days=s.retention_days or 0) <= now:
            out.append({"subject_id": s.id, "case_id": s.case_id, "retention_days": s.retention_days})
    return out
