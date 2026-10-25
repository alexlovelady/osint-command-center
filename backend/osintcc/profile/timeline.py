"""Dated timeline for a subject, assembled only from stored records (each entry names its basis and links to evidence)."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    ExposureIndicator,
    ImageMatch,
    ProfileCandidateLink,
    ProfileClaim,
    ProfileReviewEvent,
    RemediationTask,
    ResearchTask,
    Subject,
    SubjectConsent,
)


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def build(db: Session, subject: Subject, *, include_restricted: bool = True) -> list[dict]:
    ev: list[dict] = []

    def add(at: datetime | None, kind: str, text: str, basis: str, evidence_ids: list[str] | None = None, **extra) -> None:
        if at is not None:
            ev.append({"at": _aware(at), "kind": kind, "text": text, "basis": basis, "evidence_ids": evidence_ids or [], **extra})

    add(subject.created_at, "subject", "Subject created", "recorded")
    for c in db.scalars(select(SubjectConsent).where(SubjectConsent.subject_id == subject.id)):
        add(c.obtained_at, "authorization", f"Authorization recorded ({c.verification_method}); expires {c.expires_at:%Y-%m-%d}", "recorded", id=c.id)
        if c.revoked_at:
            add(c.revoked_at, "authorization", "Authorization revoked", "recorded", id=c.id)
    for k in db.scalars(select(ProfileCandidateLink).where(ProfileCandidateLink.subject_id == subject.id)):
        add(k.first_seen_at, "candidate", f"Candidate account first seen ({k.site or 'unknown site'})", "observed", k.evidence_ids, id=k.id, url=k.canonical_url)
    for e in db.scalars(select(ProfileReviewEvent).where(ProfileReviewEvent.subject_id == subject.id)):
        add(e.created_at, "review", f"{e.target_type} {e.from_state} → {e.to_state} by {e.reviewer}", "decision", e.evidence_ids, id=e.id)
    for cl in db.scalars(select(ProfileClaim).where(ProfileClaim.subject_id == subject.id)):
        if cl.sensitivity == "RESTRICTED" and not include_restricted:
            continue
        add(cl.observed_from or cl.created_at, "claim", f"{cl.field}: {cl.validation_state.replace('_', '-')}", "published/observed" if cl.observed_from else "recorded",
            cl.evidence_ids, id=cl.id)
    for t in db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id)):
        add(t.last_attempt, "research", f"{t.source_id}: {t.status}", "run", id=t.id)
    for m in db.scalars(select(ImageMatch).where(ImageMatch.subject_id == subject.id)):
        add(m.observed_at, "image", f"Image {m.match_type.replace('_', ' ')} ({m.review_state})", "observed", m.evidence_ids, id=m.id)
    for x in db.scalars(select(ExposureIndicator).where(ExposureIndicator.subject_id == subject.id)):
        add(x.exposure_date or x.last_checked, "exposure", f"{x.cls}: {x.status.replace('_', ' ')} ({x.provider})", "provider", id=x.id)
    for r in db.scalars(select(RemediationTask).where(RemediationTask.subject_id == subject.id)):
        add(r.created_at, "remediation", f"Remediation: {r.issue[:80]} ({r.state})", "recorded", id=r.id)
    ev.sort(key=lambda e: e["at"])
    return ev
