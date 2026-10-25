"""Subjects, identifiers and claims. Everything is case-scoped; every state change is attributable and audited."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    Case,
    Evidence,
    ExposureIndicator,
    ImageMatch,
    ProfileClaim,
    ProfileReviewEvent,
    RemediationTask,
    Subject,
    SubjectIdentifier,
    Target,
)
from ..db.models.profile import CLAIM_STATES, SUBJECT_MODES, SUBJECT_TYPES
from ..telemetry import audit
from .normalize import IdentifierError, identifier_hash, mask_value, normalize_identifier

PERSON_CATEGORIES = ("people",)
CLAIM_FIELDS = ("name", "alias", "handle", "professional_contact", "employer", "role", "education", "business_association",
                "owned_domain", "document", "publication", "location_public", "other")
SENSITIVE_FIELDS = {"location_public"}
LABELS = {"verified": "verified", "subject_confirmed": "subject-confirmed", "candidate": "candidate", "conflicting": "conflicting",
          "rejected": "rejected", "not_assessed": "not assessed"}
# profile sections shown on the Target Profile page, in order
SECTIONS = [
    ("identity", "Identity and aliases", ("name", "alias")),
    ("handles", "Public handles", ("handle",)),
    ("contact", "Verified public professional contact", ("professional_contact",)),
    ("work", "Work and education", ("employer", "role", "education")),
    ("business", "Public business associations", ("business_association",)),
    ("domains", "Owned domains", ("owned_domain",)),
    ("documents", "Documents and publications", ("document", "publication")),
    ("location", "Public locations (coarse unless owner-approved)", ("location_public",)),
    ("other", "Other", ("other",)),
]


class ProfileError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def _now() -> datetime:
    return datetime.now(UTC)


def create_subject(db: Session, case: Case, *, display_name: str, type: str = "person", mode: str = "self", purpose: str = "",
                   owner: str | None = None, actor: str = "local", retention_days: int | None = None) -> Subject:
    if type not in SUBJECT_TYPES:
        raise ProfileError("invalid_subject_type", f"type must be one of {', '.join(SUBJECT_TYPES)}")
    if mode not in SUBJECT_MODES:
        raise ProfileError("invalid_mode", f"mode must be one of {', '.join(SUBJECT_MODES)}")
    name = " ".join(display_name.split())
    if not name:
        raise ProfileError("invalid_name", "a display label is required (it can be an alias)")
    purpose = (purpose or case.purpose).strip()
    if type == "person" and not purpose:
        raise ProfileError("purpose_required", "A documented purpose is required for a person subject.")
    s = Subject(case_id=case.id, type=type, display_name=name[:300], mode=mode, purpose=purpose, owner=owner or actor,
                retention_days=retention_days, sensitivity="RESTRICTED" if type == "person" else "INTERNAL")
    db.add(s)
    db.flush()
    audit.record(db, "subject.create", actor=actor, case_id=case.id, resource_type="subject", resource_id=s.id,
                 metadata={"type": type, "mode": mode})
    return s


def ensure_subject_for_case(db: Session, case: Case, actor: str = "local") -> Subject | None:
    """Lazy, idempotent upgrade of an existing person case: one subject from the case, identifiers from its targets.
    Existing rows are only read; nothing in the old tables changes."""
    existing = db.scalars(select(Subject).where(Subject.case_id == case.id).order_by(Subject.created_at)).first()
    if existing or case.category not in PERSON_CATEGORIES:
        return existing
    s = create_subject(db, case, display_name=case.title, type="person", mode="self", purpose=case.purpose, owner=case.owner_id, actor=actor)
    for t in db.scalars(select(Target).where(Target.case_id == case.id)):
        kind = {"username": "username", "email": "email", "domain": "domain", "url": "url"}.get(t.type)
        if kind:
            try:
                add_identifier(db, s, kind, t.canonical_value, actor=actor, quiet=True)
            except ProfileError:
                continue
    audit.record(db, "subject.upgrade_from_case", actor=actor, case_id=case.id, resource_type="subject", resource_id=s.id)
    return s


def add_identifier(db: Session, subject: Subject, kind: str, value: str, *, actor: str = "local", source_evidence_id: str | None = None,
                   quiet: bool = False) -> SubjectIdentifier:
    try:
        norm = normalize_identifier(kind, value)
    except IdentifierError as exc:
        raise ProfileError("invalid_identifier", str(exc)) from exc
    h = identifier_hash(kind, norm)
    cur = db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.kind == kind,
                                                     SubjectIdentifier.value_hash == h)).first()
    if cur:
        if cur.status == "removed":
            cur.status = "active"
        return cur
    if source_evidence_id:
        _check_evidence(db, subject, [source_evidence_id])
    ident = SubjectIdentifier(subject_id=subject.id, case_id=subject.case_id, kind=kind, value=norm, value_hash=h,
                              source_evidence_id=source_evidence_id)
    db.add(ident)
    db.flush()
    if not quiet:  # identifier values are never written to the audit log; only the kind and an opaque id
        audit.record(db, "subject.identifier_add", actor=actor, case_id=subject.case_id, resource_type="subject_identifier",
                     resource_id=ident.id, metadata={"kind": kind})
    return ident


def remove_identifier(db: Session, subject: Subject, identifier_id: str, actor: str = "local") -> None:
    ident = db.get(SubjectIdentifier, identifier_id)
    if not ident or ident.subject_id != subject.id:
        raise ProfileError("not_found", "identifier not found")
    ident.status = "removed"
    audit.record(db, "subject.identifier_remove", actor=actor, case_id=subject.case_id, resource_type="subject_identifier", resource_id=ident.id)


def _check_evidence(db: Session, subject: Subject, ids: list[str]) -> list[str]:
    out = []
    for eid in dict.fromkeys(ids):
        ev = db.get(Evidence, eid)
        if not ev or ev.case_id != subject.case_id:
            raise ProfileError("evidence_not_in_case", f"evidence {eid} is not in this case")
        out.append(eid)
    return out


def add_claim(db: Session, subject: Subject, *, field: str, value: Any, evidence_ids: list[str] | None = None,
              assertion_source: str = "analyst", state: str = "candidate", actor: str = "local", sensitivity: str = "INTERNAL",
              observed_from: datetime | None = None, observed_to: datetime | None = None) -> ProfileClaim:
    if field not in CLAIM_FIELDS:
        raise ProfileError("invalid_field", f"field must be one of {', '.join(CLAIM_FIELDS)}")
    if state not in ("candidate", "not_assessed"):
        raise ProfileError("invalid_state", "a new claim starts as candidate or not assessed; only a review can verify it")
    if not isinstance(value, dict | str) or (isinstance(value, str) and not value.strip()):
        raise ProfileError("invalid_value", "value must be text or an object")
    struct = value if isinstance(value, dict) else {"text": value.strip()[:2000]}
    ev = _check_evidence(db, subject, evidence_ids or [])
    c = ProfileClaim(subject_id=subject.id, case_id=subject.case_id, field=field, structured_value=struct, evidence_ids=ev,
                     assertion_source=assertion_source, validation_state=state, observed_from=observed_from, observed_to=observed_to,
                     sensitivity="RESTRICTED" if field in SENSITIVE_FIELDS else sensitivity)
    db.add(c)
    db.flush()
    audit.record(db, "profile.claim_add", actor=actor, case_id=subject.case_id, resource_type="profile_claim", resource_id=c.id,
                 metadata={"field": field})
    return c


def review_claim(db: Session, subject: Subject, claim_id: str, *, to_state: str, reviewer: str, basis: str,
                 evidence_ids: list[str] | None = None, attestation: str = "none", bulk_id: str | None = None) -> ProfileClaim:
    """Only a person calls this (there is no code path from the model or a workflow). A verified claim needs evidence."""
    c = db.get(ProfileClaim, claim_id)
    if not c or c.subject_id != subject.id:
        raise ProfileError("not_found", "claim not found")
    if to_state not in CLAIM_STATES:
        raise ProfileError("invalid_state", f"state must be one of {', '.join(CLAIM_STATES)}")
    if not basis.strip():
        raise ProfileError("basis_required", "state the method or reason for this decision")
    ev = list(dict.fromkeys([*c.evidence_ids, *_check_evidence(db, subject, evidence_ids or [])]))
    if to_state in ("verified", "subject_confirmed") and not ev:
        raise ProfileError("evidence_required", "a claim cannot be verified without supporting evidence")
    if to_state == "subject_confirmed" and attestation != "subject":
        raise ProfileError("attestation_required", "subject-confirmed needs a subject attestation (who, how, when) in the basis")
    prev = c.validation_state
    now = _now()
    c.validation_state, c.reviewer, c.reviewed_at, c.reason, c.evidence_ids, c.updated_at = to_state, reviewer, now, basis.strip(), ev, now
    db.add(ProfileReviewEvent(subject_id=subject.id, case_id=subject.case_id, target_type="claim", target_id=c.id, from_state=prev,
                              to_state=to_state, reviewer=reviewer, basis=basis.strip(), attestation=attestation, evidence_ids=ev, bulk_id=bulk_id))
    audit.record(db, "profile.claim_review", actor=reviewer, case_id=subject.case_id, resource_type="profile_claim", resource_id=c.id,
                 metadata={"from": prev, "to": to_state})
    return c


def evidence_refs(db: Session, ids: list[str]) -> list[dict]:
    out = []
    for eid in ids:
        ev = db.get(Evidence, eid)
        if ev:
            out.append({"id": ev.id, "title": ev.title, "kind": ev.kind, "sha256": ev.sha256, "url": ev.original_url,
                        "retrieved_at": ev.retrieved_at})
    return out


def claim_dict(db: Session, c: ProfileClaim) -> dict:
    return {"id": c.id, "field": c.field, "value": c.structured_value, "state": c.validation_state, "state_label": LABELS[c.validation_state],
            "sensitivity": c.sensitivity, "assertion_source": c.assertion_source, "reviewer": c.reviewer, "reviewed_at": c.reviewed_at,
            "reason": c.reason, "observed_from": c.observed_from, "observed_to": c.observed_to,
            "evidence": evidence_refs(db, c.evidence_ids), "created_at": c.created_at}


def identifier_dict(i: SubjectIdentifier, *, mask: bool) -> dict:
    return {"id": i.id, "kind": i.kind, "value": mask_value(i.kind, i.value) if mask else i.value, "masked": mask, "status": i.status,
            "recorded_at": i.recorded_at}


def subject_dict(s: Subject) -> dict:
    return {"id": s.id, "case_id": s.case_id, "type": s.type, "display_name": s.display_name, "mode": s.mode, "purpose": s.purpose,
            "status": s.status, "owner": s.owner, "sensitivity": s.sensitivity, "retention_days": s.retention_days,
            "created_at": s.created_at, "updated_at": s.updated_at}


def build_profile(db: Session, subject: Subject, *, role: str) -> dict:
    """The Target Profile document. Viewers see masked identifiers and no restricted claims; editors/owners see full values."""
    from . import candidates, consent  # local imports: they depend on this module
    mask = role == "viewer"
    idents = [i for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id).order_by(SubjectIdentifier.recorded_at))
              if i.status == "active"]
    claims = list(db.scalars(select(ProfileClaim).where(ProfileClaim.subject_id == subject.id).order_by(ProfileClaim.created_at)))
    if mask:
        claims = [c for c in claims if c.sensitivity != "RESTRICTED"]
    by_field: dict[str, list[dict]] = {}
    for c in claims:
        by_field.setdefault(c.field, []).append(claim_dict(db, c))
    cands = candidates.list_candidates(db, subject)
    sections = []
    for key, title, fields in SECTIONS:
        items = [it for f in fields for it in by_field.get(f, [])]
        extra: list[dict] = []
        if key == "identity":
            extra = [identifier_dict(i, mask=mask) for i in idents if i.kind in ("name", "alias")]
        if key == "handles":
            extra = [identifier_dict(i, mask=mask) for i in idents if i.kind == "username"]
            items += [{"id": c["id"], "field": "handle", "value": {"url": c["canonical_url"], "site": c["site"]}, "state": "verified",
                       "state_label": "verified (owner confirmed)", "evidence": c["evidence"], "from": "candidate_queue"}
                      for c in cands if c["state"] == "confirmed"]
        if key == "domains":
            extra = [identifier_dict(i, mask=mask) for i in idents if i.kind == "domain"]
        sections.append({"key": key, "title": title, "identifiers": extra, "claims": items,
                         "state_note": "" if items or extra else "Not assessed. No claim recorded; this does not mean the information does not exist."})
    expos = [{"id": e.id, "class": e.cls, "provider": e.provider, "status": e.status, "risk": e.risk, "descriptor": e.masked_descriptor,
              "last_checked": e.last_checked, "remediation_state": e.remediation_state}
             for e in db.scalars(select(ExposureIndicator).where(ExposureIndicator.subject_id == subject.id))]
    rem = [{"id": r.id, "issue": r.issue, "priority": r.priority, "state": r.state, "due_at": r.due_at, "guidance": r.guidance}
           for r in db.scalars(select(RemediationTask).where(RemediationTask.subject_id == subject.id))]
    images = db.scalars(select(ImageMatch).where(ImageMatch.subject_id == subject.id)).all()
    case = db.get(Case, subject.case_id)
    assert case is not None
    return {
        "subject": subject_dict(subject), "case": {"id": case.id, "title": case.title, "category": case.category},
        "authorization": consent.current_status(db, subject), "sections": sections, "identifiers": [identifier_dict(i, mask=mask) for i in idents],
        "unresolved_leads": [c for c in cands if c["state"] in ("candidate", "unsure")],
        "image_matches": {"total": len(images), "unreviewed": sum(1 for m in images if m.review_state == "candidate")},
        "exposure": expos if not mask else [{**e, "descriptor": ""} for e in expos], "remediation": rem,
        "risk_summary": _risk_summary(expos), "role": role,
        "counts": {"identifiers": len(idents), "claims": len(claims), "candidates": len(cands),
                   "verified": sum(1 for c in claims if c.validation_state in ("verified", "subject_confirmed"))},
        "notice": "Findings are leads, not facts. Absent results are never proof that information does not exist.",
    }


def _risk_summary(expos: list[dict]) -> dict:
    order = ["unknown", "low", "medium", "high", "critical"]
    confirmed = [e for e in expos if e["status"] == "confirmed_exposure"]
    top = max((e["risk"] for e in confirmed), key=order.index, default="none")
    return {"confirmed_exposures": len(confirmed), "highest_risk": top, "not_assessed": sum(1 for e in expos if e["status"] == "not_assessed")}
