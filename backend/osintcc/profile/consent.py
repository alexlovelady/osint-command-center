"""Verifiable, scoped, time-limited, revocable authorization for researching a person. Fail-closed.

A signed engagement is not authorization to test unrelated systems: infrastructure scope stays in `scope_authorizations` (policy engine) and is
checked independently. This module only answers: "may we research THIS subject, with THIS class of source, right now?"
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import Evidence, ResearchTask, Subject, SubjectConsent
from ..telemetry import audit
from .service import ProfileError

# What a source does, not how it is implemented.
SOURCE_CLASSES = ("public_passive", "public_site_query", "documents", "image_analysis", "reverse_image", "exposure_check", "professional_history")
SENSITIVE_CLASSES = {"exposure_check", "reverse_image"}
VERIFICATION_METHODS = ("self_attestation", "email_confirmation", "provider_verification", "signed_document", "in_person")
STRONG_METHODS = {"email_confirmation", "provider_verification", "signed_document", "in_person"}  # proof that someone other than the operator agreed
ORG_TYPES = ("organization", "domain", "business_record")
MAX_DURATION_DAYS = {"self": 365, "client": 180, "organization": 365}

# Called after a revocation or expiry sweep so dependents (scheduled workflows etc.) stop at once. Registered by other modules.
REVOKE_HOOKS: list[Callable[[Session, Subject, str], int]] = []


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    consent_id: str | None = None
    code: str = "ok"


def _aware(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=UTC)


def _now() -> datetime:
    return datetime.now(UTC)


def grant(db: Session, subject: Subject, *, verification_method: str, verifier: str, source_classes: list[str], permitted_purposes: list[str],
          expires_at: datetime, identifier_ids: list[str] | None = None, proof_evidence_id: str | None = None, retention_policy: dict | None = None,
          actor: str = "local") -> SubjectConsent:
    if verification_method not in VERIFICATION_METHODS:
        raise ProfileError("invalid_method", f"verification_method must be one of {', '.join(VERIFICATION_METHODS)}")
    bad = [c for c in source_classes if c not in SOURCE_CLASSES]
    if bad or not source_classes:
        raise ProfileError("invalid_source_classes", f"choose at least one of: {', '.join(SOURCE_CLASSES)}")
    if not verifier.strip():
        raise ProfileError("verifier_required", "record who verified this authorization")
    exp = _aware(expires_at)
    assert exp is not None
    if exp <= _now():
        raise ProfileError("expiry_in_past", "the authorization must expire in the future")
    if exp > _now() + timedelta(days=MAX_DURATION_DAYS[subject.mode]):
        raise ProfileError("duration_too_long", f"{subject.mode} authorizations are limited to {MAX_DURATION_DAYS[subject.mode]} days; renew instead")
    if proof_evidence_id:
        ev = db.get(Evidence, proof_evidence_id)
        if not ev or ev.case_id != subject.case_id:
            raise ProfileError("evidence_not_in_case", "proof evidence is not in this case")
    if subject.mode == "client":
        if verification_method == "self_attestation":
            raise ProfileError("proof_required", "client engagements need verifiable consent (signed document, email confirmation or in-person), not a self-attestation")
        if not proof_evidence_id:
            raise ProfileError("proof_required", "attach the consent proof (for example the signed engagement) as case evidence")
        if not permitted_purposes:
            raise ProfileError("purposes_required", "list the permitted purposes")
        if not identifier_ids:
            raise ProfileError("scope_required", "client consent must name the identities/assets it covers")
    if set(source_classes) & SENSITIVE_CLASSES and verification_method == "self_attestation":
        raise ProfileError("verification_too_weak", "sensitive checks (exposure, reverse image) need more than a self-attestation: email confirmation, "
                                                    "provider verification, a signed document or in-person verification")
    c = SubjectConsent(subject_id=subject.id, case_id=subject.case_id, mode=subject.mode, verification_method=verification_method,
                       verifier=verifier.strip()[:200], scope_json={"identifier_ids": identifier_ids or []}, source_classes=list(source_classes),
                       permitted_purposes=permitted_purposes, expires_at=exp, proof_evidence_id=proof_evidence_id,
                       retention_policy=retention_policy or {"days": subject.retention_days or 90}, created_by=actor)
    db.add(c)
    db.flush()
    audit.record(db, "consent.grant", actor=actor, case_id=subject.case_id, resource_type="subject_consent", resource_id=c.id,
                 metadata={"mode": subject.mode, "method": verification_method, "classes": source_classes})
    return c


def _consents(db: Session, subject: Subject) -> list[SubjectConsent]:
    return list(db.scalars(select(SubjectConsent).where(SubjectConsent.subject_id == subject.id).order_by(SubjectConsent.created_at.desc())))


def _state(c: SubjectConsent, now: datetime) -> str:
    if c.revoked_at is not None:
        return "revoked"
    exp = _aware(c.expires_at)
    if exp is not None and exp <= now:
        return "expired"
    if (_aware(c.obtained_at) or now) > now + timedelta(seconds=5):
        return "not_yet_valid"
    return "active"


def current_status(db: Session, subject: Subject, now: datetime | None = None) -> dict:
    now = now or _now()
    cs = _consents(db, subject)
    org_ok = subject.type in ORG_TYPES
    if not cs:
        return {"status": "not_required_for_public_org_sources" if org_ok else "none", "mode": subject.mode, "consent_id": None, "expires_at": None,
                "source_classes": [], "receipt": None,
                "message": "Public organisation sources need no personal consent; sensitive checks are unavailable." if org_ok
                else "No authorization on record: collection about this person is blocked until one is added."}
    live = [c for c in cs if _state(c, now) == "active"]
    pick = live[0] if live else cs[0]
    st = _state(pick, now)
    return {"status": st, "mode": pick.mode, "consent_id": pick.id, "expires_at": pick.expires_at, "revoked_at": pick.revoked_at,
            "source_classes": pick.source_classes, "verification_method": pick.verification_method, "verifier": pick.verifier,
            "purposes": pick.permitted_purposes, "has_proof": bool(pick.proof_evidence_id),
            "receipt": {"id": pick.id, "obtained_at": pick.obtained_at, "scope": pick.scope_json, "retention": pick.retention_policy},
            "message": {"active": "Authorization is current.", "expired": "Authorization expired: collection is blocked.",
                        "revoked": "Authorization was revoked: collection is blocked and pending work was cancelled.",
                        "not_yet_valid": "Authorization is not valid yet."}[st]}


def check(db: Session, subject: Subject, source_class: str, *, identifier_id: str | None = None, now: datetime | None = None) -> Decision:
    """Deterministic gate used by every research approval, scheduled job and enrichment step. Never overridden by AI or plugins."""
    now = now or _now()
    if source_class not in SOURCE_CLASSES:
        return Decision(False, f"unknown source class {source_class}", code="unknown_class")
    if subject.status != "active":
        return Decision(False, f"subject is {subject.status}", code="subject_inactive")
    if subject.type in ORG_TYPES and source_class in ("public_passive", "documents", "professional_history", "image_analysis"):
        return Decision(True, "public organisation source")  # still subject to scope, SSRF and approval checks elsewhere
    cs = _consents(db, subject)
    if not cs:
        return Decision(False, "no authorization on record for this subject", code="consent_required")
    states = {c.id: _state(c, now) for c in cs}
    live = [c for c in cs if states[c.id] == "active"]
    if not live:
        newest = states[cs[0].id]
        return Decision(False, f"authorization is {newest.replace('_', ' ')}", cs[0].id, code=f"consent_{newest}")
    for c in live:
        if source_class not in c.source_classes:
            continue
        ids = (c.scope_json or {}).get("identifier_ids") or []
        if ids and identifier_id and identifier_id not in ids:
            continue
        if source_class in SENSITIVE_CLASSES and c.verification_method == "self_attestation":
            continue
        if c.mode == "client" and (not c.proof_evidence_id or c.verification_method == "self_attestation"):
            continue
        return Decision(True, "authorized", c.id)
    return Decision(False, f"no live authorization covers '{source_class}'" + (" for this identifier" if identifier_id else ""), live[0].id, code="out_of_scope")


def require(db: Session, subject: Subject, source_class: str, *, identifier_id: str | None = None) -> Decision:
    d = check(db, subject, source_class, identifier_id=identifier_id)
    if not d.allowed:
        raise ProfileError(d.code, d.reason)
    return d


def revoke(db: Session, subject: Subject, consent_id: str, *, reason: str, actor: str = "local") -> dict:
    c = db.get(SubjectConsent, consent_id)
    if not c or c.subject_id != subject.id:
        raise ProfileError("not_found", "authorization not found")
    if c.revoked_at is None:
        c.revoked_at, c.revoked_reason = _now(), reason.strip()[:1000]
    audit.record(db, "consent.revoke", actor=actor, case_id=subject.case_id, resource_type="subject_consent", resource_id=c.id)
    return {"cancelled_tasks": stop_dependents(db, subject, "consent revoked"), "consent_id": c.id}


def stop_dependents(db: Session, subject: Subject, why: str) -> int:
    """Cancel everything that has not finished, and every hook-registered dependent (scheduled workflows). Idempotent."""
    n = 0
    for t in db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id, ResearchTask.status.in_(("planned", "approved", "running")))):
        t.status, t.limitations = "cancelled", why
        n += 1
    for hook in REVOKE_HOOKS:
        n += hook(db, subject, why)
    return n


def sweep_expired(db: Session, now: datetime | None = None) -> int:
    """Called by the scheduler tick: any subject whose only consents have lapsed has its pending work cancelled."""
    now = now or _now()
    n = 0
    for s in db.scalars(select(Subject).where(Subject.status == "active")):
        cs = _consents(db, s)
        if cs and not any(_state(c, now) == "active" for c in cs):
            n += stop_dependents(db, s, "authorization expired or revoked")
    return n
