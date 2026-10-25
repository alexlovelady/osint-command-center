"""Target profile API (addendum TP-1.0 section 9): subjects, identifiers, claims, candidate review, consent, coverage, timeline.

Conventions match the rest of /api/v1: case-membership roles (non-members get 404), the common error envelope, audit on every sensitive read/write.
Every mutation re-checks role and (for collection) live consent server-side; nothing here trusts the UI.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...db.models import Case, CaseMember, Subject, SubjectIdentifier
from ...main import ApiError
from ...profile import candidates, consent, service, timeline
from ...profile.service import ProfileError
from ...telemetry import audit
from .routes import ROLE_RANK, S, actor, case_for

router: APIRouter = APIRouter()


def subject_for(db, request: Request, subject_id: str, need: str = "viewer") -> tuple[Subject, Case, str]:
    s = db.get(Subject, subject_id)
    if not s:
        raise ApiError(404, "not_found", "subject not found")
    case = case_for(db, request, s.case_id, need)  # 404 for non-members; raises for insufficient role
    m = db.get(CaseMember, (case.id, actor(request)))
    return s, case, m.access_role


def perr(exc: ProfileError) -> ApiError:
    status = 403 if exc.code.startswith("consent_") or exc.code in ("out_of_scope", "subject_inactive") else 409 if exc.code in ("changed_since",) else 422
    if exc.code == "not_found":
        status = 404
    return ApiError(status, exc.code, exc.message)


class SubjectIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=300)
    type: Literal["person", "organization", "domain", "email", "username", "business_record", "image", "document", "imported"] = "person"
    mode: Literal["self", "client", "organization"] = "self"
    purpose: str = Field(default="", max_length=2000)
    retention_days: int | None = Field(default=None, ge=1, le=3650)


class SubjectPatch(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=300)
    purpose: str | None = Field(default=None, max_length=2000)
    status: Literal["active", "paused", "closed"] | None = None
    retention_days: int | None = Field(default=None, ge=1, le=3650)


@router.post("/cases/{case_id}/subjects", status_code=201)
async def create_subject(request: Request, case_id: str, body: SubjectIn):
    with S(request).sm() as db:
        case = case_for(db, request, case_id, "editor")
        try:
            s = service.create_subject(db, case, display_name=body.display_name, type=body.type, mode=body.mode, purpose=body.purpose,
                                       actor=actor(request), retention_days=body.retention_days)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return service.subject_dict(s)


@router.get("/cases/{case_id}/subjects")
async def list_subjects(request: Request, case_id: str):
    """For a people case this lazily upgrades an existing case (idempotent, read-only on old tables) and returns its subject(s)."""
    with S(request).sm() as db:
        case = case_for(db, request, case_id, "viewer")
        m = db.get(CaseMember, (case_id, actor(request)))
        if m and ROLE_RANK[m.access_role] >= ROLE_RANK["editor"]:
            service.ensure_subject_for_case(db, case, actor(request))
            db.commit()
        items = db.scalars(select(Subject).where(Subject.case_id == case_id).order_by(Subject.created_at)).all()
        return {"total": len(items), "items": [service.subject_dict(s) for s in items], "case_category": case.category}


@router.get("/subjects/{subject_id}")
async def get_subject(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id)
        return service.subject_dict(s)


@router.patch("/subjects/{subject_id}")
async def patch_subject(request: Request, subject_id: str, body: SubjectPatch):
    with S(request).sm() as db:
        s, case, _ = subject_for(db, request, subject_id, "editor")
        if body.display_name is not None:
            s.display_name = " ".join(body.display_name.split())
        if body.purpose is not None:
            s.purpose = body.purpose.strip()
        if body.retention_days is not None:
            s.retention_days = body.retention_days
        if body.status is not None:
            s.status = body.status
            if body.status != "active":
                consent.stop_dependents(db, s, f"subject {body.status}")
        audit.record(db, "subject.update", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id,
                     metadata={"status": s.status})
        db.commit()
        return service.subject_dict(s)


@router.get("/subjects/{subject_id}/profile")
async def get_profile(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, case, role = subject_for(db, request, subject_id)
        out = service.build_profile(db, s, role=role)
        from ...profile import research  # local: research imports the search service
        cov = research.coverage(db, s, S(request).adapters)
        out["next_action"], out["last_collected"] = research.next_action(db, s, cov), research.last_collected(db, s)
        audit.record(db, "profile.view", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id, metadata={"role": role})
        db.commit()
        return out


@router.get("/subjects/{subject_id}/timeline")
async def get_timeline(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id)
        items = timeline.build(db, s, include_restricted=role != "viewer")
        db.commit()
        return {"total": len(items), "items": items}


class IdentifierIn(BaseModel):
    kind: Literal["name", "alias", "username", "email", "domain", "url", "organization"]
    value: str = Field(min_length=1, max_length=2048)
    source_evidence_id: str | None = None


@router.post("/subjects/{subject_id}/identifiers", status_code=201)
async def add_identifier(request: Request, subject_id: str, body: IdentifierIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            i = service.add_identifier(db, s, body.kind, body.value, actor=actor(request), source_evidence_id=body.source_evidence_id)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return service.identifier_dict(i, mask=False)


@router.delete("/subjects/{subject_id}/identifiers/{identifier_id}")
async def remove_identifier(request: Request, subject_id: str, identifier_id: str):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            service.remove_identifier(db, s, identifier_id, actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return {"ok": True}


class ClaimIn(BaseModel):
    field: str
    value: Any
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    observed_from: datetime | None = None
    observed_to: datetime | None = None
    assertion_source: Literal["analyst", "import", "subject"] = "analyst"


@router.post("/subjects/{subject_id}/claims", status_code=201)
async def add_claim(request: Request, subject_id: str, body: ClaimIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            c = service.add_claim(db, s, field=body.field, value=body.value, evidence_ids=body.evidence_ids, actor=actor(request),
                                  assertion_source=body.assertion_source, observed_from=body.observed_from, observed_to=body.observed_to)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return service.claim_dict(db, c)


class VerifyIn(BaseModel):
    state: Literal["verified", "subject_confirmed", "candidate", "conflicting", "rejected", "not_assessed"]
    basis: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    attestation: Literal["none", "subject"] = "none"


@router.post("/subjects/{subject_id}/claims/{claim_id}/verify")
async def verify_claim(request: Request, subject_id: str, claim_id: str, body: VerifyIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            c = service.review_claim(db, s, claim_id, to_state=body.state, reviewer=actor(request), basis=body.basis,
                                     evidence_ids=body.evidence_ids, attestation=body.attestation)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return service.claim_dict(db, c)


@router.get("/subjects/{subject_id}/candidates")
async def list_candidates(request: Request, subject_id: str, state: str | None = None):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id)
        items = candidates.list_candidates(db, s, state)
        db.commit()
        return {"total": len(items), "items": items}


class BulkReviewIn(BaseModel):
    candidate_ids: list[str] = Field(min_length=1, max_length=200)
    state: Literal["confirmed", "rejected", "unsure", "candidate"]
    basis: str = Field(min_length=1, max_length=2000)
    attestation: Literal["none", "subject"] = "none"
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)


@router.post("/subjects/{subject_id}/candidates/bulk-review")
async def bulk_review(request: Request, subject_id: str, body: BulkReviewIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            out = candidates.review(db, s, body.candidate_ids, to_state=body.state, reviewer=actor(request), basis=body.basis,
                                    attestation=body.attestation, evidence_ids=body.evidence_ids)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return out


class ReverseIn(BaseModel):
    event_id: str | None = None
    bulk_id: str | None = None


@router.post("/subjects/{subject_id}/candidates/reverse")
async def reverse_review(request: Request, subject_id: str, body: ReverseIn):
    if not (body.event_id or body.bulk_id):
        raise ApiError(422, "validation_error", "give event_id or bulk_id")
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            out = candidates.reverse(db, s, event_id=body.event_id, bulk_id=body.bulk_id, reviewer=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return out


@router.get("/subjects/{subject_id}/review-history")
async def review_history(request: Request, subject_id: str, target_id: str | None = None):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id)
        items = candidates.history(db, s, target_id)
        return {"total": len(items), "items": items}


class ConsentIn(BaseModel):
    verification_method: Literal["self_attestation", "email_confirmation", "provider_verification", "signed_document", "in_person"]
    verifier: str = Field(min_length=1, max_length=200)
    source_classes: list[str] = Field(min_length=1)
    permitted_purposes: list[str] = Field(default_factory=list)
    expires_at: datetime
    identifier_ids: list[str] = Field(default_factory=list)
    proof_evidence_id: str | None = None
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    providers: list[str] = Field(default_factory=list, max_length=8)      # DARKINT: permitted exposure providers (empty = any enabled provider)


@router.get("/subjects/{subject_id}/consent")
async def get_consent(request: Request, subject_id: str):
    from ...db.models import SubjectConsent
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id)
        rows = db.scalars(select(SubjectConsent).where(SubjectConsent.subject_id == s.id).order_by(SubjectConsent.created_at.desc())).all()
        return {"current": consent.current_status(db, s),
                "history": [{"id": c.id, "method": c.verification_method, "verifier": c.verifier, "classes": c.source_classes, "obtained_at": c.obtained_at,
                             "expires_at": c.expires_at, "revoked_at": c.revoked_at, "has_proof": bool(c.proof_evidence_id)} for c in rows]}


@router.post("/subjects/{subject_id}/consent", status_code=201)
async def add_consent(request: Request, subject_id: str, body: ConsentIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "owner")  # only a case owner can authorize research about a person
        try:
            c = consent.grant(db, s, verification_method=body.verification_method, verifier=body.verifier, source_classes=body.source_classes,
                              permitted_purposes=body.permitted_purposes, expires_at=body.expires_at, identifier_ids=body.identifier_ids,
                              proof_evidence_id=body.proof_evidence_id, retention_policy={"days": body.retention_days} if body.retention_days else None,
                              actor=actor(request), providers=body.providers or None)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return {"id": c.id, "status": consent.current_status(db, s)}


class RevokeIn(BaseModel):
    consent_id: str
    reason: str = Field(default="", max_length=1000)


@router.post("/subjects/{subject_id}/consent/revoke")
async def revoke_consent(request: Request, subject_id: str, body: RevokeIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")  # revoking is never harder than granting
        try:
            out = consent.revoke(db, s, body.consent_id, reason=body.reason, actor=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return {**out, "status": consent.current_status(db, s)}


@router.get("/subjects/{subject_id}/identifiers")
async def list_identifiers(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id)
        rows = db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == s.id, SubjectIdentifier.status == "active")).all()
        return {"total": len(rows), "items": [service.identifier_dict(i, mask=role == "viewer") for i in rows]}
