"""Exposure indicators, remediation, correction requests and retention (addendum TP-1.0 sections 6, 7, 9).

Request models forbid unknown fields, so a body that carries `password`, `ssn`, `token`, `dump` or any other extra field is refused before it reaches any code.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ...db.models import Case, CaseMember, RemediationTask, RetentionAction, Subject, SubjectCorrection
from ...main import ApiError
from ...profile import exposure, lifecycle
from ...profile.service import ProfileError
from ...telemetry import audit
from .profile import perr, subject_for
from .routes import S, actor

router: APIRouter = APIRouter()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


@router.get("/profile/exposure/providers")
async def exposure_providers(request: Request):
    return {"providers": exposure.PROVIDERS, "classes": {k: {"label": v["label"], "guidance": v["guidance"]} for k, v in exposure.CLASSES.items()},
            "never_stored": ["plaintext passwords", "password hashes", "session tokens", "recovery secrets", "full government identifiers", "raw breach dumps"]}


@router.get("/subjects/{subject_id}/exposure")
async def list_exposure(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, case, role = subject_for(db, request, subject_id)
        items = exposure.list_for(db, s, role=role)
        if role in ("owner", "editor"):
            audit.record(db, "exposure.view", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id)
            db.commit()
        return {"items": items, "total": len(items), "role": role, "redacted": role not in ("owner", "editor")}


class ExposureIn(Strict):
    cls: Literal["breach_account", "password_exposure", "data_broker_listing", "public_document_disclosure", "precise_location_disclosure", "social_oversharing"]
    provider: Literal["hibp", "pwned_passwords", "manual"] = "manual"
    status: Literal["not_assessed", "not_found_in_checked_sources", "confirmed_exposure"]
    risk: Literal["unknown", "low", "medium", "high", "critical"] = "unknown"
    descriptor: str = Field(default="", max_length=200)
    verification_basis: Literal["provider_api", "owner_confirmed", "provider_notice", "manual_review"]
    exposure_date: datetime | None = None
    evidence_id: str | None = None


@router.post("/subjects/{subject_id}/exposure", status_code=201)
async def record_exposure(request: Request, subject_id: str, body: ExposureIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            x = exposure.record(db, s, cls=body.cls, provider=body.provider, status=body.status, risk=body.risk, descriptor=body.descriptor, basis=body.verification_basis,
                                actor=actor(request), exposure_date=body.exposure_date, evidence_id=body.evidence_id)
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return exposure.indicator_dict(x, redact=False)


class AccountCheckIn(Strict):
    identifier_id: str
    confirm: bool = False


@router.post("/subjects/{subject_id}/exposure/preview")
async def exposure_preview(request: Request, subject_id: str, body: AccountCheckIn):
    """Exactly what would leave this machine, to whom, at what cost. Sends nothing."""
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            out = exposure.account_check_preview(db, s, body.identifier_id)
        except ProfileError as exc:
            raise perr(exc) from exc
        return out


@router.post("/subjects/{subject_id}/exposure/approve")
async def exposure_approve(request: Request, subject_id: str, body: AccountCheckIn):
    st = S(request)
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "confirm the data preview before the address is sent to the provider")
    with st.sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            out = await exposure.run_account_check(db, st.runner.ctx_factory(), s, body.identifier_id, actor(request))
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return out


class PasswordRangeIn(Strict):
    prefix: str = Field(min_length=5, max_length=5)


@router.post("/subjects/{subject_id}/exposure/password-range")
async def password_range(request: Request, subject_id: str, body: PasswordRangeIn):
    """k-anonymity relay: accepts exactly five hex characters (never a password or a full hash), stores nothing."""
    st = S(request)
    with st.sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            out = await exposure.password_range(db, st.runner.ctx_factory(), s, body.prefix, actor(request))
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return out


# ---- remediation ------------------------------------------------------------------------------------------------------------------------
@router.get("/subjects/{subject_id}/remediations")
async def list_remediations(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        rows = db.scalars(select(RemediationTask).where(RemediationTask.subject_id == s.id).order_by(RemediationTask.created_at)).all()
        return {"total": len(rows), "items": [lifecycle.remediation_dict(t) for t in rows], "role": role}


class RemediationIn(Strict):
    issue: str = Field(min_length=1, max_length=2000)
    priority: Literal["low", "medium", "high"] = "medium"
    guidance: str = Field(default="", max_length=4000)
    owner: str | None = Field(default=None, max_length=80)
    due_in_days: int | None = Field(default=None, ge=1, le=730)
    indicator_id: str | None = None


@router.post("/subjects/{subject_id}/remediations", status_code=201)
async def create_remediation(request: Request, subject_id: str, body: RemediationIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            t = lifecycle.create_remediation(db, s, issue=body.issue, priority=body.priority, guidance=body.guidance, owner=body.owner, due_in_days=body.due_in_days,
                                             indicator_id=body.indicator_id, actor=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return lifecycle.remediation_dict(t)


class RemediationPatch(Strict):
    state: Literal["open", "in_progress", "resolved", "wont_fix"] | None = None
    resolution_evidence_id: str | None = None
    owner: str | None = Field(default=None, max_length=80)
    recheck_in_days: int | None = Field(default=None, ge=1, le=730)


@router.patch("/subjects/{subject_id}/remediations/{task_id}")
async def update_remediation(request: Request, subject_id: str, task_id: str, body: RemediationPatch):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            t = lifecycle.update_remediation(db, s, task_id, state=body.state, resolution_evidence_id=body.resolution_evidence_id, owner=body.owner,
                                             recheck_in_days=body.recheck_in_days, actor=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return lifecycle.remediation_dict(t)


# ---- corrections ------------------------------------------------------------------------------------------------------------------------
class CorrectionIn(Strict):
    target_type: Literal["claim", "candidate", "exposure", "image_match", "identifier", "other"]
    target_id: str | None = None
    request: str = Field(min_length=1, max_length=4000)
    justification: str = Field(default="", max_length=4000)
    requested_by: str = Field(default="subject", max_length=200)


@router.get("/subjects/{subject_id}/corrections")
async def list_corrections(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        rows = db.scalars(select(SubjectCorrection).where(SubjectCorrection.subject_id == s.id).order_by(SubjectCorrection.event_time.desc())).all()
        return {"total": len(rows), "items": [lifecycle.correction_dict(c) for c in rows]}


@router.post("/subjects/{subject_id}/corrections", status_code=201)
async def request_correction(request: Request, subject_id: str, body: CorrectionIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            c = lifecycle.request_correction(db, s, target_type=body.target_type, target_id=body.target_id, request_text=body.request, justification=body.justification,
                                             requested_by=body.requested_by, actor=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return lifecycle.correction_dict(c)


class ResolveIn(Strict):
    decision: Literal["accepted", "declined", "applied"]
    resolution: str = Field(min_length=1, max_length=4000)


@router.post("/subjects/{subject_id}/corrections/{correction_id}/resolve")
async def resolve_correction(request: Request, subject_id: str, correction_id: str, body: ResolveIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            c = lifecycle.resolve_correction(db, s, correction_id, decision=body.decision, resolution=body.resolution, actor=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return lifecycle.correction_dict(c)


# ---- retention --------------------------------------------------------------------------------------------------------------------------
@router.get("/subjects/{subject_id}/retention/preview")
async def retention_preview(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "owner")
        out = lifecycle.purge_preview(db, s, actor(request))
        db.commit()
        return out


class PurgeIn(Strict):
    confirm: str


@router.post("/subjects/{subject_id}/retention/purge")
async def retention_purge(request: Request, subject_id: str, body: PurgeIn):
    st = S(request)
    with st.sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "owner")
        try:
            out = lifecycle.purge(db, st.vault.root, s, body.confirm, actor(request))
        except ProfileError as exc:
            db.rollback()
            raise ApiError(422, exc.code, exc.message) from exc
        db.commit()
        return out


@router.get("/subjects/{subject_id}/retention/history")
async def retention_history(request: Request, subject_id: str):
    with S(request).sm() as db:
        subject_for(db, request, subject_id, "owner")
        rows = db.scalars(select(RetentionAction).where(RetentionAction.subject_id == subject_id).order_by(RetentionAction.event_time)).all()
        return {"items": [{"id": r.id, "action": r.action, "status": r.status, "summary": r.summary_json, "by": r.performed_by, "at": r.event_time, "audit_seq": r.audit_seq} for r in rows]}


@router.get("/profile/retention/due")
async def retention_due(request: Request):
    """Subjects past their retention period in cases you own. Nothing is deleted automatically."""
    with S(request).sm() as db:
        mine = {m.case_id for m in db.scalars(select(CaseMember).where(CaseMember.user_id == actor(request), CaseMember.access_role == "owner"))}
        items = [d for d in lifecycle.due_for_expiry(db) if d["case_id"] in mine]
        names = {s.id: s.display_name for s in db.scalars(select(Subject).where(Subject.id.in_([d["subject_id"] for d in items])))} if items else {}
        titles = {c.id: c.title for c in db.scalars(select(Case).where(Case.id.in_([d["case_id"] for d in items])))} if items else {}
        return {"items": [{**d, "display_name": names.get(d["subject_id"], ""), "case_title": titles.get(d["case_id"], "")} for d in items]}
