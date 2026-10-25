"""Active Intelligence & Verification API (addendum v1.1 section 7). Off until an administrator switches it on; every route needs case membership; policy lives in `aiv/policy.py`."""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ...aiv import policy, service, tools
from ...aiv.executor import RunRefused
from ...db.models import (
    AivApproval,
    AivObservation,
    AivPlan,
    AivRun,
    AivRunEvent,
    AivTemplateApproval,
    AssetAuthorization,
    Setting,
)
from ...main import ApiError
from ...telemetry import audit
from .routes import S, actor, case_for, require_admin

router: APIRouter = APIRouter()

FORBIDDEN = ["exploitation or payload delivery", "credential testing, guessing or brute force", "login automation or authenticated intrusion", "intrusive fuzzing or denial of service",
             "stealth or evasion", "arbitrary shell commands", "scanning an asset nobody authorized because a person's name appears on it"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def enabled(request: Request) -> bool:
    with S(request).sm() as db:
        row = db.get(Setting, "aiv_enabled")
        return bool(row and row.value_json is True)


def need_enabled(request: Request) -> None:
    if not enabled(request):
        raise ApiError(403, "aiv_disabled", "Active verification is switched off. An administrator can turn it on in Verification > Settings; nothing active runs while it is off.")


def serr(exc: service.AivError) -> ApiError:
    return ApiError(exc.status, exc.code, exc.message)


@router.get("/aiv/capabilities")
async def capabilities(request: Request):
    st = S(request)
    health = await tools.tools_health(st)
    return {"enabled": enabled(request), "offline": st.settings.offline, "classes": list(policy.CLASSES), "lab_class": policy.LAB_CLASS, "asset_types": list(policy.ASSET_TYPES),
            "attestation_kinds": list(policy.ATTESTATION_KINDS), "default_limits": policy.DEFAULT_LIMITS, "forbidden": FORBIDDEN, "tools": health,
            "boundary": "AIV verifies assets someone has authorized, with bounded and disclosed checks. Exploitation and intrusive testing belong to PHANTOM, a separate program with its own controls; "
                        "nothing here launches it or turns an AIV authorization into permission for it."}


@router.get("/aiv/tools/health")
async def tools_health(request: Request):
    return {"items": await tools.tools_health(S(request))}


class SettingsIn(Strict):
    enabled: bool


@router.put("/aiv/settings", dependencies=[Depends(require_admin)])
async def put_settings(request: Request, body: SettingsIn):
    with S(request).sm() as db:
        db.merge(Setting(key="aiv_enabled", value_json=body.enabled))
        audit.record(db, "aiv.settings", actor=actor(request), metadata={"enabled": body.enabled})
        db.commit()
    return {"enabled": body.enabled}


# ---- asset authorizations ---------------------------------------------------------------------------------------------------------------
class AuthIn(Strict):
    asset_type: Literal["fqdn", "ip", "cidr", "url_prefix"]
    scope: list[str] = Field(min_length=1, max_length=20)
    ports: list[int] = Field(min_length=1, max_length=20)
    paths: list[str] = Field(default_factory=lambda: ["/"], max_length=20)
    allowed_classes: list[str] = Field(min_length=1, max_length=8)
    exclusions: list[str] = Field(default_factory=list, max_length=50)
    limits: dict[str, Any] = Field(default_factory=dict)
    authorized_by: str = Field(min_length=1, max_length=200)
    authority_role: str = Field(default="", max_length=120)
    source_of_authority: str = Field(default="", max_length=2000)
    attestation_kind: Literal["signed_document", "owner_statement", "email_confirmation", "domain_control_record", "mandate_letter"] = "owner_statement"
    attestation_ref: str | None = None
    starts_at: datetime | None = None
    expires_at: datetime
    retention_terms: str = Field(default="", max_length=1000)
    notes: str = Field(default="", max_length=2000)
    owner_subject_id: str | None = None


@router.post("/cases/{case_id}/asset-authorizations", status_code=201)
async def create_auth(request: Request, case_id: str, body: AuthIn):
    need_enabled(request)
    with S(request).sm() as db:
        case = case_for(db, request, case_id, "owner")           # deciding that an asset may be tested is the case owner's call
        try:
            a = service.create_authorization(db, case, asset_type=body.asset_type, scope=body.scope, ports=body.ports, paths=body.paths, classes=body.allowed_classes,
                                             exclusions=body.exclusions, limits=body.limits, authorized_by=body.authorized_by, authority_role=body.authority_role,
                                             source_of_authority=body.source_of_authority, attestation_kind=body.attestation_kind, attestation_ref=body.attestation_ref,
                                             starts_at=body.starts_at, expires_at=body.expires_at, retention_terms=body.retention_terms, notes=body.notes,
                                             owner_subject_id=body.owner_subject_id, actor=actor(request))
        except service.AivError as exc:
            raise serr(exc) from exc
        db.commit()
        return service.authorization_dict(a)


@router.get("/cases/{case_id}/asset-authorizations")
async def list_auths(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id, "viewer")
        rows = db.scalars(select(AssetAuthorization).where(AssetAuthorization.case_id == case_id).order_by(AssetAuthorization.created_at.desc())).all()
        return {"total": len(rows), "items": [service.authorization_dict(a) for a in rows]}


class RevokeIn(Strict):
    reason: str = Field(default="", max_length=500)


@router.post("/cases/{case_id}/asset-authorizations/{auth_id}/revoke")
async def revoke_auth(request: Request, case_id: str, auth_id: str, body: RevokeIn):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "editor")                  # stopping is never harder than starting
        a = db.get(AssetAuthorization, auth_id)
        if not a or a.case_id != case_id:
            raise ApiError(404, "not_found", "authorization not found")
        out = service.revoke_authorization(db, a, st.aiv, actor(request), body.reason)
        db.commit()
        return {**out, "authorization": service.authorization_dict(a)}


# ---- plans --------------------------------------------------------------------------------------------------------------------------
class PlanIn(Strict):
    authorization_id: str
    steps: list[dict[str, Any]] = Field(min_length=1, max_length=12)
    target_profile_id: str | None = None
    supersedes: str | None = None


def _auth(db, case_id: str, auth_id: str) -> AssetAuthorization:
    a = db.get(AssetAuthorization, auth_id)
    if not a or a.case_id != case_id:
        raise ApiError(404, "not_found", "authorization not found in this case")
    return a


@router.post("/cases/{case_id}/aiv/plans/preview")
async def preview_plan(request: Request, case_id: str, body: PlanIn):
    """Offline: no DNS and no packets. Shows exactly what each step would do and whether policy allows it."""
    need_enabled(request)
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
        a = _auth(db, case_id, body.authorization_id)
        try:
            pv = await service.preview_plan(db, st, a, body.steps)
        except service.AivError as exc:
            raise serr(exc) from exc
        audit.record(db, "aiv.plan_preview", actor=actor(request), case_id=case_id, resource_type="asset_authorization", resource_id=a.id, metadata={"ok": pv["ok"], "steps": len(pv["steps"])})
        db.commit()
        return pv


@router.post("/cases/{case_id}/aiv/plans", status_code=201)
async def create_plan(request: Request, case_id: str, body: PlanIn):
    need_enabled(request)
    st = S(request)
    with st.sm() as db:
        case = case_for(db, request, case_id, "editor")
        if case.status != "open":
            raise ApiError(409, "case_not_open", "the case must be open")
        a = _auth(db, case_id, body.authorization_id)
        try:
            p = await service.create_plan(db, st, case, a, body.steps, body.target_profile_id, actor(request), body.supersedes)
        except service.AivError as exc:
            db.commit()
            raise serr(exc) from exc
        db.commit()
        return service.plan_dict(p)


@router.get("/cases/{case_id}/aiv/plans")
async def list_plans(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id, "viewer")
        rows = db.scalars(select(AivPlan).where(AivPlan.case_id == case_id).order_by(AivPlan.created_at.desc())).all()
        return {"total": len(rows), "items": [service.plan_dict(p) for p in rows]}


def _plan(db, request: Request, plan_id: str, need: str) -> AivPlan:
    p = db.get(AivPlan, plan_id)
    if not p:
        raise ApiError(404, "not_found", "plan not found")
    case_for(db, request, p.case_id, need)
    return p


@router.get("/aiv/plans/{plan_id}")
async def get_plan(request: Request, plan_id: str):
    with S(request).sm() as db:
        p = _plan(db, request, plan_id, "viewer")
        aps = db.scalars(select(AivApproval).where(AivApproval.plan_id == p.id).order_by(AivApproval.approved_at)).all()
        return {**service.plan_dict(p), "approvals": [{"id": a.id, "approver": a.approver_id, "approved_at": a.approved_at, "expires_at": a.expires_at, "uses": a.uses, "maximum_uses": a.maximum_uses,
                                                       "revoked_at": a.revoked_at} for a in aps]}


class ApproveIn(Strict):
    confirm: bool = False
    expires_in_minutes: int = Field(default=60, ge=1, le=240)


@router.post("/aiv/plans/{plan_id}/approve")
async def approve(request: Request, plan_id: str, body: ApproveIn):
    need_enabled(request)
    st = S(request)
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "read the plan preview and confirm; approving is a deliberate act and is never implied by anything else you clicked")
    with st.sm() as db:
        p = _plan(db, request, plan_id, "editor")
        try:
            ap = await service.approve_plan(db, st, p, actor(request), body.expires_in_minutes)
        except service.AivError as exc:
            db.commit()
            raise serr(exc) from exc
        db.commit()
        return {"approval_id": ap.id, "plan_id": p.id, "plan_hash": ap.plan_hash, "version": ap.plan_version, "expires_at": ap.expires_at, "maximum_uses": ap.maximum_uses, "approver": ap.approver_id}


class RunIn(Strict):
    approval_id: str
    wait: bool = False


@router.post("/aiv/plans/{plan_id}/run", status_code=202)
async def run_plan(request: Request, plan_id: str, body: RunIn):
    need_enabled(request)
    st = S(request)
    with st.sm() as db:
        p = _plan(db, request, plan_id, "editor")
        try:
            run_id = await st.aiv.start(db, p, body.approval_id, actor(request))
        except RunRefused as exc:
            raise ApiError(409 if exc.code.startswith("approval") else 403, exc.code, exc.message) from exc
    if body.wait:
        await st.aiv.wait(run_id)
    with st.sm() as db:
        return service.run_dict(db.get(AivRun, run_id))


def _run(db, request: Request, run_id: str, need: str = "viewer") -> AivRun:
    r = db.get(AivRun, run_id)
    if not r:
        raise ApiError(404, "not_found", "run not found")
    case_for(db, request, r.case_id, need)
    return r


@router.get("/aiv/runs/{run_id}")
async def get_run(request: Request, run_id: str):
    with S(request).sm() as db:
        r = _run(db, request, run_id)
        return service.run_dict(r)


@router.post("/aiv/runs/{run_id}/cancel")
async def cancel_run(request: Request, run_id: str):
    st = S(request)
    with st.sm() as db:
        r = _run(db, request, run_id, "editor")
        was = st.aiv.cancel(r.id)
        audit.record(db, "aiv.run_cancel", actor=actor(request), case_id=r.case_id, resource_type="aiv_run", resource_id=r.id)
        db.commit()
    return {"cancelling": was}


@router.get("/aiv/runs/{run_id}/events")
async def run_events(request: Request, run_id: str, after: int = 0):
    with S(request).sm() as db:
        r = _run(db, request, run_id)
        rows = db.scalars(select(AivRunEvent).where(AivRunEvent.run_id == r.id, AivRunEvent.seq > after).order_by(AivRunEvent.seq)).all()
        return {"status": r.status, "items": [{"seq": e.seq, "kind": e.kind, "payload": e.payload_json, "at": e.at} for e in rows]}


@router.get("/aiv/runs/{run_id}/compare/{other_id}")
async def compare(request: Request, run_id: str, other_id: str):
    with S(request).sm() as db:
        a, b = _run(db, request, run_id), _run(db, request, other_id)
        if a.case_id != b.case_id:
            raise ApiError(404, "not_found", "runs are in different cases")
        return service.compare_runs(db, a, b)


# ---- observations ------------------------------------------------------------------------------------------------------------------------
@router.get("/cases/{case_id}/aiv/observations")
async def list_observations(request: Request, case_id: str, run_id: str | None = None, review_status: str | None = None, severity: str | None = None):
    with S(request).sm() as db:
        case_for(db, request, case_id, "viewer")
        q = select(AivObservation).where(AivObservation.case_id == case_id).order_by(AivObservation.observed_at.desc())
        if run_id:
            q = q.where(AivObservation.run_id == run_id)
        if review_status:
            q = q.where(AivObservation.review_status == review_status)
        if severity:
            q = q.where(AivObservation.severity == severity)
        rows = db.scalars(q.limit(500)).all()
        return {"total": len(rows), "items": [service.observation_dict(o) for o in rows]}


class ReviewIn(Strict):
    status: Literal["confirmed", "false_positive", "accepted_risk", "unreviewed"]
    note: str = Field(default="", max_length=1000)


@router.post("/cases/{case_id}/aiv/observations/{obs_id}/review")
async def review_observation(request: Request, case_id: str, obs_id: str, body: ReviewIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        o = db.get(AivObservation, obs_id)
        if not o or o.case_id != case_id:
            raise ApiError(404, "not_found", "observation not found")
        try:
            service.review_observation(db, o, body.status, body.note, actor(request))
        except service.AivError as exc:
            raise serr(exc) from exc
        db.commit()
        return service.observation_dict(o)


# ---- reviewed signature templates -------------------------------------------------------------------------------------------------------
class TemplateIn(Strict):
    content: str = Field(min_length=10, max_length=tools.MAX_TEMPLATE_BYTES)
    notes: str = Field(default="", max_length=1000)
    confirm_reviewed: bool = False


@router.post("/aiv/templates/review")
async def review_template(request: Request, body: TemplateIn):
    """Static review only: nothing is stored or run."""
    r = tools.review_template(body.content)
    return {**r, "sha256": hashlib.sha256(body.content.encode()).hexdigest()}


@router.post("/aiv/templates", status_code=201, dependencies=[Depends(require_admin)])
async def approve_template(request: Request, body: TemplateIn):
    need_enabled(request)
    if not body.confirm_reviewed:
        raise ApiError(422, "confirmation_required", "confirm that you read the request semantics shown by the review")
    r = tools.review_template(body.content)
    if not r["ok"]:
        raise ApiError(422, "template_rejected", "; ".join(r["errors"][:3]), False, {"errors": r["errors"]})
    sha = hashlib.sha256(body.content.encode()).hexdigest()
    with S(request).sm() as db:
        existing = db.scalars(select(AivTemplateApproval).where(AivTemplateApproval.template_id == r["id"], AivTemplateApproval.sha256 == sha)).first()
        if existing and existing.revoked_at is None:
            return {"id": existing.id, "template_id": r["id"], "sha256": sha, "semantics": r["semantics"], "already_approved": True}
        for old in db.scalars(select(AivTemplateApproval).where(AivTemplateApproval.template_id == r["id"], AivTemplateApproval.revoked_at.is_(None))):
            old.revoked_at = datetime.now(old.reviewed_at.tzinfo)       # a new hash replaces the previous approval: only one pinned version is ever active
        row = AivTemplateApproval(template_id=r["id"], sha256=sha, content=body.content, semantics_json=r["semantics"], reviewed_by=actor(request), notes=body.notes)
        db.add(row)
        audit.record(db, "aiv.template_approve", actor=actor(request), resource_type="aiv_template", resource_id=r["id"], metadata={"sha256": sha[:12], "requests": r["semantics"]["request_count"]})
        db.commit()
        return {"id": row.id, "template_id": r["id"], "sha256": sha, "semantics": r["semantics"], "already_approved": False}


@router.get("/aiv/templates")
async def list_templates(request: Request):
    with S(request).sm() as db:
        rows = db.scalars(select(AivTemplateApproval).order_by(AivTemplateApproval.reviewed_at.desc())).all()
        return {"items": [{"id": t.id, "template_id": t.template_id, "sha256": t.sha256, "semantics": t.semantics_json, "reviewed_by": t.reviewed_by, "reviewed_at": t.reviewed_at,
                           "revoked_at": t.revoked_at} for t in rows]}


@router.post("/aiv/templates/{tid}/revoke", dependencies=[Depends(require_admin)])
async def revoke_template(request: Request, tid: str):
    with S(request).sm() as db:
        t = db.get(AivTemplateApproval, tid)
        if not t:
            raise ApiError(404, "not_found", "template approval not found")
        if t.revoked_at is None:
            t.revoked_at = datetime.now(t.reviewed_at.tzinfo)
            audit.record(db, "aiv.template_revoke", actor=actor(request), resource_type="aiv_template", resource_id=t.template_id)
        db.commit()
        return {"revoked": True}
