"""AI Automation Builder & Workflow Library API (addendum A1.0). Routes live under /api/v1/automations.

Authentication and per-case authorisation apply even in single-user mode. Approving, activating and publishing are people's actions: nothing in the
AI endpoints can reach them."""
from __future__ import annotations

import asyncio
import json
import platform
import re
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ... import __version__
from ...automations import ai as aai
from ...automations import catalog, cron, permissions, service
from ...automations import notifications as notes
from ...automations import settings as aset
from ...automations import suggestions as sug
from ...automations.executor import ACTIVE_STATES, TERMINAL
from ...automations.graph_validator import validate
from ...automations.models import CONFIGS, content_hash, json_schema
from ...automations.registry import ERROR_CODES, SPECS
from ...copilot import context as cx
from ...copilot.engine import Engine
from ...db.models import (
    AutomationApproval,
    AutomationNodeRun,
    AutomationNotification,
    AutomationRun,
    AutomationSuggestion,
    AutomationVersion,
    AutomationWorkflow,
    Case,
    CaseMember,
    Evidence,
    Finding,
    ScopeAuthorization,
)
from ...main import ApiError
from ...telemetry import audit
from .routes import ROLE_RANK, S, actor, case_for, page, require_admin

router: APIRouter = APIRouter(prefix="/automations")


def _err(exc: service.ServiceError) -> ApiError:
    return ApiError(exc.status, exc.code, exc.message, False, exc.details)


async def _status(st: Any) -> dict[str, str]:
    t = await cx.tool_status(st)
    return {k: v["status"] for k, v in t.items()}


def _wf(db: Any, request: Request, wid: str, need: str = "viewer") -> AutomationWorkflow:
    wf = db.get(AutomationWorkflow, wid)
    if wf is None or wf.deleted_at is not None:
        raise ApiError(404, "not_found", "workflow not found")
    me = actor(request)
    if wf.owner_id != me:
        m = db.get(CaseMember, (wf.case_id, me)) if wf.case_id else None
        if m is None or ROLE_RANK[m.access_role] < ROLE_RANK[need]:
            raise ApiError(404, "not_found", "workflow not found")
    return wf


def _wf_dict(wf: AutomationWorkflow, db: Any, detail: bool = False) -> dict[str, Any]:
    last = service.latest_version(db, wf.id)
    d = {"id": wf.id, "name": wf.name, "case_id": wf.case_id, "owner_id": wf.owner_id, "template_slug": wf.template_slug, "state": wf.state, "rev": wf.draft_rev,
         "active_version_id": wf.active_version_id, "latest_revision": last.revision if last else None, "published": last is not None,
         "unpublished_changes": bool(last is None or last.content_hash != content_hash(wf.draft_json)),
         "trigger": (wf.draft_json or {}).get("trigger", {}), "created_at": wf.created_at, "updated_at": wf.updated_at}
    if detail:
        d["definition"] = wf.draft_json
    return d


def _run_dict(r: AutomationRun, db: Any, wf: AutomationWorkflow | None = None) -> dict[str, Any]:
    wf = wf or db.get(AutomationWorkflow, r.workflow_id)
    v = db.get(AutomationVersion, r.version_id) if r.version_id else None
    return {"id": r.id, "workflow_id": r.workflow_id, "workflow_name": wf.name if wf else None, "template_slug": wf.template_slug if wf else None, "case_id": r.case_id,
            "revision": v.revision if v else None, "state": r.state, "trigger_type": r.trigger_type, "dry_run": r.dry_run, "simulated": r.dry_run, "queued_at": r.queued_at,
            "started_at": r.started_at, "ended_at": r.ended_at, "error_code": r.error_code, "evidence_count": r.evidence_count, "created_by": r.created_by,
            "summary": {k: v2 for k, v2 in (r.summary_json or {}).items() if k in ("nodes", "warnings", "failures", "requests", "simulated", "error")}}


def _spawn(st: Any, run_id: str) -> asyncio.Task:
    t = asyncio.create_task(st.automation.execute(run_id))
    st.tasks.add(t)
    t.add_done_callback(st.tasks.discard)
    return t


# ----------------------------------------------------------------------------------------------------------------------- catalog
@router.get("/templates")
async def templates(request: Request, q: str | None = None, category: str | None = None, tag: str | None = None):
    st = S(request)
    status = await _status(st)
    out = []
    for t in catalog.load_all():
        if category and t["category"].lower() != category.lower():
            continue
        if tag and tag not in t["tags"]:
            continue
        if q and q.lower() not in (t["name"] + " " + t["description"] + " " + " ".join(t["tags"]) + " " + t["key"]).lower():
            continue
        out.append(catalog.public(t, catalog.availability(t, status, st.adapters)))
    return {"items": out, "total": len(out), "categories": sorted({t["category"] for t in catalog.load_all()}),
            "note": "All templates are installed DISABLED. Availability reflects tools and keys on this computer right now."}


@router.get("/templates/{slug}")
async def template(request: Request, slug: str):
    st = S(request)
    t = catalog.get(slug)
    if t is None:
        raise ApiError(404, "not_found", "no such template")
    return catalog.public(t, catalog.availability(t, await _status(st), st.adapters), detail=True)


@router.get("/node-types")
async def node_types(request: Request):
    return {"items": [{"type": s.type, "title": s.title, "description": s.description, "produces": s.out_type, "side_effects": s.side_effects, "risk": s.risk, "network": s.network,
                       "fields": list(s.fields), "ref_types": {k: list(v) for k, v in s.ref_types.items()}, "config_schema": CONFIGS[s.type].model_json_schema()} for s in SPECS.values()],
            "error_codes": list(ERROR_CODES)}


@router.get("/schema")
async def schema(request: Request):
    return json_schema()


@router.get("/capabilities")
async def capabilities(request: Request):
    st = S(request)
    status = await _status(st)
    return aai.capability_registry(st, status) | {"templates_detail": [{"key": t["key"], "availability": catalog.availability(t, status, st.adapters)["state"], "maturity": t["maturity"]}
                                                                     for t in catalog.load_all()]}


# ----------------------------------------------------------------------------------------------------------------------- workflows
class FromTemplate(BaseModel):
    slug: str
    case_id: str | None = None
    name: str | None = Field(default=None, max_length=200)
    inputs: dict[str, Any] = Field(default_factory=dict)


@router.post("/from-template", status_code=201)
async def from_template(request: Request, body: FromTemplate):
    st = S(request)
    t = catalog.get(body.slug)
    if t is None:
        raise ApiError(404, "not_found", "no such template")
    d = json.loads(json.dumps(t["definition"]))
    for k, v in body.inputs.items():
        if k not in d["inputs"] or not isinstance(v, str | int | float | bool | type(None)):
            raise ApiError(422, "INVALID_GRAPH", f"unknown or invalid input {k!r}")
        d["inputs"][k] = v
    with st.sm() as db:
        if body.case_id:
            case_for(db, request, body.case_id, "editor")
        try:
            wf = service.create_workflow(db, owner=actor(request), definition=d, case_id=body.case_id, name=body.name, template_slug=t["slug"])
        except service.ServiceError as exc:
            raise _err(exc) from exc
        db.commit()
        return _wf_dict(wf, db, True)


class WfIn(BaseModel):
    definition: dict[str, Any]
    case_id: str | None = None
    name: str | None = Field(default=None, max_length=200)


@router.post("/workflows", status_code=201)
async def create_wf(request: Request, body: WfIn):
    with S(request).sm() as db:
        if body.case_id:
            case_for(db, request, body.case_id, "editor")
        try:
            wf = service.create_workflow(db, owner=actor(request), definition=body.definition, case_id=body.case_id, name=body.name)
        except service.ServiceError as exc:
            raise _err(exc) from exc
        db.commit()
        return _wf_dict(wf, db, True)


@router.get("/workflows")
async def list_wf(request: Request, case_id: str | None = None, limit: int = 50, offset: int = 0):
    with S(request).sm() as db:
        me = actor(request)
        q = select(AutomationWorkflow).where(AutomationWorkflow.deleted_at.is_(None))
        if case_id:
            case_for(db, request, case_id)
            q = q.where(AutomationWorkflow.case_id == case_id)
        else:
            q = q.where((AutomationWorkflow.owner_id == me) | AutomationWorkflow.case_id.in_(select(CaseMember.case_id).where(CaseMember.user_id == me)))
        total, rows = page(q.order_by(AutomationWorkflow.updated_at.desc()), db, min(limit, 200), offset)
        return {"total": total, "items": [_wf_dict(w, db) for w in rows]}


@router.get("/workflows/{wid}")
async def get_wf(request: Request, wid: str):
    from fastapi.encoders import jsonable_encoder
    from fastapi.responses import JSONResponse
    with S(request).sm() as db:
        wf = _wf(db, request, wid)
        d = _wf_dict(wf, db, True)
        d["versions"] = [{"id": v.id, "revision": v.revision, "hash": v.content_hash, "published_at": v.published_at, "created_by": v.created_by}
                         for v in db.scalars(select(AutomationVersion).where(AutomationVersion.workflow_id == wid).order_by(AutomationVersion.revision.desc()))]
        return JSONResponse(jsonable_encoder(d), headers={"ETag": f'"{wf.draft_rev}"'})


class PatchIn(BaseModel):
    definition: dict[str, Any]
    name: str | None = Field(default=None, max_length=200)
    rev: int | None = None


@router.patch("/workflows/{wid}")
async def patch_wf(request: Request, wid: str, body: PatchIn):
    expected = body.rev
    if expected is None:
        m = re.fullmatch(r'"?(\d+)"?', request.headers.get("if-match", ""))
        expected = int(m.group(1)) if m else None
    with S(request).sm() as db:
        wf = _wf(db, request, wid, "editor")
        try:
            service.update_draft(db, wf, body.definition, expected, actor(request), body.name)
        except service.ServiceError as exc:
            raise _err(exc) from exc
        db.commit()
        return _wf_dict(wf, db, True)


@router.delete("/workflows/{wid}")
async def delete_wf(request: Request, wid: str):
    with S(request).sm() as db:
        wf = _wf(db, request, wid, "editor")
        service.deactivate(db, wf, actor(request), reason="deleted")
        wf.deleted_at = datetime.now(UTC)
        audit.record(db, "automation.deleted", actor=actor(request), case_id=wf.case_id, resource_id=wid)
        db.commit()
    return {"deleted": wid}


@router.post("/workflows/{wid}/validate")
async def validate_wf(request: Request, wid: str):
    st = S(request)
    status = await _status(st)
    with st.sm() as db:
        wf = _wf(db, request, wid)
        rep = validate(wf.draft_json, st.adapters, status)
    return rep | {"explanation": aai.explain(wf.draft_json, st, status) if rep["valid"] else None}


class DryRunIn(BaseModel):
    case_id: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)


@router.post("/workflows/{wid}/dry-run", status_code=201)
async def dry_run(request: Request, wid: str, body: DryRunIn):
    """Runs the DRAFT against the template's fixture: no network, no writes. Every output is labelled simulated."""
    st = S(request)
    with st.sm() as db:
        wf = _wf(db, request, wid)
        if body.case_id:
            case_for(db, request, body.case_id, "viewer")
        tpl = catalog.get(wf.template_slug) if wf.template_slug else None
        fixture = dict(tpl["fixture"]) if tpl else {}
        fixture_inputs = {**fixture.get("inputs", {}), **body.inputs}
        run = st.automation.enqueue(db, wf, None, trigger_type="manual", inputs=fixture_inputs, dry_run=True, idem=f"dry:{wid}:{datetime.now(UTC).timestamp()}", actor=actor(request),
                                    case_id=body.case_id or wf.case_id, definition=wf.draft_json, fixture=fixture)
        db.commit()
        rid = run.id
    await st.automation.execute(rid)
    with st.sm() as db:
        r = db.get(AutomationRun, rid)
        return {"run": _run_dict(r, db), "nodes": _node_dicts(db, rid, st), "label": "SIMULATED: fixture data, no network, nothing written"}


@router.post("/workflows/{wid}/publish", status_code=201)
async def publish(request: Request, wid: str):
    st = S(request)
    status = await _status(st)
    with st.sm() as db:
        wf = _wf(db, request, wid, "editor")
        try:
            v = service.publish(db, wf, st, actor(request), status)
        except service.ServiceError as exc:
            raise _err(exc) from exc
        db.commit()
        return {"version_id": v.id, "revision": v.revision, "hash": v.content_hash, "active_version_id": wf.active_version_id,
                "note": ("this does not change the active version; it needs its own approval and activation" if wf.active_version_id and wf.active_version_id != v.id else "published; approval is only needed to schedule it")}


class ApprovalReq(BaseModel):
    revision: int | None = None


@router.post("/workflows/{wid}/request-approval", status_code=201)
async def request_approval(request: Request, wid: str, body: ApprovalReq):
    st = S(request)
    with st.sm() as db:
        wf = _wf(db, request, wid, "editor")
        v = _version(db, wid, body.revision)
        items = service.request_approval(db, wf, v, st, actor(request))
        db.commit()
        return {"items": [_appr(a) for a in items], "note": "Nothing runs until a person decides each request."}


def _version(db: Any, wid: str, rev: int | None) -> AutomationVersion:
    v = db.scalars(select(AutomationVersion).where(AutomationVersion.workflow_id == wid, *( [AutomationVersion.revision == rev] if rev else [] ))
                   .order_by(AutomationVersion.revision.desc())).first()
    if v is None:
        raise ApiError(409, "APPROVAL_REQUIRED", "publish the workflow first: only published versions can be approved or run")
    return v


def _appr(a: AutomationApproval) -> dict[str, Any]:
    return {"id": a.id, "workflow_id": a.workflow_id, "version_id": a.version_id, "kind": a.kind, "status": a.status, "scope": a.action_scope_json, "requested_at": a.requested_at,
            "approved_at": a.approved_at, "expires_at": a.expires_at, "approver_id": a.approver_id, "authorization_id": a.authorization_id}


@router.get("/approvals")
async def approvals(request: Request, workflow_id: str | None = None, status: str | None = None):
    with S(request).sm() as db:
        q = select(AutomationApproval).order_by(AutomationApproval.requested_at.desc())
        if workflow_id:
            _wf(db, request, workflow_id)
            q = q.where(AutomationApproval.workflow_id == workflow_id)
        if status:
            q = q.where(AutomationApproval.status == status)
        rows = [a for a in db.scalars(q.limit(200)) if _can_see(db, request, a.workflow_id)]
        return {"items": [_appr(a) for a in rows]}


def _can_see(db: Any, request: Request, wid: str) -> bool:
    try:
        _wf(db, request, wid)
        return True
    except ApiError:
        return False


class DecideIn(BaseModel):
    approve: bool
    expires_in_days: int = 30
    confirmed_adapters: list[str] = Field(default_factory=list)
    authorization_id: str | None = None


@router.post("/approvals/{aid}/decide")
async def decide(request: Request, aid: str, body: DecideIn):
    with S(request).sm() as db:
        a = db.get(AutomationApproval, aid)
        if a is None:
            raise ApiError(404, "not_found", "approval not found")
        wf = _wf(db, request, a.workflow_id, "editor")
        member = db.get(CaseMember, (wf.case_id, actor(request))) if wf.case_id else None
        if wf.owner_id != actor(request) and not (member and member.access_role == "owner"):
            raise ApiError(403, "forbidden", "only the workflow owner or the case owner can decide approvals")
        try:
            service.decide_approval(db, a, wf, approve=body.approve, by=actor(request), expires_in_days=body.expires_in_days, confirmed_adapters=body.confirmed_adapters,
                                    authorization_id=body.authorization_id)
        except service.ServiceError as exc:
            raise _err(exc) from exc
        db.commit()
        return _appr(a)


@router.post("/approvals/{aid}/revoke")
async def revoke(request: Request, aid: str):
    with S(request).sm() as db:
        a = db.get(AutomationApproval, aid)
        if a is None:
            raise ApiError(404, "not_found", "approval not found")
        wf = _wf(db, request, a.workflow_id, "editor")
        service.revoke_approval(db, a, wf, actor(request))
        db.commit()
        return _appr(a)


@router.get("/scope-authorizations")
async def scope_auths(request: Request, case_id: str):
    from ...policy import engine as policy
    with S(request).sm() as db:
        case_for(db, request, case_id)
        live = {a.id for a in policy.active_authorizations(db, case_id)}
        return {"items": [{"id": a.id, "scope": a.scope_value, "type": a.authorization_type, "classes": a.allowed_classes_json, "expires_at": a.expires_at, "current": a.id in live}
                          for a in db.scalars(select(ScopeAuthorization).where(ScopeAuthorization.case_id == case_id))]}


class ActivateIn(BaseModel):
    revision: int | None = None


@router.post("/workflows/{wid}/activate")
async def activate(request: Request, wid: str, body: ActivateIn):
    st = S(request)
    status = await _status(st)
    with st.sm() as db:
        wf = _wf(db, request, wid, "editor")
        v = _version(db, wid, body.revision)
        try:
            t = service.activate(db, wf, v, st, actor(request), status)
        except service.ServiceError as exc:
            raise _err(exc) from exc
        db.commit()
        return {"state": wf.state, "active_revision": v.revision, "next_due_at": t.next_due_at if t else None,
                "note": "Scheduled runs happen only while this application is running; missed slots follow the trigger's policy when it next starts."}


@router.post("/workflows/{wid}/deactivate")
async def deactivate(request: Request, wid: str):
    with S(request).sm() as db:
        wf = _wf(db, request, wid, "editor")
        service.deactivate(db, wf, actor(request))
        db.commit()
        return {"state": wf.state}


class RunIn(BaseModel):
    case_id: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)
    confirmed_adapters: list[str] = Field(default_factory=list)
    revision: int | None = None
    wait: bool = False


@router.post("/workflows/{wid}/run", status_code=202)
async def run_wf(request: Request, wid: str, body: RunIn):
    st = S(request)
    with st.sm() as db:
        wf = _wf(db, request, wid, "editor")
        case_id = body.case_id or wf.case_id
        if not case_id:
            raise ApiError(422, "INVALID", "choose the case this run should put its evidence in")
        case_for(db, request, case_id, "editor")
        v = _version(db, wid, body.revision)
        run = st.automation.enqueue(db, wf, v, trigger_type="manual", inputs=body.inputs, dry_run=False, idem=f"manual:{wid}:{datetime.now(UTC).timestamp()}", actor=actor(request),
                                    case_id=case_id, confirmed=body.confirmed_adapters)
        db.commit()
        rid = run.id
    if body.wait:
        await st.automation.execute(rid)
    else:
        _spawn(st, rid)
    with st.sm() as db:
        return _run_dict(db.get(AutomationRun, rid), db)


@router.post("/workflows/{wid}/run-file", status_code=202)
async def run_file(request: Request, wid: str, filename: str, case_id: str | None = None, consent_confirmed: bool = False, wait: bool = False, revision: int | None = None):
    """File-triggered workflows: the file is parsed offline and stored like an import, then the workflow runs on it."""
    import os

    from ...ingest import exiftool, parsers
    from ...ingest import service as ingest_service
    from ...setup.state import managed_path
    st = S(request)
    if not consent_confirmed:
        raise ApiError(422, "consent_required", "confirm you own or are authorised to analyse this file")
    with st.sm() as db:
        wf = _wf(db, request, wid, "editor")
        cid = case_id or wf.case_id
        if not cid:
            raise ApiError(422, "INVALID", "choose a case for this file")
        case_for(db, request, cid, "editor")
        v = _version(db, wid, revision)
        if (v.definition_json.get("trigger") or {}).get("type") != "file":
            raise ApiError(422, "INVALID", "this workflow does not take a file")
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > st.settings.max_import_bytes:
            raise ApiError(413, "too_large", "upload exceeds the size limit")
    safe = re.sub(r"[^\w.\- ]", "_", os.path.basename(filename.replace("\\", "/")))[:120] or "file"
    kind = parsers.detect_kind(safe, raw[:512])
    if not kind or kind not in parsers.PARSERS:
        raise ApiError(422, "unsupported_kind", "cannot detect the file type; supported kinds: " + ", ".join(sorted(parsers.PARSERS)))
    try:
        parsed = await asyncio.to_thread(parsers.PARSERS[kind], raw)
    except parsers.IngestError as exc:
        raise ApiError(422, "malformed_input", str(exc)) from exc
    if kind in exiftool.KINDS:
        exe = managed_path(st.settings.tools_state_path, "exiftool") or __import__("shutil").which("exiftool")
        extra = await exiftool.read_tags(exe, raw, safe) if exe else None
        if extra:
            parsed.observations.append(extra)
    with st.sm() as db:
        wf = db.get(AutomationWorkflow, wid)
        before = db.scalars(select(Evidence).where(Evidence.case_id == cid, Evidence.kind == f"import.{kind}")).all()
        import hashlib as _h
        dup = any(e.sha256 == _h.sha256(raw).hexdigest() for e in before)
        out = ingest_service.persist(db, st.vault, cid, parsed, raw, safe, actor(request), None)
        eid = out.get("evidence_id") or out.get("id")
        v = _version(db, wid, revision)
        run = st.automation.enqueue(db, wf, v, trigger_type="manual", inputs={"evidence_id": eid, "duplicate": dup}, dry_run=False, idem=f"file:{wid}:{datetime.now(UTC).timestamp()}",
                                    actor=actor(request), case_id=cid)
        db.commit()
        rid = run.id
    if wait:
        await st.automation.execute(rid)
    else:
        _spawn(st, rid)
    with st.sm() as db:
        return _run_dict(db.get(AutomationRun, rid), db) | {"evidence_id": eid, "duplicate": dup}


@router.get("/workflows/{wid}/export")
async def export_wf(request: Request, wid: str):
    with S(request).sm() as db:
        wf = _wf(db, request, wid)
        return catalog.export_workflow(wf.name, wf.draft_json)


class ImportIn(BaseModel):
    document: dict[str, Any]
    case_id: str | None = None


@router.post("/import", status_code=201)
async def import_wf(request: Request, body: ImportIn):
    st = S(request)
    try:
        d = catalog.verify_import(body.document)
    except ValueError as exc:
        raise ApiError(422, "INVALID_GRAPH", str(exc)) from exc
    status = await _status(st)
    with st.sm() as db:
        if body.case_id:
            case_for(db, request, body.case_id, "editor")
        try:
            wf = service.create_workflow(db, owner=actor(request), definition=d, case_id=body.case_id, name=body.document.get("name"))
        except service.ServiceError as exc:
            raise _err(exc) from exc
        rep = validate(wf.draft_json, st.adapters, status)
        audit.record(db, "automation.imported", actor=actor(request), case_id=body.case_id, resource_id=wf.id, metadata={"valid": rep["valid"]})
        db.commit()
        return _wf_dict(wf, db, True) | {"validation": {"valid": rep["valid"], "errors": rep["errors"], "warnings": rep["warnings"]}, "permissions": rep["permissions"],
                                         "note": "Imported disabled. Review the permissions above; it is never activated automatically."}


@router.post("/workflows/{wid}/versions/{rev}/clone")
async def clone_version(request: Request, wid: str, rev: int):
    with S(request).sm() as db:
        wf = _wf(db, request, wid, "editor")
        v = db.scalars(select(AutomationVersion).where(AutomationVersion.workflow_id == wid, AutomationVersion.revision == rev)).first()
        if v is None:
            raise ApiError(404, "not_found", "no such revision")
        service.update_draft(db, wf, v.definition_json, None, actor(request))
        db.commit()
        return _wf_dict(wf, db, True)


class RepairIn(BaseModel):
    ops: list[dict[str, Any]]
    rev: int | None = None


@router.post("/workflows/{wid}/repair")
async def repair(request: Request, wid: str, body: RepairIn):
    """Apply diagnostic repair proposals to the DRAFT (never to a published version). Returns the diff and validation; publishing stays yours."""
    st = S(request)
    status = await _status(st)
    with st.sm() as db:
        wf = _wf(db, request, wid, "editor")
        try:
            res = aai.apply_repairs(wf.draft_json, body.ops, st, status)
            service.update_draft(db, wf, res["definition"], body.rev, actor(request))
        except service.ServiceError as exc:
            raise _err(exc) from exc
        audit.record(db, "automation.repair_applied", actor=actor(request), case_id=wf.case_id, resource_id=wid, metadata={"changes": res["changes"]})
        db.commit()
        return {"changes": res["changes"], "validation": res["validation"], "rev": wf.draft_rev, "note": "Applied to the draft only. Dry-run it, then publish and re-approve if you want it live."}


# ----------------------------------------------------------------------------------------------------------------------- runs
def _node_dicts(db: Any, rid: str, st: Any) -> list[dict[str, Any]]:
    out = []
    for nr in db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == rid).order_by(AutomationNodeRun.started_at)):
        o = nr.output_json
        brief: Any = None
        if isinstance(o, dict):
            brief = {k: o[k] for k in ("count", "changed", "added_count", "removed_count", "changed_count", "sent", "target", "allowed", "evidence_id", "report_id", "value", "approved",
                                      "kind", "duplicate", "partial", "simulated", "skipped_optional", "note", "baseline", "reason", "deduplicated", "sources_changed") if k in o}
            if isinstance(o.get("uncertain"), list):
                brief["uncertain_count"] = len(o["uncertain"])
        dur = (nr.ended_at - nr.started_at).total_seconds() * 1000 if nr.ended_at and nr.started_at else None
        out.append({"node": nr.node_id, "attempt": nr.attempt, "state": nr.state, "started_at": nr.started_at, "ended_at": nr.ended_at, "duration_ms": dur, "input_digest": nr.input_digest,
                    "error_code": nr.error_code, "output": brief, "diagnostics": nr.diagnostics_json})
    return out


@router.get("/runs")
async def list_runs(request: Request, case_id: str | None = None, workflow_id: str | None = None, template: str | None = None, state: str | None = None, source: str | None = None,
                    since: datetime | None = None, until: datetime | None = None, dry_run: bool | None = None, sort: str = "-queued_at", limit: int = 50, offset: int = 0):
    st = S(request)
    with st.sm() as db:
        q = select(AutomationRun).join(AutomationWorkflow, AutomationWorkflow.id == AutomationRun.workflow_id)
        me = actor(request)
        q = q.where((AutomationWorkflow.owner_id == me) | AutomationWorkflow.case_id.in_(select(CaseMember.case_id).where(CaseMember.user_id == me)))
        if case_id:
            q = q.where(AutomationRun.case_id == case_id)
        if workflow_id:
            q = q.where(AutomationRun.workflow_id == workflow_id)
        if template:
            q = q.where(AutomationWorkflow.template_slug == template)
        if state:
            q = q.where(AutomationRun.state == state)
        if since:
            q = q.where(AutomationRun.queued_at >= since)
        if until:
            q = q.where(AutomationRun.queued_at <= until)
        if dry_run is not None:
            q = q.where(AutomationRun.dry_run.is_(dry_run))
        if source:                                                      # runs that used a given source adapter
            q = q.where(AutomationRun.summary_json.like(f'%"{re.sub(r"[^a-z0-9_]", "", source)}"%') | AutomationRun.inputs_json.like(f'%"{re.sub(r"[^a-z0-9_]", "", source)}"%'))
        col = {"queued_at": AutomationRun.queued_at, "state": AutomationRun.state, "ended_at": AutomationRun.ended_at}.get(sort.lstrip("-"), AutomationRun.queued_at)
        q = q.order_by(col.desc() if sort.startswith("-") else col.asc())
        total, rows = page(q, db, min(limit, 200), offset)
        return {"total": total, "items": [_run_dict(r, db) for r in rows]}


def _run(db: Any, request: Request, rid: str, need: str = "viewer") -> AutomationRun:
    r = db.get(AutomationRun, rid)
    if r is None:
        raise ApiError(404, "not_found", "run not found")
    _wf(db, request, r.workflow_id, need)
    return r


@router.get("/workflows/{wid}/runs")
async def wf_runs(request: Request, wid: str, limit: int = 50, offset: int = 0):
    with S(request).sm() as db:
        _wf(db, request, wid)
        total, rows = page(select(AutomationRun).where(AutomationRun.workflow_id == wid).order_by(AutomationRun.queued_at.desc()), db, min(limit, 200), offset)
        return {"total": total, "items": [_run_dict(r, db) for r in rows]}


@router.get("/runs/{rid}")
async def get_run(request: Request, rid: str):
    st = S(request)
    with st.sm() as db:
        r = _run(db, request, rid)
        v = db.get(AutomationVersion, r.version_id) if r.version_id else None
        nodes = _node_dicts(db, rid, st)
        urls: list[str] = []
        for sr in (r.summary_json or {}).get("search_runs", []):               # the actual source URLs the run's evidence came from
            urls += [u for (u,) in db.execute(select(Evidence.original_url).join(Finding, Finding.evidence_id == Evidence.id).where(Finding.run_id == sr).distinct()) if u]
        return _run_dict(r, db) | {"nodes": nodes, "version": {"id": v.id, "revision": v.revision, "hash": v.content_hash} if v else None, "source_urls": sorted(set(urls))[:50],
                                   "environment": {"app": __version__, "platform": platform.platform(), "python": platform.python_version()},
                                   "inputs": (r.summary_json or {}).get("inputs") or (r.inputs_json or {}).get("inputs", {}), "summary_full": r.summary_json,
                                   "label": "SIMULATED (dry run)" if r.dry_run else None}


@router.post("/runs/{rid}/cancel")
async def cancel(request: Request, rid: str):
    st = S(request)
    with st.sm() as db:
        r = _run(db, request, rid, "editor")
        if r.state in TERMINAL:
            raise ApiError(409, "INVALID", f"the run is already {r.state}")
    st.automation.request_cancel(rid)
    with st.sm() as db:
        return _run_dict(db.get(AutomationRun, rid), db)


SAFE_RETRY = {"TIMEOUT", "SOURCE_UNAVAILABLE", "RATE_LIMITED", "OFFLINE", "INTERRUPTED", "CREDENTIAL_MISSING", "UPSTREAM_FAILED", "PARTIAL_RESULT", "RUN_CANCELLED"}


@router.post("/runs/{rid}/retry", status_code=202)
async def retry(request: Request, rid: str, wait: bool = False):
    st = S(request)
    with st.sm() as db:
        r = _run(db, request, rid, "editor")
        wf = db.get(AutomationWorkflow, r.workflow_id)
        if r.state == "paused":
            r.state, r.error_code = "queued", None
            audit.record(db, "automation.run_resumed", actor=actor(request), case_id=r.case_id, resource_id=rid)
            db.commit()
            new_id = rid
        else:
            if r.state not in ("failed", "cancelled", "completed_with_warnings"):
                raise ApiError(409, "INVALID", f"a {r.state} run cannot be retried")
            codes = {n.error_code for n in db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == rid, AutomationNodeRun.state == "failed")) if n.error_code}
            unsafe = sorted(codes - SAFE_RETRY)
            if unsafe:
                raise ApiError(409, "INVALID", f"not retried: {', '.join(unsafe)} are policy or definition problems; fix the cause first")
            v = db.get(AutomationVersion, r.version_id) if r.version_id else None
            payload = r.inputs_json or {}
            new = st.automation.enqueue(db, wf, v, trigger_type="manual", inputs=payload.get("inputs", {}), dry_run=r.dry_run, idem=f"retry:{rid}:{datetime.now(UTC).timestamp()}",
                                        actor=actor(request), case_id=r.case_id, definition=payload.get("definition"), fixture=payload.get("fixture"),
                                        confirmed=payload.get("confirmed_adapters"))
            db.commit()
            new_id = new.id
    if wait:
        await st.automation.execute(new_id)
    else:
        _spawn(st, new_id)
    with st.sm() as db:
        return _run_dict(db.get(AutomationRun, new_id), db)


class ReviewIn(BaseModel):
    node: str
    approve: bool


@router.post("/runs/{rid}/review")
async def review(request: Request, rid: str, body: ReviewIn, wait: bool = False):
    st = S(request)
    with st.sm() as db:
        _run(db, request, rid, "editor")
        ok = st.automation.decide_review(db, rid, body.node, body.approve, actor(request))
        db.commit()
    if not ok:
        raise ApiError(409, "INVALID", "that step is not waiting for a decision")
    if wait:
        await st.automation.execute(rid)
    else:
        _spawn(st, rid)
    with st.sm() as db:
        return _run_dict(db.get(AutomationRun, rid), db)


@router.get("/runs/{rid}/compare/{other}")
async def compare_runs(request: Request, rid: str, other: str):
    st = S(request)
    with st.sm() as db:
        a, b = _run(db, request, rid), _run(db, request, other)
        na = {n["node"]: n for n in _node_dicts(db, a.id, st)}
        nb = {n["node"]: n for n in _node_dicts(db, b.id, st)}
        rows = []
        for k in sorted(set(na) | set(nb)):
            x, y = na.get(k), nb.get(k)
            rows.append({"node": k, "a": {"state": x["state"], "output": x["output"]} if x else None, "b": {"state": y["state"], "output": y["output"]} if y else None,
                         "same_input": bool(x and y and x["input_digest"] == y["input_digest"]), "differs": (x or {}).get("output") != (y or {}).get("output")})
        return {"a": _run_dict(a, db), "b": _run_dict(b, db), "nodes": rows}


@router.get("/runs/{rid}/events")
async def run_events(request: Request, rid: str):
    """Server-sent events: node records as they appear, then the final state."""
    st = S(request)
    with st.sm() as db:
        _run(db, request, rid)

    async def gen():
        seen = 0
        for _ in range(240):
            with st.sm() as db:
                r = db.get(AutomationRun, rid)
                rows = _node_dicts(db, rid, st)
                state = r.state if r else "gone"
            for n in rows[seen:]:
                yield f"event: node\ndata: {json.dumps(n, default=str)}\n\n"
            seen = len(rows)
            yield f"event: state\ndata: {json.dumps({'state': state})}\n\n"
            if state in TERMINAL or state in ("paused", "waiting_for_approval", "gone"):
                return
            await asyncio.sleep(0.5)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})


# ----------------------------------------------------------------------------------------------------------------------- AI builder
class ProposeIn(BaseModel):
    goal: str = Field(min_length=8, max_length=1500)
    case_id: str | None = None
    profile_id: str | None = None


@router.post("/ai/propose")
async def ai_propose(request: Request, body: ProposeIn):
    st = S(request)
    status = await _status(st)
    if body.case_id:
        with st.sm() as db:
            case_for(db, request, body.case_id, "viewer")
    try:
        return await aai.propose(st, Engine(st, actor(request)), actor(request), body.goal, body.case_id, body.profile_id, status)
    except service.ServiceError as exc:
        raise _err(exc) from exc


class ExplainIn(BaseModel):
    workflow_id: str | None = None
    definition: dict[str, Any] | None = None


@router.post("/ai/explain")
async def ai_explain(request: Request, body: ExplainIn):
    st = S(request)
    status = await _status(st)
    if body.workflow_id:
        with st.sm() as db:
            d = _wf(db, request, body.workflow_id).draft_json
    elif body.definition:
        try:
            d = service.normalise(body.definition)
        except service.ServiceError as exc:
            raise _err(exc) from exc
    else:
        raise ApiError(422, "INVALID", "give a workflow_id or a definition")
    return aai.explain(d, st, status)


class DiagIn(BaseModel):
    run_id: str


@router.post("/ai/diagnose")
async def ai_diagnose(request: Request, body: DiagIn):
    st = S(request)
    status = await _status(st)
    with st.sm() as db:
        r = _run(db, request, body.run_id)
        return aai.diagnose(db, st, r, status)


# ----------------------------------------------------------------------------------------------------------------------- suggestions & notifications & settings
@router.get("/suggestions")
async def suggestions(request: Request):
    with S(request).sm() as db:
        enabled = aset.load(db)["suggestions"]["enabled"]
        if enabled:
            sug.refresh(db, actor(request))
            db.commit()
        now = datetime.now(UTC)
        rows = [] if not enabled else [s for s in db.scalars(select(AutomationSuggestion).where(AutomationSuggestion.owner_id == actor(request)).order_by(AutomationSuggestion.created_at.desc()))
                if s.state == "open" or (s.state == "snoozed" and (permissions.aware(s.snooze_until) or now) <= now)]
        return {"enabled": enabled, "items": [{"id": s.id, "case_id": s.case_id, "template": s.proposed_template_key, "category": s.category, "rationale": s.rationale, "basis": s.basis_json,
                                               "created_at": s.created_at} for s in rows],
                "note": "Suggestions come from searches and reports you ran in this app. They never turn anything on." if enabled else "Suggestions are off. Enable them in Settings -> Automations."}


class SnoozeIn(BaseModel):
    days: int = Field(default=7, ge=1, le=90)


def _sug(db: Any, request: Request, sid: str) -> AutomationSuggestion:
    s = db.get(AutomationSuggestion, sid)
    if s is None or s.owner_id != actor(request):
        raise ApiError(404, "not_found", "suggestion not found")
    return s


@router.post("/suggestions/{sid}/dismiss")
async def dismiss(request: Request, sid: str):
    with S(request).sm() as db:
        s = _sug(db, request, sid)
        s.state, s.dismissed_at = "dismissed", datetime.now(UTC)
        db.commit()
        return {"id": sid, "state": s.state}


@router.post("/suggestions/{sid}/snooze")
async def snooze(request: Request, sid: str, body: SnoozeIn):
    from datetime import timedelta
    with S(request).sm() as db:
        s = _sug(db, request, sid)
        s.state, s.snooze_until = "snoozed", datetime.now(UTC) + timedelta(days=body.days)
        db.commit()
        return {"id": sid, "state": s.state, "until": s.snooze_until}


@router.get("/notifications")
async def notifications(request: Request, unacknowledged: bool = False, status: str | None = None, limit: int = 50, offset: int = 0):
    with S(request).sm() as db:
        q = select(AutomationNotification).where(AutomationNotification.owner_id == actor(request), AutomationNotification.status != "suppressed")
        if unacknowledged:
            q = q.where(AutomationNotification.acknowledged_at.is_(None))
        if status:
            q = q.where(AutomationNotification.status == status)
        total, rows = page(q.order_by(AutomationNotification.created_at.desc()), db, min(limit, 200), offset)
        unack = db.scalar(select(func.count()).select_from(AutomationNotification).where(AutomationNotification.owner_id == actor(request), AutomationNotification.acknowledged_at.is_(None),
                                                                                         AutomationNotification.status == "delivered")) or 0
        return {"total": total, "unacknowledged": unack, "items": [{"id": n.id, "workflow_id": n.workflow_id, "run_id": n.run_id, "channel": n.channel, "severity": n.severity,
                                                                    "status": n.status, "title": n.title, "body": n.body, "details": n.details_json, "count": n.count,
                                                                    "created_at": n.created_at, "delivered_at": n.delivered_at, "acknowledged_at": n.acknowledged_at} for n in rows]}


class NotePatch(BaseModel):
    acknowledge: bool = True


@router.patch("/notifications/{nid}")
async def patch_note(request: Request, nid: str, body: NotePatch):
    with S(request).sm() as db:
        n = db.get(AutomationNotification, nid)
        if n is None or n.owner_id != actor(request):
            raise ApiError(404, "not_found", "notification not found")
        n.acknowledged_at = datetime.now(UTC) if body.acknowledge else None
        db.commit()
        return {"id": nid, "acknowledged": body.acknowledge}


class SettingsPatch(BaseModel):
    values: dict[str, Any]


@router.get("/settings")
async def get_settings(request: Request):
    with S(request).sm() as db:
        s = aset.load(db)
    return s | {"email": {"available": False, "note": "email delivery is not implemented; use in-app, desktop or an approved webhook"},
                "timezone_hint": "Pick your own IANA zone (for example America/New_York); the default is UTC"}


@router.patch("/settings", dependencies=[Depends(require_admin)])
async def patch_settings(request: Request, body: SettingsPatch):
    with S(request).sm() as db:
        try:
            new = aset.save(db, body.values)
        except (aset.SettingsError, cron.CronError) as exc:
            raise ApiError(422, "INVALID", str(exc)) from exc
        audit.record(db, "automation.settings", actor=actor(request), metadata={"keys": sorted(body.values)})
        db.commit()
        return new


_ = (ACTIVE_STATES, Case, notes, ERROR_CODES)
