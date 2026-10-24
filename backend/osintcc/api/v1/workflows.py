"""Workflow, schedule and alert endpoints (spec 7, 10)."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...db.models import Alert, Case, Schedule, Workflow, WorkflowRun
from ...main import ApiError
from ...policy.targets import TargetError, detect_target
from ...search import service
from ...telemetry import audit
from ...workflows import WorkflowError, execute, load_templates, parse_definition, parse_interval, waves
from .routes import S, actor, case_for

router: APIRouter = APIRouter()
TEMPLATE_DIR = Path(__file__).resolve().parents[4] / "configs" / "workflow-templates"


def _wf(db, request, wid: str, need="viewer") -> Workflow:
    wf = db.get(Workflow, wid)
    if not wf:
        raise ApiError(404, "not_found", "workflow not found")
    if wf.case_id:
        case_for(db, request, wf.case_id, need)
    return wf


def _problems(exc: WorkflowError) -> ApiError:
    return ApiError(422, "invalid_workflow", "the workflow definition is not valid", False, {"problems": exc.problems})


class WfIn(BaseModel):
    case_id: str | None = None
    definition: dict[str, Any]


@router.get("/workflow-templates")
async def templates(request: Request):
    st = S(request)
    out = []
    for t in load_templates(TEMPLATE_DIR):
        try:
            parse_definition(t, st.adapters)
            out.append({**t, "valid": True})
        except WorkflowError as exc:
            out.append({**t, "valid": False, "problems": exc.problems})
    return {"items": out}


@router.post("/workflows", status_code=201)
async def create_workflow(request: Request, body: WfIn):
    st = S(request)
    try:
        d = parse_definition(body.definition, st.adapters)
    except WorkflowError as exc:
        raise _problems(exc) from exc
    with st.sm() as db:
        if body.case_id:
            case_for(db, request, body.case_id, "editor")
        wf = Workflow(case_id=body.case_id, name=d.name, definition_json=d.model_dump(), created_by=actor(request))
        db.add(wf)
        db.flush()
        audit.record(db, "workflow.create", actor=actor(request), case_id=body.case_id, resource_id=wf.id)
        db.commit()
        return {"id": wf.id, "name": wf.name, "definition": wf.definition_json}


@router.get("/workflows")
async def list_workflows(request: Request, case_id: str | None = None):
    with S(request).sm() as db:
        if case_id:
            case_for(db, request, case_id)
        q = select(Workflow).where(Workflow.case_id == case_id) if case_id else select(Workflow).where(Workflow.case_id.is_(None))
        return {"items": [{"id": w.id, "name": w.name, "case_id": w.case_id, "enabled": w.enabled,
                           "nodes": len(w.definition_json["nodes"])} for w in db.scalars(q)]}


class RunIn(BaseModel):
    case_id: str
    target: str = Field(min_length=1, max_length=2048)
    target_type: str | None = None
    confirmed_adapters: list[str] = Field(default_factory=list)
    wait: bool = True


@router.post("/workflows/{wid}/preview")
async def preview_workflow(request: Request, wid: str, body: RunIn):
    """Validation + every request the whole DAG would make. Contacts nothing."""
    st = S(request)
    with st.sm() as db:
        wf = _wf(db, request, wid)
        case = case_for(db, request, body.case_id, "viewer")
        try:
            d = parse_definition(wf.definition_json, st.adapters)
            parsed = detect_target(body.target, body.target_type)
            steps, warnings = [], []
            for i, wave in enumerate(waves(d), start=1):
                ids = [n.adapter for n in wave if n.adapter]
                if ids:
                    plan = service.build_plan(db, case, parsed, st.adapters, st.settings, selected=ids,
                                              mode="active" if d.policy.active_allowed else "passive")
                    steps += [{**s, "wave": i} for s in plan["steps"]]
                    warnings += plan["warnings"]
        except WorkflowError as exc:
            raise _problems(exc) from exc
        except (TargetError, service.PlanError) as exc:
            raise ApiError(422, "plan_rejected", str(exc)) from exc
        return {"workflow": wf.name, "target": parsed.as_dict(), "waves": [[n.id for n in w] for w in waves(d)], "steps": steps,
                "warnings": sorted(set(warnings)),
                "estimated_requests": sum(1 for s in steps if s["runnable"] and s.get("needs_network")),
                "paid_requests": 0, "note": "Nothing has been sent."}


@router.post("/workflows/{wid}/run", status_code=202)
async def run_workflow(request: Request, wid: str, body: RunIn):
    st = S(request)
    with st.sm() as db:
        _wf(db, request, wid, "editor")
        case_for(db, request, body.case_id, "editor")
    try:
        if body.wait:
            return await execute(st, wid, body.case_id, body.target, body.target_type, body.confirmed_adapters, "manual",
                                 None, actor(request))
        t = asyncio.create_task(execute(st, wid, body.case_id, body.target, body.target_type, body.confirmed_adapters, "manual",
                                        None, actor(request)))
        st.tasks.add(t)
        t.add_done_callback(st.tasks.discard)
        return {"status": "started"}
    except WorkflowError as exc:
        raise _problems(exc) from exc
    except (TargetError, service.PlanError) as exc:
        raise ApiError(422, "plan_rejected", str(exc)) from exc


@router.get("/workflows/{wid}/runs")
async def workflow_runs(request: Request, wid: str):
    with S(request).sm() as db:
        _wf(db, request, wid)
        return {"items": [{"id": r.id, "status": r.status, "trigger": r.trigger, "started_at": r.started_at, "ended_at": r.ended_at,
                           "summary": r.summary_json} for r in db.scalars(select(WorkflowRun).where(WorkflowRun.workflow_id == wid)
                                                                          .order_by(WorkflowRun.started_at.desc()).limit(50))]}


# ------------------------------------------------------------------ schedules -----------------------------------------
class SchedIn(BaseModel):
    workflow_id: str
    case_id: str
    target: str = Field(min_length=1, max_length=2048)
    target_type: str | None = None
    interval: str
    confirmed_adapters: list[str] = Field(default_factory=list)
    acknowledge_individual_monitoring: bool = False
    reason: str = Field(min_length=3, max_length=1000)


def _sched_dict(s: Schedule) -> dict:
    return {"id": s.id, "workflow_id": s.workflow_id, "case_id": s.case_id, "target": s.target_raw, "interval": s.cron_or_interval,
            "enabled": s.enabled, "next_run_at": s.next_run_at, "last_run_at": s.last_run_at, "last_status": s.last_status,
            "consecutive_failures": s.consecutive_failures, "policy_snapshot": s.target_policy_snapshot_json}


@router.post("/schedules", status_code=201)
async def create_schedule(request: Request, body: SchedIn):
    """Created DISABLED. Monitoring individuals needs an explicit acknowledgement and a documented case purpose."""
    st = S(request)
    try:
        parse_interval(body.interval)
        parsed = detect_target(body.target, body.target_type)
    except (WorkflowError, TargetError) as exc:
        raise ApiError(422, "invalid_schedule", str(exc)) from exc
    with st.sm() as db:
        case = case_for(db, request, body.case_id, "editor")
        wf = _wf(db, request, body.workflow_id, "editor")
        if wf.case_id and wf.case_id != body.case_id:
            raise ApiError(409, "workflow_case_mismatch", "this workflow belongs to a different case")
        personal = case.category == "people" or parsed.type in ("username", "email")
        if personal and not (body.acknowledge_individual_monitoring and case.purpose.strip()):
            raise ApiError(422, "individual_monitoring_blocked",
                           "recurring monitoring of an individual needs a documented case purpose and "
                           "acknowledge_individual_monitoring=true; it is off by default")
        s = Schedule(workflow_id=wf.id, case_id=case.id, target_raw=body.target, target_type=body.target_type,
                     cron_or_interval=body.interval, next_run_at=datetime.now(UTC), enabled=False,
                     confirmed_adapters_json=body.confirmed_adapters, created_by=actor(request),
                     target_policy_snapshot_json={"reason": body.reason, "personal": personal, "category": case.category,
                                                  "purpose": case.purpose[:200], "created": datetime.now(UTC).isoformat()})
        db.add(s)
        db.flush()
        audit.record(db, "schedule.create", actor=actor(request), case_id=case.id, resource_id=s.id, metadata={"interval": body.interval})
        db.commit()
        return _sched_dict(s)


class EnableIn(BaseModel):
    confirm: bool = False


@router.post("/schedules/{sid}/enable")
async def enable_schedule(request: Request, sid: str, body: EnableIn):
    st = S(request)
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "enabling recurring collection needs confirm=true")
    with st.sm() as db:
        s = db.get(Schedule, sid)
        if not s:
            raise ApiError(404, "not_found", "schedule not found")
        case = case_for(db, request, s.case_id, "owner")
        if case.status != "open":
            raise ApiError(409, "case_not_open", "case must be open")
        wf = db.get(Workflow, s.workflow_id)
        try:  # dry-run policy now; execution re-checks again every time
            d = parse_definition(wf.definition_json, st.adapters)
            parsed = detect_target(s.target_raw, s.target_type)
            for wave in waves(d):
                ids = [n.adapter for n in wave if n.adapter]
                if ids:
                    plan = service.build_plan(db, case, parsed, st.adapters, st.settings, selected=ids,
                                              mode="active" if d.policy.active_allowed else "passive")
                    blocked = [x for x in plan["steps"] if not x["runnable"]]
                    unconfirmed = [x["adapter_id"] for x in plan["steps"] if x.get("requires_confirmation")
                                   and x["adapter_id"] not in s.confirmed_adapters_json]
                    if blocked or unconfirmed:
                        raise ApiError(409, "policy_blocked", "policy would currently block part of this workflow",
                                       False, {"blocked": [b["adapter_id"] for b in blocked], "unconfirmed": unconfirmed})
        except (WorkflowError, TargetError, service.PlanError) as exc:
            raise ApiError(409, "policy_blocked", str(exc)) from exc
        s.enabled, s.consecutive_failures, s.last_status = True, 0, "enabled"
        s.next_run_at = datetime.now(UTC) + parse_interval(s.cron_or_interval)
        audit.record(db, "schedule.enable", actor=actor(request), case_id=s.case_id, resource_id=sid)
        db.commit()
        return _sched_dict(s)


@router.post("/schedules/{sid}/disable")
async def disable_schedule(request: Request, sid: str):
    with S(request).sm() as db:
        s = db.get(Schedule, sid)
        if not s:
            raise ApiError(404, "not_found", "schedule not found")
        case_for(db, request, s.case_id, "editor")
        s.enabled, s.last_status = False, "disabled"
        audit.record(db, "schedule.disable", actor=actor(request), case_id=s.case_id, resource_id=sid)
        db.commit()
        return _sched_dict(s)


@router.get("/schedules")
async def list_schedules(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [_sched_dict(s) for s in db.scalars(select(Schedule).where(Schedule.case_id == case_id))]}


@router.delete("/schedules/{sid}")
async def delete_schedule(request: Request, sid: str):
    with S(request).sm() as db:
        s = db.get(Schedule, sid)
        if not s:
            raise ApiError(404, "not_found", "schedule not found")
        case_for(db, request, s.case_id, "editor")
        db.delete(s)
        audit.record(db, "schedule.delete", actor=actor(request), case_id=s.case_id, resource_id=sid)
        db.commit()
        return {"deleted": sid}


# ------------------------------------------------------------------ alerts ---------------------------------------------
@router.get("/cases/{case_id}/alerts")
async def list_alerts(request: Request, case_id: str, unacknowledged: bool = False):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        q = select(Alert).where(Alert.case_id == case_id).order_by(Alert.created_at.desc())
        if unacknowledged:
            q = q.where(Alert.acknowledged_at.is_(None))
        return {"items": [{"id": a.id, "type": a.type, "severity": a.severity, "message": a.message, "details": a.details_json,
                           "created_at": a.created_at, "acknowledged_at": a.acknowledged_at,
                           "old_fingerprint": a.old_fingerprint, "new_fingerprint": a.new_fingerprint} for a in db.scalars(q)]}


@router.post("/alerts/{aid}/acknowledge")
async def ack_alert(request: Request, aid: str):
    with S(request).sm() as db:
        a = db.get(Alert, aid)
        if not a:
            raise ApiError(404, "not_found", "alert not found")
        case_for(db, request, a.case_id, "editor")
        a.acknowledged_at = datetime.now(UTC)
        db.commit()
        return {"id": aid, "acknowledged_at": a.acknowledged_at}


_ = Case
