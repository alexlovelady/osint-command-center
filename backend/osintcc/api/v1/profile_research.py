"""Research planning, coverage and subject-bound automation templates (addendum TP-1.0 sections 4, 9). Same conventions as profile.py."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...automations import catalog
from ...automations import service as auto
from ...db.models import ResearchTask, Subject
from ...main import ApiError
from ...profile import hooks, registry, research
from ...profile.service import ProfileError
from ...telemetry import audit
from .automations import _wf_dict
from .profile import perr, subject_for
from .routes import S, actor

router: APIRouter = APIRouter()


async def _health(st, ids: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for i in ids:
        if i in st.adapters:
            out[i] = (await st.adapters[i].health())["status"]
    return out


@router.get("/profile/sources")
async def profile_sources(request: Request):
    """The capability matrix for subject research: what each method needs, produces, costs and how well it has been exercised."""
    st = S(request)
    rows = registry.capability_matrix(st.adapters)
    health = await _health(st, [r["id"] for r in rows if r["registered"] and r["operation_class"] != "manual"])
    return {"items": [{**r, "health": health.get(r["id"])} for r in rows], "categories": registry.CATEGORIES}


class ResearchPreviewIn(BaseModel):
    identifier_ids: list[str] | None = None


@router.post("/subjects/{subject_id}/research/preview")
async def research_preview(request: Request, subject_id: str, body: ResearchPreviewIn):
    st = S(request)
    with st.sm() as db:
        s, case, _ = subject_for(db, request, subject_id, "editor")
        out = research.preview(db, s, case, st.adapters, st.settings, body.identifier_ids)
        audit.record(db, "research.preview", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id,
                     metadata={"entries": len(out["entries"])})
        db.commit()
    health = await _health(st, sorted({e["source_id"] for e in out["entries"] if e["runnable"]}))
    for e in out["entries"]:
        h = health.get(e["source_id"])
        if h:
            e["health"] = h
            if h != "healthy":
                e["warnings"] = [*e["warnings"], f"Tool state: {h.replace('_', ' ')}; it will be skipped."]
                e["runnable"] = False
                e["reason"] = f"tool state: {h.replace('_', ' ')}"
    return out


class ResearchApproveIn(BaseModel):
    keys: list[str] = Field(min_length=1, max_length=research.MAX_TASKS_PER_APPROVAL)
    confirmed_sources: list[str] = Field(default_factory=list)
    wait: bool = False


async def _run_then_refresh(st, run_id: str, subject_id: str) -> None:
    await st.runner.run_until_idle(run_id)
    with st.sm() as db:
        s = db.get(Subject, subject_id)
        if s:
            research.refresh_tasks(db, s)
            db.commit()


@router.post("/subjects/{subject_id}/research/approve", status_code=202)
async def research_approve(request: Request, subject_id: str, body: ResearchApproveIn):
    st = S(request)
    with st.sm() as db:
        s, case, _ = subject_for(db, request, subject_id, "editor")
        try:
            runs = research.approve(db, s, case, st.adapters, st.settings, keys=body.keys, confirmed_sources=body.confirmed_sources, actor=actor(request))
        except ProfileError as exc:
            db.commit()  # keep the refusal's audit entry
            raise perr(exc) from exc
        db.commit()
        run_ids = [r.id for r in runs]
    for rid in run_ids:
        if body.wait:
            await _run_then_refresh(st, rid, subject_id)
        else:
            t = asyncio.create_task(_run_then_refresh(st, rid, subject_id))
            st.tasks.add(t)
            t.add_done_callback(st.tasks.discard)
    return {"run_ids": run_ids, "tasks": len(body.keys)}


@router.get("/subjects/{subject_id}/research/runs")
async def research_runs(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id)
        research.refresh_tasks(db, s)
        db.commit()
        rows = db.scalars(select(ResearchTask).where(ResearchTask.subject_id == s.id).order_by(ResearchTask.created_at.desc())).all()
        return {"total": len(rows), "items": [
            {"id": t.id, "category": t.category, "source_id": t.source_id, "status": t.status, "run_id": t.run_id, "last_attempt": t.last_attempt,
             "last_success": t.last_success, "result_count": t.result_count, "limitations": t.limitations, "approval_reference": t.approval_reference}
            for t in rows]}


@router.get("/subjects/{subject_id}/coverage")
async def get_coverage(request: Request, subject_id: str):
    st = S(request)
    with st.sm() as db:
        subject_for(db, request, subject_id)
    health = await _health(st, [i for i in st.adapters if i in registry.SOURCES])
    with st.sm() as db:
        s = db.get(Subject, subject_id)
        assert s is not None
        cov = research.coverage(db, s, st.adapters, health)
        cov["next_action"] = research.next_action(db, s, cov)
        cov["last_collected"] = research.last_collected(db, s)
        db.commit()
    return cov


@router.get("/subjects/{subject_id}/templates")
async def subject_templates(request: Request, subject_id: str):
    st = S(request)
    with st.sm() as db:
        subject_for(db, request, subject_id)
    health = await _health(st, list(st.adapters))
    return {"items": [catalog.public(t, catalog.availability(t, health, st.adapters), detail=False) for t in catalog.load_all() if t["category"] == "Target profile"]}


class SubjectWorkflowIn(BaseModel):
    slug: str
    inputs: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


@router.post("/subjects/{subject_id}/workflows", status_code=201)
async def subject_workflow(request: Request, subject_id: str, body: SubjectWorkflowIn):
    """Installs a Target-profile template as a DISABLED draft bound to this subject: every run then needs the subject's live authorization."""
    st = S(request)
    t = catalog.get(body.slug)
    if t is None or t["category"] != "Target profile":
        raise ApiError(404, "not_found", "no such Target profile template")
    d: dict[str, Any] = json.loads(json.dumps(t["definition"]))
    for k, v in body.inputs.items():
        if k not in d["inputs"]:
            raise ApiError(422, "INVALID_GRAPH", f"unknown input {k!r}")
        d["inputs"][k] = v
    with st.sm() as db:
        s, case, _ = subject_for(db, request, subject_id, "editor")
        d["tags"] = [*d.get("tags", [])[:10], f"{hooks.TAG_PREFIX}{s.id}"]
        try:
            wf = auto.create_workflow(db, owner=actor(request), definition=d, case_id=case.id, name=None, template_slug=t["slug"])
        except auto.ServiceError as exc:
            raise ApiError(exc.status, exc.code, exc.message) from exc
        audit.record(db, "subject.workflow_install", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id,
                     metadata={"slug": t["slug"]})
        db.commit()
        return _wf_dict(wf, db, True)
