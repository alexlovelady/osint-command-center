"""/api/v1 routes. Every route checks the caller's case membership server-side (spec 23.1.2)."""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import backup as backup_mod
from ...db import encrypt as dbenc
from ...db.models import (
    Case,
    CaseMember,
    Entity,
    Evidence,
    Finding,
    GraphProposal,
    Job,
    JobEvent,
    Note,
    Relationship,
    RelationshipEvidence,
    ReportRun,
    Requirement,
    ScopeAuthorization,
    SearchRun,
    Setting,
    Source,
    Target,
)
from ...doctor import run_doctor
from ...evidence.vault import IntegrityError, VaultError, VaultLocked
from ...main import ApiError, AppState
from ...policy.targets import TargetError
from ...reporting import build as report_build
from ...reporting import store as report_store
from ...search import service
from ...telemetry import audit

router: APIRouter = APIRouter()
ROLE_RANK = {"viewer": 1, "editor": 2, "owner": 3}


def S(request: Request) -> AppState:
    return request.app.state.core


def actor(request: Request) -> str:
    return request.state.user_id


def case_for(db: Session, request: Request, case_id: str, need: str = "viewer") -> Case:
    """Membership check at the API boundary. Non-members get 404 (existence is not disclosed)."""
    m = db.get(CaseMember, (case_id, actor(request)))
    case = db.get(Case, case_id)
    if not case or not m or ROLE_RANK[m.access_role] < ROLE_RANK[need]:
        audit.record(db, "access.denied", actor=actor(request), case_id=case_id, decision="deny",
                     metadata={"need": need})
        db.commit()
        raise ApiError(404, "not_found", "case not found")
    return case


def require_admin(request: Request) -> None:
    """Global (not case-scoped) operations need the admin role, enforced here and not in the UI."""
    from ...db.models import UserRole
    with S(request).sm() as db:
        if db.get(UserRole, (actor(request), "role-admin")) is None:
            audit.record(db, "access.denied", actor=actor(request), decision="deny", metadata={"need": "admin", "path": request.url.path})
            db.commit()
            raise ApiError(403, "admin_required", "this action needs the admin role")


def page(q, db: Session, limit: int, offset: int):
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    return total, db.scalars(q.limit(limit).offset(offset)).all()


def case_dict(c: Case) -> dict:
    return {"id": c.id, "title": c.title, "description": c.description, "category": c.category, "status": c.status,
            "purpose": c.purpose, "scope": c.scope_json, "created_at": c.created_at, "updated_at": c.updated_at,
            "archived_at": c.archived_at}


# ---- health / system ----------------------------------------------------------------------------------------------
@router.get("/health/live")
async def live():
    return {"status": "ok"}


@router.get("/health/ready")
async def ready(request: Request):
    st = S(request)
    with st.sm() as db:
        db.execute(select(1))
        q = db.connection().exec_driver_sql("PRAGMA quick_check").fetchone()[0]
    return {"status": "ready" if q == "ok" else "degraded", "db_quick_check": q, "offline": st.settings.offline,
            "vault": str(st.vault.root.name), "recovered_jobs": getattr(request.app.state, "recovered_jobs", 0)}


@router.get("/system/doctor")
async def doctor(request: Request):
    st = S(request)
    rep = await asyncio.to_thread(run_doctor)
    with st.sm() as db:
        ok, n, bad = audit.verify_chain(db)
        rep["audit_chain"] = {"ok": ok, "events": n, "first_bad_seq": bad}
        rep["db_integrity"] = db.connection().exec_driver_sql("PRAGMA quick_check").fetchone()[0]
        sample = db.scalars(select(Evidence).where(Evidence.vault_relpath.is_not(None)).limit(25)).all()
        rep["evidence_sample_verified"] = {"checked": len(sample),
                                           "bad": [e.id for e in sample if not st.vault.verify(e.vault_relpath, e.sha256)]}
    backups = sorted(st.settings.backup_dir.glob("OSINTCC-backup-*.zip")) if st.settings.backup_dir.exists() else []
    rep["last_backup"] = backups[-1].name if backups else None
    return rep


# ---- cases ---------------------------------------------------------------------------------------------------------
class CaseIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = ""
    category: Literal["cyber", "business", "geospatial", "media", "people", "threat"] = "cyber"
    purpose: str = ""
    legal_basis_notes: str = ""
    scope: dict[str, Any] = Field(default_factory=dict)


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = None
    purpose: str | None = None
    status: Literal["open", "paused", "closed"] | None = None
    scope: dict[str, Any] | None = None


@router.get("/cases")
async def list_cases(request: Request, limit: int = Query(50, le=200), offset: int = 0, status: str | None = None):
    with S(request).sm() as db:
        q = (select(Case).join(CaseMember, CaseMember.case_id == Case.id)
             .where(CaseMember.user_id == actor(request)).order_by(Case.updated_at.desc()))
        if status:
            q = q.where(Case.status == status)
        total, rows = page(q, db, limit, offset)
        out = []
        for c in rows:
            d = case_dict(c)
            d["finding_count"] = db.scalar(select(func.count()).select_from(Finding).where(Finding.case_id == c.id))
            out.append(d)
        return {"total": total, "items": out}


@router.post("/cases", status_code=201)
async def create_case(request: Request, body: CaseIn):
    if body.category == "people" and not body.purpose.strip():
        raise ApiError(422, "purpose_required", "A documented purpose is required for public-identity cases.")
    with S(request).sm() as db:
        c = Case(title=body.title, description=body.description, category=body.category, purpose=body.purpose,
                 legal_basis_notes=body.legal_basis_notes, scope_json=body.scope, owner_id=actor(request))
        db.add(c)
        db.flush()
        db.add(CaseMember(case_id=c.id, user_id=actor(request), access_role="owner"))
        audit.record(db, "case.create", actor=actor(request), case_id=c.id, resource_type="case", resource_id=c.id)
        db.commit()
        return case_dict(c)


@router.get("/cases/{case_id}")
async def get_case(request: Request, case_id: str):
    with S(request).sm() as db:
        return case_dict(case_for(db, request, case_id))


@router.patch("/cases/{case_id}")
async def patch_case(request: Request, case_id: str, body: CasePatch):
    with S(request).sm() as db:
        c = case_for(db, request, case_id, "editor")
        if c.status == "archived":
            raise ApiError(409, "archived", "archived cases are read-only")
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(c, "scope_json" if k == "scope" else k, v)
        audit.record(db, "case.update", actor=actor(request), case_id=c.id, resource_type="case", resource_id=c.id,
                     metadata={"fields": list(body.model_dump(exclude_none=True))})
        db.commit()
        return case_dict(c)


class Confirm(BaseModel):
    confirm: bool = False


@router.post("/cases/{case_id}/archive")
async def archive_case(request: Request, case_id: str, body: Confirm):
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "archive requires confirm=true")
    with S(request).sm() as db:
        c = case_for(db, request, case_id, "owner")
        c.status, c.archived_at = "archived", datetime.now(UTC)
        audit.record(db, "case.archive", actor=actor(request), case_id=c.id, resource_type="case", resource_id=c.id)
        db.commit()
        return case_dict(c)


class MemberIn(BaseModel):
    user_id: str
    access_role: Literal["viewer", "editor", "owner"] = "viewer"


@router.post("/cases/{case_id}/members", status_code=201)
async def add_member(request: Request, case_id: str, body: MemberIn):
    from ...db.models import User
    with S(request).sm() as db:
        case_for(db, request, case_id, "owner")
        if not db.get(User, body.user_id):
            raise ApiError(404, "not_found", "user not found")
        db.merge(CaseMember(case_id=case_id, user_id=body.user_id, access_role=body.access_role))
        audit.record(db, "case.member_add", actor=actor(request), case_id=case_id, metadata=body.model_dump())
        db.commit()
        return {"ok": True}


# ---- targets / searches ------------------------------------------------------------------------------------------------
class SearchIn(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    target_type: Literal["domain", "ip", "url", "email", "username"] | None = None
    adapters: list[str] | None = None
    mode: Literal["passive", "public_site_query", "active"] = "passive"
    confirmed_adapters: list[str] = Field(default_factory=list)
    wait: bool = False


def _preview(db, st, case, body: SearchIn):
    try:
        return service.preview(db, case, body.target, body.target_type, st.adapters, st.settings, body.adapters, body.mode)
    except TargetError as exc:
        raise ApiError(422, "invalid_target", str(exc)) from exc
    except service.PlanError as exc:
        raise ApiError(422, "plan_rejected", str(exc)) from exc


@router.post("/cases/{case_id}/searches/preview")
async def search_preview(request: Request, case_id: str, body: SearchIn):
    st = S(request)
    with st.sm() as db:
        case = case_for(db, request, case_id, "viewer")
        _, plan = _preview(db, st, case, body)
    for step in plan["steps"]:  # local smoke test only (--version); never contacts targets
        h = await st.adapters[step["adapter_id"]].health()
        step["health"] = h["status"]
        if h["status"] != "healthy":
            step["warnings"] = [*step.get("warnings", []), f"Tool state: {h['status'].replace('_', ' ')}; it will be skipped."]
    return plan  # no side effects, no network


@router.post("/cases/{case_id}/searches", status_code=202)
async def search_launch(request: Request, case_id: str, body: SearchIn):
    st = S(request)
    with st.sm() as db:
        case = case_for(db, request, case_id, "editor")
        if case.status != "open":
            raise ApiError(409, "case_not_open", "case must be open to run searches")
        parsed, plan = _preview(db, st, case, body)
        try:
            run = service.create_run(db, case, parsed, plan, confirmed=body.confirmed_adapters, mode=body.mode)
        except service.PlanError as exc:
            audit.record(db, "search.refused", actor=actor(request), case_id=case_id, decision="deny",
                         metadata={"reason": str(exc)})
            db.commit()
            raise ApiError(409, "plan_refused", str(exc)) from exc
        db.commit()
        run_id = run.id
    if body.wait:
        await st.runner.run_until_idle(run_id)
    else:
        t = asyncio.create_task(st.runner.run_until_idle(run_id))
        st.tasks.add(t)
        t.add_done_callback(st.tasks.discard)
    return _run_dict(st, run_id)


def _run_dict(st: AppState, run_id: str) -> dict:
    with st.sm() as db:
        run = db.get(SearchRun, run_id)
        jobs = db.scalars(select(Job).where(Job.run_id == run_id)).all()
        return {"id": run.id, "case_id": run.case_id, "status": run.status, "mode": run.mode,
                "started_at": run.started_at, "ended_at": run.ended_at, "summary": run.summary_json,
                "permission_snapshot": run.permission_snapshot_json,
                "jobs": [{"id": j.id, "adapter_id": j.adapter_id, "status": j.status, "attempts": j.attempts,
                          "error_code": j.last_error_code, "warnings": j.warnings_json,
                          "next_retry_at": j.next_retry_at} for j in jobs]}


def run_case(db, request, run_id: str, need="viewer") -> SearchRun:
    run = db.get(SearchRun, run_id)
    if not run:
        raise ApiError(404, "not_found", "run not found")
    case_for(db, request, run.case_id, need)
    return run


@router.get("/search-runs/{run_id}")
async def get_run(request: Request, run_id: str):
    st = S(request)
    with st.sm() as db:
        run_case(db, request, run_id)
    return _run_dict(st, run_id)


@router.post("/search-runs/{run_id}/cancel")
async def cancel_run(request: Request, run_id: str):
    st = S(request)
    with st.sm() as db:
        run_case(db, request, run_id, "editor")
    st.runner.cancel_run(run_id)
    return _run_dict(st, run_id)


@router.get("/search-runs/{run_id}/events")
async def run_events(request: Request, run_id: str):
    st = S(request)
    with st.sm() as db:
        run_case(db, request, run_id)
    start = int(request.headers.get("last-event-id", "-1") or -1) + 1

    async def gen():
        idx = start
        for _ in range(600):
            with st.sm() as db:
                evs = db.scalars(select(JobEvent).where(JobEvent.run_id == run_id)
                                 .order_by(JobEvent.occurred_at, JobEvent.sequence)).all()
                run = db.get(SearchRun, run_id)
                jobs = {j.id: j.adapter_id for j in db.scalars(select(Job).where(Job.run_id == run_id))}
                terminal = run.status not in ("queued", "running")
            for i, e in enumerate(evs[idx:], start=idx):
                payload = json.dumps({"adapter": jobs.get(e.job_id), "type": e.event_type, **e.payload_json})
                yield f"id: {i}\nevent: job\ndata: {payload}\n\n"
                idx = i + 1
            if terminal and idx >= len(evs):
                yield f"event: done\ndata: {json.dumps({'status': run.status})}\n\n"
                return
            yield ": keepalive\n\n"
            await asyncio.sleep(0.25)

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/cases/{case_id}/runs")
async def list_runs(request: Request, case_id: str, limit: int = Query(50, le=200), offset: int = 0):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id)
        total, rows = page(select(SearchRun).where(SearchRun.case_id == case_id).order_by(SearchRun.started_at.desc()),
                           db, limit, offset)
        items = [{"id": r.id, "status": r.status, "started_at": r.started_at, "adapters": r.selected_adapters_json,
                  "target": db.get(Target, r.target_id).canonical_value} for r in rows]
    return {"total": total, "items": items}


@router.get("/cases/{case_id}/targets")
async def list_targets(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [{"id": t.id, "type": t.type, "value": t.canonical_value, "scope_status": t.scope_status}
                          for t in db.scalars(select(Target).where(Target.case_id == case_id))]}


# ---- findings / entities / graph / timeline ----------------------------------------------------------------------------------
@router.get("/cases/{case_id}/findings")
async def findings(request: Request, case_id: str, q: str | None = None, adapter: str | None = None,
                   confidence: str | None = None, limit: int = Query(100, le=500), offset: int = 0):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        qq = (select(Finding, Entity, Evidence).join(Entity, Entity.id == Finding.subject_entity_id)
              .join(Evidence, Evidence.id == Finding.evidence_id).where(Finding.case_id == case_id)
              .order_by(Finding.observed_at, Finding.predicate))
        if adapter:
            qq = qq.where(Finding.adapter_id == adapter)
        if confidence:
            qq = qq.where(Finding.confidence == confidence)
        if q:
            like = f"%{q.lower()}%"
            qq = qq.where(func.lower(Entity.display_name).like(like) | func.lower(Finding.predicate).like(like)
                          | func.lower(func.cast(Finding.value_json, __import__("sqlalchemy").String)).like(like))
        total = db.scalar(select(func.count()).select_from(qq.subquery()))
        rows = db.execute(qq.limit(limit).offset(offset)).all()
        return {"total": total, "items": [{
            "id": f.id, "subject": e.display_name, "subject_type": e.type, "predicate": f.predicate,
            "value": f.value_json, "confidence": f.confidence, "confidence_reason": f.confidence_reason,
            "status": f.status, "adapter": f.adapter_id, "adapter_version": f.adapter_version,
            "evidence_id": f.evidence_id, "source_url": ev.original_url, "observed_at": f.observed_at,
            "source_published_at": f.source_published_at} for f, e, ev in rows]}


@router.get("/cases/{case_id}/entities")
async def entities(request: Request, case_id: str, type: str | None = None, q: str | None = None,
                   limit: int = Query(200, le=1000), offset: int = 0):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        qq = select(Entity).where(Entity.case_id == case_id).order_by(Entity.type, Entity.canonical_key)
        if type:
            qq = qq.where(Entity.type == type)
        if q:
            qq = qq.where(func.lower(Entity.display_name).like(f"%{q.lower()}%"))
        total, rows = page(qq, db, limit, offset)
        return {"total": total, "items": [{"id": e.id, "type": e.type, "key": e.canonical_key,
                                           "display": e.display_name, "first_seen_at": e.first_seen_at,
                                           "last_seen_at": e.last_seen_at} for e in rows]}


@router.get("/cases/{case_id}/graph")
async def graph(request: Request, case_id: str, node_limit: int = Query(250, le=250),
                status: str | None = None, entity_type: str | None = None, apply_merges: bool = False):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        rq = select(Relationship).where(Relationship.case_id == case_id, Relationship.status != "rejected")
        if status:
            rq = rq.where(Relationship.status == status)
        rels = db.scalars(rq).all()
        from ...graph.fusion import active_merge_map
        mm = active_merge_map(db, case_id) if apply_merges else {}
        deg: dict[str, int] = {}
        for r in rels:
            a, b = mm.get(r.from_entity_id, r.from_entity_id), mm.get(r.to_entity_id, r.to_entity_id)
            if a == b:
                continue  # a merge can collapse an edge into a self-loop; drop it from the merged view only
            deg[a] = deg.get(a, 0) + 1
            deg[b] = deg.get(b, 0) + 1
        ents = {e.id: e for e in db.scalars(select(Entity).where(Entity.case_id == case_id))}
        keep = sorted(deg, key=lambda i: -deg[i])[:node_limit]
        keepset = set(keep)
        if entity_type:
            keepset = {i for i in keepset if ents[i].type == entity_type}
        edges = []
        for r in rels:
            fa, fb = mm.get(r.from_entity_id, r.from_entity_id), mm.get(r.to_entity_id, r.to_entity_id)
            if fa != fb and fa in keepset and fb in keepset:
                eids = [x.evidence_id for x in db.scalars(select(RelationshipEvidence)
                                                          .where(RelationshipEvidence.relationship_id == r.id))]
                edges.append({"id": r.id, "source": fa, "target": fb, "type": r.relation_type,
                              "status": r.status, "confidence": r.confidence,
                              "confidence_reason": r.confidence_reason, "evidence_ids": eids})
        return {"nodes": [{"id": i, "type": ents[i].type, "label": ents[i].display_name, "degree": deg[i]}
                          for i in keepset],
                "edges": edges, "truncated": len(deg) > node_limit, "total_nodes": len(deg),
                "note": "Edges are source assertions with attached evidence, not verified real-world relationships."}


class ProposalIn(BaseModel):
    subject_id: str
    candidate_id: str
    reason: str = ""


class DecisionIn(BaseModel):
    decision: Literal["accept", "reject"]
    evidence_id: str | None = None


@router.post("/cases/{case_id}/graph/proposals", status_code=201)
async def create_proposal(request: Request, case_id: str, body: ProposalIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        for i in (body.subject_id, body.candidate_id):
            e = db.get(Entity, i)
            if not e or e.case_id != case_id:
                raise ApiError(404, "not_found", "entity not in this case")
        p = GraphProposal(case_id=case_id, subject_id=body.subject_id, candidate_id=body.candidate_id,
                          reason=body.reason)
        db.add(p)
        db.commit()
        return {"id": p.id, "status": p.status}


@router.post("/cases/{case_id}/graph/proposals/{pid}/decision")
async def decide_proposal(request: Request, case_id: str, pid: str, body: DecisionIn):
    """Accepting never merges entities: it records a manual, evidence-backed `same_as` assertion that is reversible."""
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        p = db.get(GraphProposal, pid)
        if not p or p.case_id != case_id:
            raise ApiError(404, "not_found", "proposal not found")
        if p.status != "pending":
            raise ApiError(409, "already_decided", "proposal already decided")
        if body.decision == "accept":
            ev = db.get(Evidence, body.evidence_id) if body.evidence_id else None
            if not ev or ev.case_id != case_id:
                raise ApiError(422, "evidence_required", "accepting requires an evidence item from this case")
            rel = Relationship(case_id=case_id, from_entity_id=p.subject_id, to_entity_id=p.candidate_id,
                               relation_type="same_as", confidence="unknown", status="manual",
                               confidence_reason="Analyst decision; see attached evidence", asserted_by=actor(request))
            db.add(rel)
            db.flush()
            db.add(RelationshipEvidence(relationship_id=rel.id, evidence_id=ev.id))
        p.status = "accepted" if body.decision == "accept" else "rejected"
        p.decided_at = datetime.now(UTC)
        audit.record(db, "graph.proposal_decision", actor=actor(request), case_id=case_id, resource_id=pid,
                     metadata={"decision": body.decision})
        db.commit()
        return {"id": p.id, "status": p.status}


@router.post("/cases/{case_id}/relationships/{rel_id}/reject")
async def reject_relationship(request: Request, case_id: str, rel_id: str):
    """Reversible: rejection only flips status; the row and its evidence stay."""
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        r = db.get(Relationship, rel_id)
        if not r or r.case_id != case_id:
            raise ApiError(404, "not_found", "relationship not found")
        r.status = "rejected"
        audit.record(db, "graph.relationship_reject", actor=actor(request), case_id=case_id, resource_id=rel_id)
        db.commit()
        return {"id": r.id, "status": r.status}


@router.get("/cases/{case_id}/timeline")
async def timeline(request: Request, case_id: str, limit: int = Query(200, le=1000), offset: int = 0):
    """Three distinct times per item; `time_unknown` is explicit rather than silently substituted."""
    with S(request).sm() as db:
        case_for(db, request, case_id)
        rows = db.execute(select(Finding, Entity, Evidence).join(Entity, Entity.id == Finding.subject_entity_id)
                          .join(Evidence, Evidence.id == Finding.evidence_id).where(Finding.case_id == case_id)
                          .order_by(func.coalesce(Finding.source_published_at, Finding.observed_at))
                          .limit(limit).offset(offset)).all()
        return {"items": [{"finding_id": f.id, "subject": e.display_name, "predicate": f.predicate, "value": f.value_json,
                           "observed_at": f.observed_at, "source_published_at": f.source_published_at,
                           "captured_at": ev.retrieved_at, "time_unknown": f.source_published_at is None}
                          for f, e, ev in rows]}


# ---- notes / requirements -------------------------------------------------------------------------------------------------------
class NoteIn(BaseModel):
    body_markdown: str = Field(min_length=1, max_length=20000)
    entity_id: str | None = None
    evidence_id: str | None = None


@router.get("/cases/{case_id}/notes")
async def get_notes(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [{"id": n.id, "markdown": n.body_markdown,
                           "html": report_build.render_markdown_safe(n.body_markdown), "created_at": n.created_at,
                           "entity_id": n.entity_id, "evidence_id": n.evidence_id}
                          for n in db.scalars(select(Note).where(Note.case_id == case_id).order_by(Note.created_at))]}


@router.post("/cases/{case_id}/notes", status_code=201)
async def add_note(request: Request, case_id: str, body: NoteIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        n = Note(case_id=case_id, body_markdown=body.body_markdown, entity_id=body.entity_id,
                 evidence_id=body.evidence_id)
        db.add(n)
        audit.record(db, "note.create", actor=actor(request), case_id=case_id)
        db.commit()
        return {"id": n.id, "html": report_build.render_markdown_safe(n.body_markdown)}


class ReqIn(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    priority: Literal["low", "medium", "high"] = "medium"


@router.get("/cases/{case_id}/requirements")
async def get_reqs(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [{"id": r.id, "question": r.question, "priority": r.priority, "status": r.status}
                          for r in db.scalars(select(Requirement).where(Requirement.case_id == case_id))]}


@router.post("/cases/{case_id}/requirements", status_code=201)
async def add_req(request: Request, case_id: str, body: ReqIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        r = Requirement(case_id=case_id, question=body.question, priority=body.priority, created_by=actor(request))
        db.add(r)
        db.commit()
        return {"id": r.id, "status": r.status}


# ---- authorizations -----------------------------------------------------------------------------------------------------------------
class AuthIn(BaseModel):
    scope_type: Literal["domain", "ip", "cidr", "url"]
    scope_value: str = Field(min_length=3, max_length=255)
    authorized_by: str = Field(min_length=2, max_length=200)
    document_ref: str | None = None
    allowed_classes: list[Literal["passive", "public_site_query", "active"]] = Field(default_factory=lambda: ["passive"])  # type: ignore[arg-type]
    expires_at: datetime | None = None


@router.post("/cases/{case_id}/authorizations", status_code=201)
async def add_auth(request: Request, case_id: str, body: AuthIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "owner")
        a = ScopeAuthorization(case_id=case_id, scope_type=body.scope_type, scope_value=body.scope_value.lower(),
                               authorized_by=body.authorized_by, document_ref=body.document_ref,
                               allowed_classes_json=list(body.allowed_classes), expires_at=body.expires_at)
        db.add(a)
        db.flush()
        audit.record(db, "authorization.create", actor=actor(request), case_id=case_id, resource_id=a.id,
                     metadata={"scope": a.scope_value, "classes": a.allowed_classes_json})
        db.commit()
        return {"id": a.id}


@router.post("/authorizations/{auth_id}/revoke")
async def revoke_auth(request: Request, auth_id: str):
    with S(request).sm() as db:
        a = db.get(ScopeAuthorization, auth_id)
        if not a:
            raise ApiError(404, "not_found", "authorization not found")
        case_for(db, request, a.case_id, "owner")
        a.revoked_at = datetime.now(UTC)
        audit.record(db, "authorization.revoke", actor=actor(request), case_id=a.case_id, resource_id=a.id)
        db.commit()
        return {"id": a.id, "revoked_at": a.revoked_at}


# ---- evidence ---------------------------------------------------------------------------------------------------------------------------
_MAGIC = [(b"\xff\xd8\xff", "image/jpeg"), (b"\x89PNG\r\n\x1a\n", "image/png"), (b"%PDF-", "application/pdf"),
          (b"PK\x03\x04", "application/zip"), (b"MZ", "application/x-msdownload"), (b"\x7fELF", "application/x-elf"),
          (b"GIF8", "image/gif")]
DANGEROUS = {"application/x-msdownload", "application/x-elf"}


def sniff(head: bytes) -> str:
    for sig, mime in _MAGIC:
        if head.startswith(sig):
            return mime
    try:
        head.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def evidence_dict(e: Evidence, verified: bool | None = None) -> dict:
    return {"id": e.id, "case_id": e.case_id, "kind": e.kind, "title": e.title, "description": e.description,
            "sha256": e.sha256, "byte_size": e.byte_size, "mime_type": e.mime_type, "original_url": e.original_url,
            "retrieved_at": e.retrieved_at, "observed_at": e.observed_at, "capture_method": e.capture_method,
            "sensitivity": e.sensitivity, "redacted": e.redacted, "reference_only": e.vault_relpath is None,
            "chain_of_custody": e.chain_of_custody_json, "integrity_verified": verified}


@router.post("/cases/{case_id}/evidence/import", status_code=201)
async def import_evidence(request: Request, case_id: str, filename: str = Query(min_length=1, max_length=255),
                          sensitivity: Literal["PUBLIC", "INTERNAL", "RESTRICTED"] = "INTERNAL",
                          consent_confirmed: bool = False):
    st = S(request)
    if not consent_confirmed:
        raise ApiError(422, "consent_required", "confirm you own or are authorized to import this material")
    safe = re.sub(r"[^\w.\- ]", "_", os.path.basename(filename.replace("\\", "/")))[:120] or "file"
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
    cap = st.settings.max_import_bytes
    tmp = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
    size = 0
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > cap:
                raise ApiError(413, "too_large", f"upload exceeds {cap} bytes")
            tmp.write(chunk)
        if size == 0:
            raise ApiError(422, "empty", "empty upload")
        tmp.seek(0)
        head = tmp.read(512)
        tmp.seek(0)
        try:
            sha256, sha512, rel, n = st.vault.store_stream(tmp, cap)
        except VaultLocked as exc:
            raise ApiError(503, "vault_locked", str(exc), True) from exc
        except VaultError as exc:
            raise ApiError(413, "too_large", str(exc)) from exc
    finally:
        tmp.close()
    mime = sniff(head)
    now = datetime.now(UTC)
    with st.sm() as db:
        ev = Evidence(case_id=case_id, kind="import.file", title=safe, sha256=sha256, sha512=sha512, byte_size=n,
                      mime_type=mime, vault_relpath=rel, retrieved_at=now, observed_at=now,
                      capture_method="manual_import", sensitivity=sensitivity, created_by=actor(request),
                      description="Quarantined import; content is stored inert and never executed or rendered.",
                      chain_of_custody_json=[{"event": "imported", "at": now.isoformat(), "by": actor(request),
                                              "sha256": sha256, "ownership_confirmed": True}])
        db.add(ev)
        db.flush()
        audit.record(db, "evidence.import", actor=actor(request), case_id=case_id, resource_type="evidence",
                     resource_id=ev.id, metadata={"bytes": n, "mime": mime})
        db.commit()
        d = evidence_dict(ev, True)
    d["warnings"] = ([f"File content looks like {mime}; it is stored inert and cannot be executed here."]
                     if mime in DANGEROUS else [])
    return d


@router.get("/cases/{case_id}/evidence")
async def list_evidence(request: Request, case_id: str, limit: int = Query(100, le=500), offset: int = 0):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        total, rows = page(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.created_at), db,
                           limit, offset)
        return {"total": total, "items": [evidence_dict(e) for e in rows]}


def _ev(db, request, ev_id: str) -> Evidence:
    ev = db.get(Evidence, ev_id)
    if not ev:
        raise ApiError(404, "not_found", "evidence not found")
    case_for(db, request, ev.case_id)
    return ev


@router.get("/evidence/{ev_id}")
async def get_evidence(request: Request, ev_id: str):
    st = S(request)
    with st.sm() as db:
        ev = _ev(db, request, ev_id)
        ok = st.vault.verify(ev.vault_relpath, ev.sha256) if ev.vault_relpath else None
        d = evidence_dict(ev, ok)
        if ev.source_id:
            s = db.get(Source, ev.source_id)
            d["source"] = {"adapter_id": s.adapter_id, "url": s.source_url, "terms_url": s.terms_url,
                           "license": s.license_notes, "metadata": s.metadata_json}
        return d


@router.get("/evidence/{ev_id}/download")
async def download_evidence(request: Request, ev_id: str):
    st = S(request)
    with st.sm() as db:
        ev = _ev(db, request, ev_id)
        if not ev.vault_relpath:
            raise ApiError(404, "reference_only", "no stored content for reference-only evidence")
        try:
            data = st.vault.read(ev.vault_relpath, ev.sha256)  # hash verified on every read/export
        except IntegrityError as exc:
            audit.record(db, "evidence.integrity_failure", actor=actor(request), case_id=ev.case_id, resource_id=ev.id,
                         decision="deny")
            db.commit()
            raise ApiError(409, "integrity_failure", str(exc)) from exc
        audit.record(db, "evidence.download", actor=actor(request), case_id=ev.case_id, resource_id=ev.id)
        db.commit()
        name = re.sub(r"[^\w.\-]", "_", ev.title or ev.id)
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ---- reports ----------------------------------------------------------------------------------------------------------------------------------
class ReportIn(BaseModel):
    profile: Literal["executive", "technical", "evidence_pack", "multi_int"] = "technical"
    format: Literal["html", "markdown", "json", "pdf"] = "html"
    include_sensitive: bool = False


@router.post("/cases/{case_id}/reports", status_code=201)
async def make_report(request: Request, case_id: str, body: ReportIn):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "viewer")
        data = report_build.collect(db, case_id, body.profile, redact_sensitive=not body.include_sensitive)
        rr = ReportRun(case_id=case_id, template=body.profile, redaction_profile="none" if body.include_sensitive
                       else "default", evidence_manifest_sha256=data["evidence_manifest_sha256"], status="running")
        db.add(rr)
        db.flush()
        try:
            path = await asyncio.to_thread(report_build.write_report, data, body.format, st.settings.export_dir,
                                           f"report-{case_id[:8]}-{rr.id[:8]}")
        except Exception as exc:
            rr.status = "failed"
            db.commit()
            raise ApiError(500, "report_failed", f"{type(exc).__name__}", True) from exc
        try:
            path, digest = await asyncio.to_thread(report_store.seal, st.vault, rr.id, path)
        except VaultLocked as exc:
            rr.status = "failed"
            db.commit()
            raise ApiError(503, "vault_locked", str(exc)) from exc
        rr.export_path, rr.status, rr.sha256 = path.name, "done", digest
        audit.record(db, "report.export", actor=actor(request), case_id=case_id, resource_id=rr.id,
                     metadata={"format": body.format, "profile": body.profile, "sensitive": body.include_sensitive})
        db.commit()
        return {"id": rr.id, "status": rr.status, "file": path.name, "sha256": rr.sha256,
                "evidence_manifest_sha256": rr.evidence_manifest_sha256}


@router.get("/reports/{rid}")
async def get_report(request: Request, rid: str):
    with S(request).sm() as db:
        rr = db.get(ReportRun, rid)
        if not rr:
            raise ApiError(404, "not_found", "report not found")
        case_for(db, request, rr.case_id)
        return {"id": rr.id, "status": rr.status, "template": rr.template, "file": rr.export_path,
                "sha256": rr.sha256, "generated_at": rr.generated_at}


@router.get("/reports/{rid}/download")
async def download_report(request: Request, rid: str):
    st = S(request)
    with st.sm() as db:
        rr = db.get(ReportRun, rid)
        if not rr or not rr.export_path:
            raise ApiError(404, "not_found", "report not found")
        case_for(db, request, rr.case_id)
        p = (st.settings.export_dir / rr.export_path).resolve()
        if st.settings.export_dir.resolve() not in p.parents or not p.is_file():
            raise ApiError(404, "not_found", "report file missing")
        rid_ = rr.id
    try:
        body, name = await asyncio.to_thread(report_store.read, st.vault, rid_, p)
    except VaultLocked as exc:
        raise ApiError(503, "vault_locked", str(exc)) from exc
    return Response(body, media_type=report_store.media_type(name), headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ---- tools / settings / secrets ---------------------------------------------------------------------------------------------------------------------
@router.get("/tools")
async def tools(request: Request):
    st = S(request)
    out = []
    for aid, ad in st.adapters.items():
        m = ad.manifest
        h = await ad.health()
        out.append({**m.model_dump(), "health": h, "enabled": True})
    return {"items": out}


@router.post("/tools/{tool_id}/healthcheck")
async def tool_health(request: Request, tool_id: str):
    ad = S(request).adapters.get(tool_id)
    if not ad:
        raise ApiError(404, "not_found", "unknown tool")
    return await ad.health()


ALLOWED_SETTINGS = {"offline": bool, "theme": str, "max_concurrency": int, "edgar_contact": str, "ai_enabled": bool, "update_manifest_url": str}


class SettingsIn(BaseModel):
    values: dict[str, Any]


@router.get("/settings")
async def get_settings(request: Request):
    st = S(request)
    with st.sm() as db:
        saved = {s.key: s.value_json for s in db.scalars(select(Setting))}
    return {"offline": st.settings.offline, "max_concurrency": st.settings.max_concurrency,
            "theme": saved.get("theme", "dark"), "data_dir": str(st.settings.data_dir),
            "ai_enabled": saved.get("ai_enabled", False), "edgar_contact": saved.get("edgar_contact"),
            "update_manifest_url": saved.get("update_manifest_url") or st.settings.update_manifest_url or ""}


@router.put("/settings", dependencies=[Depends(require_admin)])
async def put_settings(request: Request, body: SettingsIn):
    st = S(request)
    for k, v in body.values.items():
        if k not in ALLOWED_SETTINGS or not isinstance(v, ALLOWED_SETTINGS[k]) or isinstance(v, bool) != (k in ("offline", "ai_enabled")):
            raise ApiError(422, "invalid_setting", f"unsupported setting or value: {k}")
    um = body.values.get("update_manifest_url")
    if um is not None and um != "" and not re.fullmatch(r"https?://[^\s]{3,500}", um):
        raise ApiError(422, "invalid_setting", "update_manifest_url must be an http(s) URL (or empty to clear it)")
    with st.sm() as db:
        for k, v in body.values.items():
            db.merge(Setting(key=k, value_json=v))
            if k == "offline":
                st.settings.offline = v
        audit.record(db, "settings.update", actor=actor(request), metadata={"keys": list(body.values)})
        db.commit()
    return await get_settings(request)


class SecretIn(BaseModel):
    value: str = Field(min_length=1, max_length=4096)


# What each key is for, so Setup can show a labelled spot for it. The value is never returned by any endpoint.
SECRET_CATALOG = {
    "virustotal": {"label": "VirusTotal API key", "format": "a 64-character key", "get": "https://www.virustotal.com/gui/my-apikey"},
    "urlscan": {"label": "urlscan.io API key (optional: raises rate limits)", "format": "a UUID", "get": "https://urlscan.io/user/profile/"},
    "shodan": {"label": "Shodan API key", "format": "a 32-character key", "get": "https://account.shodan.io/"},
    "censys": {"label": "Censys credentials", "format": "API_ID:API_SECRET (joined by a colon)", "get": "https://search.censys.io/account/api"},
    "opencorporates": {"label": "OpenCorporates API token", "format": "a token", "get": "https://opencorporates.com/api_accounts/new"},
}


@router.get("/secrets", dependencies=[Depends(require_admin)])
async def list_secrets(request: Request):
    store = S(request).secrets
    used: dict[str, list[str]] = {}
    for aid, ad in S(request).adapters.items():
        if ad.manifest.api_key_name:
            used.setdefault(ad.manifest.api_key_name, []).append(aid)
    names = sorted(set(SECRET_CATALOG) | set(used))
    return {"items": [{"provider": n, **SECRET_CATALOG.get(n, {"label": f"{n} key", "format": "", "get": ""}), "set": store.exists(n),
                       "used_by": used.get(n, [])} for n in names],
            "note": "Keys are stored in the OS credential store (or, without one, sealed in the encrypted database). They are never shown again."}


@router.post("/secrets/{provider}", dependencies=[Depends(require_admin)])
async def save_secret(request: Request, provider: str, body: SecretIn):
    from ...secrets_store import NAME, SecretStoreError
    if not NAME.fullmatch(provider):
        raise ApiError(422, "invalid_provider", "invalid provider name")
    try:
        where = S(request).secrets.set(provider, body.value.strip())
    except SecretStoreError as exc:
        raise ApiError(503, "secret_store_unavailable", str(exc), True) from exc
    with S(request).sm() as db:
        audit.record(db, "secret.save", actor=actor(request), metadata={"provider": provider, "store": where})
        db.commit()
    return {"provider": provider, "stored": True, "store": where}  # the value is never echoed or logged


@router.delete("/secrets/{provider}", dependencies=[Depends(require_admin)])
async def delete_secret(request: Request, provider: str):
    from ...secrets_store import NAME
    if not NAME.fullmatch(provider):
        raise ApiError(422, "invalid_provider", "invalid provider name")
    gone = S(request).secrets.delete(provider)
    with S(request).sm() as db:
        audit.record(db, "secret.delete", actor=actor(request), metadata={"provider": provider, "existed": gone})
        db.commit()
    return {"provider": provider, "removed": gone}


# ---- backups / vault ------------------------------------------------------------------------------------------------------------------------------
class BackupIn(BaseModel):
    passphrase: str | None = Field(default=None, min_length=8, max_length=256)
    allow_plaintext: bool = False


class BackupPathIn(BaseModel):
    file: str = Field(min_length=1, max_length=255)
    passphrase: str | None = Field(default=None, max_length=256)


def _backup_path(st: AppState, name: str) -> Path:
    p = (st.settings.backup_dir / Path(name).name).resolve()
    if st.settings.backup_dir.resolve() not in p.parents or not p.is_file():
        raise ApiError(404, "not_found", "backup file not found in the backup directory")
    return p


@router.post("/backups", status_code=201, dependencies=[Depends(require_admin)])
async def make_backup(request: Request, body: BackupIn | None = None):
    st = S(request)
    body = body or BackupIn()
    try:
        p = await asyncio.to_thread(backup_mod.create_backup, st.settings, st.vault, db_key=st.db_key, passphrase=body.passphrase,
                                    allow_plaintext=body.allow_plaintext)
    except backup_mod.BackupError as exc:
        raise ApiError(409, "backup_refused", str(exc)) from exc
    with st.sm() as db:
        audit.record(db, "backup.create", actor=actor(request),
                     metadata={"file": p.name, "encrypted": bool(body.passphrase)})
        db.commit()
    return {"file": p.name, "bytes": p.stat().st_size, "encrypted": bool(body.passphrase),
            "verification": backup_mod.verify_backup(p, body.passphrase)}


@router.post("/backups/verify", dependencies=[Depends(require_admin)])
async def verify_backup(request: Request, body: BackupPathIn):
    return await asyncio.to_thread(backup_mod.verify_backup, _backup_path(S(request), body.file), body.passphrase)


class RestoreIn(BaseModel):
    file: str
    target_name: str = Field(pattern=r"^[A-Za-z0-9_\-]{3,60}$")
    confirm: bool = False
    passphrase: str | None = Field(default=None, max_length=256)


@router.post("/backups/restore/preview", dependencies=[Depends(require_admin)])
async def restore_preview(request: Request, body: RestoreIn):
    st = S(request)
    return await asyncio.to_thread(backup_mod.restore_preview, _backup_path(st, body.file),
                                   st.settings.data_dir / "restores" / body.target_name, body.passphrase)


@router.post("/backups/restore", dependencies=[Depends(require_admin)])
async def restore(request: Request, body: RestoreIn):
    st = S(request)

    def factory(root: Path):
        from ...evidence.vault import Vault
        return Vault(root, st.vault.cipher, st.vault.require_encryption)
    try:
        out = await asyncio.to_thread(backup_mod.restore, _backup_path(st, body.file),
                                      st.settings.data_dir / "restores" / body.target_name, confirm=body.confirm,
                                      passphrase=body.passphrase, vault_factory=factory)
    except backup_mod.BackupError as exc:
        raise ApiError(409, "restore_refused", str(exc)) from exc
    with st.sm() as db:
        audit.record(db, "backup.restore", actor=actor(request), metadata={"target": body.target_name})
        db.commit()
    return {"restored_to": str(out), "note": "Restored into a NEW directory. Point OSINTCC_DATA_DIR at it to switch over."}


@router.get("/system/egress-check")
async def egress_check(request: Request):
    """Result of the start-up self-check: did the app's own processes open outside connections while idle?"""
    mon = S(request).egress
    if mon is None:
        return {"enabled": False, "state": "disabled", "verdict": None, "note": "The start-up egress self-check is not running in this mode."}
    return mon.state


@router.get("/system/vault")
async def vault_status(request: Request):
    st = S(request)
    objs = [f for f in st.vault.root.glob("sha256/*/*") if f.is_file() and not f.name.startswith(".")]
    enc = sum(1 for f in objs if st.vault.is_object_encrypted(f.relative_to(st.vault.root).as_posix()))
    return {"mode": st.settings.vault_encryption, "key_available": st.vault.encrypting, "objects": len(objs),
            "encrypted_objects": enc, "plaintext_objects": len(objs) - enc, "database_encrypted": st.db_key is not None,
            "plaintext_leftovers": [p.name for p in dbenc.plaintext_leftovers(st.settings.db_path)],
            "note": ("The database is encrypted with SQLCipher (AES-256). Exported reports are encrypted at rest while the vault key exists."
                     if st.db_key is not None else "The SQLite database is NOT encrypted (database encryption is off).")}


@router.post("/system/database/remove-plaintext-leftovers", dependencies=[Depends(require_admin)])
async def remove_plaintext_leftovers(request: Request):
    """Overwrite-and-delete the plaintext copies left by the one-time encryption migration (and pre-migration .bak files)."""
    st = S(request)
    if st.db_key is None:
        raise ApiError(409, "not_encrypted", "the database is not encrypted; there is nothing safe to remove")
    gone = await asyncio.to_thread(dbenc.remove_plaintext_leftovers, st.settings.db_path)
    with st.sm() as db:
        audit.record(db, "db.plaintext_leftovers_removed", actor=actor(request), metadata={"files": gone})
        db.commit()
    return {"removed": gone}


@router.post("/system/vault/encrypt-existing", dependencies=[Depends(require_admin)])
async def vault_encrypt_existing(request: Request):
    st = S(request)
    try:
        out = await asyncio.to_thread(st.vault.encrypt_existing)
    except VaultError as exc:
        raise ApiError(503, "vault_locked", str(exc)) from exc
    with st.sm() as db:
        audit.record(db, "vault.encrypt_existing", actor=actor(request), metadata=out)
        db.commit()
    return out


@router.get("/overview")
async def overview(request: Request):
    st = S(request)
    with st.sm() as db:
        mine = select(CaseMember.case_id).where(CaseMember.user_id == actor(request))
        n = lambda q: db.scalar(q) or 0
        return {
            "open_cases": n(select(func.count()).select_from(Case).where(Case.id.in_(mine), Case.status == "open")),
            "pending_jobs": n(select(func.count()).select_from(Job).where(Job.status.in_(("queued", "running", "deferred")))),
            "findings": n(select(func.count()).select_from(Finding).where(Finding.case_id.in_(mine))),
            "offline": st.settings.offline,
            "adapters": {a: (await ad.health())["status"] for a, ad in st.adapters.items()},
            "storage_bytes": sum(f.stat().st_size for f in st.settings.vault_dir.rglob("*") if f.is_file()),
        }


# ---- multi-INT ingest / observations / search / purge -------------------------------------------------------------------------------------------------
@router.post("/cases/{case_id}/ingest", status_code=201)
async def ingest(request: Request, case_id: str, filename: str = Query(min_length=1, max_length=255),
                 kind: str = "auto", consent_confirmed: bool = False,
                 sensitivity: Literal["PUBLIC", "INTERNAL", "RESTRICTED"] | None = None,
                 licensor: str | None = None, license_basis: str | None = None):
    """Import-only: parse first, store second. A malformed file is rejected (422) and nothing is written."""
    from ...ingest import exiftool, parsers
    from ...ingest import service as ingest_service
    from ...setup.state import managed_path
    st = S(request)
    if not consent_confirmed:
        raise ApiError(422, "consent_required", "confirm you own or are authorized to import this material")
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > st.settings.max_import_bytes:
            raise ApiError(413, "too_large", "upload exceeds the size limit")
        chunks.append(chunk)
    raw = b"".join(chunks)
    safe = re.sub(r"[^\w.\- ]", "_", os.path.basename(filename.replace("\\", "/")))[:120] or "file"
    k = kind if kind != "auto" else parsers.detect_kind(safe, raw[:512])
    if not k or k not in parsers.PARSERS:
        raise ApiError(422, "unsupported_kind", "cannot detect the file type; supported kinds: "
                       + ", ".join(sorted(parsers.PARSERS)))
    if k == "sanctions_csv":
        from ...ingest import fin as fin_mod
        blocked = fin_mod.check_licence(license_basis, licensor)
        if blocked:
            with st.sm() as db:
                audit.record(db, "ingest.license_blocked", actor=actor(request), case_id=case_id, decision="deny",
                             metadata={"kind": k, "basis": license_basis or ""})
                db.commit()
            raise ApiError(403, "license_blocked", blocked)
    try:
        parsed = await asyncio.to_thread(parsers.PARSERS[k], raw)
    except parsers.IngestError as exc:
        with st.sm() as db:
            audit.record(db, "ingest.rejected", actor=actor(request), case_id=case_id, decision="deny",
                         metadata={"kind": k, "reason": str(exc)[:150]})
            db.commit()
        raise ApiError(422, "malformed_input", str(exc)) from exc
    if k in exiftool.KINDS:  # optional enrichment when ExifTool is installed (first-run setup or PATH)
        exe = managed_path(st.settings.tools_state_path, "exiftool") or shutil.which("exiftool")
        extra = await exiftool.read_tags(exe, raw, safe) if exe else None
        if extra:
            parsed.observations.append(extra)
    with st.sm() as db:
        out = ingest_service.persist(db, st.vault, case_id, parsed, raw, safe, actor(request), sensitivity)
        if k == "sanctions_csv":
            audit.record(db, "ingest.sanctions", actor=actor(request), case_id=case_id,
                         metadata={"licensor": licensor, "basis": license_basis})
        db.commit()
    return out


@router.get("/disciplines")
async def disciplines(request: Request):
    from ...db.models import Discipline
    with S(request).sm() as db:
        return {"items": [{"id": d.id, "label": d.label, "parent_id": d.parent_id, "enabled": d.enabled}
                          for d in db.scalars(select(Discipline))]}


@router.get("/cases/{case_id}/observations")
async def observations(request: Request, case_id: str, discipline: str | None = None, kind: str | None = None,
                       limit: int = Query(100, le=500), offset: int = 0, start: Annotated[datetime | None, Query(alias="from")] = None,
                       to: datetime | None = None):
    from ...db.models import Observation
    with S(request).sm() as db:
        case_for(db, request, case_id)
        q = select(Observation).where(Observation.case_id == case_id).order_by(Observation.observed_at)
        if discipline:
            q = q.where(Observation.discipline_id == discipline)
        if kind:
            q = q.where(Observation.kind == kind)
        if start:
            q = q.where(Observation.observed_at >= (start if start.tzinfo else start.replace(tzinfo=UTC)))
        if to:
            q = q.where(Observation.observed_at <= (to if to.tzinfo else to.replace(tzinfo=UTC)))
        total, rows = page(q, db, limit, offset)
        return {"total": total, "items": [{
            "id": o.id, "discipline": o.discipline_id, "kind": o.kind, "access_class": o.access_class,
            "observed_at": o.observed_at, "ingested_at": o.ingested_at, "data": o.data_json,
            "raw_evidence_id": o.raw_evidence_id, "confidence": o.confidence, "review_status": o.review_status,
            "sensitivity": o.sensitivity, "parser_version": o.parser_version} for o in rows]}


def _fts_query(q: str) -> str:
    toks = [t for t in re.split(r"\s+", q.strip()) if t]
    return " ".join('"' + t.replace('"', "") + '"' for t in toks[:12])


@router.get("/cases/{case_id}/search")
async def case_search(request: Request, case_id: str, q: str = Query(min_length=1, max_length=200),
                      limit: int = Query(50, le=200)):
    """Full-text search (SQLite FTS5) across findings, notes, evidence titles and observations of ONE case."""
    from sqlalchemy import text
    with S(request).sm() as db:
        case_for(db, request, case_id)
        fq = _fts_query(q)
        if not fq:
            return {"items": []}
        rows = db.execute(text("SELECT kind, ref_id, snippet(search_index, 3, '[', ']', '…', 12) FROM search_index "
                               "WHERE search_index MATCH :m AND case_id = :c ORDER BY rank LIMIT :n"),
                          {"m": fq, "c": case_id, "n": limit}).all()
        return {"items": [{"kind": k, "id": i, "snippet": sn} for k, i, sn in rows]}


class PurgeIn(BaseModel):
    confirm: bool = False
    confirm_title: str = ""


def _purge_counts(db: Session, case_id: str) -> dict[str, int]:
    from ...db.models import Observation
    out = {}
    for name, model in (("targets", Target), ("entities", Entity), ("findings", Finding), ("relationships", Relationship),
                        ("evidence", Evidence), ("notes", Note), ("observations", Observation),
                        ("search_runs", SearchRun), ("requirements", Requirement)):
        out[name] = db.scalar(select(func.count()).select_from(model).where(model.case_id == case_id)) or 0
    return out


@router.get("/cases/{case_id}/purge/preview")
async def purge_preview(request: Request, case_id: str):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "owner")
        mine = db.scalars(select(Evidence.sha256).where(Evidence.case_id == case_id)).all()
        shared = {h for h in mine if (db.scalar(select(func.count()).select_from(Evidence).where(
            Evidence.sha256 == h, Evidence.case_id != case_id)) or 0) > 0}
        return {"will_delete": _purge_counts(db, case_id), "vault_objects_deleted": len(set(mine) - shared),
                "vault_objects_kept_shared_with_other_cases": len(shared),
                "note": "Irreversible. Backups made earlier still contain this case. SSD wear-levelling means deletion "
                        "is not guaranteed secure erasure; use full-disk encryption."}


@router.post("/cases/{case_id}/purge")
async def purge_case(request: Request, case_id: str, body: PurgeIn):
    st = S(request)
    with st.sm() as db:
        case = case_for(db, request, case_id, "owner")
        if not body.confirm or body.confirm_title != case.title:
            raise ApiError(422, "confirmation_required", "send confirm=true and confirm_title equal to the case title")
        counts = _purge_counts(db, case_id)
        rows = db.execute(select(Evidence.sha256, Evidence.vault_relpath).where(Evidence.case_id == case_id)).all()
        other = {h for (h,) in db.execute(select(Evidence.sha256).where(Evidence.case_id != case_id))}
        db.delete(case)
        audit.record(db, "case.purge", actor=actor(request), case_id=case_id, resource_type="case", resource_id=case_id,
                     metadata={"deleted": counts})
        db.commit()
    removed = 0
    for sha, rel in rows:
        if rel and sha not in other:
            p = (st.vault.root / rel)
            if p.is_file():
                p.unlink()
                removed += 1
    return {"purged": counts, "vault_objects_removed": removed}


@router.post("/system/shutdown", status_code=202, dependencies=[Depends(require_admin)])
async def shutdown(request: Request):
    """Graceful stop requested by the desktop shell (lifespan then cancels jobs and checkpoints the WAL)."""
    st = S(request)
    if not callable(st.request_shutdown):
        raise ApiError(409, "not_supported", "this server was not started by the headless launcher")
    with st.sm() as db:
        audit.record(db, "system.shutdown", actor=actor(request))
        db.commit()
    asyncio.get_running_loop().call_later(0.2, st.request_shutdown)
    return {"status": "stopping"}


from . import fusion as _fusion

router.include_router(_fusion.router)

from . import intel as _intel

router.include_router(_intel.router)

from . import humint as _humint

router.include_router(_humint.router)

from . import workflows as _workflows

router.include_router(_workflows.router)

from . import ai as _ai

router.include_router(_ai.router)

from . import mcp_admin as _mcp_admin

router.include_router(_mcp_admin.router)

from . import hardware as _hardware

router.include_router(_hardware.router)

from . import plugins as _plugins

router.include_router(_plugins.router)

from . import briefing as _briefing

router.include_router(_briefing.router)
from . import updates as _updates

router.include_router(_updates.router)
from . import setup as _setup

router.include_router(_setup.router)
from . import copilot as _copilot

router.include_router(_copilot.router)
from . import automations as _automations

router.include_router(_automations.router)
