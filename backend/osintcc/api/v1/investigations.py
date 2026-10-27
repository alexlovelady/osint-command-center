"""One-click investigation API: prepare, start, watch, pause/resume/cancel, approve, review.

It composes the services that already exist (cases, subjects, consent, research, expansion, review) and adds no second research engine. Every route re-checks case
membership and role on the server; the UI is never trusted. Request bodies forbid unknown fields.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ...db.models import Case, CaseMember, InvestigationRun, Subject
from ...main import ApiError
from ...profile import candidates, consent, investigate, master, service
from ...profile.service import ProfileError
from ...telemetry import audit
from .profile import perr, subject_for
from .routes import S, actor, case_for

router: APIRouter = APIRouter()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def run_for(db, request: Request, run_id: str, need: str = "viewer"):
    run = db.get(InvestigationRun, run_id)
    if run is None:
        raise ApiError(404, "not_found", "investigation not found")
    s, case, role = subject_for(db, request, run.subject_id, need)
    return run, s, case, role


class DetectIn(Strict):
    text: str = Field(max_length=2000)
    investigation: Literal["person", "business"] = "person"


@router.post("/investigations/detect")
async def detect(request: Request, body: DetectIn):
    """Smart paste: split on commas, semicolons and new lines and guess each value's type. The person can correct every guess; nothing is stored here."""
    import re
    parts = [p for p in re.split(r"[\n;,]+", body.text) if p.strip()][:20]
    return {"inputs": [investigate.detect_kind(p, body.investigation) for p in parts]}


class InputIn(Strict):
    kind: Literal["name", "email", "phone", "username", "alias", "url", "domain", "organization"]
    value: str = Field(min_length=1, max_length=600)


class AuthIn(Strict):
    verification_method: str = "self_attestation"
    verifier: str = Field(default="", max_length=200)
    expires_days: int = Field(default=30, ge=1, le=365)
    source_classes: list[str] | None = None
    permitted_purposes: list[str] | None = None
    proof_evidence_id: str | None = None


class PrepareIn(Strict):
    kind: Literal["person", "business"] = "person"
    display_name: str = Field(default="", max_length=300)
    purpose: str = Field(default="", max_length=2000)
    mode: Literal["self", "client", "organization"] = "self"
    inputs: list[InputIn] = Field(min_length=1, max_length=20)
    case_id: str | None = None
    subject_id: str | None = None
    authorization: AuthIn | None = None
    start: bool = False
    approved_sources: list[str] | Literal["listed"] = Field(default_factory=list)
    excluded_sources: list[str] = Field(default_factory=list)
    policy: dict[str, Any] | None = None
    idempotency_key: str | None = Field(default=None, max_length=64)


def _name_for(inputs: list[InputIn], given: str) -> str:
    if given.strip():
        return given.strip()
    for k in ("name", "organization", "alias", "username", "email", "domain", "url"):
        for i in inputs:
            if i.kind == k:
                return i.value.strip()[:120]
    return "New investigation"


@router.post("/investigations", status_code=201)
async def prepare(request: Request, body: PrepareIn):
    """Create (or reuse) the case and subject, record the inputs and the authorization, and return the manifest: what will run, what cannot and why, and who would receive what.
    With start=true the investigation begins at once; the named providers in approved_sources are the single approval for sources that send an input to a third party."""
    st = S(request)
    me = actor(request)
    with st.sm() as db:
        try:
            if body.subject_id:
                subject, case, _ = subject_for(db, request, body.subject_id, "editor")
            else:
                if body.case_id:
                    case = case_for(db, request, body.case_id, "editor")
                else:
                    name = _name_for(body.inputs, body.display_name)
                    purpose = body.purpose.strip() or ("self audit of my own public footprint" if body.mode == "self" else "")
                    if body.kind == "person" and not purpose:
                        raise ApiError(422, "purpose_required", "A documented purpose is required for an investigation of a person.")
                    case = Case(title=name, description="", category="people" if body.kind == "person" else "business", purpose=purpose, legal_basis_notes="", scope_json={}, owner_id=me)
                    db.add(case)
                    db.flush()
                    db.add(CaseMember(case_id=case.id, user_id=me, access_role="owner"))
                    audit.record(db, "case.create", actor=me, case_id=case.id, resource_type="case", resource_id=case.id)
                subject = service.create_subject(db, case, display_name=_name_for(body.inputs, body.display_name), type="person" if body.kind == "person" else "organization",
                                                 mode=body.mode if body.kind == "person" else ("organization" if body.mode == "self" else body.mode), purpose=body.purpose or case.purpose, actor=me)
            if body.authorization is not None and consent.current_status(db, subject)["status"] not in ("active",):
                a = body.authorization
                classes = a.source_classes or ["public_passive", "public_site_query"]
                consent.grant(db, subject, verification_method=a.verification_method, verifier=a.verifier or me, source_classes=classes,
                              permitted_purposes=a.permitted_purposes or [subject.purpose or "investigation"], expires_at=datetime.now(UTC) + timedelta(days=a.expires_days),
                              proof_evidence_id=a.proof_evidence_id, actor=me)
            role = db.get(CaseMember, (case.id, me)).access_role
            added, skipped = [], []
            for inp in body.inputs:
                if inp.kind == "phone":
                    it, _created = master.add_item(db, subject, type="phone", value=inp.value, role=role, actor=me, origin="subject_provided" if body.mode == "self" else "analyst_supplied",
                                                   need_to_know="given as an investigation input; stored masked and not searched")
                    added.append({"kind": "phone", "id": f"item:{it.id}"})
                    continue
                try:
                    ident = service.add_identifier(db, subject, inp.kind, inp.value, actor=me)
                    added.append({"kind": inp.kind, "id": ident.id})
                except ProfileError as exc:
                    skipped.append({"kind": inp.kind, "code": exc.code, "message": exc.message})
            if not added:
                raise ProfileError("no_valid_inputs", "none of the inputs could be used: " + "; ".join(s["message"] for s in skipped))
            db.flush()
            man = investigate.build_manifest(db, st, subject, case)
            out: dict[str, Any] = {"case_id": case.id, "subject_id": subject.id, "added": added, "skipped": skipped, "manifest": man, "run": None}
            if body.start:
                approved = man["approvable"] if body.approved_sources == "listed" else list(body.approved_sources)
                run = investigate.start(db, st, subject, case, actor=me, kind=body.kind, approved_sources=approved, excluded_sources=body.excluded_sources, policy=body.policy,
                                        idempotency_key=body.idempotency_key)
                out["run"] = {"id": run.id, "status": run.status, "stop_reason": run.stop_reason}
                db.commit()
                if run.status == "queued":
                    investigate.launch(st, run.id)
                return out
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return out


class StartIn(Strict):
    approved_sources: list[str] | Literal["listed"] = Field(default_factory=list)
    excluded_sources: list[str] = Field(default_factory=list)
    policy: dict[str, Any] | None = None
    kind: Literal["person", "business"] = "person"
    idempotency_key: str | None = Field(default=None, max_length=64)


@router.post("/subjects/{subject_id}/investigations", status_code=201)
async def start_run(request: Request, subject_id: str, body: StartIn):
    st = S(request)
    with st.sm() as db:
        s, case, _ = subject_for(db, request, subject_id, "editor")
        try:
            approved = investigate.build_manifest(db, st, s, case)["approvable"] if body.approved_sources == "listed" else list(body.approved_sources)
            run = investigate.start(db, st, s, case, actor=actor(request), kind=body.kind, approved_sources=approved, excluded_sources=body.excluded_sources, policy=body.policy,
                                    idempotency_key=body.idempotency_key)
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        status = run.status
        rid = run.id
    if status == "queued":
        investigate.launch(st, rid)
    return {"id": rid, "status": status}


@router.get("/investigations")
async def list_runs(request: Request, case_id: str | None = None, limit: int = 30):
    st = S(request)
    me = actor(request)
    with st.sm() as db:
        q = select(InvestigationRun).order_by(InvestigationRun.updated_at.desc()).limit(min(max(limit, 1), 100))
        if case_id:
            case_for(db, request, case_id)
            q = q.where(InvestigationRun.case_id == case_id)
        out = []
        for r in db.scalars(q):
            if db.get(CaseMember, (r.case_id, me)) is None:
                continue
            s = db.get(Subject, r.subject_id)
            p = investigate.progress(db, st, r)
            out.append({"id": r.id, "case_id": r.case_id, "subject_id": r.subject_id, "name": s.display_name if s else "", "kind": r.kind, "status": r.status, "stop_reason": r.stop_reason,
                        "updated_at": r.updated_at, "created_at": r.created_at, "units": p["units"], "pending_decisions": p["pending_decisions"]})
        db.commit()
        return {"items": out, "total": len(out)}


@router.get("/investigations/review")
async def global_review(request: Request):
    """Everything waiting for a person's decision across the investigations they can see."""
    st = S(request)
    me = actor(request)
    with st.sm() as db:
        out = []
        seen: set[str] = set()
        for r in db.scalars(select(InvestigationRun).order_by(InvestigationRun.updated_at.desc())):
            if r.subject_id in seen or db.get(CaseMember, (r.case_id, me)) is None:
                continue
            seen.add(r.subject_id)
            s = db.get(Subject, r.subject_id)
            if s is None:
                continue
            role = db.get(CaseMember, (r.case_id, me)).access_role
            inbox = investigate.review_inbox(db, st, s, role=role)
            out.append({"subject_id": s.id, "case_id": r.case_id, "name": s.display_name, "role": role, **inbox})
        db.commit()
        return {"subjects": out, "total": sum(x["total"] for x in out)}


@router.get("/investigations/{run_id}")
async def get_run(request: Request, run_id: str):
    st = S(request)
    with st.sm() as db:
        run, s, _case, _ = run_for(db, request, run_id)
        out = {**investigate.progress(db, st, run), "subject_id": s.id, "case_id": run.case_id, "kind": run.kind, "approved_sources": run.approved_sources,
               "excluded_sources": run.excluded_sources, "counts": run.counts_json}
        db.commit()
        return out


@router.get("/investigations/{run_id}/events")
async def get_events(request: Request, run_id: str, after: int = 0):
    """Durable replay: ask for events after the last sequence number you saw. A dropped connection loses nothing."""
    with S(request).sm() as db:
        run, _s, _c, _ = run_for(db, request, run_id)
        ev = investigate.events(db, run, after)
        return {"events": ev, "last": ev[-1]["seq"] if ev else after, "status": run.status}


@router.get("/investigations/{run_id}/summary")
async def get_summary(request: Request, run_id: str):
    st = S(request)
    with st.sm() as db:
        run, _s, _c, role = run_for(db, request, run_id)
        out = investigate.summary(db, st, run, role=role)
        db.commit()
        return out


@router.post("/investigations/{run_id}/pause")
async def pause(request: Request, run_id: str):
    with S(request).sm() as db:
        run, _s, _c, _ = run_for(db, request, run_id, "editor")
        try:
            investigate.pause(db, run, actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return {"id": run.id, "status": run.status}


@router.post("/investigations/{run_id}/resume")
async def resume(request: Request, run_id: str):
    st = S(request)
    with st.sm() as db:
        run, _s, _c, _ = run_for(db, request, run_id, "editor")
        try:
            investigate.resume(db, run, actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        out = {"id": run.id, "status": run.status}
    investigate.launch(st, run_id)
    return out


@router.post("/investigations/{run_id}/cancel")
async def cancel(request: Request, run_id: str):
    with S(request).sm() as db:
        run, _s, _c, _ = run_for(db, request, run_id, "editor")
        try:
            investigate.cancel(db, run, actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return {"id": run.id, "status": run.status}


class ApproveIn(Strict):
    sources: list[str] = Field(min_length=1, max_length=40)


@router.post("/investigations/{run_id}/approve")
async def approve(request: Request, run_id: str, body: ApproveIn):
    """One bounded approval naming providers. The investigation continues on its own afterwards."""
    st = S(request)
    with st.sm() as db:
        run, _s, _c, _ = run_for(db, request, run_id, "editor")
        try:
            investigate.approve_more(db, st, run, body.sources, actor(request))
            if run.status in ("awaiting_review", "complete_with_limits"):
                investigate.resume(db, run, actor(request))
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        status = run.status
    if status == "queued":
        investigate.launch(st, run_id)
    return {"id": run_id, "status": status}


@router.post("/investigations/{run_id}/advance")
async def advance(request: Request, run_id: str):
    """Run the next step now and wait for what it starts. Normally the background driver does this; it is here for tests and for a stalled driver."""
    st = S(request)
    with st.sm() as db:
        run_for(db, request, run_id, "editor")
    res = investigate.advance(st, run_id)
    for rid in res["run_ids"]:
        await st.runner.run_until_idle(rid)
    return {"finished": res["finished"], "wait": res["wait"], "started": len(res["run_ids"])}


@router.get("/subjects/{subject_id}/review-inbox")
async def inbox(request: Request, subject_id: str):
    st = S(request)
    with st.sm() as db:
        s, _c, role = subject_for(db, request, subject_id, "viewer")
        out = investigate.review_inbox(db, st, s, role=role)
        db.commit()
        return out


class ReviewIn(Strict):
    ids: list[str] = Field(min_length=1, max_length=200)
    action: Literal["mine", "not_mine", "unsure", "need_evidence"]
    basis: str = Field(default="", max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    preview: bool = False


@router.post("/subjects/{subject_id}/review-inbox/decide")
async def decide(request: Request, subject_id: str, body: ReviewIn):
    """Bulk decisions with an impact preview. 'Mine' records the owner's own attestation; it is never independent corroboration."""
    with S(request).sm() as db:
        s, _c, role = subject_for(db, request, subject_id, "editor")
        try:
            out = investigate.apply_reviews(db, s, body.ids, body.action, actor=actor(request), role=role, basis=body.basis, evidence_ids=body.evidence_ids, preview=body.preview)
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return out


class UndoIn(Strict):
    bulk_id: str


@router.post("/subjects/{subject_id}/review-inbox/undo")
async def undo(request: Request, subject_id: str, body: UndoIn):
    with S(request).sm() as db:
        s, _c, _ = subject_for(db, request, subject_id, "editor")
        try:
            out = candidates.reverse(db, s, bulk_id=body.bulk_id, reviewer=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return out
