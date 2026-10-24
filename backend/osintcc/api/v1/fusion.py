"""Claims, hypotheses, requirements, entity links, gap assessment and collection plans (spec 23.2-23.4, 23.8)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ...db.models import (
    Claim,
    ClaimSource,
    CollectionPlan,
    CollectionStep,
    Entity,
    EntityLink,
    Evidence,
    Finding,
    Hypothesis,
    HypothesisClaim,
    Job,
    Requirement,
    RequirementEvidence,
)
from ...graph import fusion
from ...main import ApiError
from ...policy.targets import TargetError
from ...search import service
from ...telemetry import audit
from .routes import S, actor, case_for

router: APIRouter = APIRouter()


def _entity(db, case_id: str, entity_id: str) -> Entity:
    e = db.get(Entity, entity_id)
    if not e or e.case_id != case_id:
        raise ApiError(404, "not_found", "entity not in this case")
    return e


def _evidence(db, case_id: str, evidence_id: str) -> Evidence:
    ev = db.get(Evidence, evidence_id)
    if not ev or ev.case_id != case_id:  # cross-case citations are rejected (spec 16)
        raise ApiError(422, "invalid_citation", "evidence does not belong to this case")
    return ev


def _default_group(db, evidence_id: str) -> str:
    """Human reports from different sources are different groups by default; machine evidence is grouped by adapter."""
    ev = db.get(Evidence, evidence_id)
    if ev and ev.kind == "human.report":
        return "human:" + ev.title.split(":")[0]
    return ""


def _claim(db, request, claim_id: str, need="viewer") -> Claim:
    c = db.get(Claim, claim_id)
    if not c:
        raise ApiError(404, "not_found", "claim not found")
    case_for(db, request, c.case_id, need)
    return c


# ------------------------------------------------------------------ claims -----------------------------------------
class SourceIn(BaseModel):
    evidence_id: str
    method: str = Field(default="manual", max_length=60)
    independent_source_group: str = Field(default="", max_length=80)


class ClaimIn(BaseModel):
    case_id: str
    subject_entity_id: str
    predicate: str = Field(min_length=1, max_length=120)
    object_entity_id: str | None = None
    value: Any = None
    epistemic_status: Literal["observed", "reported", "inferred"] = "reported"
    observed_at: datetime | None = None
    sources: list[SourceIn] = Field(min_length=1)


@router.get("/fusion/heuristics")
async def heuristics():
    return fusion.HEURISTICS


@router.post("/claims", status_code=201)
async def create_claim(request: Request, body: ClaimIn):
    if body.object_entity_id is None and body.value is None:
        raise ApiError(422, "claim_empty", "a claim needs an object entity or a value")
    with S(request).sm() as db:
        case_for(db, request, body.case_id, "editor")
        _entity(db, body.case_id, body.subject_entity_id)
        if body.object_entity_id:
            _entity(db, body.case_id, body.object_entity_id)
        for s in body.sources:
            _evidence(db, body.case_id, s.evidence_id)
        c = Claim(case_id=body.case_id, subject_entity_id=body.subject_entity_id, predicate=body.predicate,
                  object_entity_id=body.object_entity_id, value_json=body.value,
                  epistemic_status=body.epistemic_status, observed_at=body.observed_at, created_by=actor(request))
        db.add(c)
        db.flush()
        for s in body.sources:
            db.add(ClaimSource(claim_id=c.id, evidence_id=s.evidence_id, method=s.method,
                               independent_source_group=s.independent_source_group or _default_group(db, s.evidence_id)))
        db.flush()
        fusion.recompute_claim(db, c)
        audit.record(db, "claim.create", actor=actor(request), case_id=body.case_id, resource_id=c.id)
        db.commit()
        return fusion.claim_dict(db, c)


class FromFinding(BaseModel):
    finding_id: str


@router.post("/claims/from-finding", status_code=201)
async def claim_from_finding(request: Request, body: FromFinding):
    """Promote an adapter finding to an analyst-owned claim. The adapter becomes the source group."""
    with S(request).sm() as db:
        f = db.get(Finding, body.finding_id)
        if not f:
            raise ApiError(404, "not_found", "finding not found")
        case_for(db, request, f.case_id, "editor")
        c = Claim(case_id=f.case_id, subject_entity_id=f.subject_entity_id, predicate=f.predicate,
                  value_json=f.value_json, epistemic_status="reported", observed_at=f.observed_at,
                  created_by=actor(request))
        db.add(c)
        db.flush()
        db.add(ClaimSource(claim_id=c.id, evidence_id=f.evidence_id, method=f"adapter:{f.adapter_id}",
                           independent_source_group=f.adapter_id))
        db.flush()
        fusion.recompute_claim(db, c)
        db.commit()
        return fusion.claim_dict(db, c)


@router.get("/claims")
async def list_claims(request: Request, case_id: str, predicate: str | None = None,
                      verification_status: str | None = None, limit: int = Query(100, le=500), offset: int = 0):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        q = select(Claim).where(Claim.case_id == case_id).order_by(Claim.created_at)
        if predicate:
            q = q.where(Claim.predicate == predicate)
        if verification_status:
            q = q.where(Claim.verification_status == verification_status)
        total = db.scalar(select(func.count()).select_from(q.subquery()))
        return {"total": total, "items": [fusion.claim_dict(db, c) for c in db.scalars(q.limit(limit).offset(offset))]}


@router.post("/claims/{claim_id}/sources", status_code=201)
async def add_claim_source(request: Request, claim_id: str, body: SourceIn):
    with S(request).sm() as db:
        c = _claim(db, request, claim_id, "editor")
        _evidence(db, c.case_id, body.evidence_id)
        if db.get(ClaimSource, (c.id, body.evidence_id)):
            raise ApiError(409, "duplicate", "that evidence already supports this claim")
        db.add(ClaimSource(claim_id=c.id, evidence_id=body.evidence_id, method=body.method,
                           independent_source_group=body.independent_source_group or _default_group(db, body.evidence_id)))
        db.flush()
        fusion.recompute_claim(db, c)
        db.commit()
        return fusion.claim_dict(db, c)


class VerifyIn(BaseModel):
    status: Literal["unverified", "analyst_verified", "disputed", "rejected"]
    note: str = Field(default="", max_length=2000)


@router.post("/claims/{claim_id}/verification")
async def verify_claim(request: Request, claim_id: str, body: VerifyIn):
    """Only an analyst can mark a claim verified; models and adapters cannot. Reversible (set back to unverified)."""
    with S(request).sm() as db:
        c = _claim(db, request, claim_id, "editor")
        n = db.scalar(select(func.count()).select_from(ClaimSource).where(ClaimSource.claim_id == c.id)) or 0
        if body.status == "analyst_verified" and n == 0:
            raise ApiError(422, "no_evidence", "cannot verify a claim that has no evidence")
        c.verification_status = body.status
        fusion.recompute_claim(db, c)
        audit.record(db, "claim.verification", actor=actor(request), case_id=c.case_id, resource_id=c.id,
                     metadata={"status": body.status, "note": body.note})
        db.commit()
        return fusion.claim_dict(db, c)


@router.get("/claims/{claim_id}/provenance")
async def claim_provenance(request: Request, claim_id: str):
    """claim -> sources -> evidence -> acquisition record, so every statement can be traced to a hashed artifact."""
    from ...db.models import Observation, Source
    with S(request).sm() as db:
        c = _claim(db, request, claim_id)
        chain = []
        for cs in db.scalars(select(ClaimSource).where(ClaimSource.claim_id == c.id)):
            ev = db.get(Evidence, cs.evidence_id)
            src = db.get(Source, ev.source_id) if ev.source_id else None
            obs = db.scalars(select(Observation.id).where(Observation.raw_evidence_id == ev.id)).all()
            chain.append({"method": cs.method, "group": cs.independent_source_group,
                          "evidence": {"id": ev.id, "kind": ev.kind, "sha256": ev.sha256, "retrieved_at": ev.retrieved_at,
                                       "capture_method": ev.capture_method, "chain_of_custody": ev.chain_of_custody_json},
                          "source": ({"adapter": src.adapter_id, "url": src.source_url, "terms_url": src.terms_url,
                                      "license": src.license_notes} if src else None),
                          "derived_observations": obs})
        return {"claim": fusion.claim_dict(db, c), "provenance": chain}


@router.get("/cases/{case_id}/contradictions")
async def get_contradictions(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": fusion.contradictions(db, case_id)}


@router.get("/cases/{case_id}/gaps")
async def get_gaps(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return fusion.gap_assessment(db, case_id)


# ------------------------------------------------------------------ hypotheses -----------------------------------------
class HypIn(BaseModel):
    case_id: str
    statement: str = Field(min_length=3, max_length=2000)
    rationale: str = Field(default="", max_length=4000)


def _hyp_dict(db, h: Hypothesis) -> dict:
    rows = db.scalars(select(HypothesisClaim).where(HypothesisClaim.hypothesis_id == h.id)).all()
    counts = {"support": 0, "contradict": 0, "neutral": 0}
    for r in rows:
        counts[r.stance] += 1
    return {"id": h.id, "case_id": h.case_id, "statement": h.statement, "status": h.status, "rationale": h.rationale,
            "claims": [{"claim_id": r.claim_id, "stance": r.stance} for r in rows], "tally": counts,
            "note": "Tallies count claims; they are not a probability. Status is set by an analyst."}


@router.post("/hypotheses", status_code=201)
async def create_hypothesis(request: Request, body: HypIn):
    with S(request).sm() as db:
        case_for(db, request, body.case_id, "editor")
        h = Hypothesis(case_id=body.case_id, statement=body.statement, rationale=body.rationale,
                       created_by=actor(request))
        db.add(h)
        db.commit()
        return _hyp_dict(db, h)


@router.get("/hypotheses")
async def list_hypotheses(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [_hyp_dict(db, h) for h in db.scalars(select(Hypothesis).where(Hypothesis.case_id == case_id))]}


class HypClaimIn(BaseModel):
    claim_id: str
    stance: Literal["support", "contradict", "neutral"] = "support"


@router.post("/hypotheses/{hid}/claims")
async def link_hypothesis_claim(request: Request, hid: str, body: HypClaimIn):
    with S(request).sm() as db:
        h = db.get(Hypothesis, hid)
        if not h:
            raise ApiError(404, "not_found", "hypothesis not found")
        case_for(db, request, h.case_id, "editor")
        c = db.get(Claim, body.claim_id)
        if not c or c.case_id != h.case_id:
            raise ApiError(422, "invalid_citation", "claim does not belong to this case")
        db.merge(HypothesisClaim(hypothesis_id=hid, claim_id=body.claim_id, stance=body.stance))
        db.commit()
        return _hyp_dict(db, h)


class HypStatusIn(BaseModel):
    status: Literal["open", "supported", "refuted", "unresolved"]


@router.patch("/hypotheses/{hid}")
async def set_hypothesis_status(request: Request, hid: str, body: HypStatusIn):
    with S(request).sm() as db:
        h = db.get(Hypothesis, hid)
        if not h:
            raise ApiError(404, "not_found", "hypothesis not found")
        case_for(db, request, h.case_id, "editor")
        h.status = body.status
        audit.record(db, "hypothesis.status", actor=actor(request), case_id=h.case_id, resource_id=hid,
                     metadata={"status": body.status})
        db.commit()
        return _hyp_dict(db, h)


# ------------------------------------------------------------------ requirements -----------------------------------------
class ReqIn(BaseModel):
    case_id: str
    question: str = Field(min_length=1, max_length=2000)
    objective: str = Field(default="", max_length=2000)
    information_requirement: str = Field(default="", max_length=2000)
    collection_constraint: str = Field(default="", max_length=2000)
    priority: Literal["low", "medium", "high"] = "medium"
    assigned_actor: str | None = None
    due_at: datetime | None = None


def _req_dict(db, r: Requirement) -> dict:
    ev = db.scalars(select(RequirementEvidence).where(RequirementEvidence.requirement_id == r.id)).all()
    return {"id": r.id, "case_id": r.case_id, "question": r.question, "objective": r.objective,
            "information_requirement": r.information_requirement, "collection_constraint": r.collection_constraint,
            "priority": r.priority, "status": r.status, "answer_status": r.answer_status,
            "assigned_actor": r.assigned_actor, "due_at": r.due_at,
            "supporting": [{"evidence_id": e.evidence_id, "claim_id": e.claim_id, "note": e.relevance_note} for e in ev],
            "supporting_claim_ids": [e.claim_id for e in ev if e.claim_id]}


@router.post("/requirements", status_code=201)
async def create_requirement(request: Request, body: ReqIn):
    with S(request).sm() as db:
        case_for(db, request, body.case_id, "editor")
        r = Requirement(**body.model_dump(), created_by=actor(request))
        db.add(r)
        db.commit()
        return _req_dict(db, r)


@router.get("/requirements")
async def list_requirements(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [_req_dict(db, r) for r in db.scalars(select(Requirement).where(Requirement.case_id == case_id))]}


class ReqLinkIn(BaseModel):
    evidence_id: str
    claim_id: str | None = None
    relevance_note: str = Field(default="", max_length=1000)


@router.post("/requirements/{rid}/evidence")
async def link_requirement_evidence(request: Request, rid: str, body: ReqLinkIn):
    with S(request).sm() as db:
        r = db.get(Requirement, rid)
        if not r:
            raise ApiError(404, "not_found", "requirement not found")
        case_for(db, request, r.case_id, "editor")
        _evidence(db, r.case_id, body.evidence_id)
        if body.claim_id:
            c = db.get(Claim, body.claim_id)
            if not c or c.case_id != r.case_id:
                raise ApiError(422, "invalid_citation", "claim does not belong to this case")
        db.merge(RequirementEvidence(requirement_id=rid, evidence_id=body.evidence_id, claim_id=body.claim_id,
                                     relevance_note=body.relevance_note))
        db.commit()
        return _req_dict(db, r)


class ReqPatch(BaseModel):
    status: Literal["open", "in_progress", "closed"] | None = None
    answer_status: Literal["unanswered", "partial", "answered", "unanswerable"] | None = None
    assigned_actor: str | None = None


@router.patch("/requirements/{rid}")
async def patch_requirement(request: Request, rid: str, body: ReqPatch):
    with S(request).sm() as db:
        r = db.get(Requirement, rid)
        if not r:
            raise ApiError(404, "not_found", "requirement not found")
        case_for(db, request, r.case_id, "editor")
        if body.answer_status in ("answered", "partial"):
            n = db.scalar(select(func.count()).select_from(RequirementEvidence)
                          .where(RequirementEvidence.requirement_id == rid)) or 0
            if n == 0:
                raise ApiError(422, "no_evidence", "link supporting evidence before marking a requirement answered")
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(r, k, v)
        db.commit()
        return _req_dict(db, r)


# ------------------------------------------------------------------ entity links (reversible merges) ------------------
class LinkIn(BaseModel):
    entity_id: str
    canonical_entity_id: str
    reason: str = Field(min_length=3, max_length=2000)


@router.post("/cases/{case_id}/entity-links", status_code=201)
async def create_link(request: Request, case_id: str, body: LinkIn):
    """Logical merge for views/analysis only. Underlying entities, claims and evidence are never altered."""
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        a, b = _entity(db, case_id, body.entity_id), _entity(db, case_id, body.canonical_entity_id)
        if a.id == b.id or fusion.would_cycle(db, case_id, a.id, b.id):
            raise ApiError(409, "merge_cycle", "this merge would be circular or self-referential")
        if a.type != b.type:
            raise ApiError(409, "type_mismatch", f"cannot merge a {a.type} into a {b.type}")
        if db.scalars(select(EntityLink).where(EntityLink.entity_id == a.id, EntityLink.status == "active")).first():
            raise ApiError(409, "already_linked", "this entity is already merged; revert that decision first")
        link = EntityLink(case_id=case_id, entity_id=a.id, canonical_entity_id=b.id, decided_by=actor(request),
                          reason=body.reason)
        db.add(link)
        db.flush()
        audit.record(db, "entity.merge", actor=actor(request), case_id=case_id, resource_id=link.id,
                     metadata={"entity": a.id, "canonical": b.id})
        db.commit()
        return {"id": link.id, "status": link.status}


@router.post("/entity-links/{lid}/revert")
async def revert_link(request: Request, lid: str):
    from datetime import UTC
    with S(request).sm() as db:
        link = db.get(EntityLink, lid)
        if not link:
            raise ApiError(404, "not_found", "link not found")
        case_for(db, request, link.case_id, "editor")
        link.status, link.reverted_at = "reverted", datetime.now(UTC)
        audit.record(db, "entity.split", actor=actor(request), case_id=link.case_id, resource_id=lid)
        db.commit()
        return {"id": lid, "status": "reverted"}


@router.get("/cases/{case_id}/entity-links")
async def list_links(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [{"id": link.id, "entity_id": link.entity_id, "canonical_entity_id": link.canonical_entity_id,
                           "status": link.status, "reason": link.reason, "decided_by": link.decided_by}
                          for link in db.scalars(select(EntityLink).where(EntityLink.case_id == case_id))]}


# ------------------------------------------------------------------ collection plans -----------------------------------------
class PlanIn(BaseModel):
    case_id: str
    target: str = Field(min_length=1, max_length=2048)
    target_type: Literal["domain", "ip", "url", "email", "username"] | None = None
    adapters: list[str] | None = None
    mode: Literal["passive", "public_site_query", "active"] = "passive"
    reason: str = Field(min_length=3, max_length=2000)
    data_sensitivity: Literal["PUBLIC", "INTERNAL", "RESTRICTED"] = "INTERNAL"


def _plan_json(db, st, case, body: PlanIn):
    try:
        parsed, plan = service.preview(db, case, body.target, body.target_type, st.adapters, st.settings,
                                       body.adapters, body.mode)
    except TargetError as exc:
        raise ApiError(422, "invalid_target", str(exc)) from exc
    except service.PlanError as exc:
        raise ApiError(422, "plan_rejected", str(exc)) from exc
    steps = plan["steps"]
    status = ("denied" if not any(s["runnable"] for s in steps) else
              "needs_confirmation" if any(s.get("requires_confirmation") and s["runnable"] for s in steps) else "allowed")
    plan.update({"reason": body.reason, "data_sensitivity": body.data_sensitivity,
                 "cache_policy": "raw responses stored in the evidence vault; re-runs deduplicate by hash",
                 "budget": {"paid_requests": 0, "estimated_requests": sum(1 for s in steps if s["runnable"]),
                            "currency": "none (no paid sources are configured)"},
                 "recursion": "none: results never trigger follow-up collection automatically"})
    return parsed, plan, status


@router.post("/collection-plans/preview")
async def plan_preview(request: Request, body: PlanIn):
    st = S(request)
    with st.sm() as db:
        case = case_for(db, request, body.case_id, "viewer")
        _, plan, status = _plan_json(db, st, case, body)
    return {**plan, "policy_status": status}


@router.post("/collection-plans", status_code=201)
async def plan_create(request: Request, body: PlanIn):
    st = S(request)
    with st.sm() as db:
        case = case_for(db, request, body.case_id, "editor")
        parsed, plan, status = _plan_json(db, st, case, body)
        p = CollectionPlan(case_id=case.id, created_by=actor(request), reason=body.reason, policy_status=status,
                           plan_json={**plan, "request": body.model_dump()})
        db.add(p)
        db.flush()
        for s in plan["steps"]:
            db.add(CollectionStep(plan_id=p.id, adapter_id=s["adapter_id"],
                                  scope_json={"target": parsed.canonical, "runnable": s["runnable"]},
                                  status="planned" if s["runnable"] else "blocked"))
        audit.record(db, "plan.create", actor=actor(request), case_id=case.id, resource_id=p.id,
                     metadata={"policy": status})
        db.commit()
        return {"id": p.id, "policy_status": status, "status": p.status, "plan": plan}


class ApproveIn(BaseModel):
    confirmed_adapters: list[str] = Field(default_factory=list)
    wait: bool = False


@router.post("/collection-plans/{pid}/approve", status_code=202)
async def plan_approve(request: Request, pid: str, body: ApproveIn):
    import asyncio
    st = S(request)
    with st.sm() as db:
        p = db.get(CollectionPlan, pid)
        if not p:
            raise ApiError(404, "not_found", "plan not found")
        case = case_for(db, request, p.case_id, "editor")
        if p.status != "draft":
            raise ApiError(409, "not_draft", f"plan is {p.status}")
        if p.policy_status == "denied":
            audit.record(db, "plan.denied", actor=actor(request), case_id=case.id, resource_id=pid, decision="deny")
            db.commit()
            raise ApiError(409, "policy_denied", "policy denies this plan; nothing was started")
        req = PlanIn(**p.plan_json["request"])
        # Re-evaluate at approval time: scope/authorizations/offline state may have changed since the preview.
        parsed, plan, status = _plan_json(db, st, case, req)
        try:
            run = service.create_run(db, case, parsed, plan, confirmed=body.confirmed_adapters, mode=req.mode)
        except service.PlanError as exc:
            raise ApiError(409, "plan_refused", str(exc)) from exc
        p.status, p.run_id, p.policy_status = "approved", run.id, status
        for stp in db.scalars(select(CollectionStep).where(CollectionStep.plan_id == pid)):
            if stp.status == "planned":
                stp.status = "queued"
        audit.record(db, "plan.approve", actor=actor(request), case_id=case.id, resource_id=pid)
        db.commit()
        run_id = run.id
    if body.wait:
        await st.runner.run_until_idle(run_id)
    else:
        t = asyncio.create_task(st.runner.run_until_idle(run_id))
        st.tasks.add(t)
        t.add_done_callback(st.tasks.discard)
    return {"id": pid, "status": "approved", "run_id": run_id}


@router.get("/collection-plans/{pid}")
async def plan_get(request: Request, pid: str):
    with S(request).sm() as db:
        p = db.get(CollectionPlan, pid)
        if not p:
            raise ApiError(404, "not_found", "plan not found")
        case_for(db, request, p.case_id)
        steps = db.scalars(select(CollectionStep).where(CollectionStep.plan_id == pid)).all()
        jobs = {j.adapter_id: j for j in db.scalars(select(Job).where(Job.run_id == p.run_id))} if p.run_id else {}
        return {"id": p.id, "status": p.status, "policy_status": p.policy_status, "reason": p.reason, "run_id": p.run_id,
                "plan": p.plan_json,
                "steps": [{"adapter_id": s.adapter_id, "status": jobs[s.adapter_id].status if s.adapter_id in jobs
                           else s.status, "error_code": jobs[s.adapter_id].last_error_code if s.adapter_id in jobs
                           else s.error_code} for s in steps]}


@router.post("/collection-plans/{pid}/cancel")
async def plan_cancel(request: Request, pid: str):
    st = S(request)
    with st.sm() as db:
        p = db.get(CollectionPlan, pid)
        if not p:
            raise ApiError(404, "not_found", "plan not found")
        case_for(db, request, p.case_id, "editor")
        run_id = p.run_id
        p.status = "cancelled"
        db.commit()
    if run_id:
        st.runner.cancel_run(run_id)
    return {"id": pid, "status": "cancelled"}
