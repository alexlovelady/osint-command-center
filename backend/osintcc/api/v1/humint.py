"""HUMINT workspace (spec 21.2, 21.7 P2B): consented human sources known only by alias.

Principles enforced in code: consent is mandatory and revocable; reliability/credibility are analyst judgements (never
computed); source reports are RESTRICTED evidence in the (encrypted) vault; conflicting reports stay separate;
revocation blocks reuse and can delete content; no real-name fields exist.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ...db.models import (
    Claim,
    ClaimSource,
    ConsentAuthorization,
    Evidence,
    HumanSource,
    Observation,
    RequirementEvidence,
)
from ...evidence.vault import VaultError, VaultLocked
from ...graph import fusion
from ...main import ApiError
from ...telemetry import audit
from .routes import S, actor, case_for

router: APIRouter = APIRouter()
BASES = ("informed_consent", "contract", "public_interview", "legal_duty")


def _aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=UTC) if d is not None and d.tzinfo is None else d


class ConsentIn(BaseModel):
    basis: Literal["informed_consent", "contract", "public_interview", "legal_duty"]
    authorizing_party: str = Field(min_length=2, max_length=200)
    scope: list[str] = Field(min_length=1, max_length=20)
    expires_at: datetime | None = None
    supporting_evidence_id: str | None = None


class SourceIn(BaseModel):
    alias: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9 _\-]+$")
    consent: ConsentIn
    retention_days: int | None = Field(default=None, ge=1, le=3650)


def _src(db, request, sid: str, need="viewer") -> HumanSource:
    s = db.get(HumanSource, sid)
    if not s:
        raise ApiError(404, "not_found", "source not found")
    case_for(db, request, s.case_id, need)
    return s


def _src_dict(db, s: HumanSource) -> dict:
    c = db.get(ConsentAuthorization, s.consent_id)
    n = db.scalar(select(func.count()).select_from(Evidence).where(
        Evidence.case_id == s.case_id, Evidence.kind == "human.report", Evidence.title.like(f"{s.id}:%"))) or 0
    now = datetime.now(UTC)
    exp = _aware(c.expires_at)
    return {"id": s.id, "alias": s.alias, "case_id": s.case_id, "reliability_assessment": s.reliability_assessment,
            "reliability_note": "analyst judgement (A-F); the system never computes or implies a trust score",
            "restricted": s.restricted, "reports": n, "retention_until": s.retention_until,
            "status": "revoked" if s.revoked_at else ("consent_expired" if exp and exp <= now else "active"),
            "consent": {"id": c.id, "basis": c.basis, "authorizing_party": c.authorizing_party, "scope": c.scope_json.get("items", []),
                        "expires_at": c.expires_at, "revoked_at": c.revoked_at}}


def _usable(db, s: HumanSource) -> ConsentAuthorization:
    c = db.get(ConsentAuthorization, s.consent_id)
    if s.revoked_at or c.revoked_at:
        raise ApiError(409, "consent_revoked", "consent for this source was withdrawn; no further material may be added or used")
    exp = _aware(c.expires_at)
    if exp and exp <= datetime.now(UTC):
        raise ApiError(409, "consent_expired", "consent for this source has expired; renew it before adding material")
    return c


@router.post("/cases/{case_id}/human-sources", status_code=201)
async def create_source(request: Request, case_id: str, body: SourceIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        if db.scalars(select(HumanSource).where(HumanSource.case_id == case_id, HumanSource.alias == body.alias)).first():
            raise ApiError(409, "duplicate_alias", "that alias already exists in this case")
        if body.consent.supporting_evidence_id:
            ev = db.get(Evidence, body.consent.supporting_evidence_id)
            if not ev or ev.case_id != case_id:
                raise ApiError(422, "invalid_citation", "supporting evidence does not belong to this case")
        c = ConsentAuthorization(case_id=case_id, basis=body.consent.basis, authorizing_party=body.consent.authorizing_party,
                                 scope_json={"items": body.consent.scope}, expires_at=body.consent.expires_at,
                                 supporting_evidence_id=body.consent.supporting_evidence_id)
        db.add(c)
        db.flush()
        s = HumanSource(case_id=case_id, alias=body.alias, consent_id=c.id,
                        retention_until=(datetime.now(UTC) + timedelta(days=body.retention_days)) if body.retention_days else None)
        db.add(s)
        db.flush()
        audit.record(db, "humint.source_create", actor=actor(request), case_id=case_id, resource_id=s.id,
                     metadata={"basis": body.consent.basis})  # alias deliberately not logged
        db.commit()
        return _src_dict(db, s)


@router.get("/cases/{case_id}/human-sources")
async def list_sources(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [_src_dict(db, s) for s in db.scalars(select(HumanSource).where(HumanSource.case_id == case_id))]}


class AssessIn(BaseModel):
    reliability: Literal["A", "B", "C", "D", "E", "F"]
    note: str = Field(default="", max_length=1000)


@router.post("/human-sources/{sid}/assessment")
async def assess_source(request: Request, sid: str, body: AssessIn):
    with S(request).sm() as db:
        s = _src(db, request, sid, "editor")
        s.reliability_assessment = body.reliability
        audit.record(db, "humint.assessment", actor=actor(request), case_id=s.case_id, resource_id=sid,
                     metadata={"reliability": body.reliability})
        db.commit()
        return _src_dict(db, s)


class ReportIn(BaseModel):
    text: str = Field(min_length=1, max_length=50000)
    information_credibility: Literal[1, 2, 3, 4, 5, 6] | None = None
    observed_at: datetime | None = None
    claims: list[str] = Field(default_factory=list, max_length=50)


@router.post("/human-sources/{sid}/reports", status_code=201)
async def add_report(request: Request, sid: str, body: ReportIn):
    st = S(request)
    with st.sm() as db:
        s = _src(db, request, sid, "editor")
        _usable(db, s)
        try:
            sha256, sha512, rel, size = st.vault.store(body.text.encode())
        except VaultLocked as exc:
            raise ApiError(503, "vault_locked", str(exc), True) from exc
        now = datetime.now(UTC)
        ev = Evidence(case_id=s.case_id, kind="human.report", title=f"{s.id}:{now:%Y%m%dT%H%M%S}", sha256=sha256, sha512=sha512,
                      byte_size=size, mime_type="text/plain", vault_relpath=rel, retrieved_at=now, observed_at=body.observed_at or now,
                      capture_method="analyst_entry", sensitivity="RESTRICTED", created_by=actor(request),
                      description="Human source report (RESTRICTED). Statement of the source, not verified fact.",
                      chain_of_custody_json=[{"event": "recorded", "at": now.isoformat(), "by": actor(request), "sha256": sha256}])
        db.add(ev)
        db.flush()
        obs = Observation(case_id=s.case_id, discipline_id="HUMINT", kind="humint.report", access_class="CONSENTED",
                          observed_at=body.observed_at, ingested_at=now, raw_evidence_id=ev.id, sensitivity="RESTRICTED",
                          confidence="unknown", parser_version="1",
                          data_json={"source_alias": s.alias, "source_id": s.id, "reliability": s.reliability_assessment,
                                     "information_credibility": body.information_credibility,
                                     "stated_claims": body.claims, "status": "uncorroborated source statement",
                                     "note": "credibility/reliability are analyst assigned; they are not probabilities"})
        db.add(obs)
        audit.record(db, "humint.report_add", actor=actor(request), case_id=s.case_id, resource_id=ev.id,
                     metadata={"bytes": size})  # content and alias never enter the audit log
        db.commit()
        return {"observation_id": obs.id, "evidence_id": ev.id, "status": "recorded as an uncorroborated statement"}


class RevokeIn(BaseModel):
    delete_content: bool = False
    reason: str = Field(default="", max_length=1000)
    confirm: bool = False


@router.post("/human-sources/{sid}/revoke")
async def revoke_source(request: Request, sid: str, body: RevokeIn):
    """Withdraws consent immediately. With delete_content the source's reports, derived claims and index entries are
    removed (vault object kept only if another evidence row still references the same hash)."""
    st = S(request)
    with st.sm() as db:
        s = _src(db, request, sid, "owner")
        if body.delete_content and not body.confirm:
            raise ApiError(422, "confirmation_required", "deleting content is irreversible: send confirm=true")
        now = datetime.now(UTC)
        c = db.get(ConsentAuthorization, s.consent_id)
        c.revoked_at = s.revoked_at = now
        removed = {"evidence": 0, "observations": 0, "claims": 0}
        paths: list[tuple[str, str]] = []
        if body.delete_content:
            evs = db.scalars(select(Evidence).where(Evidence.case_id == s.case_id, Evidence.kind == "human.report",
                                                    Evidence.title.like(f"{s.id}:%"))).all()
            for ev in evs:
                for o in db.scalars(select(Observation).where(Observation.raw_evidence_id == ev.id)):
                    db.delete(o)
                    removed["observations"] += 1
                affected = {cs.claim_id for cs in db.scalars(select(ClaimSource).where(ClaimSource.evidence_id == ev.id))}
                for cs in db.scalars(select(ClaimSource).where(ClaimSource.evidence_id == ev.id)):
                    db.delete(cs)
                for re_ in db.scalars(select(RequirementEvidence).where(RequirementEvidence.evidence_id == ev.id)):
                    db.delete(re_)
                db.flush()
                for cid in affected:
                    left = db.scalar(select(func.count()).select_from(ClaimSource).where(ClaimSource.claim_id == cid)) or 0
                    cl = db.get(Claim, cid)
                    if left == 0:
                        db.delete(cl)
                        removed["claims"] += 1
                    else:
                        fusion.recompute_claim(db, cl)
                if ev.vault_relpath:
                    paths.append((ev.sha256, ev.vault_relpath))
                db.delete(ev)
                removed["evidence"] += 1
        audit.record(db, "humint.revoke", actor=actor(request), case_id=s.case_id, resource_id=sid,
                     metadata={"delete_content": body.delete_content, "removed": removed, "reason": body.reason[:200]})
        db.commit()
        still = {h for (h,) in db.execute(select(Evidence.sha256))}
    deleted_files = 0
    for sha, rel in paths:
        if sha not in still:
            try:
                p = st.vault._abs(rel)
                if p.is_file():
                    p.unlink()
                    deleted_files += 1
            except VaultError:
                pass
    with st.sm() as db:
        return {**_src_dict(db, db.get(HumanSource, sid)), "removed": removed, "vault_objects_deleted": deleted_files}


@router.get("/cases/{case_id}/humint/corroboration")
async def corroboration(request: Request, case_id: str):
    """Claims touched by human sources, with how many independent source groups back each. Single-source claims are
    flagged. Nothing is scored."""
    with S(request).sm() as db:
        case_for(db, request, case_id)
        rows = []
        for cl in db.scalars(select(Claim).where(Claim.case_id == case_id)):
            srcs = db.scalars(select(ClaimSource).where(ClaimSource.claim_id == cl.id)).all()
            human = [x for x in srcs if (db.get(Evidence, x.evidence_id) or Evidence()).kind == "human.report"]
            if not human:
                continue
            groups = sorted({x.independent_source_group or x.evidence_id for x in srcs})
            rows.append({**fusion.claim_dict(db, cl), "human_sources": len({x.independent_source_group for x in human}),
                         "groups": groups, "single_source": len(groups) < 2,
                         "corroborated_by_non_human": any(x not in human for x in srcs)})
        return {"items": rows, "note": "A claim is 'corroborated' only when independent groups agree; "
                                       "an analyst still decides verification."}


@router.get("/system/retention/due")
async def retention_due(request: Request):
    """Lists sources past their retention date. Nothing is deleted automatically."""
    now = datetime.now(UTC)
    out = []
    with S(request).sm() as db:
        for s in db.scalars(select(HumanSource).where(HumanSource.retention_until.is_not(None))):
            try:
                case_for(db, request, s.case_id)
            except ApiError:
                continue
            ru = _aware(s.retention_until)
            if ru is not None and ru <= now:
                out.append({"source_id": s.id, "case_id": s.case_id, "retention_until": s.retention_until})
    return {"items": out, "note": "Review and revoke with delete_content to remove; the system never deletes evidence by itself."}
