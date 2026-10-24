"""Cross-discipline views and briefing generation (spec 5B, 13, 21.6, 23.5): cross-links, unified timeline, redaction preview."""
from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ...db.models import Correlation, Evidence, Observation, ReportRun
from ...graph import correlate
from ...main import ApiError
from ...reporting import build as report_build
from ...telemetry import audit
from .routes import ReportIn, S, actor, case_for, make_report

router: APIRouter = APIRouter()


@router.get("/cases/{case_id}/cross-links")
async def cross_links(request: Request, case_id: str, window_s: float = Query(300, ge=1, le=86400), radius_m: float = Query(1000, ge=1, le=100000),
                      include_restricted: bool = False):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return correlate.suggest(db, case_id, window_s, radius_m, include_restricted)


class DecisionIn(BaseModel):
    obs_a: str
    obs_b: str
    kind: Literal["temporal", "spatial", "both"]
    decision: Literal["accept", "reject"]
    note: str = Field(default="", max_length=1000)


@router.post("/cases/{case_id}/cross-links/decision", status_code=201)
async def decide(request: Request, case_id: str, body: DecisionIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        for oid in (body.obs_a, body.obs_b):
            o = db.get(Observation, oid)
            if not o or o.case_id != case_id:
                raise ApiError(404, "not_found", "observation not in this case")
        if body.obs_a == body.obs_b:
            raise ApiError(422, "invalid", "pick two different observations")
        x, y, k = correlate.pair_key(body.obs_a, body.obs_b, body.kind)
        sug = {i["key"]: i for i in correlate.suggest(db, case_id, 86400, 100000, True)["items"]}
        key = hashlib.sha256(f"{x}|{y}|{k}".encode()).hexdigest()[:16]
        if body.decision == "accept" and key not in sug:
            raise ApiError(409, "not_suggested", "that pair is not currently a suggestion; a coincidence must exist before it can be accepted")
        prior = db.scalars(select(Correlation).where(Correlation.case_id == case_id, Correlation.obs_a_id == x, Correlation.obs_b_id == y,
                                                     Correlation.kind == k)).first()
        s = sug.get(key, {})
        row = prior or Correlation(case_id=case_id, obs_a_id=x, obs_b_id=y, kind=k)
        row.status = "accepted" if body.decision == "accept" else "rejected"
        row.note, row.decided_by, row.decided_at = body.note, actor(request), datetime.now(UTC)
        row.delta_s, row.distance_m = s.get("delta_s"), s.get("distance_m")
        db.add(row)
        db.flush()
        audit.record(db, "correlation.decision", actor=actor(request), case_id=case_id, resource_id=row.id, metadata={"decision": row.status, "kind": k})
        db.commit()
        return {"id": row.id, "status": row.status, "kind": k, "caveat": correlate.CAVEAT}


@router.post("/correlations/{cid}/revoke")
async def revoke(request: Request, cid: str):
    with S(request).sm() as db:
        c = db.get(Correlation, cid)
        if not c:
            raise ApiError(404, "not_found", "correlation not found")
        case_for(db, request, c.case_id, "editor")
        c.status, c.decided_at, c.decided_by = "revoked", datetime.now(UTC), actor(request)
        audit.record(db, "correlation.revoke", actor=actor(request), case_id=c.case_id, resource_id=cid)
        db.commit()
        return {"id": cid, "status": "revoked"}


@router.get("/cases/{case_id}/timeline/unified")
async def unified(request: Request, case_id: str, start: Annotated[datetime | None, Query(alias="from")] = None, to: datetime | None = None,
                  discipline: str | None = None, limit: Annotated[int, Query(le=2000)] = 500, include_restricted: bool = False):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        s = start.replace(tzinfo=UTC) if start and start.tzinfo is None else start
        e = to.replace(tzinfo=UTC) if to and to.tzinfo is None else to
        return {"items": correlate.unified_timeline(db, case_id, s, e, discipline, limit, include_restricted),
                "note": "Every row states which of its times is shown; unknown event times fall back to the import time and say so."}


class PreviewIn(BaseModel):
    profile: Literal["executive", "technical", "evidence_pack", "multi_int"] = "technical"
    include_sensitive: bool = False


@router.post("/cases/{case_id}/reports/preview")
async def report_preview(request: Request, case_id: str, body: PreviewIn):
    """What an export would contain and withhold, shown BEFORE anything is written (spec 13)."""
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id)
        sens = {s: n for s, n in db.execute(select(Evidence.sensitivity, func.count()).where(Evidence.case_id == case_id).group_by(Evidence.sensitivity))}
        osens = {s: n for s, n in db.execute(select(Observation.sensitivity, func.count()).where(Observation.case_id == case_id).group_by(Observation.sensitivity))}
        data = report_build.collect(db, case_id, body.profile, redact_sensitive=not body.include_sensitive)
        geo = [o for o in data["observations"] if isinstance(o["summary"].get("location"), dict)]
        withheld_ev = sum(n for s, n in sens.items() if s in ("RESTRICTED", "SECRET")) if not body.include_sensitive else 0
        withheld_obs = sum(n for s, n in osens.items() if s in ("RESTRICTED", "SECRET")) if not body.include_sensitive else 0
        return {"profile": body.profile, "destination": str(st.settings.export_dir), "will_include": {"findings": len(data["findings"]),
                "relationships": len(data["relationships"]), "evidence_items": len(data["evidence_manifest"]), "observations": len(data["observations"]),
                "claims": len(data.get("claims", [])), "notes": len(data["notes"])},
                "will_withhold": {"restricted_evidence": withheld_ev, "restricted_observations": withheld_obs},
                "sensitive_included": body.include_sensitive, "coordinates": ("exact (sensitive export)" if body.include_sensitive else
                                                                             f"rounded to ~1 km for {len(geo)} located item(s)"),
                "encryption": {"vault_encrypted": st.vault.encrypting, "report_file_encrypted": False,
                               "note": "Reports are written as plain files in the export folder; share them only over channels you trust and store them on an encrypted disk."},
                "manifest_sha256": data["evidence_manifest_sha256"]}


@router.post("/cases/{case_id}/reports/multi-int", status_code=201)
async def multi_int_report(request: Request, case_id: str, format: Literal["html", "markdown", "json", "pdf"] = "html", include_sensitive: bool = False):
    return await make_report(request, case_id, ReportIn(profile="multi_int", format=format, include_sensitive=include_sensitive))


class GenIn(BaseModel):
    case_id: str
    profile: Literal["executive", "technical", "evidence_pack", "multi_int"] = "technical"
    format: Literal["html", "markdown", "json", "pdf"] = "html"
    include_sensitive: bool = False


@router.post("/reports/generate", status_code=201)
async def generate(request: Request, body: GenIn):
    """Spec 23.8 alias of POST /cases/{id}/reports."""
    return await make_report(request, body.case_id, ReportIn(profile=body.profile, format=body.format, include_sensitive=body.include_sensitive))


_ = (asyncio, ReportRun)
