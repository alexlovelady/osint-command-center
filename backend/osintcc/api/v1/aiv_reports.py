"""AIV report, PHANTOM handoff export and the Target Profile verification view (addendum v1.1 sections 8, 10, 11).

Exports are sealed like every other report (encrypted at rest when the vault encrypts) and downloaded through the existing report download route.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ...aiv import reporting, service
from ...db.models import AivObservation, AivPlan, AivRun, AssetAuthorization, ReportRun, Setting
from ...evidence.vault import VaultLocked
from ...main import ApiError
from ...reporting import store as report_store
from ...telemetry import audit
from .aiv import need_enabled, serr
from .profile import subject_for
from .routes import S, actor, case_for

router: APIRouter = APIRouter()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def _store(st: Any, db: Any, case_id: str, template: str, profile: str, manifest: dict[str, Any], data: bytes, ext: str, stem: str) -> tuple[ReportRun, str]:
    rr = ReportRun(case_id=case_id, template=template, redaction_profile=profile, evidence_manifest_sha256=hashlib.sha256(json.dumps(manifest, sort_keys=True, default=str).encode()).hexdigest(), status="running")
    db.add(rr)
    db.flush()
    out = st.settings.export_dir
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{stem}-{rr.id[:8]}.{ext}"
    path.write_bytes(data)
    try:
        path, digest = await asyncio.to_thread(report_store.seal, st.vault, rr.id, path)
    except VaultLocked as exc:
        rr.status = "failed"
        db.commit()
        raise ApiError(503, "vault_locked", str(exc)) from exc
    rr.export_path, rr.status, rr.sha256 = path.name, "done", digest
    return rr, path.name


class ReportIn(Strict):
    format: Literal["html", "markdown", "json"] = "html"
    run_ids: list[str] | None = Field(default=None, max_length=50)
    include_false_positive: bool = False


@router.post("/cases/{case_id}/aiv/report", status_code=201)
async def create_report(request: Request, case_id: str, body: ReportIn):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
        try:
            d = reporting.collect(db, case_id, run_ids=body.run_ids, include_false_positive=body.include_false_positive)
        except service.AivError as exc:
            raise serr(exc) from exc
        if not d["runs"]:
            raise ApiError(409, "nothing_to_report", "there are no verification runs to report on yet")
        rr, name = await _store(st, db, case_id, "aiv-report", "aiv", {"runs": [r["id"] for r in d["runs"]], "observations": [o["id"] for o in d["observations"]]},
                                reporting.write(d, body.format), {"markdown": "md"}.get(body.format, body.format), f"aiv-report-{case_id[:8]}")
        audit.record(db, "aiv.report_export", actor=actor(request), case_id=case_id, resource_type="report", resource_id=rr.id, metadata={"format": body.format, "observations": len(d["observations"])})
        db.commit()
        return {"id": rr.id, "file": name, "sha256": rr.sha256, "summary": d["summary"], "audit_chain_ok": d["audit_appendix"]["chain_ok"]}


class HandoffIn(Strict):
    confirm_handoff: bool = False
    min_severity: Literal["info", "low", "medium", "high"] = "medium"


@router.post("/cases/{case_id}/aiv/handoff", status_code=201)
async def create_handoff(request: Request, case_id: str, body: HandoffIn):
    """Exports confirmed observations as a PHANTOM handoff file. It launches nothing; the case owner approves the export."""
    need_enabled(request)
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "owner")
        d = reporting.handoff(db, case_id, min_severity=body.min_severity)
        preview = {"observations": len(d["observations"]), "excluded": d["excluded"], "authorizations": len(d["authorizations"]), "restrictions": d["restrictions"]}
        if not body.confirm_handoff:
            raise ApiError(422, "approval_required", "exporting a handoff needs your explicit approval; review what it contains first", False, {"preview": preview})
        if not d["observations"]:
            raise ApiError(409, "nothing_to_hand_off", "there are no confirmed observations at or above that severity; review observations first", False, {"preview": preview})
        rr, name = await _store(st, db, case_id, "aiv-handoff", "aiv", {"observations": [o["id"] for o in d["observations"]]}, json.dumps(d, indent=2, sort_keys=True, default=str).encode(), "json", f"aiv-handoff-{case_id[:8]}")
        audit.record(db, "aiv.handoff_export", actor=actor(request), case_id=case_id, resource_type="report", resource_id=rr.id, metadata={"observations": len(d["observations"]), "schema": reporting.HANDOFF_SCHEMA})
        db.commit()
        return {"id": rr.id, "file": name, "sha256": rr.sha256, "preview": preview, "launches_anything": False}


class VerifyIn(Strict):
    document: dict[str, Any]


@router.post("/aiv/handoff/verify")
async def verify_handoff(request: Request, body: VerifyIn):
    return {"valid": reporting.verify_handoff(body.document), "schema": reporting.HANDOFF_SCHEMA}


# ---- Target Profile view: explicit links only ---------------------------------------------------------------------------------------------
@router.get("/subjects/{subject_id}/verification")
async def profile_verification(request: Request, subject_id: str):
    """What verification exists for this target profile. Assets belong to a profile only through an explicit link made by a person (owner_subject_id on the
    authorization, target_profile_id on the plan); a name that merely looks similar links nothing."""
    st = S(request)
    with st.sm() as db:
        s, case, _role = subject_for(db, request, subject_id, "editor")
        row = db.get(Setting, "aiv_enabled")
        on = bool(row and row.value_json is True)
        auths = list(db.scalars(select(AssetAuthorization).where(AssetAuthorization.case_id == case.id, AssetAuthorization.owner_subject_id == s.id)))
        plans = list(db.scalars(select(AivPlan).where(AivPlan.case_id == case.id, AivPlan.target_profile_id == s.id).order_by(AivPlan.created_at.desc())))
        runs = list(db.scalars(select(AivRun).where(AivRun.plan_id.in_([p.id for p in plans])))) if plans else []
        obs = list(db.scalars(select(AivObservation).where(AivObservation.run_id.in_([r.id for r in runs])).order_by(AivObservation.observed_at.desc()).limit(200))) if runs else []
        unlinked = len(list(db.scalars(select(AssetAuthorization.id).where(AssetAuthorization.case_id == case.id, AssetAuthorization.owner_subject_id.is_(None)))))
        return {"enabled": on, "subject_id": s.id,
                "authorizations": [service.authorization_dict(a) for a in auths], "plans": [service.plan_dict(p) for p in plans], "runs": [service.run_dict(r) for r in runs],
                "observations": [service.observation_dict(o) for o in obs],
                "unlinked_case_authorizations": unlinked,
                "notice": ("Consent from this person is not authorization to test a domain, server or company that merely carries their name. An asset appears here only after the case owner "
                           "linked its authorization to this profile, and every check still needs its own asset authorization and an approved plan.")}
