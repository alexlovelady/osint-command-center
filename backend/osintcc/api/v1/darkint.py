"""DARKINT API (addendum v1.1 section 14.5): provider sources, consent-gated checks, events, reviews, monitors, reports.

Request models forbid unknown fields, so a body carrying `password`, `hash`, `ssn`, `token` or similar is refused before any code runs. Nothing sensitive travels in
a URL or query string: identifiers are referenced by id, and API keys live in the secret store.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ...darkint import service
from ...db.models import ExposureEvent, ExposureMonitorConfig, ExposureReview, ReportRun, Subject
from ...evidence.vault import VaultLocked
from ...main import ApiError
from ...reporting import store as report_store
from ...telemetry import audit
from .routes import S, actor, case_for, require_admin

router: APIRouter = APIRouter()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def derr(exc: service.DarkError) -> ApiError:
    return ApiError(exc.status, exc.code, exc.message)


def _subject(db, case_id: str, subject_id: str) -> Subject:
    s = db.get(Subject, subject_id)
    if s is None or s.case_id != case_id or s.status == "purged":
        raise ApiError(404, "not_found", "subject not found in this case")
    return s


# ---- sources --------------------------------------------------------------------------------------------------------------------------------
@router.get("/darkint/sources")
async def list_sources(request: Request):
    st = S(request)
    with st.sm() as db:
        return {"items": service.sources(db, st), "mock_mode": service.mock_mode(db),
                "notice": "Each provider shows one honest state: live, mocked, manual only or disabled. 'Live' means the next check will call its documented API; none has been exercised against the live service in this build (verification: fixture_tested)."}


class SourceIn(Strict):
    enabled: bool
    acknowledge_terms: bool = False


@router.put("/darkint/sources/{provider_id}", dependencies=[Depends(require_admin)])
async def put_source(request: Request, provider_id: str, body: SourceIn):
    st = S(request)
    with st.sm() as db:
        try:
            service.set_source(db, provider_id, enabled=body.enabled, acknowledge_terms=body.acknowledge_terms, actor=actor(request))
        except service.DarkError as exc:
            db.commit()
            raise derr(exc) from exc
        db.commit()
        return next(x for x in service.sources(db, st) if x["provider_id"] == provider_id)


class MockIn(Strict):
    enabled: bool


@router.put("/darkint/mock-mode", dependencies=[Depends(require_admin)])
async def put_mock(request: Request, body: MockIn):
    with S(request).sm() as db:
        service.set_mock_mode(db, body.enabled, actor(request))
        db.commit()
    return {"mock_mode": body.enabled}


@router.get("/darkint/dashboard")
async def dashboard(request: Request):
    with S(request).sm() as db:
        return service.dashboard(db, actor(request))


# ---- checks ---------------------------------------------------------------------------------------------------------------------------------
class CheckIn(Strict):
    subject_id: str
    identifier_ids: list[str] = Field(min_length=1, max_length=20)
    provider_ids: list[str] = Field(min_length=1, max_length=8)
    domain_control_attested: bool = False
    confirm: bool = False


@router.post("/cases/{case_id}/darkint/preview")
async def preview(request: Request, case_id: str, body: CheckIn):
    """Exactly what would leave this machine, to whom, under what terms. Sends nothing. Refusals are explained here."""
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
        s = _subject(db, case_id, body.subject_id)
        try:
            out = service.preview(db, st, s, body.identifier_ids, body.provider_ids, domain_attested=body.domain_control_attested)
        except service.DarkError as exc:
            raise derr(exc) from exc
        audit.record(db, "darkint.preview", actor=actor(request), case_id=case_id, resource_type="subject", resource_id=s.id, metadata={"runnable": out["runnable"]})
        db.commit()
        return out


@router.post("/cases/{case_id}/darkint/check")
async def check(request: Request, case_id: str, body: CheckIn):
    st = S(request)
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "review the preview and confirm; the identifier is sent to each provider only after you do")
    with st.sm() as db:
        case = case_for(db, request, case_id, "editor")
        if case.status != "open":
            raise ApiError(409, "case_not_open", "the case must be open")
        s = _subject(db, case_id, body.subject_id)
        try:
            out = await service.run_check(db, st, s, body.identifier_ids, body.provider_ids, actor(request), domain_attested=body.domain_control_attested)
        except service.DarkError as exc:
            db.commit()
            raise derr(exc) from exc
        db.commit()
        return out


# ---- exposures ------------------------------------------------------------------------------------------------------------------------------
@router.get("/cases/{case_id}/darkint/exposures")
async def exposures(request: Request, case_id: str, subject_id: str):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
        s = _subject(db, case_id, subject_id)
        audit.record(db, "darkint.view", actor=actor(request), case_id=case_id, resource_type="subject", resource_id=s.id)
        db.commit()
        cov = service.coverage(db, st, s)
        groups = service.grouped_events(db, s)
        reviews = {}
        for g in groups:
            for e in g["events"]:
                reviews[e["id"]] = [{"status": r.status, "rationale": r.rationale, "reviewer": r.reviewer, "at": r.created_at, "actions": r.action_items_json}
                                    for r in db.scalars(select(ExposureReview).where(ExposureReview.event_id == e["id"]).order_by(ExposureReview.created_at))]
        return {"coverage": cov, "groups": groups, "reviews": reviews, "actions": service.ACTION_TYPES, "suggested": {e["id"]: service.suggest_actions(db.get(ExposureEvent, e["id"])) for g in groups for e in g["events"]}}


class ReviewIn(Strict):
    status: Literal["acknowledged", "relevant", "not_relevant", "corroborated", "resolved", "accepted_risk"]
    rationale: str = Field(min_length=3, max_length=1000)
    action_items: list[str] = Field(default_factory=list, max_length=10)


def _event(db, case_id: str, event_id: str) -> ExposureEvent:
    e = db.get(ExposureEvent, event_id)
    if e is None or e.case_id != case_id:
        raise ApiError(404, "not_found", "event not found in this case")
    return e


@router.patch("/cases/{case_id}/darkint/exposures/{event_id}/review")
async def review_event(request: Request, case_id: str, event_id: str, body: ReviewIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        e = _event(db, case_id, event_id)
        try:
            r = service.review(db, e, status=body.status, rationale=body.rationale, action_items=body.action_items, reviewer=actor(request))
        except service.DarkError as exc:
            raise derr(exc) from exc
        db.commit()
        return {"id": r.id, "status": r.status, "event": service.event_dict(e)}


class RemediationIn(Strict):
    action_type: Literal["mfa", "password_reset", "domain_hygiene", "takedown", "notify", "follow_up_check"]


@router.post("/cases/{case_id}/darkint/exposures/{event_id}/remediation", status_code=201)
async def add_remediation(request: Request, case_id: str, event_id: str, body: RemediationIn):
    """Creates a task. It never sends a message or submits a takedown: a person does that outside this application."""
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        e = _event(db, case_id, event_id)
        s = db.get(Subject, e.subject_id) if e.subject_id else None
        if s is None:
            raise ApiError(404, "not_found", "the event has no subject")
        try:
            t = service.create_remediation(db, s, e, body.action_type, actor(request))
        except service.DarkError as exc:
            raise derr(exc) from exc
        db.commit()
        return {"id": t.id, "issue": t.issue, "state": t.state, "priority": t.priority, "guidance": t.guidance, "sends_anything": False}


class ManualIn(Strict):
    subject_id: str
    identifier_id: str | None = None
    title: str = Field(min_length=3, max_length=200)
    event_type: Literal["breach", "paste", "darkweb_mention", "ransomware_listing", "advisory", "manual_report"] = "manual_report"
    categories: list[str] = Field(default_factory=list, max_length=20)
    reported_at: str | None = Field(default=None, max_length=40)
    source_url: str = Field(default="", max_length=300)
    claim_status: Literal["reported", "corroborated", "disputed"] = "reported"


@router.post("/cases/{case_id}/darkint/manual", status_code=201)
async def manual(request: Request, case_id: str, body: ManualIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        s = _subject(db, case_id, body.subject_id)
        try:
            e = service.manual_event(db, s, identifier_id=body.identifier_id, title=body.title, event_type=body.event_type, categories=body.categories, reported_at=body.reported_at,
                                     source_url=body.source_url, claim_status=body.claim_status, provider="manual", actor=actor(request))
        except service.DarkError as exc:
            raise derr(exc) from exc
        db.commit()
        return service.event_dict(e)


class ImportIn(Strict):
    subject_id: str
    kind: Literal["csv", "json", "misp"]
    content: str = Field(max_length=service.MAX_IMPORT_BYTES)
    identifier_id: str | None = None


@router.post("/cases/{case_id}/darkint/import")
async def import_file(request: Request, case_id: str, body: ImportIn):
    """Sanitized import (CSV, JSON, or a MISP event export). The file is read, redacted and discarded."""
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        s = _subject(db, case_id, body.subject_id)
        try:
            out = service.import_events(db, s, body.kind, body.content.encode(), body.identifier_id, actor(request))
        except service.DarkError as exc:
            db.commit()
            raise derr(exc) from exc
        db.commit()
        return out


# ---- monitors -------------------------------------------------------------------------------------------------------------------------------
def _mon(m: ExposureMonitorConfig) -> dict:
    return {"id": m.id, "subject_id": m.subject_id, "name": m.name, "identifier_ids": m.identifier_ids_json, "providers": m.providers_json, "cadence_hours": m.cadence_hours,
            "consent_id": m.consent_id, "expires_at": m.expires_at, "enabled": m.enabled, "disabled_reason": m.disabled_reason, "last_run_at": m.last_run_at, "last_outcome": m.last_outcome_json}


class MonitorIn(Strict):
    subject_id: str
    name: str = Field(min_length=1, max_length=120)
    identifier_ids: list[str] = Field(min_length=1, max_length=20)
    provider_ids: list[str] = Field(min_length=1, max_length=8)
    cadence_hours: int = Field(default=168, ge=24, le=720)
    expires_at: datetime


@router.get("/cases/{case_id}/darkint/monitors")
async def list_monitors(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        rows = db.scalars(select(ExposureMonitorConfig).where(ExposureMonitorConfig.case_id == case_id).order_by(ExposureMonitorConfig.created_at.desc())).all()
        return {"items": [_mon(m) for m in rows]}


@router.post("/cases/{case_id}/darkint/monitors", status_code=201)
async def create_monitor(request: Request, case_id: str, body: MonitorIn):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "owner")                 # scheduled lookups about someone are the case owner's decision
        s = _subject(db, case_id, body.subject_id)
        try:
            m = service.create_monitor(db, st, s, name=body.name, identifier_ids=body.identifier_ids, provider_ids=body.provider_ids, cadence_hours=body.cadence_hours,
                                       expires_at=body.expires_at, actor=actor(request))
        except service.DarkError as exc:
            db.commit()
            raise derr(exc) from exc
        db.commit()
        return _mon(m)


class MonitorSet(Strict):
    enabled: bool


@router.patch("/cases/{case_id}/darkint/monitors/{monitor_id}")
async def set_monitor(request: Request, case_id: str, monitor_id: str, body: MonitorSet):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "owner" if body.enabled else "editor")      # stopping is never harder than starting
        m = db.get(ExposureMonitorConfig, monitor_id)
        if m is None or m.case_id != case_id:
            raise ApiError(404, "not_found", "monitor not found")
        s = _subject(db, case_id, m.subject_id)
        try:
            service.set_monitor(db, st, m, s, body.enabled, actor(request))
        except service.DarkError as exc:
            db.commit()
            raise derr(exc) from exc
        db.commit()
        return _mon(m)


# ---- reports --------------------------------------------------------------------------------------------------------------------------------
class ReportIn(Strict):
    subject_id: str
    format: Literal["markdown", "html", "json"] = "markdown"


@router.post("/cases/{case_id}/darkint/reports/preview")
async def report_preview(request: Request, case_id: str, body: ReportIn):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
        s = _subject(db, case_id, body.subject_id)
        r = service.report(db, st, s)
        return {"report": r, "markdown": service.report_markdown(r), "exports_nothing": True}


@router.post("/cases/{case_id}/darkint/reports", status_code=201)
async def report_create(request: Request, case_id: str, body: ReportIn):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
        s = _subject(db, case_id, body.subject_id)
        r = service.report(db, st, s)
        text = {"markdown": service.report_markdown(r), "json": json.dumps(r, indent=2, sort_keys=True, default=str)}.get(body.format)
        if text is None:
            import html
            text = "<!doctype html><meta charset=\"utf-8\"><title>Exposure assessment</title><pre>" + html.escape(service.report_markdown(r)) + "</pre>"
        rr = ReportRun(case_id=case_id, template="darkint-report", redaction_profile="darkint", evidence_manifest_sha256="0" * 64, status="running")
        db.add(rr)
        db.flush()
        out = st.settings.export_dir
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"darkint-{s.id[:8]}-{rr.id[:8]}.{ {'markdown': 'md'}.get(body.format, body.format) }"
        path.write_text(text, encoding="utf-8")
        try:
            path, digest = await asyncio.to_thread(report_store.seal, st.vault, rr.id, path)
        except VaultLocked as exc:
            rr.status = "failed"
            db.commit()
            raise ApiError(503, "vault_locked", str(exc)) from exc
        rr.export_path, rr.status, rr.sha256 = path.name, "done", digest
        audit.record(db, "darkint.report_export", actor=actor(request), case_id=case_id, resource_type="report", resource_id=rr.id, metadata={"format": body.format})
        db.commit()
        return {"id": rr.id, "file": path.name, "sha256": digest}
