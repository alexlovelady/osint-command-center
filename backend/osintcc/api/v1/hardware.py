"""Device manager and capture sessions (spec 21.2 sensor console, 23.6).

Sensor collection is opt-in per session: explicit confirmation, ownership/authorization assessment for real receivers, a visible
active-session list with a stop button, a hard duration cap, receive-only drivers, and hotplug/restart recovery.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...db.models import CaptureSession, HardwareDevice
from ...hardware import CaptureResult, DeviceGone, Discovered, Handle, NotSupported, default_drivers
from ...ingest import parsers
from ...ingest import service as ingest_service
from ...main import ApiError
from ...telemetry import audit
from .routes import S, actor, case_for

router: APIRouter = APIRouter()
_DRIVERS = default_drivers()
_HANDLES: dict[str, tuple[Handle, Discovered]] = {}  # in-memory by session id; a restart marks open sessions interrupted
MAX_SECONDS = 300


def _dd(d: HardwareDevice) -> dict:
    return {"id": d.id, "driver_id": d.driver_id, "kind": d.device_kind, "name": d.logical_name, "present": d.present,
            "simulated": d.simulated, "receive_only": d.receive_only, "permission_scope": d.permission_scope, "last_seen_at": d.last_seen_at,
            "label": "SIMULATION ONLY" if d.simulated else "real hardware"}


def rescan(db) -> list[HardwareDevice]:
    """Discovery is passive and idempotent; devices not seen again are marked absent (hotplug), never deleted."""
    now = datetime.now(UTC)
    seen: set[str] = set()
    for drv in _DRIVERS.values():
        try:
            found = drv.discover()
        except Exception:
            found = []
        for f in found:
            row = db.scalars(select(HardwareDevice).where(HardwareDevice.driver_id == drv.id, HardwareDevice.hw_key == f.hw_key)).first()
            if row is None:
                row = HardwareDevice(driver_id=drv.id, device_kind=drv.device_kind, logical_name=f.logical_name, hw_key=f.hw_key,
                                     receive_only=drv.receive_only, simulated=drv.simulated, metadata_json=f.metadata)
                db.add(row)
                db.flush()
            row.present, row.last_seen_at, row.metadata_json = True, now, f.metadata
            seen.add(row.id)
    for row in db.scalars(select(HardwareDevice)):
        if row.id not in seen:
            row.present = False
    db.flush()
    return list(db.scalars(select(HardwareDevice)))


@router.get("/devices")
async def devices(request: Request):
    with S(request).sm() as db:
        rows = rescan(db)
        db.commit()
        return {"items": [_dd(d) for d in rows]}


@router.get("/hardware/diagnostics")
async def diagnostics(request: Request):
    """Non-blocking: every driver reports independently; missing libraries/drivers never affect anything else."""
    out = []
    for drv in _DRIVERS.values():
        out.append({"driver_id": drv.id, "kind": drv.device_kind, "simulated": drv.simulated, "receive_only": drv.receive_only, **drv.health()})
    return {"drivers": out, "note": "No device is required for any workflow; simulated drivers and imports cover every test path."}


@router.get("/devices/{did}/capabilities")
async def capabilities(request: Request, did: str):
    with S(request).sm() as db:
        d = db.get(HardwareDevice, did)
        if not d:
            raise ApiError(404, "not_found", "device not found")
        drv = _DRIVERS[d.driver_id]
        return drv.capabilities(Discovered(d.hw_key, d.logical_name, d.metadata_json))


@router.post("/devices/{did}/disconnect")
async def disconnect(request: Request, did: str):
    with S(request).sm() as db:
        d = db.get(HardwareDevice, did)
        if not d:
            raise ApiError(404, "not_found", "device not found")
        _DRIVERS[d.driver_id].disconnect(Discovered(d.hw_key, d.logical_name, d.metadata_json))
        d.present = False
        audit.record(db, "hardware.disconnect", actor=actor(request), resource_id=did)
        db.commit()
        return _dd(d)


class Scope(BaseModel):
    purpose: str = Field(min_length=3, max_length=500)
    ownership: Literal["owned_signal", "authorized_lab", "public_broadcast", "simulation"] = "simulation"
    region: str | None = Field(default=None, max_length=40)
    acknowledged_laws: bool = False
    centre_hz: float | None = Field(default=None, gt=0, lt=6e9)


class CaptureIn(BaseModel):
    device_id: str
    case_id: str
    scope: Scope
    duration_s: float = Field(default=2.0, gt=0, le=MAX_SECONDS)
    confirm: bool = False


def _sd(s: CaptureSession) -> dict:
    return {"id": s.id, "device_id": s.device_id, "case_id": s.case_id, "status": s.status, "started_at": s.started_at, "ended_at": s.ended_at,
            "artifact_id": s.artifact_id, "clock_sync": s.clock_sync, "detail": s.detail, "scope": s.capture_scope_json}


@router.post("/captures", status_code=201)
async def start_capture(request: Request, body: CaptureIn):
    st = S(request)
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "starting a capture is an explicit action: send confirm=true")
    with st.sm() as db:
        case_for(db, request, body.case_id, "editor")
        d = db.get(HardwareDevice, body.device_id)
        if not d or not d.present:
            raise ApiError(404, "not_found", "device not found or not connected")
        if not d.simulated:
            sc = body.scope
            if sc.ownership == "simulation" or not sc.acknowledged_laws or not (sc.region or "").strip():
                raise ApiError(422, "assessment_required", "real receivers need an ownership/authorization assessment, your region, and "
                                                           "acknowledgement of local radio/recording laws before any capture")
        if db.scalars(select(CaptureSession).where(CaptureSession.device_id == d.id, CaptureSession.status == "recording")).first():
            raise ApiError(409, "device_busy", "this device is already recording")
        drv = _DRIVERS[d.driver_id]
        disc = Discovered(d.hw_key, d.logical_name, d.metadata_json)
        scope = {**body.scope.model_dump(), "duration_s": body.duration_s}
        try:
            handle = drv.start_capture(disc, scope)
        except NotSupported as exc:
            raise ApiError(409, "not_supported", str(exc)) from exc
        s = CaptureSession(device_id=d.id, case_id=body.case_id, capture_scope_json=scope, started_by=actor(request),
                           detail="recording (receive only)")
        db.add(s)
        db.flush()
        audit.record(db, "capture.start", actor=actor(request), case_id=body.case_id, resource_id=s.id,
                     metadata={"driver": d.driver_id, "ownership": body.scope.ownership, "simulated": d.simulated, "seconds": body.duration_s})
        db.commit()
        _HANDLES[s.id] = (handle, disc)
        sid, who, secs = s.id, actor(request), body.duration_s

        async def auto_finish() -> None:  # hard cap: a session can never record longer than the requested duration
            await asyncio.sleep(secs)
            await _finish(st, sid, who, False)
        t = asyncio.create_task(auto_finish())
        st.tasks.add(t)
        t.add_done_callback(st.tasks.discard)
        return _sd(s)


async def _finish(st, sid: str, who: str, stopped_by_user: bool) -> dict:
    with st.sm() as db:
        s = db.get(CaptureSession, sid)
        if s.status != "recording":  # stop and the duration timer can race; only the first one finishes the session
            return _sd(s)
    handle, _disc = _HANDLES.pop(sid, (None, None))
    with st.sm() as db:
        s = db.get(CaptureSession, sid)
        d = db.get(HardwareDevice, s.device_id)
        drv = _DRIVERS[d.driver_id]
        case_id, simulated = s.case_id, d.simulated
    result: CaptureResult | None = None
    status, detail = "completed" if not stopped_by_user else "stopped", ""
    if handle is None:
        status, detail = "interrupted", "capture handle lost (application restarted)"
    else:
        try:
            result = await asyncio.to_thread(drv.stop_capture, handle)
        except DeviceGone as exc:
            result, status, detail = exc.partial, "interrupted", "device disconnected during capture; partial data kept" if exc.partial else "device disconnected; no data"
            with st.sm() as db:
                db.get(HardwareDevice, d.id).present = False
                db.commit()
        except NotSupported as exc:
            status, detail = "failed", str(exc)
    artifact = None
    warnings: list[str] = []
    if result is not None:
        try:
            parsed = await asyncio.to_thread(parsers.PARSERS[result.kind], result.data)
            if simulated:
                parsed.access_class = "SIMULATION"
                parsed.warnings.append("SIMULATED capture: no real signal was received.")
            with st.sm() as db:
                out = ingest_service.persist(db, st.vault, case_id, parsed, result.data, result.filename, who)
                db.commit()
            artifact, warnings = out["evidence_id"], out["warnings"]
        except parsers.IngestError as exc:
            status, detail = "failed", f"capture could not be parsed: {exc}"
    with st.sm() as db:
        s = db.get(CaptureSession, sid)
        s.status, s.ended_at, s.artifact_id, s.detail = status, datetime.now(UTC), artifact, (detail or "; ".join(warnings))[:500]
        audit.record(db, "capture.end", actor=who, case_id=case_id, resource_id=sid, metadata={"status": status})
        db.commit()
        return _sd(s)


@router.post("/captures/{sid}/stop")
async def stop_capture(request: Request, sid: str):
    st = S(request)
    with st.sm() as db:
        s = db.get(CaptureSession, sid)
        if not s:
            raise ApiError(404, "not_found", "capture not found")
        case_for(db, request, s.case_id, "editor")
        if s.status != "recording":
            return _sd(s)  # idempotent
    return await _finish(st, sid, actor(request), True)


@router.get("/captures")
async def list_captures(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [_sd(s) for s in db.scalars(select(CaptureSession).where(CaptureSession.case_id == case_id).order_by(CaptureSession.started_at.desc()))]}


@router.get("/captures/active")
async def active(request: Request):
    """The session indicator: anything still recording, visible from anywhere in the UI."""
    with S(request).sm() as db:
        out = []
        for s in db.scalars(select(CaptureSession).where(CaptureSession.status == "recording")):
            try:
                case_for(db, request, s.case_id)
            except ApiError:
                continue
            out.append(_sd(s))
        return {"items": out}


class ReplayIn(BaseModel):
    case_id: str
    filename: str = Field(min_length=1, max_length=200)


@router.post("/captures/replay", status_code=201)
async def replay(request: Request, case_id: str, filename: str):
    """`import_capture` via the replay driver: bring an existing recording in through the device pipeline (raw body)."""
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
        rows = rescan(db)
        dev = next(d for d in rows if d.driver_id == "replay")
        db.commit()
    raw = await request.body()
    if not raw or len(raw) > st.settings.max_import_bytes:
        raise ApiError(413 if raw else 422, "invalid_upload", "empty or oversized upload")
    try:
        res = _DRIVERS["replay"].import_capture(raw, filename)
        parsed = await asyncio.to_thread(parsers.PARSERS[res.kind], raw)
    except (NotSupported, parsers.IngestError) as exc:
        raise ApiError(422, "malformed_input", str(exc)) from exc
    with st.sm() as db:
        out = ingest_service.persist(db, st.vault, case_id, parsed, raw, filename, actor(request))
        s = CaptureSession(device_id=dev.id, case_id=case_id, status="completed", ended_at=datetime.now(UTC), artifact_id=out["evidence_id"],
                           started_by=actor(request), capture_scope_json={"purpose": "replay of an existing recording"}, detail="imported, not captured")
        db.add(s)
        db.commit()
        return _sd(s)


def recover_sessions(sm) -> int:
    """Power loss / crash: any session left 'recording' is interrupted. Data already persisted stays intact."""
    n = 0
    with sm() as db:
        for s in db.scalars(select(CaptureSession).where(CaptureSession.status == "recording")):
            s.status, s.ended_at, s.detail = "interrupted", datetime.now(UTC), "application stopped during capture; no artifact was written"
            n += 1
        db.commit()
    return n
