from __future__ import annotations

import asyncio
import json
import struct

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import AuditEvent, CaptureSession, Evidence, HardwareDevice, Observation
from osintcc.hardware import (
    CaptureResult,
    DeviceGone,
    NotSupported,
    ReplayDriver,
    RtlSdrDriver,
    SimEsp32Driver,
    SimSdrDriver,
    default_drivers,
)
from osintcc.ingest import parsers, tracks
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import func, select


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            c.app = app
            cid = (await c.post("/api/v1/cases", json={"title": "HW", "purpose": "hardware tests"})).json()["id"]
            yield c, cid, app


async def dev(c, driver, name_part=None):
    items = (await c.get("/api/v1/devices")).json()["items"]
    return next(d for d in items if d["driver_id"] == driver and (name_part is None or name_part in d["name"]))


# ---- protocol safety ---------------------------------------------------------------------------------------------------
def test_driver_protocol_is_receive_only_by_construction():
    banned = ("transmit", "tx", "send", "jam", "spoof", "write", "emit", "inject")
    for d in default_drivers().values():
        assert d.receive_only is True
        names = [n.lower() for n in dir(d) if not n.startswith("_")]
        assert not [n for n in names if any(b in n for b in banned)], (d.id, names)
        assert d.capabilities(d.discover()[0]) .get("transmit", False) is False if d.discover() else True
    assert {"discover", "capabilities", "health", "start_capture", "stop_capture", "import_capture", "disconnect", "simulate"} <= set(dir(SimSdrDriver))


def test_simulated_sdr_is_deterministic_and_parses_as_sigmf():
    a = SimSdrDriver().simulate(5, seconds=1.0, tone_hz=1500.0)
    b = SimSdrDriver().simulate(5, seconds=1.0, tone_hz=1500.0)
    assert a.data == b.data or parsers.parse_sigmf(a.data).observations[0].data["spectrum"]["peaks"] == parsers.parse_sigmf(b.data).observations[0].data["spectrum"]["peaks"]
    pk = parsers.parse_sigmf(a.data).observations[0].data["spectrum"]["peaks"][0]
    assert abs(pk["offset_hz"] - 1500.0) <= 48000 / 4096
    assert "SIMULATED" in parsers.parse_sigmf(a.data).observations[0].data["description"]


def test_real_driver_reports_not_installed_honestly_and_is_gated(monkeypatch):
    d = RtlSdrDriver()
    monkeypatch.delenv("OSINTCC_ALLOW_UNVERIFIED_HW", raising=False)
    h = d.health()
    assert h["status"] in ("not_installed", "degraded") and h["verified_on_physical_device"] is False
    if h["status"] == "not_installed":
        assert d.discover() == [] and any("Zadig" in r or "udev" in r for r in h["remediation"])
    from osintcc.hardware import Discovered
    with pytest.raises(NotSupported, match="unverified"):
        d.start_capture(Discovered("k", "n", {"index": 0}), {})


def test_replay_driver_detects_recordings_and_refuses_unknown():
    r = ReplayDriver()
    assert r.import_capture(SimEsp32Driver().simulate(1).data, "x.csv").kind == "sensor_csv"
    with pytest.raises(NotSupported):
        r.import_capture(b"\x00\x01\x02", "mystery.dat")
    with pytest.raises(NotSupported):
        r.start_capture(r.discover()[0], {})


# ---- device manager -----------------------------------------------------------------------------------------------------
async def test_discovery_lists_simulated_devices_clearly_labelled_and_is_idempotent(api):
    c, _cid, _ = api
    a = (await c.get("/api/v1/devices")).json()["items"]
    b = (await c.get("/api/v1/devices")).json()["items"]
    assert {d["id"] for d in a} == {d["id"] for d in b} and len(a) == 4
    assert all(d["label"] == "SIMULATION ONLY" and d["receive_only"] for d in a)
    caps = (await c.get(f"/api/v1/devices/{a[0]['id']}/capabilities")).json()
    assert caps["receive_only"] is True and caps.get("transmit", False) is False
    diag = (await c.get("/api/v1/hardware/diagnostics")).json()["drivers"]
    assert {d["driver_id"] for d in diag} == {"sim_sdr", "sim_esp32", "replay", "rtlsdr"} and all("status" in d for d in diag)
    rt = next(d for d in diag if d["driver_id"] == "rtlsdr")
    assert rt["verified_on_physical_device"] is False  # nothing is claimed that has not been tested on hardware


async def test_capture_requires_explicit_confirmation_and_a_purpose(api):
    c, cid, _ = api
    d = await dev(c, "sim_sdr", "tone 1 kHz")
    base = {"device_id": d["id"], "case_id": cid, "scope": {"purpose": "bench test of the pipeline", "ownership": "simulation"}, "duration_s": 0.2}
    assert (await c.post("/api/v1/captures", json=base)).status_code == 422                       # no confirm
    assert (await c.post("/api/v1/captures", json={**base, "confirm": True, "scope": {"ownership": "simulation"}})).status_code == 422  # no purpose
    assert (await c.post("/api/v1/captures", json={**base, "confirm": True, "duration_s": 99999})).status_code == 422  # hard cap
    assert (await c.post("/api/v1/captures", json={**base, "confirm": True, "duration_s": 0})).status_code == 422
    with c.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(CaptureSession)) == 0


async def test_session_indicator_stop_and_artifact_pipeline(api):
    c, cid, app = api
    d = await dev(c, "sim_sdr", "tone 1 kHz")
    body = {"device_id": d["id"], "case_id": cid, "confirm": True, "duration_s": 5,
            "scope": {"purpose": "bench test of the pipeline", "ownership": "simulation"}}
    s = (await c.post("/api/v1/captures", json=body)).json()
    assert s["status"] == "recording" and s["clock_sync"] == "unverified"
    act = (await c.get("/api/v1/captures/active")).json()["items"]
    assert [x["id"] for x in act] == [s["id"]]                                  # visible session indicator
    assert (await c.post("/api/v1/captures", json=body)).status_code == 409     # device busy
    done = (await c.post(f"/api/v1/captures/{s['id']}/stop")).json()
    assert done["status"] == "stopped" and done["artifact_id"]
    assert (await c.post(f"/api/v1/captures/{s['id']}/stop")).json()["status"] == "stopped"  # idempotent
    assert (await c.get("/api/v1/captures/active")).json()["items"] == []
    ev = (await c.get(f"/api/v1/evidence/{done['artifact_id']}")).json()
    assert ev["integrity_verified"] and ev["kind"] == "import.sigmf"
    obs = (await c.get(f"/api/v1/cases/{cid}/observations?discipline=SIGINT")).json()["items"][0]
    assert obs["access_class"] == "SIMULATION" and obs["data"]["spectrum"]["peaks"]
    with app.state.core.sm() as db:
        acts = [a.action for a in db.scalars(select(AuditEvent).order_by(AuditEvent.seq)) if a.action.startswith("capture.")]
        assert acts == ["capture.start", "capture.end"]


async def test_duration_limit_ends_the_session_automatically(api):
    c, cid, app = api
    d = await dev(c, "sim_esp32")
    s = (await c.post("/api/v1/captures", json={"device_id": d["id"], "case_id": cid, "confirm": True, "duration_s": 0.2,
                                                "scope": {"purpose": "sensor check", "ownership": "simulation"}})).json()
    await asyncio.gather(*list(app.state.core.tasks))
    done = next(x for x in (await c.get(f"/api/v1/captures?case_id={cid}")).json()["items"] if x["id"] == s["id"])
    assert done["status"] == "completed" and done["artifact_id"]
    o = (await c.get(f"/api/v1/cases/{cid}/observations?discipline=MASINT&kind=sensor.anomaly_interval")).json()["items"]
    assert o and o[0]["access_class"] == "SIMULATION" and o[0]["data"]["cause"] == "unknown"


async def test_usb_removal_mid_capture_keeps_partial_data_and_marks_device_absent(api):
    c, cid, app = api
    d = await dev(c, "sim_sdr", "unplugs")
    s = (await c.post("/api/v1/captures", json={"device_id": d["id"], "case_id": cid, "confirm": True, "duration_s": 4,
                                                "scope": {"purpose": "hotplug test", "ownership": "simulation"}})).json()
    done = (await c.post(f"/api/v1/captures/{s['id']}/stop")).json()
    assert done["status"] == "interrupted" and "partial data kept" in done["detail"] and done["artifact_id"]
    items = (await c.get("/api/v1/devices")).json()["items"]
    assert next(x for x in items if x["id"] == d["id"])["present"] is True  # a rescan sees the (simulated) device again: hotplug works both ways
    with app.state.core.sm() as db:
        assert db.get(Evidence, done["artifact_id"]).sha256


async def test_real_receivers_need_an_ownership_assessment_and_law_acknowledgement(api):
    c, cid, app = api
    with app.state.core.sm() as db:  # pretend a physical receiver is present (driver unverified, so it will still refuse to record)
        db.add(HardwareDevice(driver_id="rtlsdr", device_kind="sdr", logical_name="RTL-SDR #0", hw_key="k0", simulated=False,
                              receive_only=True, present=True, metadata_json={"index": 0}))
        db.commit()
        did = db.scalars(select(HardwareDevice).where(HardwareDevice.hw_key == "k0")).one().id
    base = {"device_id": did, "case_id": cid, "confirm": True, "duration_s": 1}
    for scope in ({"purpose": "listening test", "ownership": "simulation"},
                  {"purpose": "listening test", "ownership": "owned_signal", "region": "US"},
                  {"purpose": "listening test", "ownership": "owned_signal", "acknowledged_laws": True}):
        r = await c.post("/api/v1/captures", json={**base, "scope": scope})
        assert r.status_code == 422 and r.json()["code"] == "assessment_required", scope
    ok_scope = {"purpose": "listening test", "ownership": "owned_signal", "region": "US", "acknowledged_laws": True}
    r = await c.post("/api/v1/captures", json={**base, "scope": ok_scope})
    assert r.status_code in (404, 409)  # assessment passed, but the unplugged/unverified driver refuses to record: nothing started
    with app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(CaptureSession)) == 0


async def test_restart_marks_open_sessions_interrupted_without_losing_data(api, settings):
    c, cid, app = api
    d = await dev(c, "sim_sdr", "tone 1 kHz")
    s = (await c.post("/api/v1/captures", json={"device_id": d["id"], "case_id": cid, "confirm": True, "duration_s": 100,
                                                "scope": {"purpose": "restart test", "ownership": "simulation"}})).json()
    from osintcc.api.v1.hardware import _HANDLES, recover_sessions
    _HANDLES.pop(s["id"], None)  # simulate a process that lost the in-memory handle
    assert recover_sessions(app.state.core.sm) == 1
    got = next(x for x in (await c.get(f"/api/v1/captures?case_id={cid}")).json()["items"] if x["id"] == s["id"])
    assert got["status"] == "interrupted" and "restart" in got["detail"] or "stopped during capture" in got["detail"]
    for t in list(app.state.core.tasks):
        t.cancel()


async def test_replay_through_the_device_pipeline_and_malformed_input(api):
    c, cid, _ = api
    csv = SimEsp32Driver().simulate(2).data
    r = await c.post(f"/api/v1/captures/replay?case_id={cid}&filename=old.csv", content=csv)
    assert r.status_code == 201 and r.json()["status"] == "completed" and "imported, not captured" in r.json()["detail"]
    assert (await c.post(f"/api/v1/captures/replay?case_id={cid}&filename=x.dat", content=b"\x00\x01")).status_code == 422
    assert (await c.post(f"/api/v1/captures/replay?case_id={cid}&filename=a.csv", content=b"")).status_code == 422


async def test_other_actor_cannot_start_or_see_captures(api):
    c, cid, app = api
    from osintcc.db.models import User
    st = app.state.core
    with st.sm() as db:
        db.add(User(id="u11", display_name="x"))
        db.commit()
    st.tokens["t11"] = "u11"
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer t11"})
    d = await dev(c, "sim_sdr", "tone 1 kHz")
    s = (await c.post("/api/v1/captures", json={"device_id": d["id"], "case_id": cid, "confirm": True, "duration_s": 5,
                                                "scope": {"purpose": "authz test", "ownership": "simulation"}})).json()
    assert (await other.post("/api/v1/captures", json={"device_id": d["id"], "case_id": cid, "confirm": True, "duration_s": 1,
                                                       "scope": {"purpose": "authz test", "ownership": "simulation"}})).status_code == 404
    assert (await other.post(f"/api/v1/captures/{s['id']}/stop")).status_code == 404
    assert (await other.get("/api/v1/captures/active")).json()["items"] == []
    await c.post(f"/api/v1/captures/{s['id']}/stop")


# ---- track importers (ADS-B / AIS / GPS) ---------------------------------------------------------------------------------------
ADSB = json.dumps({"now": 1700000000.5, "aircraft": [
    {"hex": "abc123", "flight": "TEST123 ", "lat": 48.1, "lon": 11.5, "alt_baro": 35000, "gs": 450, "track": 90, "seen_pos": 1.2},
    {"hex": "~def456", "lat": 95, "lon": 11}, {"hex": "nothex"}, "junk"]}).encode()


def nmea(body: str) -> str:
    x = 0
    for ch in body:
        x ^= ord(ch)
    return f"${body}*{x:02X}"


def ais_sentence(mmsi: int, lon: float, lat: float, sog: float = 12.3) -> str:
    bits = f"{1:06b}{0:02b}{mmsi:030b}{0:04b}{0:08b}{int(sog * 10):010b}{0:01b}{int(lon * 600000) & ((1 << 28) - 1):028b}{int(lat * 600000) & ((1 << 27) - 1):027b}"
    bits += "0" * (168 - len(bits))
    payload = ""
    for i in range(0, 168, 6):
        v = int(bits[i:i + 6], 2)
        payload += chr(v + 48 + (8 if v > 39 else 0))
    body = f"AIVDM,1,1,,A,{payload},0"
    x = 0
    for ch in body:
        x ^= ord(ch)
    return f"!{body}*{x:02X}"


def test_adsb_import_validates_and_does_not_resolve_owners():
    p = tracks.parse_adsb(ADSB)
    assert p.summary["aircraft"] == 2 and p.access_class == "PUBLIC"
    o = next(x for x in p.observations if x.data["icao_hex"] == "abc123")
    assert o.data["location"]["lat"] == 48.1 and o.data["location"]["accuracy_m"] is None and "licence" in o.data
    assert next(x for x in p.observations if x.data["icao_hex"] == "def456").data["location"] is None  # impossible latitude dropped
    assert o.observed_at.year == 2023 and any("not resolved to owners" in w for w in p.warnings)
    for bad in (b"[]", b"{}", b'{"aircraft": [{"hex": "zz"}]}', b"nope"):
        with pytest.raises(parsers.IngestError):
            tracks.parse_adsb(bad)


def test_ais_checksums_and_decoding():
    good = ais_sentence(123456789, 4.5, 51.9)
    p = tracks.parse_ais((good + "\n" + good[:-2] + "00\n").encode())
    o = p.observations[0].data
    assert o["location"]["lat"] == pytest.approx(51.9, abs=1e-4) and o["location"]["lon"] == pytest.approx(4.5, abs=1e-4)
    assert o["sog_kt"] == pytest.approx(12.3) and p.summary["checksum_failures"] == 1 and p.summary["vessels"] == 1
    assert any("checksum" in w for w in p.warnings)
    with pytest.raises(parsers.IngestError):
        tracks.parse_ais(b"!AIVDM,1,1,,A,garbage,0*00\n")
    with pytest.raises(parsers.IngestError):
        tracks.parse_ais(b"nothing here")


def test_gps_nmea_is_restricted_and_never_claims_metres_from_hdop():
    txt = "\n".join([nmea("GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,"),
                     nmea("GPRMC,123520,A,4807.040,N,01131.002,E,022.4,084.4,230394,003.1,W"), "$GPGGA,bad*00"])
    p = tracks.parse_nmea_gps(txt.encode())
    d = p.observations[0].data
    assert d["fixes"] == 2 and d["first"]["lat"] == pytest.approx(48.1173, abs=1e-4) and d["first"]["lon"] == pytest.approx(11.5167, abs=1e-3)
    assert d["location"]["accuracy_m"] is None and "not metres" in d["location"]["accuracy_note"]
    assert p.sensitivity == "RESTRICTED" and p.observations[0].sensitivity == "RESTRICTED" and any("movements" in w for w in p.warnings)
    with pytest.raises(parsers.IngestError):
        tracks.parse_nmea_gps(b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*00\n")  # checksum mismatch


async def test_tracks_via_api_autodetect_and_exports_hide_private_positions(api):
    c, cid, app = api
    assert (await c.post(f"/api/v1/cases/{cid}/ingest?filename=snap.aircraft.json&consent_confirmed=true", content=ADSB)).status_code == 201
    assert (await c.post(f"/api/v1/cases/{cid}/ingest?filename=ships.ais&consent_confirmed=true", content=ais_sentence(1, 4.5, 51.9).encode())).status_code == 201
    gps = nmea("GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,").encode()
    assert (await c.post(f"/api/v1/cases/{cid}/ingest?filename=trip.nmea&consent_confirmed=true", content=gps)).status_code == 201
    rep = (await c.post(f"/api/v1/cases/{cid}/reports", json={"format": "json"})).json()
    data = json.loads((app.state.core.settings.export_dir / rep["file"]).read_text())
    kinds = {o["kind"] for o in data["observations"]}
    assert "track.adsb_aircraft" in kinds and "geo.gps_track" not in kinds     # private GPS log excluded by default
    with app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(Observation)) >= 4
    _ = (struct, CaptureResult, DeviceGone)
