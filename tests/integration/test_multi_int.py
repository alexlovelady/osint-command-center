from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select

sys.path.insert(0, str(Path(__file__).parents[1] / "fixtures"))
import synthetic
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import Evidence, Observation
from osintcc.ingest import parsers
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


async def mk_case(c):
    return (await c.post("/api/v1/cases", json={"title": "Mixed", "purpose": "fixtures only"})).json()["id"]


async def imp(c, cid, name, data, **kw):
    q = f"filename={name}&consent_confirmed={str(kw.pop('consent', True)).lower()}" + "".join(f"&{k}={v}" for k, v in kw.items())
    return await c.post(f"/api/v1/cases/{cid}/ingest?{q}", content=data)


# ---- SIGINT -------------------------------------------------------------------------------------------------------
def test_one_khz_tone_detected_within_fft_tolerance():
    p = parsers.parse_sigmf(synthetic.sigmf_archive(tone_hz=1000.0, fs=48000.0))
    spec = p.observations[0].data["spectrum"]
    top = spec["peaks"][0]
    assert abs(top["offset_hz"] - 1000.0) <= spec["bin_width_hz"]  # within one FFT bin (11.7 Hz)
    assert top["snr_db"] > 25 and abs(top["absolute_hz"] - (100e6 + 1000.0)) <= spec["bin_width_hz"]


@pytest.mark.parametrize("tone", [-5000.0, 250.0, 7321.0])
def test_peak_tracks_tone_frequency_deterministically(tone):
    a = parsers.parse_sigmf(synthetic.sigmf_archive(tone_hz=tone)).observations[0].data["spectrum"]["peaks"][0]
    b = parsers.parse_sigmf(synthetic.sigmf_archive(tone_hz=tone)).observations[0].data["spectrum"]["peaks"][0]
    assert a == b and abs(a["offset_hz"] - tone) <= 48000 / 4096


@pytest.mark.parametrize("bad", [
    {"global": {"core:datatype": "cf32_le"}},                                   # missing sample rate/version
    {"global": {"core:datatype": "zz99", "core:sample_rate": 1e3, "core:version": "1"}},
    {"global": {"core:datatype": "cf32_le", "core:sample_rate": -5, "core:version": "1"}},
    {"global": {"core:datatype": "cf32_le", "core:sample_rate": True, "core:version": "1"}},
    {"nope": 1},
])
def test_malformed_sigmf_metadata_rejected(bad):
    with pytest.raises(parsers.IngestError):
        parsers.parse_sigmf(synthetic.sigmf_archive(meta_override=bad))


def test_sigmf_rejects_unsafe_archives():
    import io
    import tarfile
    for name in ("../evil.sigmf-meta", "/abs.sigmf-data"):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            ti = tarfile.TarInfo(name)
            ti.size = 2
            tf.addfile(ti, io.BytesIO(b"{}"))
        with pytest.raises(parsers.IngestError):
            parsers.parse_sigmf(buf.getvalue())
    with pytest.raises(parsers.IngestError):
        parsers.parse_sigmf(b"not a tar at all")


async def test_malformed_sigmf_via_api_stores_nothing(api, settings):
    cid = await mk_case(api)
    bad = synthetic.sigmf_archive(meta_override={"global": {"core:datatype": "cf32_le"}})
    r = await imp(api, cid, "bad.sigmf", bad)
    assert r.status_code == 422 and r.json()["code"] == "malformed_input"
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(Evidence)) == 0
        assert db.scalar(select(func.count()).select_from(Observation)) == 0
    assert not any(p.is_file() for p in settings.vault_dir.rglob("*"))


# ---- COMINT -------------------------------------------------------------------------------------------------------
def test_eml_fields_are_claims_html_sanitised_attachment_quarantined():
    p = parsers.parse_eml(synthetic.EML_HTML)
    d = p.observations[0].data
    assert d["claimed_from"] == ["alice@example.com"] and d["claimed_to"] == ["bob@example.org", "carol@example.net"]
    assert d["claimed_sent_at"].startswith("2024-01-02T10:30:00") and "unverified" in d["authenticity"]
    assert "<script" not in d["body_text_excerpt"] and "<img" not in d["body_text_excerpt"]
    assert "alert(1)" not in d["body_text_excerpt"] or "<" not in d["body_text_excerpt"]
    att = d["attachments"][0]
    assert att["filename"] == "invoice.exe" and "quarantined" in att["status"] and len(att["sha256"]) == 64
    assert p.sensitivity == "RESTRICTED"


async def test_eml_import_creates_claim_edges_not_facts(api, calls):
    cid = await mk_case(api)
    r = await imp(api, cid, "msg.eml", synthetic.EML_HTML)
    assert r.status_code == 201, r.text
    assert calls == []  # no provider contact, no network of any kind
    g = (await api.get(f"/api/v1/cases/{cid}/graph")).json()
    assert g["edges"] and all(e["type"] == "claimed_correspondent" and e["status"] == "unverified" for e in g["edges"])
    obs = (await api.get(f"/api/v1/cases/{cid}/observations?discipline=COMINT")).json()["items"]
    assert obs[0]["kind"] == "email.message" and obs[0]["sensitivity"] == "RESTRICTED"


def test_non_email_rejected():
    with pytest.raises(parsers.IngestError):
        parsers.parse_eml(b"just some text without headers")
    with pytest.raises(parsers.IngestError):
        parsers.parse_eml(b"")


# ---- MASINT -------------------------------------------------------------------------------------------------------
def test_sensor_anomaly_is_bounded_and_cause_unknown():
    p = parsers.parse_sensor_csv(synthetic.sensor_csv())
    ivs = p.observations[0].data["anomaly_intervals"]
    assert len(ivs) == 1 and ivs[0]["points"] == 5 and ivs[0]["cause"] == "unknown"
    assert ivs[0]["start"].startswith("2026-01-01T01:40") and ivs[0]["end"].startswith("2026-01-01T01:44")
    assert all(o.kind != "sensor.anomaly_interval" or o.confidence == "low" for o in p.observations)
    assert not parsers.parse_sensor_csv(synthetic.sensor_csv(anomaly=False)).observations[0].data["anomaly_intervals"]


@pytest.mark.parametrize("bad", [b"a,b\n1,2", b"timestamp,value\nnot-a-date,1\n" + b"x\n" * 12,
                                 b"timestamp,value\n" + b"2026-01-01T00:00:00,nan\n" * 12])
def test_bad_sensor_csv_rejected(bad):
    with pytest.raises(parsers.IngestError):
        parsers.parse_sensor_csv(bad)


# ---- cross-cutting -------------------------------------------------------------------------------------------------
async def test_multi_int_smoke_hash_lineage_search_and_report(api, settings):
    cid = await mk_case(api)
    out = [await imp(api, cid, "m.eml", synthetic.EML_HTML), await imp(api, cid, "t.sigmf", synthetic.sigmf_archive()),
           await imp(api, cid, "s.csv", synthetic.sensor_csv())]
    assert [o.status_code for o in out] == [201, 201, 201]
    obs = (await api.get(f"/api/v1/cases/{cid}/observations")).json()["items"]
    assert {o["discipline"] for o in obs} == {"COMINT", "SIGINT", "MASINT"}
    for o in obs:  # lineage: every observation points at hashed, verifiable raw evidence
        ev = (await api.get(f"/api/v1/evidence/{o['raw_evidence_id']}")).json()
        assert ev["integrity_verified"] is True and ev["sha256"]
    hits = (await api.get(f"/api/v1/cases/{cid}/search", params={"q": "rf.spectral_peaks"})).json()["items"]
    assert any(h["kind"] == "observation" for h in hits)
    # restricted email is excluded from the default report, included only when explicitly asked
    default = (await api.post(f"/api/v1/cases/{cid}/reports", json={"format": "json"})).json()
    full = (await api.post(f"/api/v1/cases/{cid}/reports", json={"format": "json", "include_sensitive": True})).json()
    assert default["evidence_manifest_sha256"] != full["evidence_manifest_sha256"]
    import json
    d = json.loads((settings.export_dir / default["file"]).read_text())
    assert all(m["sensitivity"] != "RESTRICTED" for m in d["evidence_manifest"])


async def test_reimport_is_idempotent(api):
    cid = await mk_case(api)
    a = (await imp(api, cid, "s.csv", synthetic.sensor_csv())).json()
    b = (await imp(api, cid, "s.csv", synthetic.sensor_csv())).json()
    assert a["evidence_id"] == b["evidence_id"] and b["observations_added"] == 0 and b["duplicate_evidence"]


async def test_ingest_requires_consent_and_membership(api):
    cid = await mk_case(api)
    assert (await imp(api, cid, "s.csv", synthetic.sensor_csv(), consent=False)).status_code == 422
    assert (await imp(api, cid, "mystery.bin", b"\x00\x01\x02")).status_code == 422
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1")
    assert (await anon.post(f"/api/v1/cases/{cid}/ingest?filename=a.csv&consent_confirmed=true", content=b"x")).status_code == 401


async def test_fts_search_is_case_scoped_and_safe(api):
    c1, c2 = await mk_case(api), await mk_case(api)
    await api.post(f"/api/v1/cases/{c1}/notes", json={"body_markdown": "met the courier near the harbour"})
    await api.post(f"/api/v1/cases/{c2}/notes", json={"body_markdown": "harbour inspection report"})
    r1 = (await api.get(f"/api/v1/cases/{c1}/search", params={"q": "harbour"})).json()["items"]
    assert len(r1) == 1 and r1[0]["kind"] == "note" and "[harbour]" in r1[0]["snippet"]
    for hostile in ['" OR 1=1 --', "harbour*", "NEAR(a b)", "col:val", "(", '"""', "a" * 150]:
        assert (await api.get(f"/api/v1/cases/{c1}/search", params={"q": hostile})).status_code == 200
    n = (await api.get(f"/api/v1/cases/{c1}/notes")).json()["items"][0]["id"]
    assert n


async def test_purge_preview_confirm_and_cascade_cleans_index(api, settings):
    cid = await mk_case(api)
    other = await mk_case(api)
    await imp(api, cid, "s.csv", synthetic.sensor_csv())
    await imp(api, other, "same.csv", synthetic.sensor_csv())  # identical bytes => shared vault object
    await api.post(f"/api/v1/cases/{cid}/notes", json={"body_markdown": "zebra marker"})
    pv = (await api.get(f"/api/v1/cases/{cid}/purge/preview")).json()
    assert pv["will_delete"]["notes"] == 1 and pv["vault_objects_kept_shared_with_other_cases"] == 1
    assert (await api.post(f"/api/v1/cases/{cid}/purge", json={"confirm": True})).status_code == 422  # title needed
    assert (await api.post(f"/api/v1/cases/{cid}/purge", json={"confirm": True, "confirm_title": "wrong"})).status_code == 422
    r = await api.post(f"/api/v1/cases/{cid}/purge", json={"confirm": True, "confirm_title": "Mixed"})
    assert r.status_code == 200, r.text
    assert (await api.get(f"/api/v1/cases/{cid}")).status_code == 404
    with api.app.state.core.sm() as db:
        assert db.execute(select(func.count()).select_from(Observation).where(Observation.case_id == cid)).scalar() == 0
        assert db.connection().exec_driver_sql("SELECT count(*) FROM search_index WHERE case_id=?", (cid,)).scalar() == 0
        from osintcc.db.models import AuditEvent
        assert db.scalars(select(AuditEvent).where(AuditEvent.action == "case.purge")).first() is not None
    # shared evidence object survives for the other case and still verifies
    ev = (await api.get(f"/api/v1/cases/{other}/evidence")).json()["items"][0]
    assert (await api.get(f"/api/v1/evidence/{ev['id']}")).json()["integrity_verified"] is True


async def test_disciplines_seeded(api):
    items = {d["id"]: d for d in (await api.get("/api/v1/disciplines")).json()["items"]}
    assert items["COMINT"]["parent_id"] == "SIGINT" and items["ELINT"]["parent_id"] == "SIGINT" and "TECHINT" in items


async def test_all_api_timestamps_carry_a_utc_designator(api):
    """Regression: SQLite returns naive datetimes; unmarked output was misread as local time by browsers."""
    cid = await mk_case(api)
    await imp(api, cid, "m.eml", synthetic.EML_HTML)
    obs = (await api.get(f"/api/v1/cases/{cid}/observations")).json()["items"][0]
    utc = ("Z", "+00:00")
    assert obs["observed_at"].endswith(utc) and obs["observed_at"].startswith("2024-01-02T10:30:00")
    assert obs["ingested_at"].endswith(utc)
    case = (await api.get(f"/api/v1/cases/{cid}")).json()
    assert case["created_at"].endswith(utc)


def test_utc_type_rejects_naive_and_roundtrips_aware():
    from datetime import UTC, datetime, timedelta, timezone

    from osintcc.db.base import UTCDateTime
    t = UTCDateTime()
    with pytest.raises(ValueError):
        t.process_bind_param(datetime(2026, 1, 1), None)
    plus5 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone(timedelta(hours=5)))
    stored = t.process_bind_param(plus5, None)
    assert stored == datetime(2026, 1, 1, 5, 0) and t.process_result_value(stored, None) == plus5.astimezone(UTC)
