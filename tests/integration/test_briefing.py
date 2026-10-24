from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import synthetic_intel as si
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import Observation
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import select

T0 = datetime(2025, 3, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


async def imp(c, cid, name, data):
    r = await c.post(f"/api/v1/cases/{cid}/ingest?filename={name}&consent_confirmed=true", content=data)
    assert r.status_code in (200, 201), r.text
    return r.json()


async def setup(api):
    """Two files from different disciplines, then pin their times/places so the test controls the coincidence."""
    cid = (await api.post("/api/v1/cases", json={"title": "B", "purpose": "briefing tests"})).json()["id"]
    await imp(api, cid, "photo.jpg", si.jpeg_with_gps(48.8584, 2.2945, hacc=5))
    await imp(api, cid, "capture.pcap", si.pcap())
    with api.app.state.core.sm() as db:
        obs = list(db.scalars(select(Observation).where(Observation.case_id == cid)))
        geo = next(o for o in obs if o.discipline_id == "GEOINT")
        cyb = next(o for o in obs if o.discipline_id == "CYBINT")
        geo.observed_at, geo.data_json = T0, {**geo.data_json, "location": {"lat": 48.8584, "lon": 2.2945, "accuracy_m": 5}}
        cyb.observed_at, cyb.data_json = T0 + timedelta(seconds=60), {**cyb.data_json, "location": {"lat": 48.8590, "lon": 2.2950, "accuracy_m": 10}}
        db.commit()
        ids = (geo.id, cyb.id)
    return cid, ids


async def test_cross_links_are_suggestions_until_an_analyst_decides(api):
    cid, (a, b) = await setup(api)
    r = (await api.get(f"/api/v1/cases/{cid}/cross-links?window_s=300&radius_m=500&include_restricted=true")).json()
    assert "not a relationship" in r["caveat"]
    hidden = (await api.get(f"/api/v1/cases/{cid}/cross-links?window_s=300&radius_m=500")).json()
    assert hidden["items"] == []  # location-bearing observations are RESTRICTED by default and are not paired unless asked
    both = [i for i in r["items"] if {i["a"]["id"], i["b"]["id"]} == {a, b}]
    assert len(both) == 1 and both[0]["type"] == "both" and both[0]["status"] == "suggested"
    assert both[0]["delta_s"] == 60 and 0 < both[0]["distance_m"] < 200
    assert both[0]["a"]["quality_hint"] and both[0]["b"]["discipline"] != both[0]["a"]["discipline"]

    d = await api.post(f"/api/v1/cases/{cid}/cross-links/decision", json={"obs_a": a, "obs_b": b, "kind": "both", "decision": "accept", "note": "same scene"})
    assert d.status_code == 201 and d.json()["status"] == "accepted"
    again = (await api.get(f"/api/v1/cases/{cid}/cross-links?window_s=300&radius_m=500&include_restricted=true")).json()["items"]
    assert next(i for i in again if {i["a"]["id"], i["b"]["id"]} == {a, b})["status"] == "accepted"

    rv = await api.post(f"/api/v1/correlations/{d.json()['id']}/revoke")
    assert rv.json()["status"] == "revoked"
    after = (await api.get(f"/api/v1/cases/{cid}/cross-links?window_s=300&radius_m=500&include_restricted=true")).json()["items"]
    assert next(i for i in after if {i["a"]["id"], i["b"]["id"]} == {a, b})["status"] == "revoked"


async def test_reject_hides_suggestion_and_non_coincidence_cannot_be_accepted(api):
    cid, (a, b) = await setup(api)
    body = {"obs_a": a, "obs_b": b, "kind": "both", "decision": "reject"}
    assert (await api.post(f"/api/v1/cases/{cid}/cross-links/decision", json=body)).status_code == 201
    items = (await api.get(f"/api/v1/cases/{cid}/cross-links?window_s=300&radius_m=500&include_restricted=true")).json()["items"]
    assert not [i for i in items if {i["a"]["id"], i["b"]["id"]} == {a, b}]
    # outside the window nothing is suggested, so accepting is refused
    far = (await api.get(f"/api/v1/cases/{cid}/cross-links?window_s=5&radius_m=1&include_restricted=true")).json()["items"]
    assert not far
    bad = await api.post(f"/api/v1/cases/{cid}/cross-links/decision", json={**body, "decision": "accept", "kind": "temporal"})
    assert bad.status_code == 409
    same = await api.post(f"/api/v1/cases/{cid}/cross-links/decision", json={**body, "obs_b": a})
    assert same.status_code == 422
    missing = await api.post(f"/api/v1/cases/{cid}/cross-links/decision", json={**body, "obs_b": "nope"})
    assert missing.status_code == 404


async def test_unaccurate_positions_are_flagged_not_assumed(api):
    cid, (a, b) = await setup(api)
    with api.app.state.core.sm() as db:
        o = db.get(Observation, b)
        loc = dict(o.data_json["location"])
        loc.pop("accuracy_m")
        o.data_json = {**o.data_json, "location": loc}
        db.commit()
    items = (await api.get(f"/api/v1/cases/{cid}/cross-links?window_s=300&radius_m=500&include_restricted=true")).json()["items"]
    hit = next(i for i in items if {i["a"]["id"], i["b"]["id"]} == {a, b})
    assert any("accuracy unknown" in w for w in hit["warnings"])


async def test_unified_timeline_states_its_time_basis_and_filters(api):
    cid, (a, b) = await setup(api)
    t = (await api.get(f"/api/v1/cases/{cid}/timeline/unified?include_restricted=true")).json()["items"]
    row = next(r for r in t if r["id"] == a)
    assert row["time_basis"] == "observed" and row["discipline"] == "GEOINT"
    assert all("time_basis" in r for r in t)
    only = (await api.get(f"/api/v1/cases/{cid}/timeline/unified", params={"discipline": "CYBINT", "include_restricted": "true"})).json()["items"]
    assert only and all(r["discipline"] == "CYBINT" for r in only)
    win = (await api.get(f"/api/v1/cases/{cid}/timeline/unified", params={"include_restricted": "true", "from": (T0 + timedelta(seconds=30)).isoformat(), "to": (T0 + timedelta(seconds=90)).isoformat()})).json()["items"]
    assert {r["id"] for r in win if r["source"] == "observation"} == {b}
    # observations endpoint honours the same window
    o = (await api.get(f"/api/v1/cases/{cid}/observations", params={"from": (T0 + timedelta(seconds=30)).isoformat()})).json()["items"]
    assert [x["id"] for x in o] == [b]


async def test_report_preview_lists_withheld_items_and_writes_nothing(api):
    cid, _ = await setup(api)
    with api.app.state.core.sm() as db:
        o = db.scalars(select(Observation).where(Observation.case_id == cid)).first()
        o.sensitivity = "RESTRICTED"
        db.commit()
    export = api.app.state.core.settings.export_dir
    before = sorted(export.glob("*")) if export.exists() else []
    p = (await api.post(f"/api/v1/cases/{cid}/reports/preview", json={"profile": "multi_int"})).json()
    assert p["will_withhold"]["restricted_observations"] >= 1 and p["sensitive_included"] is False
    assert "rounded" in p["coordinates"] and p["encryption"]["report_file_encrypted"] is False
    q = (await api.post(f"/api/v1/cases/{cid}/reports/preview", json={"profile": "multi_int", "include_sensitive": True})).json()
    assert q["will_withhold"]["restricted_observations"] == 0 and "exact" in q["coordinates"]
    after = sorted(export.glob("*")) if export.exists() else []
    assert before == after


async def test_multi_int_report_has_annexes_caveats_and_rounds_coordinates(api):
    cid, _ = await setup(api)
    safe = await api.post(f"/api/v1/cases/{cid}/reports/multi-int", params={"format": "json"})
    assert safe.status_code == 201, safe.text
    sdata = json.loads((api.app.state.core.settings.export_dir / safe.json()["file"]).read_text())
    assert sdata["profile"] == "multi_int" and sdata["annexes"] == {}  # RESTRICTED observations are withheld by default
    assert "48.8584" not in json.dumps(sdata)
    r = await api.post(f"/api/v1/cases/{cid}/reports/multi-int", params={"format": "json", "include_sensitive": "true"})
    assert r.status_code == 201, r.text
    data = json.loads((api.app.state.core.settings.export_dir / r.json()["file"]).read_text())
    assert {"GEOINT", "CYBINT"} <= set(data["annexes"])
    assert all(a["caveat"] for a in data["annexes"].values())
    assert "not a legal chain-of-custody" in data["chain_of_custody"]["note"]
    html = await api.post(f"/api/v1/cases/{cid}/reports/multi-int", params={"format": "html", "include_sensitive": "true"})
    text = (api.app.state.core.settings.export_dir / html.json()["file"]).read_text(encoding="utf8")
    assert "Discipline annexes" in text and "Caveat" in text
    md = await api.post("/api/v1/reports/generate", json={"case_id": cid, "profile": "multi_int", "format": "markdown"})
    assert md.status_code == 201


async def test_second_case_cannot_see_or_decide_cross_links(api):
    _cid, (a, b) = await setup(api)
    other = (await api.post("/api/v1/cases", json={"title": "O", "purpose": "other"})).json()["id"]
    assert (await api.get(f"/api/v1/cases/{other}/cross-links")).json()["items"] == []
    r = await api.post(f"/api/v1/cases/{other}/cross-links/decision", json={"obs_a": a, "obs_b": b, "kind": "both", "decision": "accept"})
    assert r.status_code == 404
