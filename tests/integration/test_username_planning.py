"""Regression: a username preview offers Sherlock/Maigret (never preselected); running them needs explicit selection + confirmation."""
from __future__ import annotations

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp

PUBLIC = {"sherlock", "maigret"}


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


async def mk_case(api):
    return (await api.post("/api/v1/cases", json={"title": "U", "purpose": "username planning tests", "category": "people"})).json()["id"]


async def test_username_preview_offers_public_site_tools_unselected(api, calls):
    cid = await mk_case(api)
    pv = (await api.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "someone", "target_type": "username"})).json()
    steps = {s["adapter_id"]: s for s in pv["steps"]}
    assert PUBLIC <= set(steps)
    for a in PUBLIC:
        assert steps[a]["requires_confirmation"] is True and steps[a]["offered"] is True
        assert steps[a]["default_selected"] is False
        assert any("public websites" in w for w in steps[a]["warnings"])
    assert pv["explicit"] is False and calls == []  # preview never touches the network


async def test_other_target_types_do_not_offer_username_tools(api):
    cid = await mk_case(api)
    pv = (await api.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "example.com"})).json()
    assert not PUBLIC & {s["adapter_id"] for s in pv["steps"]}


async def test_launch_without_naming_or_confirming_never_runs_public_tools(api, calls):
    cid = await mk_case(api)
    body = {"target": "someone", "target_type": "username"}
    r = await api.post(f"/api/v1/cases/{cid}/searches", json={**body, "wait": True})  # nothing selected
    assert r.status_code == 409 and r.json()["code"] == "plan_refused"
    named = {**body, "adapters": ["sherlock"], "mode": "public_site_query"}
    r = await api.post(f"/api/v1/cases/{cid}/searches", json={**named, "wait": True})  # named but not confirmed
    assert r.status_code == 409 and "explicit confirmation" in r.json()["message"]
    assert calls == []


async def test_named_and_confirmed_tool_is_the_only_one_launched(api):
    cid = await mk_case(api)
    body = {"target": "someone", "target_type": "username", "adapters": ["sherlock"], "mode": "public_site_query",
            "confirmed_adapters": ["sherlock"], "wait": True}
    r = await api.post(f"/api/v1/cases/{cid}/searches", json=body)
    assert r.status_code == 202, r.text
    assert [j["adapter_id"] for j in r.json()["jobs"]] == ["sherlock"]  # maigret was not selected, so it did not run


async def test_unknown_adapter_and_bad_target_still_rejected(api):
    cid = await mk_case(api)
    r = await api.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "someone", "target_type": "username", "adapters": ["nope"]})
    assert r.status_code == 422 and r.json()["code"] == "plan_rejected"
    r = await api.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "a b", "target_type": "username"})
    assert r.status_code == 422


async def test_missing_tools_give_an_explanation(api):
    cid = await mk_case(api)
    st = api.app.state.core
    for a in PUBLIC:
        st.adapters.pop(a)
    pv = (await api.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "someone", "target_type": "username"})).json()
    assert pv["notices"] and "Sherlock" in pv["notices"][0]


async def test_collection_plan_offers_tools_but_requires_naming_and_confirmation(api, calls):
    cid = await mk_case(api)
    base = {"case_id": cid, "target": "someone", "target_type": "username", "reason": "regression test"}
    pv = (await api.post("/api/v1/collection-plans/preview", json=base)).json()
    assert PUBLIC <= {s["adapter_id"] for s in pv["steps"] if s.get("offered")}
    assert pv["policy_status"] == "denied"  # nothing is selected, so nothing would run
    saved = (await api.post("/api/v1/collection-plans", json={**base, "adapters": ["sherlock"], "mode": "public_site_query"})).json()
    assert saved["policy_status"] == "needs_confirmation"
    refused = await api.post(f"/api/v1/collection-plans/{saved['id']}/approve", json={"confirmed_adapters": []})
    assert refused.status_code == 409 and calls == []
    ok = await api.post(f"/api/v1/collection-plans/{saved['id']}/approve", json={"confirmed_adapters": ["sherlock"], "wait": True})
    assert ok.status_code == 202
