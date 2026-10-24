from __future__ import annotations

import asyncio
import json
import socket
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import synthetic_intel as si
from conftest import fake_dns, fake_resolver
from osintcc.adapters.base import AdapterContext, Target
from osintcc.adapters.cli import MaigretAdapter, SherlockAdapter
from osintcc.adapters.http import (
    EdgarAdapter,
    OverpassAdapter,
    UrlscanAdapter,
    VirusTotalAdapter,
)
from osintcc.adapters.local import MAX_CANDIDATES, LookalikeAdapter, generate_lookalikes
from osintcc.adapters.registry import default_adapters
from osintcc.config import Settings
from osintcc.db.models import AuditEvent, Evidence, Job, Source
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from osintcc.policy.targets import TargetError, canonicalize, detect_target
from sqlalchemy import select


def ctx_with(handler, secrets=None, config=None):
    calls: list[httpx.Request] = []

    def h(req):
        calls.append(req)
        return handler(req)
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(h))
    return AdapterContext(http=http, dns_query=fake_dns, config=config or {}, secret=(secrets or {}).get), calls


def T(t, v):
    return Target(type=t, raw=v, canonical=canonicalize(t, v))


# ---- targets ---------------------------------------------------------------------------------------------------------
def test_cik_and_coordinate_targets():
    assert canonicalize("cik", "320193") == "cik:0000320193" and canonicalize("cik", "CIK 0000320193") == "cik:0000320193"
    for bad in ("", "abc", "0", "12345678901", "1;2"):
        with pytest.raises(TargetError):
            canonicalize("cik", bad)
    assert detect_target("48.8584, 2.2945").type == "coordinates" and canonicalize("coordinates", "48.8584,2.2945") == "48.858400,2.294500"
    for bad in ("91,0", "0,181", "a,b", "1,2,3", "48.8584"):
        with pytest.raises(TargetError):
            canonicalize("coordinates", bad)


# ---- EDGAR -----------------------------------------------------------------------------------------------------------
async def test_edgar_needs_contact_then_sends_it_as_user_agent():
    ctx, calls = ctx_with(lambda r: httpx.Response(200, content=si.edgar(320193, "Example Corp")))
    res = await EdgarAdapter().run(T("cik", "320193"), ctx)
    assert res.status == "skipped" and res.error_code == "requires_config" and calls == []
    ctx, calls = ctx_with(lambda r: httpx.Response(200, content=si.edgar(320193, "Example Corp")), config={"edgar_user_agent": "Jane Analyst jane@example.org"})
    res = await EdgarAdapter().run(T("cik", "320193"), ctx)
    assert res.status == "success" and calls[0].headers["user-agent"] == "Jane Analyst jane@example.org"
    assert str(calls[0].url) == "https://data.sec.gov/submissions/CIK0000320193.json"
    assert {f.predicate for f in res.findings} >= {"edgar.name", "edgar.sic"} and len(res.relationships) == 3
    assert "https://www.sec.gov/Archives" in res.relationships[0].confidence_reason and res.findings[0].confidence == "high"


async def test_edgar_failure_modes():
    cfg = {"edgar_user_agent": "A B a@b.org"}
    for status, expect in ((429, "rate_limited"), (500, "error"), (404, "success")):
        ctx, _ = ctx_with(lambda r, s=status: httpx.Response(s), config=cfg)
        assert (await EdgarAdapter().run(T("cik", "1"), ctx)).status == expect
    ctx, _ = ctx_with(lambda r: httpx.Response(200, json={"surprise": True}), config=cfg)
    res = await EdgarAdapter().run(T("cik", "1"), ctx)
    assert res.status == "error" and res.error_code == "parse_error" and res.artifacts  # raw kept for diagnosis


# ---- keyed reputation adapters ---------------------------------------------------------------------------------------
VT = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "harmless": 60}, "reputation": -3, "last_analysis_date": 1700000000,
                              "categories": {"x": "phishing"}}}}


async def test_virustotal_without_key_makes_no_request():
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=VT))
    res = await VirusTotalAdapter().run(T("domain", "example.com"), ctx)
    assert res.status == "skipped" and res.error_code == "requires_key" and calls == []


async def test_virustotal_with_key_parses_and_qualifies():
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=VT), {"virustotal": "KEY123"})
    res = await VirusTotalAdapter().run(T("domain", "example.com"), ctx)
    assert calls[0].headers["x-apikey"] == "KEY123" and calls[0].method == "GET"
    assert "KEY123" not in str(calls[0].url) and res.artifacts[0].source_url == "https://www.virustotal.com/api/v3/domains/example.com"
    st = next(f for f in res.findings if f.predicate == "vt.last_analysis_stats")
    assert st.value["malicious"] == 2 and st.confidence == "medium" and st.source_published_at.year == 2023
    assert any("not proof" in w for w in res.warnings)
    clean = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}
    ctx, _ = ctx_with(lambda r: httpx.Response(200, json=clean), {"virustotal": "K"})
    assert any("not proof it is safe" in w for w in (await VirusTotalAdapter().run(T("domain", "a.com"), ctx)).warnings)


async def test_revoked_key_and_rate_limit_are_reported_not_fatal():
    ctx, _ = ctx_with(lambda r: httpx.Response(401), {"virustotal": "BAD"})
    r = await VirusTotalAdapter().run(T("domain", "example.com"), ctx)
    assert r.status == "skipped" and r.error_code == "requires_key" and "revoked" in r.warnings[0]
    ctx, _ = ctx_with(lambda r: httpx.Response(429, headers={"retry-after": "77"}), {"virustotal": "K"})
    r = await VirusTotalAdapter().run(T("domain", "example.com"), ctx)
    assert r.status == "rate_limited" and r.retry_after_seconds == 77 and r.retryable


async def test_urlscan_only_searches_never_submits():
    body = {"total": 2, "results": [{"page": {"ip": "203.0.113.5", "country": "NL"}, "task": {"time": "2024-01-01T00:00:00Z"}},
                                    {"page": {"ip": "203.0.113.5", "country": "NL"}, "task": {"time": "2023-01-01T00:00:00Z"}}]}
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=body))
    res = await UrlscanAdapter().run(T("domain", "example.com"), ctx)
    assert len(calls) == 1 and calls[0].method == "GET" and "/api/v1/search/" in str(calls[0].url) and "scan" not in calls[0].url.path.split("search")[0][-6:]
    assert res.relationships[0].relation_type == "seen_hosted_on" and any(f.predicate == "urlscan.country_hint" and f.confidence == "low" for f in res.findings)


async def test_shodan_key_never_reaches_stored_urls_or_evidence(tmp_path):
    body = {"ports": [443, 22], "org": "ExampleNet", "hostnames": ["h.example"], "vulns": ["CVE-2020-0001"]}
    http_calls = []

    def handler(req):
        http_calls.append(str(req.url))
        return httpx.Response(200, json=body)
    s = Settings(data_dir=tmp_path / "d", vault_encryption="off")
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(handler))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, secret={"shodan": "SECRETKEY99"}.get))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            cid = (await c.post("/api/v1/cases", json={"title": "S", "purpose": "x"})).json()["id"]
            r = await c.post(f"/api/v1/cases/{cid}/searches", json={"target": "93.184.216.34", "adapters": ["shodan"], "wait": True})
            assert r.status_code == 202 and r.json()["status"] == "succeeded"
            assert "SECRETKEY99" in http_calls[0]  # the provider needs it in the query string...
            with app.state.core.sm() as db:  # ...but it must never be persisted anywhere
                assert all("SECRETKEY99" not in (x.source_url or "") for x in db.scalars(select(Source)))
                assert all("SECRETKEY99" not in (x.original_url or "") for x in db.scalars(select(Evidence)))
                assert "SECRETKEY99" not in json.dumps([e.metadata_json for e in db.scalars(select(AuditEvent))])
            for p in s.vault_dir.rglob("*"):
                if p.is_file():
                    assert b"SECRETKEY99" not in p.read_bytes()
            f = (await c.get(f"/api/v1/cases/{cid}/findings")).json()["items"]
            assert {"shodan.open_ports", "shodan.reported_vulns"} <= {x["predicate"] for x in f}
            assert next(x for x in f if x["predicate"] == "shodan.reported_vulns")["confidence"] == "low"


async def test_new_third_party_adapters_are_not_in_the_default_run(tmp_path):
    s = Settings(data_dir=tmp_path / "d", vault_encryption="off")
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns, secret={"virustotal": "K"}.get))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            cid = (await c.post("/api/v1/cases", json={"title": "D", "purpose": "x"})).json()["id"]
            plan = (await c.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "example.com"})).json()
            flags = {x["adapter_id"]: x["default_selected"] for x in plan["steps"]}
            assert flags["rdap"] and not flags["virustotal"] and not flags["urlscan"] and not flags["lookalike"]
            run = (await c.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "wait": True})).json()
            assert {j["adapter_id"] for j in run["jobs"]}.isdisjoint({"virustotal", "urlscan", "lookalike", "shodan"})
            run2 = (await c.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "adapters": ["virustotal"], "wait": True})).json()
            assert [j["adapter_id"] for j in run2["jobs"]] == ["virustotal"]


# ---- Overpass / lookalike / CLI argv ----------------------------------------------------------------------------------
async def test_overpass_query_is_bounded_and_attributed():
    body = {"elements": [{"type": "node", "id": 1, "lat": 48.8, "lon": 2.3, "tags": {"name": "Cafe X", "amenity": "cafe", "phone": "+33"}},
                         {"type": "way", "id": 2, "center": {"lat": 48.81, "lon": 2.31}, "tags": {"name": "Hall", "building": "yes"}}]}
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=body))
    res = await OverpassAdapter().run(T("coordinates", "48.8584,2.2945"), ctx)
    q = httpx.URL(str(calls[0].url)).params["data"]
    assert "around:200,48.858400,2.294500" in q and "out center 50" in q and "[timeout:25]" in q
    assert len(res.relationships) == 2 and all(r.relation_type == "near" and "does not imply" in r.confidence_reason for r in res.relationships)
    assert "phone" not in json.dumps([f.value for f in res.findings])  # only a safe tag allow-list is kept
    assert any("OpenStreetMap" in w for w in res.warnings)
    ctx, _ = ctx_with(lambda r: httpx.Response(429))
    assert (await OverpassAdapter().run(T("coordinates", "1,1"), ctx)).status == "rate_limited"


def test_lookalike_generation_is_deterministic_bounded_and_excludes_self():
    a, b = generate_lookalikes("example.com"), generate_lookalikes("example.com")
    assert a == b and "example.com" not in a and len(a) <= MAX_CANDIDATES
    assert a["exmple.com"] == "omission" and a["examlpe.com"] == "transposition" and a["examp1e.com"] == "homoglyph"
    assert a["example.net"] == "tld swap" and all(not d.startswith("-") and "--" not in d.split(".")[0] for d in a)
    assert len(generate_lookalikes("a-very-long-domain-name-for-testing.com")) <= MAX_CANDIDATES


async def test_lookalike_adapter_makes_no_requests():
    ctx, calls = ctx_with(lambda r: httpx.Response(500))
    res = await LookalikeAdapter().run(T("domain", "example.com"), ctx)
    assert calls == [] and res.status == "success" and not LookalikeAdapter.manifest.needs_network
    assert any("hypotheticals" in w for w in res.warnings) and all(f.confidence in ("high", "unknown") for f in res.findings)


def test_username_cli_argv_ends_option_parsing():
    t = T("username", "someone")
    assert SherlockAdapter().build_argv("/bin/sherlock", t)[-2:] == ["--", "someone"]
    assert MaigretAdapter().build_argv("/bin/maigret", t)[-2:] == ["--", "someone"]
    assert MaigretAdapter.manifest.operation_class == "public_site_query" and "LEAD" in MaigretAdapter.manifest.description


# ---- active module: absent by default, gated by authorization at plan AND execution time -------------------------------
def test_active_module_is_absent_unless_enabled():
    assert "tcp_connect" not in default_adapters(Settings()) and "tcp_connect" in default_adapters(Settings(enable_active_module=True))


@pytest.fixture
async def active_env(tmp_path):
    hits = []

    async def on_conn(reader, writer):
        hits.append(1)
        writer.close()
    server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
    open_port = server.sockets[0].getsockname()[1]
    with socket.socket() as sck:
        sck.bind(("127.0.0.1", 0))
        closed_port = sck.getsockname()[1]
    s = Settings(data_dir=tmp_path / "d", vault_encryption="off", enable_active_module=True)
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, config={"ports": [open_port, closed_port]}))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            cid = (await c.post("/api/v1/cases", json={"title": "A", "purpose": "owned lab"})).json()["id"]
            yield c, cid, hits, open_port, closed_port, app
    server.close()
    await server.wait_closed()


BODY = {"target": "127.0.0.1", "target_type": "ip", "adapters": ["tcp_connect"], "mode": "active"}


async def test_active_scan_refused_without_authorization_and_makes_zero_connections(active_env):
    c, cid, hits, *_ = active_env
    r = await c.post(f"/api/v1/cases/{cid}/searches/preview", json=BODY)
    assert r.status_code == 422 and "private/loopback" in r.json()["message"]  # no authorization => not even plannable
    r = await c.post(f"/api/v1/cases/{cid}/searches", json={**BODY, "confirmed_adapters": ["tcp_connect"], "wait": True})
    assert r.status_code == 422 and hits == []


async def test_active_scan_with_authorization_confirmation_and_audit(active_env):
    c, cid, hits, open_port, closed_port, _app = active_env
    a = (await c.post(f"/api/v1/cases/{cid}/authorizations", json={
        "scope_type": "cidr", "scope_value": "127.0.0.0/24", "authorized_by": "Lab owner (me)", "allowed_classes": ["active"],
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()})).json()
    plan = (await c.post(f"/api/v1/cases/{cid}/searches/preview", json=BODY)).json()
    assert plan["steps"][0]["runnable"] and plan["steps"][0]["requires_confirmation"] and hits == []  # preview connects to nothing
    unconfirmed = await c.post(f"/api/v1/cases/{cid}/searches", json={**BODY, "wait": True})
    assert unconfirmed.status_code == 409 and hits == []
    run = (await c.post(f"/api/v1/cases/{cid}/searches", json={**BODY, "confirmed_adapters": ["tcp_connect"], "wait": True})).json()
    assert run["status"] == "succeeded" and len(hits) == 1
    f = (await c.get(f"/api/v1/cases/{cid}/findings")).json()["items"]
    states = {x["value"]["port"]: x["value"]["state"] for x in f if x["predicate"] == "net.tcp_port"}
    assert states[open_port] == "open" and states[closed_port] == "closed"
    # revocation takes effect immediately: execution-time re-check denies, zero further connections
    assert (await c.post(f"/api/v1/authorizations/{a['id']}/revoke")).status_code == 200
    r2 = await c.post(f"/api/v1/cases/{cid}/searches", json={**BODY, "confirmed_adapters": ["tcp_connect"], "wait": True})
    assert r2.status_code == 422 and len(hits) == 1


async def test_authorization_revoked_between_plan_and_execution_is_denied_at_runtime(active_env):
    c, cid, hits, _o, _c2, app = active_env
    a = (await c.post(f"/api/v1/cases/{cid}/authorizations", json={
        "scope_type": "ip", "scope_value": "127.0.0.1", "authorized_by": "Lab owner", "allowed_classes": ["active"]})).json()
    run = (await c.post(f"/api/v1/cases/{cid}/searches", json={**BODY, "confirmed_adapters": ["tcp_connect"]})).json()  # background
    await c.post(f"/api/v1/authorizations/{a['id']}/revoke")  # may land before or after the job; both must be safe
    await asyncio.gather(*list(app.state.core.tasks))
    done = (await c.get(f"/api/v1/search-runs/{run['id']}")).json()
    assert done["status"] in ("succeeded", "failed", "partial")
    with app.state.core.sm() as db:
        job = db.scalars(select(Job).where(Job.run_id == run["id"])).one()
        assert (job.status == "succeeded") == (len(hits) == 1)  # a denied job connected to nothing


async def test_out_of_scope_and_class_mismatch_are_denied(active_env):
    c, cid, hits, *_ = active_env
    await c.post(f"/api/v1/cases/{cid}/authorizations", json={"scope_type": "ip", "scope_value": "10.9.9.9", "authorized_by": "X Y",
                                                              "allowed_classes": ["active"]})
    assert (await c.post(f"/api/v1/cases/{cid}/searches", json={**BODY, "confirmed_adapters": ["tcp_connect"], "wait": True})).status_code == 422
    await c.post(f"/api/v1/cases/{cid}/authorizations", json={"scope_type": "ip", "scope_value": "127.0.0.1", "authorized_by": "X Y",
                                                              "allowed_classes": ["passive"]})  # wrong class
    assert (await c.post(f"/api/v1/cases/{cid}/searches", json={**BODY, "confirmed_adapters": ["tcp_connect"], "wait": True})).status_code == 422
    assert hits == []
