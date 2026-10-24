"""Replays docs/api-examples.md so the documented calls stay valid."""
from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
import synthetic_intel as si
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp

DOC = (Path(__file__).parents[2] / "docs" / "api-examples.md").read_text(encoding="utf8")


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1/api/v1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            yield c


def documented_paths() -> set[str]:
    return set(re.findall(r"\$BASE(/[A-Za-z0-9/_$<>-]+)", DOC))


def test_every_documented_route_exists_in_the_openapi_schema(settings):
    app = create_app(settings)
    spec = app.openapi()["paths"]
    app.state.core.sm.kw["bind"].dispose()
    norm = {re.sub(r"\{[^}]+\}", "{}", p.removeprefix("/api/v1")) for p in spec}
    for path in documented_paths():
        p = re.sub(r"\$[A-Z]+|<[a-z-]+>", "{}", path).split("?")[0]
        assert p in norm, f"documented path not served: {path}"


async def test_documented_flow_runs_end_to_end(api, settings):
    case = (await api.post("/cases", json={"title": "Acme domain review", "category": "cyber", "purpose": "verify we own acme.example"})).json()["id"]
    pv = await api.post(f"/cases/{case}/searches/preview", json={"target": "example.com"})
    assert pv.status_code == 200 and pv.json()["steps"]
    run = (await api.post(f"/cases/{case}/searches", json={"target": "example.com", "adapters": ["rdap", "dns"], "wait": True})).json()
    assert run["status"] in ("succeeded", "partial")
    findings = (await api.get(f"/cases/{case}/findings?limit=50")).json()["items"]
    assert findings and (await api.get(f"/cases/{case}/evidence")).json()["items"]
    claim = (await api.post("/claims/from-finding", json={"finding_id": findings[0]["id"]})).json()
    v = await api.post(f"/claims/{claim['id']}/verification", json={"status": "analyst_verified"})
    assert v.status_code == 200
    up = await api.post(f"/cases/{case}/ingest?filename=photo.jpg&consent_confirmed=true", content=si.jpeg_with_gps(48.8, 2.3))
    assert up.status_code == 201
    assert (await api.get(f"/cases/{case}/cross-links?window_s=300&radius_m=1000&include_restricted=true")).status_code == 200
    assert (await api.get(f"/cases/{case}/timeline/unified?include_restricted=true")).status_code == 200
    assert (await api.post(f"/cases/{case}/reports/preview", json={"profile": "multi_int"})).status_code == 200
    rep = await api.post(f"/cases/{case}/reports", json={"profile": "multi_int", "format": "html"})
    assert rep.status_code == 201
    dl = await api.get(f"/reports/{rep.json()['id']}/download")
    assert dl.status_code == 200 and b"Acme domain review" in dl.content
    b = await api.post("/backups", json={"passphrase": "a long passphrase"})
    assert b.status_code == 201
    ver = await api.post("/backups/verify", json={"file": b.json()["file"], "passphrase": "a long passphrase"})
    assert ver.status_code == 200 and ver.json()["ok"]
