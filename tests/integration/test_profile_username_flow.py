"""End to end through the real adapters with fake Sherlock/Maigret executables: preview -> authorization -> explicit confirmation -> run ->
candidate queue -> clustering. Acceptance: TP-05, TP-06 (with real adapter parsing), plus the public-site confirmation rule."""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.adapters.cli import MaigretAdapter, SherlockAdapter
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp

B = "/api/v1"


def wrapper(tmp_path, name: str, output: str):
    py = tmp_path / f"{name}.py"
    py.write_text("import sys\nif '--version' in sys.argv:\n    print('1.0.0')\nelse:\n" + "".join(f"    print({line!r})\n" for line in output.splitlines()))
    w = tmp_path / (f"{name}.cmd" if sys.platform == "win32" else name)
    w.write_text(f'@echo off\r\n"{sys.executable}" "{py}" %*\r\n' if sys.platform == "win32" else f'#!/bin/sh\nexec "{sys.executable}" "{py}" "$@"\n')
    w.chmod(0o755)
    return str(w)


@pytest.fixture
async def api(settings, calls, tmp_path):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        st = app.state.core
        st.adapters["sherlock"] = SherlockAdapter(binary_path=wrapper(tmp_path, "sherlock", "[+] GitHub: https://github.com/jane_e\n[+] Forum: https://forum.test/u/jane_e"))
        st.adapters["maigret"] = MaigretAdapter(binary_path=wrapper(tmp_path, "maigret", "[+] GitHub: http://www.github.com/jane_e/?utm_source=x\n[+] Blog: https://blog.test/jane_e"))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


async def start(api):
    cid = (await api.post(f"{B}/cases", json={"title": "Jane", "category": "people", "purpose": "self audit"})).json()["id"]
    sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Jane Example"})).json()["id"]
    iid = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "username", "value": "jane_e"})).json()["id"]
    return cid, sid, iid


async def grant(api, sid, classes):
    r = await api.post(f"{B}/subjects/{sid}/consent", json={"verification_method": "self_attestation", "verifier": "Jane", "source_classes": classes,
                                                            "permitted_purposes": ["self audit"], "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat()})
    assert r.status_code == 201, r.text


async def test_public_site_tools_need_authorization_and_explicit_confirmation(api, calls):
    _cid, sid, iid = await start(api)
    pv = {e["source_id"]: e for e in (await api.post(f"{B}/subjects/{sid}/research/preview", json={})).json()["entries"]}
    assert not pv["sherlock"]["runnable"] and "authorization" in pv["sherlock"]["reason"]                # no authorization yet
    await grant(api, sid, ["public_site_query"])
    pv = {e["source_id"]: e for e in (await api.post(f"{B}/subjects/{sid}/research/preview", json={})).json()["entries"]}
    for a in ("sherlock", "maigret"):
        assert pv[a]["runnable"] and pv[a]["requires_confirmation"] and pv[a]["health"] == "healthy" and pv[a]["maturity"] == "live_tested"
        assert any("public websites" in w for w in pv[a]["warnings"])
    keys = [f"{iid}:sherlock", f"{iid}:maigret"]
    r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": keys, "wait": True})
    assert r.status_code == 422 and r.json()["code"] == "confirmation_required"
    assert (await api.get(f"{B}/subjects/{sid}/research/runs")).json()["total"] == 0                       # nothing was queued
    r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [keys[0]], "confirmed_sources": ["maigret"], "wait": True})
    assert r.status_code == 422                                                                           # confirming a different tool does not count


async def test_tp05_tp06_results_land_in_the_queue_as_clustered_unverified_candidates(api):
    _cid, sid, iid = await start(api)
    await grant(api, sid, ["public_site_query"])
    r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [f"{iid}:sherlock", f"{iid}:maigret"], "confirmed_sources": ["sherlock", "maigret"], "wait": True})
    assert r.status_code == 202, r.text
    tasks = {t["source_id"]: t for t in (await api.get(f"{B}/subjects/{sid}/research/runs")).json()["items"]}
    assert tasks["sherlock"]["status"] == "completed" and tasks["maigret"]["status"] == "completed"
    q = (await api.get(f"{B}/subjects/{sid}/candidates")).json()
    by = {c["canonical_url"]: c for c in q["items"]}
    assert sorted(by) == ["https://blog.test/jane_e", "https://forum.test/u/jane_e", "https://github.com/jane_e"]       # 4 sightings, 3 accounts
    gh = by["https://github.com/jane_e"]
    assert sorted(gh["adapters"]) == ["maigret", "sherlock"] and gh["observation_count"] == 2 and len(gh["evidence"]) == 2
    assert gh["independent_signals"] == 1 and all(c["state"] == "candidate" for c in q["items"])                      # never auto-verified
    prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
    assert prof["counts"]["verified"] == 0 and len(prof["unresolved_leads"]) == 3
    assert "Review 3 unresolved lead" in prof["next_action"]
    cov = (await api.get(f"{B}/subjects/{sid}/coverage")).json()
    cells = {c["source_id"]: c for cat in cov["categories"] for c in cat["cells"]}
    assert cells["sherlock"]["status"] == "completed" and cells["maigret"]["status"] == "completed" and cells["rdap"]["status"] == "unsupported"
    # a human decision is then the only thing that changes a state, and the profile reflects it
    gid = gh["id"]
    r = await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": [gid], "state": "confirmed", "basis": "my account", "attestation": "subject"})
    assert r.status_code == 200
    prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
    assert prof["counts"]["candidates"] == 3 and len(prof["unresolved_leads"]) == 2
