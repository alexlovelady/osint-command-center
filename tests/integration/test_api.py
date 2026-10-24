from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import AuditEvent, User
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        tr = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=tr, base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


async def mk_case(c, **kw):
    r = await c.post("/api/v1/cases", json={"title": "ACME review", "purpose": "authorized assessment", **kw})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_unauthenticated_requests_rejected_except_liveness(api):
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1")
    assert (await anon.get("/api/v1/health/live")).status_code == 200
    spec = (await api.get("/api/openapi.json")).json()
    checked = 0
    for path, ops in spec["paths"].items():
        if path == "/api/v1/health/live":
            continue
        url = path
        for p in ("case_id", "run_id", "ev_id", "rid", "auth_id", "tool_id", "provider", "pid", "rel_id"):
            url = url.replace("{" + p + "}", "x")
        for method in ops:
            r = await anon.request(method.upper(), url)
            assert r.status_code == 401, (method, path, r.status_code)
            checked += 1
    assert checked > 30
    bad = await anon.get("/api/v1/cases", headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 401 and bad.json()["code"] == "unauthorized"


async def test_disallowed_origin_blocked(api):
    assert (await api.get("/api/v1/cases", headers={"Origin": "https://evil.example"})).status_code == 403
    r = await api.get("/api/v1/cases", headers={"Origin": "http://127.0.0.1:5173"})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"


async def test_full_flow_preview_launch_results_report(api, calls):
    cid = await mk_case(api)
    pv = await api.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "Example.com"})
    assert pv.status_code == 200 and calls == []  # preview performs ZERO requests
    plan = pv.json()
    assert plan["target"]["canonical"] == "example.com"
    assert {"rdap", "dns", "crtsh"} <= {s["adapter_id"] for s in plan["steps"]}
    r = await api.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "wait": True})
    assert r.status_code == 202
    assert r.json()["status"] in ("succeeded", "partial")
    assert len(calls) >= 3
    f = (await api.get(f"/api/v1/cases/{cid}/findings?limit=500")).json()
    assert f["total"] > 10
    row = next(i for i in f["items"] if i["predicate"] == "rdap.registrar")
    assert row["value"] == "Example Registrar Inc" and row["evidence_id"] and row["source_url"].startswith("https://")
    ev = (await api.get(f"/api/v1/evidence/{row['evidence_id']}")).json()
    assert ev["integrity_verified"] is True and ev["sha256"]
    dl = await api.get(f"/api/v1/evidence/{row['evidence_id']}/download")
    assert dl.status_code == 200 and json.loads(dl.content)["handle"] == "EX-1"
    g = (await api.get(f"/api/v1/cases/{cid}/graph")).json()
    assert g["nodes"] and all(e["evidence_ids"] for e in g["edges"])
    tl = (await api.get(f"/api/v1/cases/{cid}/timeline")).json()["items"]
    assert any(not i["time_unknown"] for i in tl) and any(i["time_unknown"] for i in tl)
    for fmt in ("html", "markdown", "json", "pdf"):
        rep = await api.post(f"/api/v1/cases/{cid}/reports", json={"format": fmt})
        assert rep.status_code == 201, rep.text
        body = await api.get(f"/api/v1/reports/{rep.json()['id']}/download")
        assert body.status_code == 200 and len(body.content) > 200
        if fmt == "pdf":
            assert body.content.startswith(b"%PDF")
        if fmt == "html":
            assert "Limitations" in body.text and "Example Registrar Inc" in body.text
            assert hashlib.sha256(body.content).hexdigest() == rep.json()["sha256"]


async def test_events_stream_and_resume(api):
    cid = await mk_case(api)
    run = (await api.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "wait": True})).json()
    async with api.stream("GET", f"/api/v1/search-runs/{run['id']}/events") as resp:
        text = "".join([c async for c in resp.aiter_text()])
    assert "event: done" in text and "event: job" in text
    ids = [int(line[4:]) for line in text.splitlines() if line.startswith("id: ")]
    assert ids == sorted(ids) and ids
    async with api.stream("GET", f"/api/v1/search-runs/{run['id']}/events",
                          headers={"Last-Event-ID": str(ids[-1])}) as resp:
        again = "".join([c async for c in resp.aiter_text()])
    assert "event: job" not in again and "event: done" in again  # resumes after last seen event


async def test_invalid_and_hostile_targets_rejected(api, calls):
    cid = await mk_case(api)
    for bad in ["example.com; rm -rf /", "$(id)", "a b", "http://127.0.0.1:8765/", "x" * 3000]:
        r = await api.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": bad})
        assert r.status_code == 422, bad
    assert calls == []
    r = await api.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "someone"})
    assert r.status_code == 422  # a bare handle is never guessed to be a username
    assert set(r.json()) == {"code", "message", "request_id", "retryable", "details_safe"}


async def test_people_case_needs_purpose(api):
    r = await api.post("/api/v1/cases", json={"title": "p", "category": "people"})
    assert r.status_code == 422 and r.json()["code"] == "purpose_required"


async def test_username_search_requires_explicit_confirmation(api, calls):
    cid = await mk_case(api, category="people")
    body = {"target": "someone", "target_type": "username", "adapters": ["sherlock"], "mode": "public_site_query"}
    pv = (await api.post(f"/api/v1/cases/{cid}/searches/preview", json=body)).json()
    assert pv["steps"][0]["requires_confirmation"] is True
    r = await api.post(f"/api/v1/cases/{cid}/searches", json={**body, "wait": True})
    assert r.status_code == 409 and r.json()["code"] == "plan_refused"
    assert calls == []


async def test_second_actor_cannot_read_or_write_other_case(api):
    cid = await mk_case(api)
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="u2", display_name="second"))
        db.commit()
    st.tokens["second-token"] = "u2"
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1",
                              headers={"Authorization": "Bearer second-token"})
    assert (await other.get("/api/v1/cases")).json()["total"] == 0
    for method, url, body in [("GET", f"/api/v1/cases/{cid}", None), ("GET", f"/api/v1/cases/{cid}/findings", None),
                              ("GET", f"/api/v1/cases/{cid}/graph", None),
                              ("POST", f"/api/v1/cases/{cid}/notes", {"body_markdown": "x"}),
                              ("POST", f"/api/v1/cases/{cid}/searches", {"target": "example.com"}),
                              ("POST", f"/api/v1/cases/{cid}/reports", {}),
                              ("PATCH", f"/api/v1/cases/{cid}", {"title": "hijack"})]:
        r = await other.request(method, url, json=body)
        assert r.status_code == 404, (method, url, r.status_code)
    assert (await api.post(f"/api/v1/cases/{cid}/members",
                           json={"user_id": "u2", "access_role": "viewer"})).status_code == 201
    assert (await other.get(f"/api/v1/cases/{cid}")).status_code == 200
    assert (await other.post(f"/api/v1/cases/{cid}/notes", json={"body_markdown": "x"})).status_code == 404
    assert (await other.get(f"/api/v1/cases/{cid}/findings")).status_code == 200


async def test_notes_markdown_is_sanitized(api):
    cid = await mk_case(api)
    r = await api.post(f"/api/v1/cases/{cid}/notes", json={
        "body_markdown": "hi <script>alert(1)</script> [x](javascript:alert(1)) <img src=x onerror=alert(1)> **ok**"})
    h = r.json()["html"]
    # Dangerous markup must not survive as live HTML (escaped text is fine; live tags/hrefs are not).
    for live in ("<script", "<img", "href=\"javascript", "href='javascript", "<a "):
        assert live not in h
    assert "<strong>ok</strong>" in h
    r2 = await api.post(f"/api/v1/cases/{cid}/notes", json={"body_markdown": "[ok](https://example.com)"})
    assert 'href="https://example.com"' in r2.json()["html"]


async def test_evidence_import_hash_size_cap_and_hostile_names(api, settings):
    cid = await mk_case(api)
    data = b"%PDF-1.4 fake"
    r = await api.post(f"/api/v1/cases/{cid}/evidence/import?filename=../../evil.pdf&consent_confirmed=true",
                       content=data)
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["sha256"] == hashlib.sha256(data).hexdigest() and j["mime_type"] == "application/pdf"
    assert j["title"] == "evil.pdf"
    assert (await api.post(f"/api/v1/cases/{cid}/evidence/import?filename=a", content=b"x")).status_code == 422
    settings.max_import_bytes = 100
    big = await api.post(f"/api/v1/cases/{cid}/evidence/import?filename=big.bin&consent_confirmed=true",
                         content=b"z" * 500)
    assert big.status_code == 413
    exe = await api.post(f"/api/v1/cases/{cid}/evidence/import?filename=a.txt&consent_confirmed=true",
                         content=b"MZ\x90\x00")
    assert exe.json()["mime_type"] == "application/x-msdownload" and exe.json()["warnings"]  # sniffed, not by name


async def test_tampered_vault_object_detected_on_download(api, settings):
    cid = await mk_case(api)
    j = (await api.post(f"/api/v1/cases/{cid}/evidence/import?filename=n.txt&consent_confirmed=true",
                        content=b"original")).json()
    next(settings.vault_dir.rglob(j["sha256"])).write_bytes(b"tampered")
    d = await api.get(f"/api/v1/evidence/{j['id']}/download")
    assert d.status_code == 409 and d.json()["code"] == "integrity_failure"
    assert (await api.get(f"/api/v1/evidence/{j['id']}")).json()["integrity_verified"] is False


async def test_offline_mode_blocks_network_and_keeps_saved_data(api, calls):
    cid = await mk_case(api)
    await api.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "wait": True})
    n = len(calls)
    assert (await api.put("/api/v1/settings", json={"values": {"offline": True}})).json()["offline"] is True
    r = await api.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.org", "wait": True})
    assert r.status_code == 409
    assert len(calls) == n
    assert (await api.get(f"/api/v1/cases/{cid}/findings")).json()["total"] > 0
    assert (await api.post(f"/api/v1/cases/{cid}/reports", json={"format": "html"})).status_code == 201


async def test_settings_rejects_unknown_keys(api):
    assert (await api.put("/api/v1/settings", json={"values": {"evil": 1}})).status_code == 422
    assert (await api.put("/api/v1/settings", json={"values": {"offline": "yes"}})).status_code == 422


async def test_secret_values_never_echoed_or_logged(api, monkeypatch):
    import keyring
    store = {}
    monkeypatch.setattr(keyring, "set_password", lambda s, u, p: store.__setitem__((s, u), p))
    r = await api.post("/api/v1/secrets/shodan", json={"value": "SUPERSECRET"})
    assert r.status_code == 200 and "SUPERSECRET" not in r.text and store[("osintcc", "shodan")] == "SUPERSECRET"
    assert (await api.post("/api/v1/secrets/Bad Name!", json={"value": "x"})).status_code in (404, 422)
    with api.app.state.core.sm() as db:
        assert "SUPERSECRET" not in json.dumps([e.metadata_json for e in db.query(AuditEvent)])


async def test_tools_report_truthful_health(api):
    items = {t["id"]: t for t in (await api.get("/api/v1/tools")).json()["items"]}
    assert items["rdap"]["health"]["status"] == "healthy"
    assert items["subfinder"]["health"]["status"] in ("not_installed", "healthy", "degraded")


async def test_doctor_and_ready(api):
    d = (await api.get("/api/v1/system/doctor")).json()
    assert d["audit_chain"]["ok"] and d["db_integrity"] == "ok" and "tools" in d
    assert (await api.get("/api/v1/health/ready")).json()["status"] == "ready"


async def test_backup_verify_restore_and_corruption(api, settings):
    cid = await mk_case(api)
    await api.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "wait": True})
    b = (await api.post("/api/v1/backups")).json()
    assert b["verification"]["ok"] and b["verification"]["files"] > 1
    pv = (await api.post("/api/v1/backups/restore/preview", json={"file": b["file"], "target_name": "restore1"})).json()
    assert pv["restore_allowed"] and pv["collisions"] == []
    no_confirm = await api.post("/api/v1/backups/restore", json={"file": b["file"], "target_name": "restore1"})
    assert no_confirm.status_code == 409
    r = await api.post("/api/v1/backups/restore", json={"file": b["file"], "target_name": "restore1", "confirm": True})
    assert r.status_code == 200
    con = sqlite3.connect(settings.data_dir / "restores" / "restore1" / "osintcc.sqlite")
    assert con.execute("select count(*) from findings").fetchone()[0] > 10
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    con.close()
    again = await api.post("/api/v1/backups/restore", json={"file": b["file"], "target_name": "restore1",
                                                            "confirm": True})
    assert again.status_code == 409  # collision: never overwrite
    src = settings.backup_dir / b["file"]
    bad = settings.backup_dir / "OSINTCC-backup-corrupt.zip"
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(bad, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            zout.writestr(item, data + b"X" if item.filename.startswith("evidence/") else data)
    v = (await api.post("/api/v1/backups/verify", json={"file": bad.name})).json()
    assert not v["ok"] and any("checksum mismatch" in p for p in v["problems"])
    refused = await api.post("/api/v1/backups/restore", json={"file": bad.name, "target_name": "restore2",
                                                              "confirm": True})
    assert refused.status_code == 409 and not (settings.data_dir / "restores" / "restore2").exists()
    assert (await api.post("/api/v1/backups/verify", json={"file": "../osintcc.sqlite"})).status_code == 404


async def test_archive_requires_confirmation_and_makes_readonly(api):
    cid = await mk_case(api)
    assert (await api.post(f"/api/v1/cases/{cid}/archive", json={})).status_code == 422
    assert (await api.post(f"/api/v1/cases/{cid}/archive", json={"confirm": True})).json()["status"] == "archived"
    assert (await api.patch(f"/api/v1/cases/{cid}", json={"title": "x"})).status_code == 409
    assert (await api.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com"})).status_code == 409


async def test_graph_proposal_accept_does_not_merge_entities(api):
    cid = await mk_case(api)
    await api.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "wait": True})
    ents = (await api.get(f"/api/v1/cases/{cid}/entities?limit=1000")).json()
    n_before = ents["total"]
    a, b = ents["items"][0]["id"], ents["items"][1]["id"]
    p = (await api.post(f"/api/v1/cases/{cid}/graph/proposals",
                        json={"subject_id": a, "candidate_id": b, "reason": "same handle"})).json()
    no_ev = await api.post(f"/api/v1/cases/{cid}/graph/proposals/{p['id']}/decision", json={"decision": "accept"})
    assert no_ev.status_code == 422  # evidence required
    evid = (await api.get(f"/api/v1/cases/{cid}/evidence")).json()["items"][0]["id"]
    ok = await api.post(f"/api/v1/cases/{cid}/graph/proposals/{p['id']}/decision",
                        json={"decision": "accept", "evidence_id": evid})
    assert ok.status_code == 200
    assert (await api.get(f"/api/v1/cases/{cid}/entities?limit=1000")).json()["total"] == n_before
    edges = (await api.get(f"/api/v1/cases/{cid}/graph")).json()["edges"]
    same = [e for e in edges if e["type"] == "same_as"]
    assert same and same[0]["status"] == "manual" and same[0]["evidence_ids"] == [evid]
    rej = await api.post(f"/api/v1/cases/{cid}/relationships/{same[0]['id']}/reject")
    assert rej.json()["status"] == "rejected"


async def test_shutdown_requires_launcher_and_auth(api):
    assert (await api.post("/api/v1/system/shutdown")).status_code == 409  # not started by `run()`
    called = []
    api.app.state.core.request_shutdown = lambda: called.append(1)
    assert (await api.post("/api/v1/system/shutdown")).status_code == 202
    import asyncio
    await asyncio.sleep(0.4)
    assert called == [1]
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1")
    assert (await anon.post("/api/v1/system/shutdown")).status_code == 401
