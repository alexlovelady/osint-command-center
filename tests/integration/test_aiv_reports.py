"""AIV-5/6: the verification report, the PHANTOM handoff export, and the Target Profile view (explicit links only)."""
from __future__ import annotations

import json

import httpx
from osintcc.aiv import reporting
from osintcc.db.models import AuditEvent, CaseMember, ReportRun, User
from sqlalchemy import select
from test_aiv_core import B, approve, enable, http_step, mk_auth, mk_case, mk_plan, obs, run


async def verified_case(e, classes=("http_metadata",)):
    await enable(e)
    lb = await e["lab"]()
    cid = await mk_case(e)
    a = await mk_auth(e, cid, ["lab.test"], [lb.port], classes=classes)
    p = await mk_plan(e, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/", "GET")])
    r = await run(e, p["id"], (await approve(e, p["id"]))["approval_id"])
    assert r["status"] == "completed"
    return cid, lb, a, p, r


async def download(e, report_id):
    r = await e["api"].get(f"{B}/reports/{report_id}/download")
    assert r.status_code == 200, r.text
    return r.content.decode()


async def test_the_report_states_authorization_approval_runs_findings_limits_and_the_audit_chain(env):
    cid, lb, _a, p, r = await verified_case(env)
    items = await obs(env, cid, r["id"])
    assert items
    await env["api"].post(f"{B}/cases/{cid}/aiv/observations/{items[0]['id']}/review", json={"status": "confirmed", "note": "checked by hand"})
    made = await env["api"].post(f"{B}/cases/{cid}/aiv/report", json={"format": "markdown"})
    assert made.status_code == 201 and made.json()["audit_chain_ok"] is True and len(made.json()["sha256"]) == 64
    text = await download(env, made.json()["id"])
    for needle in ("Active verification report", "What was authorized", "lab.test", "Owner Operator", "approved by", "What this report cannot show", "No exploitation", "Audit appendix",
                   "Audit chain verified", "checked by hand"):
        assert needle in text, needle
    assert "SECRET-SESSION-VALUE" not in text                                              # cookie values are redacted before storage and never reappear
    html = await download(env, (await env["api"].post(f"{B}/cases/{cid}/aiv/report", json={"format": "html"})).json()["id"])
    assert html.startswith("<!doctype html>") and "<script" not in html
    js = json.loads(await download(env, (await env["api"].post(f"{B}/cases/{cid}/aiv/report", json={"format": "json"})).json()["id"]))
    assert js["summary"]["confirmed"] == 1 and js["audit_appendix"]["chain_ok"] and js["runs"][0]["id"] == r["id"] and js["approvals"][0]["plan_id"] == p["id"]
    assert lb.seen and all(s.method == "GET" for s in lb.seen)


async def test_report_needs_a_run_and_an_editor_and_hides_false_positives_unless_asked(env):
    await enable(env)
    cid = await mk_case(env)
    assert (await env["api"].post(f"{B}/cases/{cid}/aiv/report", json={"format": "html"})).status_code == 409
    cid, _lb, _a, _p, r = await verified_case(env)
    items = await obs(env, cid, r["id"])
    for it in items:
        await env["api"].post(f"{B}/cases/{cid}/aiv/observations/{it['id']}/review", json={"status": "false_positive", "note": "expected"})
    clean = json.loads(await download(env, (await env["api"].post(f"{B}/cases/{cid}/aiv/report", json={"format": "json"})).json()["id"]))
    assert clean["summary"]["observations"] == 0
    full = json.loads(await download(env, (await env["api"].post(f"{B}/cases/{cid}/aiv/report", json={"format": "json", "include_false_positive": True})).json()["id"]))
    assert full["summary"]["observations"] == len(items)
    st = env["st"]
    with st.sm() as db:
        db.add(User(id="v1", display_name="viewer"))
        db.flush()
        db.add(CaseMember(case_id=cid, user_id="v1", access_role="viewer"))
        db.commit()
    st.tokens["viewer-token"] = "v1"
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=env["api"].app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer viewer-token"})
    assert (await v.post(f"{B}/cases/{cid}/aiv/report", json={"format": "html"})).status_code in (403, 404)
    rid = (await env["api"].post(f"{B}/cases/{cid}/aiv/report", json={"format": "html"})).json()["id"]
    assert (await v.get(f"{B}/reports/{rid}/download")).status_code in (403, 404)


async def test_phantom_handoff_is_approved_by_the_owner_carries_only_confirmed_findings_and_launches_nothing(env):
    cid, lb, _a, _p, r = await verified_case(env)
    items = await obs(env, cid, r["id"])
    sev = sorted({i["severity"] for i in items})
    none = await env["api"].post(f"{B}/cases/{cid}/aiv/handoff", json={"confirm_handoff": True, "min_severity": "info"})
    assert none.status_code == 409 and none.json()["code"] == "nothing_to_hand_off"                 # nothing confirmed yet
    target = items[0]
    await env["api"].post(f"{B}/cases/{cid}/aiv/observations/{target['id']}/review", json={"status": "confirmed", "note": "verified manually"})
    unapproved = await env["api"].post(f"{B}/cases/{cid}/aiv/handoff", json={"confirm_handoff": False, "min_severity": "info"})
    assert unapproved.status_code == 422 and unapproved.json()["code"] == "approval_required"
    connections = lb.connections
    ok = await env["api"].post(f"{B}/cases/{cid}/aiv/handoff", json={"confirm_handoff": True, "min_severity": "info"})
    assert ok.status_code == 201 and ok.json()["launches_anything"] is False and sev
    doc = json.loads(await download(env, ok.json()["id"]))
    assert doc["schema"] == reporting.HANDOFF_SCHEMA and [o["id"] for o in doc["observations"]] == [target["id"]]
    assert any("not an instruction" in x for x in doc["restrictions"]) and any("own written authorization" in x for x in doc["restrictions"])
    blob = json.dumps(doc)
    assert "SECRET-SESSION-VALUE" not in blob and "headers" not in blob.lower().replace("security headers", "")
    assert doc["excluded"]["unreviewed_or_unconfirmed"] == len(items) - 1
    v = await env["api"].post(f"{B}/aiv/handoff/verify", json={"document": doc})
    assert v.json()["valid"] is True
    doc["observations"][0]["title"] = "tampered after export"
    assert (await env["api"].post(f"{B}/aiv/handoff/verify", json={"document": doc})).json()["valid"] is False
    assert lb.connections == connections                                                            # exporting contacted nothing
    with env["st"].sm() as db:
        assert db.scalars(select(AuditEvent).where(AuditEvent.action == "aiv.handoff_export", AuditEvent.case_id == cid)).first() is not None
        assert db.scalars(select(ReportRun).where(ReportRun.template == "aiv-handoff")).one().status == "done"


async def test_target_profile_view_lists_only_explicitly_linked_assets_never_by_name(env):
    api = env["api"]
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env, category="people")
    sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "lab.test", "mode": "self", "purpose": "self audit"})).json()["id"]    # a name that LOOKS like the asset
    linked = await mk_auth(env, cid, ["lab.test"], [lb.port], classes=("tls_handshake",), owner_subject_id=sid)
    other = await mk_auth(env, cid, ["other.test"], [lb.port], classes=("tls_handshake",))
    r = await api.post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": linked["id"], "steps": [{"kind": "tls_handshake", "host": "lab.test", "port": lb.port}], "target_profile_id": sid})
    assert r.status_code == 201, r.text
    j = (await api.get(f"{B}/subjects/{sid}/verification")).json()
    assert j["enabled"] is True and [x["id"] for x in j["authorizations"]] == [linked["id"]] and len(j["plans"]) == 1
    assert other["id"] not in json.dumps(j) and j["unlinked_case_authorizations"] == 1
    assert "not authorization" in j["notice"]
    # a subject with a similar name but no link sees nothing
    sid2 = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "other.test", "mode": "self", "purpose": "self audit"})).json()["id"]
    j2 = (await api.get(f"{B}/subjects/{sid2}/verification")).json()
    assert j2["authorizations"] == [] and j2["plans"] == [] and j2["observations"] == []
    assert (await api.get(f"{B}/subjects/nope/verification")).status_code == 404


async def test_backup_and_restore_keep_authorizations_plans_approvals_runs_observations_and_templates(tmp_path, calls):
    from aiv_lab import WEAK_HEADERS, Lab, Resolver
    from conftest import fake_dns, fake_resolver, make_handler
    from osintcc.adapters.base import AdapterContext
    from osintcc.config import Settings
    from osintcc.main import create_app
    from osintcc.policy.ssrf import SafeHttp
    ok_template = (__import__("pathlib").Path(__file__).resolve().parents[1] / "fixtures" / "aiv" / "nuclei_template_ok.yaml").read_text(encoding="utf-8")
    s = Settings(data_dir=tmp_path / "live", vault_encryption="off", db_encryption="off", run_scheduler=False)
    s.ensure_dirs()
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    lb = await Lab(routes={"*": (200, WEAK_HEADERS, b"<html>x</html>")}).start()
    try:
        async with app.router.lifespan_context(app):
            st = app.state.core
            st.aiv.resolver, st.aiv.rate_boost = Resolver({"lab.test": ["127.0.0.1"]}), 1000.0
            api = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {s.session_token}"}, timeout=60)
            e = {"api": api, "st": st}
            assert (await api.put(f"{B}/aiv/settings", json={"enabled": True})).status_code == 200
            assert (await api.post(f"{B}/aiv/templates", json={"content": ok_template, "confirm_reviewed": True})).status_code == 201
            cid = await mk_case(e)
            a = await mk_auth(e, cid, ["lab.test"], [lb.port])
            p = await mk_plan(e, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/", "GET")])
            ap = await approve(e, p["id"])
            r = await run(e, p["id"], ap["approval_id"])
            before = {"obs": sorted(i["finding_key"] for i in await obs(e, cid, r["id"])), "hash": p["plan_hash"], "auth": a["scope_snapshot_hash"]}
            b = (await api.post(f"{B}/backups", json={"passphrase": "a-long-passphrase"})).json()
            assert (await api.post(f"{B}/backups/restore", json={"file": b["file"], "target_name": "aivrestore", "passphrase": "a-long-passphrase", "confirm": True})).status_code == 200
            await api.aclose()
    finally:
        await lb.stop()
    restored = s.data_dir / "restores" / "aivrestore"
    assert all(b"SECRET-SESSION-VALUE" not in f.read_bytes() for f in restored.rglob("*") if f.is_file() and f.stat().st_size < 5_000_000)
    s2 = Settings(data_dir=restored, vault_encryption="off", db_encryption="off", run_scheduler=False)
    app2 = create_app(s2, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns), init_db=True)
    async with app2.router.lifespan_context(app2):
        api2 = httpx.AsyncClient(transport=httpx.ASGITransport(app=app2), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {s2.session_token}"}, timeout=60)
        e2 = {"api": api2, "st": app2.state.core}
        auths = (await api2.get(f"{B}/cases/{cid}/asset-authorizations")).json()["items"]
        assert [x["id"] for x in auths] == [a["id"]] and auths[0]["scope_snapshot_hash"] == before["auth"]
        pl = (await api2.get(f"{B}/aiv/plans/{p['id']}")).json()
        assert pl["plan_hash"] == before["hash"] and [x["id"] for x in pl["approvals"]] == [ap["approval_id"]] and pl["approvals"][0]["uses"] == 1     # a used approval stays used
        assert (await api2.get(f"{B}/aiv/runs/{r['id']}")).json()["status"] == "completed"
        assert sorted(i["finding_key"] for i in await obs(e2, cid, r["id"])) == before["obs"]
        assert [t["template_id"] for t in (await api2.get(f"{B}/aiv/templates")).json()["items"]] == ["lab-apache-banner"]
        reuse = await api2.post(f"{B}/aiv/plans/{p['id']}/run", json={"approval_id": ap["approval_id"], "wait": True})
        assert reuse.status_code in (403, 409, 422) and lb.connections >= 1                         # a restored, already-used approval cannot be replayed
        await api2.aclose()
