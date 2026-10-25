"""Automation Builder acceptance tests, part 3: recovery, cancellation, retries and quotas, reports, offline, cloud AI, secrets, suggestions, backup, diagnostics, audit."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.ai.providers import FixtureProvider
from osintcc.automations import catalog
from osintcc.config import Settings
from osintcc.db.models import (
    AuditEvent,
    AutomationApproval,
    AutomationNodeRun,
    AutomationNotification,
    AutomationRun,
    AutomationSuggestion,
    Case,
    Job,
    SearchRun,
    Target,
)
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import func, select
from test_automations import (
    API,
    SCOPE,
    B,
    client_for,
    from_template,
    mk_case,
    new_wf,
    node,
    publish,
    q,
    run_detail,
    run_now,
    wf_def,
)
from test_automations_2 import FakeAdapter, app_with, cy02, enable_ai, fake_wf, result, serve

pytestmark = pytest.mark.usefixtures("_no_real_keyring")


async def started(api, wid, cid, **kw):
    r = await api.post(f"{B}/workflows/{wid}/run", json={"case_id": cid, "wait": False, **kw})
    assert r.status_code == 202, r.text
    return r.json()["id"]


async def until(api, rid, states, timeout=15.0):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        d = (await api.get(f"{B}/runs/{rid}")).json()
        if d["state"] in states:
            return d
        await asyncio.sleep(0.05)
    raise AssertionError(f"run stayed {d['state']}")


# =============================================================================================== AUT-09 crash recovery
async def test_restart_resumes_replay_safe_runs_from_checkpoints_without_duplicate_notifications(settings, calls):
    seen = {"n": 0}

    async def script(t, c, n):
        seen["n"] += 1
        return result(t, ["one", "two"])
    app = app_with(settings, calls, FakeAdapter("fakesrc", script=script))
    async with app.router.lifespan_context(app):
        api = await serve(app, settings)
        cid = await mk_case(api)
        d = fake_wf([node("dd", "deduplicate", ["src"], ref="$nodes.src.output"), node("diff", "snapshot_diff", ["dd"], dataset_ref="$nodes.dd.output"),
                     node("note", "notification", ["diff"], change_ref="$nodes.dd.output", title="Always", only_if_changed=True)])
        wf = await new_wf(api, d, cid)
        await publish(api, wf["id"])
        full = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
        assert full["state"] == "completed" and seen["n"] == 1
        st = app.state.core
        # simulate a crash after 'src' and 'scope' finished and 'dd' was in flight
        with st.sm() as db:
            r = db.get(AutomationRun, full["id"])
            for nr in db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == r.id, AutomationNodeRun.node_id.in_(["dd", "diff", "note"]))):
                db.delete(nr)
            db.add(AutomationNodeRun(run_id=r.id, node_id="dd", attempt=1, state="running"))
            r.state, r.ended_at = "running", None
            db.commit()
        out = st.automation.recover()
        assert out == {"resumed": 1, "paused": 0}
        assert await st.automation.execute(full["id"]) == "completed"
        after = await run_detail(api, full["id"])
        assert seen["n"] == 1                                                           # the checkpointed source query was NOT repeated
        states = {n["node"]: n["state"] for n in after["nodes"] if n["state"] != "interrupted"}
        assert states["dd"] == "succeeded" and any(n["state"] == "interrupted" and n["node"] == "dd" for n in after["nodes"])
        # a second restart replays the whole run: notifications are de-duplicated, not repeated
        with st.sm() as db:
            for nr in db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == full["id"], AutomationNodeRun.node_id == "note")):
                db.delete(nr)
            db.get(AutomationRun, full["id"]).state = "queued"
            db.commit()
        await st.automation.execute(full["id"])
        with st.sm() as db:
            assert db.scalar(select(func.count()).select_from(AutomationNotification)) == 1
            assert db.scalars(select(AutomationNotification)).one().count >= 2
        await api.aclose()


async def test_restart_pauses_runs_whose_interrupted_step_is_not_safe_to_replay(api):
    st = api.app.state.core
    cid = await mk_case(api)
    d = wf_def([node("rep", "report", profile="technical", format="html")], inputs={})
    wf = await new_wf(api, d, cid)
    await publish(api, wf["id"])
    r = await run_now(api, wf["id"], cid)
    with st.sm() as db:
        run = db.get(AutomationRun, r["id"])
        run.state = "running"
        for nr in db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == run.id)):
            nr.state, nr.output_json = "running", None
        db.commit()
    assert st.automation.recover() == {"resumed": 0, "paused": 1}
    det = await run_detail(api, r["id"])
    assert det["state"] == "paused" and det["error_code"] == "INTERRUPTED"
    assert (await api.post(f"{B}/runs/{r['id']}/retry", params={"wait": True})).status_code == 202            # a person resumes it deliberately
    with st.sm() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "automation.run_recovered")) == 1


# =============================================================================================== AUT-10 cancellation
async def test_cancel_stops_the_source_job_and_leaves_nothing_running(settings, calls):
    started_evt = asyncio.Event()

    async def slow(t, c, n):
        started_evt.set()
        await asyncio.sleep(60)
        return result(t, ["never"])
    app = app_with(settings, calls, FakeAdapter("fakesrc", script=slow))
    async with app.router.lifespan_context(app):
        api = await serve(app, settings)
        cid = await mk_case(api)
        wf = await new_wf(api, fake_wf([node("save", "evidence_save", ["src"], ref="$nodes.src.output", title="x")]), cid)
        await publish(api, wf["id"])
        rid = await started(api, wf["id"], cid)
        await asyncio.wait_for(started_evt.wait(), 10)
        t0 = asyncio.get_running_loop().time()
        assert (await api.post(f"{B}/runs/{rid}/cancel")).status_code == 200
        d = await until(api, rid, ("cancelled",), 10)
        assert asyncio.get_running_loop().time() - t0 < 8 and d["error_code"] == "RUN_CANCELLED"
        st = app.state.core
        with st.sm() as db:
            jobs = list(db.scalars(select(Job)))
            assert jobs and all(j.status != "running" for j in jobs)                       # the adapter job was cancelled, not abandoned
            assert db.scalar(select(func.count()).select_from(AutomationNodeRun).where(AutomationNodeRun.run_id == rid, AutomationNodeRun.state == "running")) == 0
        assert (await api.post(f"{B}/runs/{rid}/cancel")).status_code == 409                # already over
        await asyncio.sleep(0.2)
        assert not [t for t in st.tasks if not t.done()]
        await api.aclose()


# =============================================================================================== AUT-11 retries, backoff, quotas
async def test_transient_failures_retry_a_bounded_number_of_times_but_policy_denials_never(settings, calls):
    async def timing_out(t, c, n):
        return result(t, [], status="error", error="timeout", retryable=True)
    fake = FakeAdapter("fakesrc", script=timing_out)
    app = app_with(settings, calls, fake)
    async with app.router.lifespan_context(app):
        api = await serve(app, settings)
        cid = await mk_case(api)
        d = fake_wf()
        d["error_policy"] = {"transient_retries": 2}
        wf = await new_wf(api, d, cid)
        await publish(api, wf["id"])
        det = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
        attempts = [n for n in det["nodes"] if n["node"] == "src"]
        assert det["state"] == "failed" and det["error_code"] == "TIMEOUT" and len(attempts) == 3 and [n["attempt"] for n in attempts] == [1, 2, 3]   # 1 try + 2 retries, no more
        d0 = fake_wf([], inputs={"domain": "10.9.9.9"})
        wf2 = await new_wf(api, d0, cid)
        await publish(api, wf2["id"])
        det2 = await run_detail(api, (await run_now(api, wf2["id"], cid))["id"])
        assert [n["attempt"] for n in det2["nodes"] if n["node"] == "scope"] == [1] and det2["error_code"] == "SCOPE_DENIED"                          # never retried
        await api.aclose()


async def test_per_run_request_budget_stops_the_run_and_never_rotates_around_it(settings, calls):
    async def ok(t, c, n):
        return result(t, ["x"])
    app = app_with(settings, calls, FakeAdapter("fakesrc", script=ok))
    async with app.router.lifespan_context(app):
        api = await serve(app, settings)
        cid = await mk_case(api)
        d = wf_def([SCOPE, q("a", "fakesrc"), q("b", "fakesrc")], policy={"max_requests_per_provider_per_run": 1})
        wf = await new_wf(api, d, cid)
        rep = (await api.post(f"{B}/workflows/{wf['id']}/validate")).json()
        assert not rep["valid"] and "per run" in rep["errors"][0]["message"]                           # caught before it can run
        d2 = wf_def([SCOPE, q("a", "fakesrc"), node("b", "adapter_query", ["a"], adapter="fakesrc", target_ref="$inputs.domain")], policy={"max_requests_per_provider_per_run": 2})
        d2["nodes"][2]["depends_on"] = ["scope", "a"]
        wf2 = await new_wf(api, d2, cid)
        await publish(api, wf2["id"])
        det = await run_detail(api, (await run_now(api, wf2["id"], cid))["id"])
        assert det["state"] == "completed" and det["summary_full"]["requests"]["fakesrc"] == 2
        await api.aclose()


# =============================================================================================== AUT-14 / AUT-23 report metadata and audit
async def test_case_reports_cite_the_workflow_version_and_run_and_runs_are_auditable(api):
    cid = await mk_case(api)
    wf = await from_template(api, "cy-01-domain-recon", cid, domain="example.com")
    v = await publish(api, wf["id"])
    r = await run_now(api, wf["id"], cid)
    det = await run_detail(api, r["id"])
    rep = (await api.post(f"{API}/cases/{cid}/reports", json={"format": "json", "profile": "technical"})).json()
    body = json.loads((await api.get(f"{API}/reports/{rep['id']}/download")).content)
    runs = body["automation_runs"]
    assert runs and runs[0]["run_id"] == r["id"] and runs[0]["revision"] == v["revision"] and runs[0]["version_hash"] == v["hash"][:16] and runs[0]["workflow"] == wf["name"]
    html = (await api.post(f"{API}/cases/{cid}/reports", json={"format": "html"})).json()
    page = (await api.get(f"{API}/reports/{html['id']}/download")).text
    assert "Automation runs" in page and r["id"] in page and body["evidence_manifest"]
    # AUT-23: input digests, timestamps, errors and evidence references are all recorded
    for n in det["nodes"]:
        assert n["input_digest"] and n["started_at"] and n["ended_at"]
    assert any(n["error_code"] == "SOURCE_UNAVAILABLE" for n in det["nodes"]) and det["evidence_count"] > 0
    with api.app.state.core.sm() as db:
        acts = {a for (a,) in db.execute(select(AuditEvent.action))}
        assert {"automation.workflow_created", "automation.published", "automation.run_queued", "automation.run_finished"} <= acts
    assert det["version"]["hash"] == v["hash"] and det["inputs"]["domain"] == "example.com"


# =============================================================================================== AUT-15 offline
async def test_offline_pauses_network_workflows_safely_while_local_ones_keep_working(api, calls):
    cid = await mk_case(api)
    net = await from_template(api, "cy-01-domain-recon", cid, domain="example.com")
    await publish(api, net["id"])
    local = await new_wf(api, wf_def([node("rep", "report", profile="technical", format="markdown")], inputs={}), cid)
    await publish(api, local["id"])
    await api.put(f"{API}/settings", json={"values": {"offline": True}})
    n = len(calls)
    det = await run_detail(api, (await run_now(api, net["id"], cid))["id"])
    assert det["state"] == "paused" and det["error_code"] == "OFFLINE" and len(calls) == n and "Retry when you are online" in det["summary_full"]["error"]
    ok = await run_detail(api, (await run_now(api, local["id"], cid))["id"])
    assert ok["state"] == "completed"                                                         # local files and reports work offline
    assert (await api.get(f"{B}/templates")).json()["total"] == 42                            # the library is local data
    assert (await api.post(f"{B}/ai/propose", json={"goal": "watch the company filing feed for a company"})).json()["source"] in ("template_match", "none")   # no model needed
    await api.put(f"{API}/settings", json={"values": {"offline": False}})
    assert (await api.post(f"{B}/runs/{det['id']}/retry", params={"wait": True})).status_code == 202
    assert (await run_detail(api, det["id"]))["state"] in ("completed", "completed_with_warnings")
    assert len(calls) > n


async def test_scheduler_skips_network_triggers_while_offline_without_piling_up_runs(api):
    cid = await mk_case(api)
    wf = await new_wf(api, cy02(), cid)
    await publish(api, wf["id"])
    a = (await api.post(f"{B}/workflows/{wf['id']}/request-approval", json={})).json()["items"][0]
    await api.post(f"{B}/approvals/{a['id']}/decide", json={"approve": True, "expires_in_days": 30})
    await api.post(f"{B}/workflows/{wf['id']}/activate", json={})
    await api.put(f"{API}/settings", json={"values": {"offline": True}})
    s = api.app.state.core.automation_scheduler
    await s.tick(datetime.now(UTC) + timedelta(days=2))
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(AutomationRun)) == 0


# =============================================================================================== AUT-16 cloud AI
async def test_cloud_ai_needs_provider_specific_opt_in_and_never_receives_case_evidence(api):
    cid = await mk_case(api)
    await api.post(f"{API}/cases/{cid}/searches", json={"target": "example.com", "wait": True})
    prov = FixtureProvider(script=lambda m: json.dumps(cy02()))
    prov.local = False
    pid = await enable_ai(api, prov, local=False)
    r = (await api.post(f"{B}/ai/propose", json={"goal": "watch example.com for new subdomains daily", "case_id": cid, "profile_id": pid})).json()
    assert prov.calls == [] and not r["model"]["used"] and "not allowed" in r["model"]["reason"]
    assert (await api.patch(f"{B}/settings", json={"values": {"cloud_ai_opt_in": [pid]}})).status_code == 200
    r2 = (await api.post(f"{B}/ai/propose", json={"goal": "watch example.com for new subdomains daily", "case_id": cid, "profile_id": pid})).json()
    assert len(prov.calls) == 1 and r2["model"]["used"]
    sent = "\n".join(m.content for m in prov.calls[0])
    assert "Example Registrar" not in sent and "a.iana-servers.net" not in sent and "93.184.216.34" not in sent       # capabilities and the goal only, never case evidence


# =============================================================================================== AUT-17 secrets
async def test_secrets_never_enter_definitions_logs_exports_or_run_records(api, settings):
    secret = "fake-secret-key-0123456789"
    await api.post(f"{API}/secrets/virustotal", json={"value": secret})
    await api.patch(f"{B}/settings", json={"values": {"notifications": {"webhooks": {"ops": "https://hooks.example.com/TOKEN-IN-URL-98765"}}}})
    cid = await mk_case(api)
    d = wf_def([SCOPE, q("vt", "virustotal"), node("note", "notification", ["vt"], change_ref="$nodes.vt.output", title="VT", channel="webhook", webhook_ref="ops", only_if_changed=False)])
    wf = await new_wf(api, d, cid)
    assert (await api.post(f"{B}/workflows", json={"definition": {**d, "nodes": [{**d["nodes"][0], "config": {**d["nodes"][0]["config"], "api_key": secret}}] + d["nodes"][1:]}})).status_code == 422
    await publish(api, wf["id"])
    det = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
    blobs = [json.dumps(det, default=str), json.dumps((await api.get(f"{B}/workflows/{wf['id']}/export")).json()), json.dumps((await api.get(f"{B}/workflows/{wf['id']}")).json(), default=str),
             json.dumps((await api.get(f"{B}/notifications")).json()), json.dumps((await api.get(f"{B}/runs")).json(), default=str)]
    with api.app.state.core.sm() as db:
        blobs.append(json.dumps([e.metadata_json for e in db.query(AuditEvent)], default=str))
        blobs.append(json.dumps([n.diagnostics_json for n in db.query(AutomationNodeRun)], default=str))
    assert all(secret not in b and "TOKEN-IN-URL" not in b for b in blobs)                       # webhook URLs live in Settings only; workflows reference a name
    assert det["state"] == "failed" and det["error_code"] in ("CREDENTIAL_MISSING", "SOURCE_UNAVAILABLE", "RATE_LIMITED") or det["state"].startswith("completed")


# =============================================================================================== AUT-18 suggestions
async def test_suggestions_are_off_by_default_use_app_events_only_and_can_be_dismissed_or_disabled(api):
    st = api.app.state.core
    cid = await mk_case(api)
    for _ in range(3):
        await api.post(f"{API}/cases/{cid}/searches", json={"target": "example.com", "wait": True})
    off = (await api.get(f"{B}/suggestions")).json()
    assert off["enabled"] is False and off["items"] == [] and "off" in off["note"].lower()
    with st.sm() as db:
        assert db.scalar(select(func.count()).select_from(AutomationSuggestion)) == 0
    await api.patch(f"{B}/settings", json={"values": {"suggestions": {"enabled": True}}})
    on = (await api.get(f"{B}/suggestions")).json()
    assert len(on["items"]) == 1 and on["items"][0]["template"] == "cy-02-domain-change-watch" and "3 searches" in on["items"][0]["rationale"] and on["items"][0]["basis"]["search_runs"] == 3
    assert (await api.get(f"{B}/suggestions")).json()["items"][0]["id"] == on["items"][0]["id"] and len((await api.get(f"{B}/suggestions")).json()["items"]) == 1       # no nagging duplicates
    with st.sm() as db:
        assert db.scalar(select(func.count()).select_from(AutomationRun)) == 0 and db.scalar(select(func.count()).select_from(AutomationApproval)) == 0     # a suggestion creates nothing
    assert (await api.post(f"{B}/suggestions/{on['items'][0]['id']}/dismiss")).json()["state"] == "dismissed"
    assert (await api.get(f"{B}/suggestions")).json()["items"] == []
    people = await mk_case(api, "People", "need a purpose", "people")
    for _ in range(3):
        await api.post(f"{API}/cases/{people}/searches", json={"target": "example.org", "wait": True})
    assert all(i["case_id"] != people for i in (await api.get(f"{B}/suggestions")).json()["items"])                  # personal investigations are not profiled unless opted in
    await api.patch(f"{B}/settings", json={"values": {"suggestions": {"include_sensitive": True}}})
    sug = (await api.get(f"{B}/suggestions")).json()["items"]
    assert any(i["case_id"] == people for i in sug)
    sid = next(i["id"] for i in sug if i["case_id"] == people)
    assert (await api.post(f"{B}/suggestions/{sid}/snooze", json={"days": 3})).json()["state"] == "snoozed"
    assert all(i["id"] != sid for i in (await api.get(f"{B}/suggestions")).json()["items"])
    await api.patch(f"{B}/settings", json={"values": {"suggestions": {"enabled": False}}})
    assert (await api.get(f"{B}/suggestions")).json()["items"] == []                                       # switching suggestions off hides them too


# =============================================================================================== AUT-22 diagnostics and repair
async def test_failed_runs_are_diagnosed_from_real_records_and_repairs_only_touch_the_draft(settings, calls):
    async def ok(t, c, n):
        return result(t, ["fine"])
    app = app_with(settings, calls, FakeAdapter("fakesrc", script=ok))
    async with app.router.lifespan_context(app):
        api = await serve(app, settings)
        cid = await mk_case(api)
        d = wf_def([SCOPE, q("sub", "subfinder"), node("save", "evidence_save", ["sub"], ref="$nodes.sub.output", title="x")])
        wf = await new_wf(api, d, cid)
        v = await publish(api, wf["id"])
        det = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
        assert det["state"] == "failed" and det["error_code"] == "SOURCE_UNAVAILABLE"
        diag = (await api.post(f"{B}/ai/diagnose", json={"run_id": det["id"]})).json()
        assert diag["healthy_run"] is False and diag["problems"][0]["code"] == "SOURCE_UNAVAILABLE" and diag["problems"][0]["node"] == "sub"
        assert "Setup" in diag["problems"][0]["fix"] or "Install" in diag["problems"][0]["fix"]
        ops = [p for p in diag["proposals"] if p["op"] == "replace_adapter" and p["to"] in ("crtsh", "wayback", "rdap", "dns", "fakesrc")]
        assert ops and any(p["op"] == "set_optional" for p in diag["proposals"])
        before = (await api.get(f"{B}/workflows/{wf['id']}")).json()
        rep = (await api.post(f"{B}/workflows/{wf['id']}/repair", json={"ops": [{"op": "replace_adapter", "node": "sub", "to": "crtsh"}], "rev": before["rev"]})).json()
        assert rep["changes"] == [{"node": "sub", "from": "subfinder", "to": "crtsh"}] and rep["validation"]["valid"]
        after = (await api.get(f"{B}/workflows/{wf['id']}")).json()
        assert after["definition"]["nodes"][1]["config"]["adapter"] == "crtsh" and after["unpublished_changes"] is True
        with app.state.core.sm() as db:
            from osintcc.db.models import AutomationVersion
            assert db.scalars(select(AutomationVersion)).one().definition_json["nodes"][1]["config"]["adapter"] == "subfinder"        # the published version is untouched
        assert (await api.post(f"{B}/workflows/{wf['id']}/repair", json={"ops": [{"op": "delete_everything", "node": "sub"}]})).status_code == 422
        assert (await api.post(f"{B}/workflows/{wf['id']}/repair", json={"ops": [{"op": "replace_adapter", "node": "sub", "to": "nmap"}]})).status_code == 422
        v2 = await publish(api, wf["id"])
        det2 = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
        assert v2["revision"] == v["revision"] + 1 and det2["state"] in ("completed", "completed_with_warnings")
        healthy = (await api.post(f"{B}/ai/diagnose", json={"run_id": det2["id"]})).json()
        assert healthy["problems"] == [] and healthy["healthy_run"] == (det2["state"] == "completed")
        await api.aclose()


# =============================================================================================== review, conditions, reentrancy, import/export, ETag/pagination
async def test_analyst_review_parks_the_run_until_a_person_decides(api):
    cid = await mk_case(api)
    d = wf_def([node("rev", "analyst_review", prompt="Confirm consent"), node("rep", "report", ["rev"], profile="technical", format="markdown")], inputs={})
    wf = await new_wf(api, d, cid)
    await publish(api, wf["id"])
    r = await api.post(f"{B}/workflows/{wf['id']}/run", json={"case_id": cid, "wait": True})
    det = await run_detail(api, r.json()["id"])
    assert det["state"] == "waiting_for_approval" and next(n for n in det["nodes"] if n["node"] == "rev")["state"] == "waiting"
    assert not [n for n in det["nodes"] if n["node"] == "rep"]
    assert (await api.post(f"{B}/runs/{det['id']}/review", json={"node": "nope", "approve": True})).status_code == 409
    done = (await api.post(f"{B}/runs/{det['id']}/review", params={"wait": True}, json={"node": "rev", "approve": True})).json()
    assert (await run_detail(api, done["id"]))["state"] == "completed"
    r2 = await api.post(f"{B}/workflows/{wf['id']}/run", json={"case_id": cid, "wait": True})
    await api.post(f"{B}/runs/{r2.json()['id']}/review", params={"wait": True}, json={"node": "rev", "approve": False})
    rej = await run_detail(api, r2.json()["id"])
    assert rej["state"] == "failed" and next(n for n in rej["nodes"] if n["node"] == "rep")["state"] == "skipped_failed" or rej["state"] == "failed"


async def test_conditions_skip_branches_and_error_handlers_run_only_on_failure(api):
    cid = await mk_case(api)
    d = wf_def([node("c", "condition", ref="$inputs.flag", op="truthy"), node("yes", "delay", ["c"], seconds=1, when={"ref": "$nodes.c.output.value", "op": "truthy"}),
                node("boom", "case_findings", [], limit=5), node("h", "error_handler", ["yes"], run_on="failure", title="Handled")], inputs={"flag": False})
    wf = await new_wf(api, d, cid)
    await publish(api, wf["id"])
    det = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
    states = {n["node"]: n["state"] for n in det["nodes"]}
    assert states["c"] == "succeeded" and states["yes"] == "skipped" and states["h"] == "skipped" and det["state"] == "completed"


async def test_reentrancy_skip_keeps_only_one_run_in_flight_for_triggered_runs(api):
    st = api.app.state.core
    cid = await mk_case(api)
    wf = await new_wf(api, cy02(), cid)
    v = await publish(api, wf["id"])
    with st.sm() as db:
        w = db.get(__import__("osintcc.db.models", fromlist=["AutomationWorkflow"]).AutomationWorkflow, wf["id"])
        ver = db.get(__import__("osintcc.db.models", fromlist=["AutomationVersion"]).AutomationVersion, v["version_id"])
        a = st.automation.enqueue(db, w, ver, trigger_type="schedule", inputs={}, dry_run=False, idem="t1", actor="scheduler", case_id=cid)
        b = st.automation.enqueue(db, w, ver, trigger_type="schedule", inputs={}, dry_run=False, idem="t2", actor="scheduler", case_id=cid)
        dup = st.automation.enqueue(db, w, ver, trigger_type="manual", inputs={}, dry_run=False, idem="t1", actor="u", case_id=cid)
        db.commit()
        assert a is not None and b is None and dup is None                                      # skip policy; and an idempotency key is never reused


async def test_export_import_with_integrity_hash_and_never_auto_activation(api):
    cid = await mk_case(api)
    wf = await from_template(api, "cy-02-domain-change-watch", cid, domain="example.com")
    doc = (await api.get(f"{B}/workflows/{wf['id']}/export")).json()
    assert doc["format"] == "osintcc-automation/1" and len(doc["sha256"]) == 64
    imp = await api.post(f"{B}/import", json={"document": doc, "case_id": cid})
    assert imp.status_code == 201 and imp.json()["state"] == "draft" and imp.json()["definition"]["trigger"]["enabled"] is False
    assert imp.json()["permissions"]["network"] and "never activated automatically" in imp.json()["note"]
    tampered = copy.deepcopy(doc)
    tampered["definition"]["policy"]["max_requests_per_provider_per_run"] = 500
    bad = await api.post(f"{B}/import", json={"document": tampered, "case_id": cid})
    assert bad.status_code == 422 and "integrity" in bad.json()["message"]
    enabled = copy.deepcopy(doc)
    enabled["definition"]["trigger"]["enabled"] = True
    enabled.pop("sha256")
    enabled["sha256"] = hashlib.sha256(json.dumps({k: v for k, v in enabled.items() if k != "sha256"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    forced = (await api.post(f"{B}/import", json={"document": enabled, "case_id": cid})).json()
    assert forced["definition"]["trigger"]["enabled"] is False                                   # an import can never arrive switched on
    with api.app.state.core.sm() as db:
        from osintcc.db.models import AutomationTrigger
        assert db.scalar(select(func.count()).select_from(AutomationTrigger)) == 0


async def test_run_console_filters_pagination_compare_and_events(api):
    cid = await mk_case(api)
    wf = await from_template(api, "case-06-report-generator", cid)
    await publish(api, wf["id"])
    ids = [(await run_now(api, wf["id"], cid))["id"] for _ in range(3)]
    await api.post(f"{B}/workflows/{wf['id']}/dry-run", json={})
    allr = (await api.get(f"{B}/runs")).json()
    assert allr["total"] == 4
    assert (await api.get(f"{B}/runs", params={"dry_run": False})).json()["total"] == 3 and (await api.get(f"{B}/runs", params={"dry_run": True})).json()["items"][0]["simulated"] is True
    assert (await api.get(f"{B}/runs", params={"template": "case-06-report-generator", "state": "completed", "limit": 2, "dry_run": False})).json()["total"] == 3
    assert len((await api.get(f"{B}/runs", params={"limit": 2, "offset": 2})).json()["items"]) == 2
    assert (await api.get(f"{B}/runs", params={"case_id": "nope"})).json()["total"] == 0
    cmp = (await api.get(f"{B}/runs/{ids[0]}/compare/{ids[1]}")).json()
    assert {n["node"] for n in cmp["nodes"]} == {"report"} and cmp["nodes"][0]["same_input"] is True
    ev = await api.get(f"{B}/runs/{ids[0]}/events")
    assert "event: node" in ev.text and '"state": "completed"' in ev.text
    wfl = (await api.get(f"{B}/workflows", params={"case_id": cid})).json()
    assert wfl["total"] == 1 and wfl["items"][0]["latest_revision"] == 1
    assert (await api.delete(f"{B}/workflows/{wf['id']}")).status_code == 200 and (await api.get(f"{B}/workflows/{wf['id']}")).status_code == 404


async def test_other_users_cannot_see_or_run_my_workflows(api):
    from osintcc.db.models import User
    st = api.app.state.core
    cid = await mk_case(api)
    wf = await from_template(api, "case-06-report-generator", cid)
    with st.sm() as db:
        db.add(User(id="u9", display_name="x"))
        db.commit()
    st.tokens["t9"] = "u9"
    h = {"Authorization": "Bearer t9"}
    assert (await api.get(f"{B}/workflows/{wf['id']}", headers=h)).status_code == 404
    assert (await api.post(f"{B}/workflows/{wf['id']}/run", json={"case_id": cid}, headers=h)).status_code == 404
    assert (await api.get(f"{B}/workflows", headers=h)).json()["total"] == 0
    assert (await api.get(f"{B}/runs", headers=h)).json()["total"] == 0
    assert (await api.patch(f"{B}/settings", json={"values": {"max_concurrent_runs": 3}}, headers=h)).status_code == 403


# =============================================================================================== AUT-19 platform independence
async def test_fixture_dry_runs_produce_identical_results_on_every_platform(api):
    golden = {}
    for t in catalog.load_all():
        wf = await from_template(api, t["slug"])
        j = (await api.post(f"{B}/workflows/{wf['id']}/dry-run", json={})).json()
        golden[t["key"]] = hashlib.sha256(json.dumps([[n["node"], n["state"], n["output"]] for n in sorted(j["nodes"], key=lambda n: (n["node"], n["attempt"]))], sort_keys=True,
                                                     default=str).encode()).hexdigest()[:16]
    import pathlib
    path = pathlib.Path(__file__).parents[1] / "fixtures" / "automation_golden.json"
    if not path.exists():                                                                     # first run writes it; CI on Windows and Linux then must match it
        path.write_text(json.dumps(golden, indent=1, sort_keys=True), encoding="utf8")
    assert json.loads(path.read_text(encoding="utf8")) == golden


# =============================================================================================== AUT-20 backup and restore
async def test_backup_restore_reconstructs_workflows_approvals_history_and_reports_without_secrets(tmp_path, calls):
    secret = "fake-restore-secret-0001"
    s = Settings(data_dir=tmp_path / "live", vault_encryption="off", db_encryption="off", run_scheduler=False, retry_scale=0.001)
    s.ensure_dirs()
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        api = await client_for(app, s)
        await api.post(f"{API}/secrets/virustotal", json={"value": secret})
        cid = await mk_case(api)
        wf = await from_template(api, "cy-02-domain-change-watch", cid, domain="example.com")
        v = await publish(api, wf["id"])
        a = (await api.post(f"{B}/workflows/{wf['id']}/request-approval", json={})).json()["items"][0]
        await api.post(f"{B}/approvals/{a['id']}/decide", json={"approve": True, "expires_in_days": 30})
        run = await run_now(api, wf["id"], cid)
        rep = (await api.post(f"{API}/cases/{cid}/reports", json={"format": "html"})).json()
        b = (await api.post(f"{API}/backups", json={"passphrase": "a-long-passphrase"})).json()
        assert (await api.post(f"{API}/backups/restore", json={"file": b["file"], "target_name": "restore1", "passphrase": "a-long-passphrase", "confirm": True})).status_code == 200
        await api.aclose()
    restored = s.data_dir / "restores" / "restore1"
    assert all(secret.encode() not in p.read_bytes() for p in restored.rglob("*") if p.is_file() and p.stat().st_size < 5_000_000)
    s2 = Settings(data_dir=restored, vault_encryption="off", db_encryption="off", run_scheduler=False)
    app2 = create_app(s2, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns), init_db=True)
    async with app2.router.lifespan_context(app2):
        api2 = await client_for(app2, s2)
        w2 = (await api2.get(f"{B}/workflows/{wf['id']}")).json()
        assert w2["name"] == wf["name"] and w2["versions"][0]["hash"] == v["hash"] and w2["latest_revision"] == 1
        assert [x["status"] for x in (await api2.get(f"{B}/approvals", params={"workflow_id": wf["id"]})).json()["items"]] == ["approved"]
        runs = (await api2.get(f"{B}/runs")).json()
        assert runs["total"] == 1 and runs["items"][0]["id"] == run["id"]
        assert (await api2.get(f"{API}/reports/{rep['id']}")).status_code == 200
        await api2.aclose()


_ = (Case, SearchRun, Target, pytest)


# =============================================================================================== live finding: optional sources and baselines
async def test_a_tool_that_is_simply_not_installed_does_not_block_baselines_but_a_new_tool_rebaselines(settings, calls):
    state = {"installed": False}

    async def script(t, c, n):
        return result(t, ["a", "b"], "extra")

    class Toggle(FakeAdapter):
        async def health(self):
            return {"status": "healthy" if state["installed"] else "not_installed", "detail": "install it"}
    app = app_with(settings, calls, FakeAdapter("fakesrc", script=lambda t, c, n: asyncio.sleep(0, result=result(t, ["x", "y"]))), Toggle("extra", script=script))
    async with app.router.lifespan_context(app):
        api = await serve(app, settings)
        cid = await mk_case(api)
        d = wf_def([SCOPE, q("a", "fakesrc"), q("b", "extra", optional=True), node("m", "transform", ["a", "b"], ref="$nodes.a.output", extra_refs=["$nodes.b.output"], op="merge"),
                    node("diff", "snapshot_diff", ["m"], dataset_ref="$nodes.m.output")])
        wf = await new_wf(api, d, cid)
        await publish(api, wf["id"])
        r1 = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
        r2 = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
        o = lambda r, n: next(x for x in r["nodes"] if x["node"] == n)["output"]
        assert r1["state"] == "completed_with_warnings" and o(r1, "m")["partial"] is False and o(r1, "diff")["baseline"] is True
        assert o(r2, "diff")["baseline"] is False and o(r2, "diff")["changed"] is False              # the missing optional tool did not keep it from ever getting a baseline
        state["installed"] = True
        from osintcc.copilot import context as cx
        cx._HEALTH.clear()
        r3 = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
        assert o(r3, "diff").get("sources_changed") is True and o(r3, "diff")["changed"] is False       # new tool: no false 'everything is new' alarm
        assert any("set of sources changed" in w for w in r3["summary"]["warnings"])
        r4 = await run_detail(api, (await run_now(api, wf["id"], cid))["id"])
        assert o(r4, "diff")["baseline"] is False and o(r4, "diff")["changed"] is False
        await api.aclose()
