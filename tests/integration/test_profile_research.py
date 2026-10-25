"""Target profile TP3: consent-gated research planning, bounded approval, coverage honesty, fail-closed revocation/expiry/recovery.

Acceptance: TP-03, TP-04 (mode differences), TP-08, TP-17 (API side), TP-23, TP-25 (availability states)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import AutomationWorkflow, Job, ResearchTask, SearchRun, Subject, SubjectConsent
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from osintcc.profile import consent, research
from sqlalchemy import select

B = "/api/v1"


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


def soon(days=30) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


async def setup_subject(api, mode="self", domain="example.com", username=None):
    cid = (await api.post(f"{B}/cases", json={"title": "Jane", "category": "people", "purpose": "self audit"})).json()["id"]
    sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Jane Example", "mode": mode})).json()["id"]
    ids = {}
    if domain:
        ids["domain"] = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "domain", "value": domain})).json()["id"]
    if username:
        ids["username"] = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "username", "value": username})).json()["id"]
    return cid, sid, ids


async def grant(api, sid, classes=("public_passive",), method="self_attestation", days=30, **extra):
    return await api.post(f"{B}/subjects/{sid}/consent", json={"verification_method": method, "verifier": "Jane (subject)", "source_classes": list(classes),
                                                               "permitted_purposes": ["self audit"], "expires_at": soon(days), **extra})


def runs_count(api) -> int:
    with api.app.state.core.sm() as db:
        return db.query(SearchRun).count()


# ---- TP-03: nothing runs on preview, or without live authorization -------------------------------------------------------------------------
async def test_tp03_preview_sends_nothing_and_creates_nothing(api, calls):
    _cid, sid, _ids = await setup_subject(api)
    await grant(api, sid)
    pv = (await api.post(f"{B}/subjects/{sid}/research/preview", json={})).json()
    keys = {e["source_id"]: e for e in pv["entries"]}
    assert {"rdap", "dns", "crtsh", "wayback"} <= set(keys) and keys["rdap"]["runnable"] and keys["rdap"]["consent"]["allowed"]
    assert pv["stop_rules"] and pv["budget"]["max_per_approval"] == 40 and "Nothing has been sent" in pv["note"]
    assert calls == [] and runs_count(api) == 0
    with api.app.state.core.sm() as db:
        assert db.query(ResearchTask).count() == 0


async def test_tp03_no_authorization_means_no_run(api, calls):
    _cid, sid, ids = await setup_subject(api)
    pv = (await api.post(f"{B}/subjects/{sid}/research/preview", json={})).json()
    assert all(not e["runnable"] and "authorization" in e["reason"] for e in pv["entries"])
    r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [f"{ids['domain']}:rdap"], "wait": True})
    assert r.status_code == 403 and r.json()["code"] == "consent_required"
    assert calls == [] and runs_count(api) == 0


async def test_tp03_expired_and_revoked_authorization_block_collection(api, calls):
    _cid, sid, ids = await setup_subject(api)
    g = (await grant(api, sid)).json()
    with api.app.state.core.sm() as db:                      # let it lapse
        c = db.get(SubjectConsent, g["id"])
        c.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
    r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [f"{ids['domain']}:rdap"], "wait": True})
    assert r.status_code == 403 and r.json()["code"] == "consent_expired"
    prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
    assert prof["authorization"]["status"] == "expired" and prof["next_action"] == "Authorization is not current: renew it to resume collection."
    g2 = (await grant(api, sid)).json()
    assert (await api.post(f"{B}/subjects/{sid}/consent/revoke", json={"consent_id": g2["id"], "reason": "changed my mind"})).status_code == 200
    r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [f"{ids['domain']}:rdap"], "wait": True})
    assert r.status_code == 403 and r.json()["code"] == "consent_revoked"
    assert calls == [] and runs_count(api) == 0


async def test_authorization_scope_class_and_identifier_are_enforced(api):
    _cid, sid, ids = await setup_subject(api, username="jane_e")
    await grant(api, sid, classes=("public_passive",))
    pv = {e["source_id"]: e for e in (await api.post(f"{B}/subjects/{sid}/research/preview", json={})).json()["entries"]}
    assert pv["rdap"]["runnable"] and not pv["sherlock"]["runnable"] and "no live authorization covers" in pv["sherlock"]["reason"]
    await grant(api, sid, classes=("public_passive",), identifier_ids=[ids["username"]])        # scoped to the username only
    # the older, broader grant still covers the domain; scope narrowing never removes another live grant
    pv = {e["source_id"]: e for e in (await api.post(f"{B}/subjects/{sid}/research/preview", json={})).json()["entries"]}
    assert pv["rdap"]["runnable"]


# ---- TP-04: self and client modes ---------------------------------------------------------------------------------------------------------
async def test_tp04_modes_require_different_proof_but_share_the_common_protections(api):
    _, sid_self, _ids_self = await setup_subject(api, mode="self")
    assert (await grant(api, sid_self, classes=("public_passive",))).status_code == 201                       # self-attestation is fine for public checks
    r = await grant(api, sid_self, classes=("exposure_check",))
    assert r.status_code == 422 and r.json()["code"] == "verification_too_weak"                                 # but not for exposure checks
    assert (await grant(api, sid_self, classes=("exposure_check",), method="email_confirmation")).status_code == 201
    cid, sid_c, ids_c = await setup_subject(api, mode="client")
    r = await grant(api, sid_c, classes=("public_passive",))
    assert r.status_code == 422 and r.json()["code"] == "proof_required"                                        # client: no self-attestation
    r = await grant(api, sid_c, classes=("public_passive",), method="signed_document")
    assert r.status_code == 422 and r.json()["code"] == "proof_required"                                        # client: proof evidence attached
    with api.app.state.core.sm() as db:
        import hashlib
        import uuid

        from osintcc.db.models import Evidence
        h = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        ev = Evidence(case_id=cid, kind="document", title="signed engagement", sha256=h, sha512=h * 2, byte_size=1)
        db.add(ev)
        db.commit()
        proof = ev.id
    r = await grant(api, sid_c, classes=("public_passive",), method="signed_document", proof_evidence_id=proof)
    assert r.status_code == 422 and r.json()["code"] == "scope_required"                                        # client: must name the identities covered
    r = await grant(api, sid_c, classes=("public_passive",), method="signed_document", proof_evidence_id=proof, identifier_ids=[ids_c["domain"]], days=400)
    assert r.status_code == 422 and r.json()["code"] == "duration_too_long"                                     # time-limited
    r = await grant(api, sid_c, classes=("public_passive",), method="signed_document", proof_evidence_id=proof, identifier_ids=[ids_c["domain"]])
    assert r.status_code == 201
    pv = {e["source_id"]: e for e in (await api.post(f"{B}/subjects/{sid_c}/research/preview", json={})).json()["entries"]}
    assert pv["rdap"]["runnable"]
    # common protections: a private/internal target is refused in both modes whatever the consent says
    _, sid_p, _ids_p = await setup_subject(api, mode="self", domain=None)
    await grant(api, sid_p, classes=("public_passive",))
    bad = await api.post(f"{B}/subjects/{sid_p}/identifiers", json={"kind": "domain", "value": "printer.local"})
    pv = (await api.post(f"{B}/subjects/{sid_p}/research/preview", json={})).json()
    assert bad.status_code == 201 and all(not e["runnable"] and "local/internal" in e["reason"] for e in pv["entries"])


async def test_only_an_owner_can_authorize_and_an_editor_can_revoke(api):
    from osintcc.db.models import CaseMember, User
    cid, sid, _ = await setup_subject(api)
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="ed", display_name="editor"))
        db.flush()
        db.add(CaseMember(case_id=cid, user_id="ed", access_role="editor"))
        db.commit()
    st.tokens["editor-token"] = "ed"
    ed = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer editor-token"})
    r = await ed.post(f"{B}/subjects/{sid}/consent", json={"verification_method": "self_attestation", "verifier": "x", "source_classes": ["public_passive"],
                                                           "permitted_purposes": [], "expires_at": soon()})
    assert r.status_code == 404                                       # insufficient role looks like a missing resource
    g = (await grant(api, sid)).json()
    assert (await ed.post(f"{B}/subjects/{sid}/consent/revoke", json={"consent_id": g["id"]})).status_code == 200


# ---- approve -> run -> coverage ---------------------------------------------------------------------------------------------------------
async def test_approved_research_runs_through_the_normal_pipeline_and_updates_coverage(api, calls):
    _cid, sid, ids = await setup_subject(api, username="jane_e")
    await grant(api, sid, classes=("public_passive",))
    r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [f"{ids['domain']}:rdap", f"{ids['domain']}:dns"], "wait": True})
    assert r.status_code == 202 and len(r.json()["run_ids"]) == 1
    assert any("rdap" in c for c in calls)
    runs = (await api.get(f"{B}/subjects/{sid}/research/runs")).json()["items"]
    assert {t["source_id"]: t["status"] for t in runs} == {"rdap": "completed", "dns": "completed"} and all(t["result_count"] > 0 for t in runs)
    cov = (await api.get(f"{B}/subjects/{sid}/coverage")).json()
    cells = {c["source_id"]: c for cat in cov["categories"] for c in cat["cells"]}
    assert cells["rdap"]["status"] == "completed" and cells["crtsh"]["status"] == "not_run"
    assert cells["sherlock"]["status"] == "unavailable" and "not installed" in cells["sherlock"]["detail"]      # the tool is absent here: not 'not_run'
    assert cells["sec_edgar"]["status"] == "unsupported" and "needs a" in cells["sec_edgar"]["detail"]
    assert cells["manual_exposure"]["status"] == "not_run" and "manual" in cells["manual_exposure"]["detail"]
    assert cov["approved_tasks"] == 2 and cov["completed_tasks"] == 2
    assert "not a measure of how much information exists" in cov["label"]
    assert cov["next_action"]
    prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
    assert prof["last_collected"]


async def test_tp08_failures_and_outdated_checks_are_labelled_not_hidden(api, settings):
    _cid, sid, ids = await setup_subject(api)
    await grant(api, sid, classes=("public_passive",))
    await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [f"{ids['domain']}:rdap"], "wait": True})
    with api.app.state.core.sm() as db:
        t = db.scalars(select(ResearchTask)).first()
        t.last_success = datetime.now(UTC) - timedelta(days=45)
        db.commit()
    cov = (await api.get(f"{B}/subjects/{sid}/coverage")).json()
    cells = {c["source_id"]: c for cat in cov["categories"] for c in cat["cells"]}
    assert cells["rdap"]["status"] == "outdated"
    with api.app.state.core.sm() as db:                       # a job that failed upstream
        job = db.scalars(select(Job)).first()
        job.status, job.last_error_code = "failed", "http_503"
        t = db.scalars(select(ResearchTask)).first()
        t.status = "approved"
        db.commit()
    cells = {c["source_id"]: c for cat in (await api.get(f"{B}/subjects/{sid}/coverage")).json()["categories"] for c in cat["cells"]}
    assert cells["rdap"]["status"] == "failed"


async def test_confirmation_budget_and_unknown_pairs(api):
    _cid, sid, ids = await setup_subject(api, username="jane_e")
    await grant(api, sid, classes=("public_passive", "public_site_query"))
    r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [f"{ids['domain']}:nonsense"], "wait": True})
    assert r.status_code == 422 and r.json()["code"] == "unknown_selection"
    r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [f"x{i}:rdap" for i in range(41)]})
    assert r.status_code == 422                                          # more than the work budget
    pv = {e["source_id"]: e for e in (await api.post(f"{B}/subjects/{sid}/research/preview", json={})).json()["entries"]}
    assert pv["sherlock"]["health"] == "not_installed" and not pv["sherlock"]["runnable"]      # an absent tool cannot be selected


# ---- TP-17 / TP-23: fail closed at execution, after revocation and after a crash ----------------------------------------------------------
async def test_tp17_revocation_cancels_pending_tasks_and_queued_jobs_never_start(api, calls):
    cid, sid, ids = await setup_subject(api)
    g = (await grant(api, sid)).json()
    st = api.app.state.core
    with st.sm() as db:
        s = db.get(Subject, sid)
        case = db.get(__import__("osintcc.db.models", fromlist=["Case"]).Case, cid)
        runs = research.approve(db, s, case, st.adapters, st.settings, keys=[f"{ids['domain']}:rdap", f"{ids['domain']}:dns"], confirmed_sources=[], actor="u")
        db.commit()
        run_id = runs[0].id
    assert calls == []                                                   # approved, queued, not started
    r = await api.post(f"{B}/subjects/{sid}/consent/revoke", json={"consent_id": g["id"], "reason": "stop"})
    assert r.json()["cancelled_tasks"] == 2
    await st.runner.run_until_idle(run_id)
    with st.sm() as db:
        jobs = db.scalars(select(Job).where(Job.run_id == run_id)).all()
        assert {j.status for j in jobs} == {"denied"} and {j.last_error_code for j in jobs} == {"authorization_revoked"}
        assert {t.status for t in db.scalars(select(ResearchTask))} == {"cancelled"}
    assert calls == []


async def test_tp23_crash_recovery_requeues_only_work_that_is_still_authorized(api, calls):
    cid, sid, ids = await setup_subject(api)
    g = (await grant(api, sid)).json()
    st = api.app.state.core
    with st.sm() as db:
        s = db.get(Subject, sid)
        case = db.get(__import__("osintcc.db.models", fromlist=["Case"]).Case, cid)
        run = research.approve(db, s, case, st.adapters, st.settings, keys=[f"{ids['domain']}:rdap"], confirmed_sources=[], actor="u")[0]
        job = db.scalars(select(Job).where(Job.run_id == run.id)).first()
        job.status = "running"                                           # the process died mid-job
        db.commit()
        run_id = run.id
    with st.sm() as db:                                                  # authorization expired while the app was down
        db.get(SubjectConsent, g["id"]).expires_at = datetime.now(UTC) - timedelta(seconds=5)
        db.commit()
    st.runner.recover_interrupted()
    await st.runner.run_until_idle(run_id)
    with st.sm() as db:
        assert db.scalars(select(Job).where(Job.run_id == run_id)).first().status == "denied"
    assert calls == []                                                   # no surprise network call


async def test_expiry_sweep_cancels_pending_work_without_a_request(api):
    cid, sid, ids = await setup_subject(api)
    g = (await grant(api, sid)).json()
    st = api.app.state.core
    with st.sm() as db:
        s = db.get(Subject, sid)
        case = db.get(__import__("osintcc.db.models", fromlist=["Case"]).Case, cid)
        research.approve(db, s, case, st.adapters, st.settings, keys=[f"{ids['domain']}:rdap"], confirmed_sources=[], actor="u")
        db.get(SubjectConsent, g["id"]).expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    with st.sm() as db:
        assert consent.sweep_expired(db) == 1
        db.commit()
        assert {t.status for t in db.scalars(select(ResearchTask))} == {"cancelled"}


# ---- subject-bound automations + templates (TP-17, TP-25) ---------------------------------------------------------------------------------
async def test_tp25_target_profile_templates_are_listed_with_honest_availability(api):
    _cid, sid, _ids = await setup_subject(api)
    items = {t["key"]: t for t in (await api.get(f"{B}/subjects/{sid}/templates")).json()["items"]}
    assert sorted(items) == [f"TP-{i:02d}" for i in range(1, 14)]
    assert items["TP-01"]["availability"]["state"] == "setup_required"                      # sherlock is not installed in tests
    assert items["TP-03"]["availability"]["state"] == "ready"
    assert items["TP-07"]["availability"]["state"] == "partial" and items["TP-07"]["capability_gaps"]
    assert all(t["installed_disabled"] for t in items.values()) and all(t["maturity"] in ("fixture_tested", "runtime_tested") for t in items.values())


async def test_tp25_every_template_dry_runs_when_bound_to_a_subject(api):
    cid, sid, _ids = await setup_subject(api)
    for i in range(1, 14):
        key = f"tp-{i:02d}"
        slug = next(t["slug"] for t in (await api.get(f"{B}/subjects/{sid}/templates")).json()["items"] if t["key"] == f"TP-{i:02d}")
        wf = await api.post(f"{B}/subjects/{sid}/workflows", json={"slug": slug})
        assert wf.status_code == 201, (key, wf.text)
        dry = (await api.post(f"{B}/automations/workflows/{wf.json()['id']}/dry-run", json={"case_id": cid})).json()
        assert dry["run"]["simulated"] is True and dry["run"]["state"] in ("completed", "completed_with_warnings"), (key, dry["run"])


async def test_bound_workflow_stops_when_authorization_is_revoked_or_missing(api):
    from osintcc.automations import permissions
    from osintcc.automations.registry import NodeError
    cid, sid, _ids = await setup_subject(api, username="jane_e")
    slug = next(t["slug"] for t in (await api.get(f"{B}/subjects/{sid}/templates")).json()["items"] if t["key"] == "TP-09")
    wf = (await api.post(f"{B}/subjects/{sid}/workflows", json={"slug": slug, "inputs": {"username": "jane_e"}})).json()
    assert f"subject:{sid}" in wf["definition"]["tags"] if "definition" in wf else True
    st = api.app.state.core
    with st.sm() as db:
        w = db.get(AutomationWorkflow, wf["id"])
        case = db.get(__import__("osintcc.db.models", fromlist=["Case"]).Case, cid)
        with pytest.raises(NodeError) as e:                                   # no authorization yet
            permissions.run_gate(db, w, "v1", "manual", "passive_only", case)
        assert e.value.code == "SCOPE_DENIED" and "authorization" in str(e.value).lower()
    g = (await grant(api, sid, classes=("public_site_query",))).json()
    with st.sm() as db:
        w = db.get(AutomationWorkflow, wf["id"])
        w.state, w.active_version_id = "active", "v-any"                      # pretend it was activated
        db.commit()
    r = await api.post(f"{B}/subjects/{sid}/consent/revoke", json={"consent_id": g["id"]})
    assert r.status_code == 200
    with st.sm() as db:
        w = db.get(AutomationWorkflow, wf["id"])
        assert w.state != "active" and w.active_version_id is None             # the schedule was switched off by the revocation


async def test_profile_sources_matrix_is_honest(api):
    items = {r["id"]: r for r in (await api.get(f"{B}/profile/sources")).json()["items"]}
    assert items["sherlock"]["maturity"] == "live_tested" and items["sherlock"]["consent_class"] == "public_site_query"
    assert items["opencorporates"]["maturity"] == "mocked_only" and items["opencorporates"]["needs_key"] == "opencorporates"
    assert items["manual_exposure"]["privacy"] == "personal_sensitive" and items["manual_exposure"]["registered"] is True
    assert "hibp" not in items                                              # no unverified provider is advertised
