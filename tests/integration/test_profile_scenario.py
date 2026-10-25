"""TP-26: an end-to-end synthetic consented-client scenario (create, verify consent, collect, review, remediate, export, revoke) and the backup/restore round trip.
Everything is synthetic: example.com, a fake Sherlock executable and mocked HTTP. Nothing touches a real person or the real network."""
from __future__ import annotations

import sys

import httpx
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.adapters.cli import SherlockAdapter
from osintcc.config import Settings
from osintcc.db.models import AutomationWorkflow
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from profile_helpers import soon, stored_evidence

B = "/api/v1"


def fake_sherlock(tmp_path) -> str:
    py = tmp_path / "sherlock.py"
    py.write_text("import sys\nif '--version' in sys.argv:\n    print('1.0.0')\nelse:\n    print('[+] GitHub: https://github.com/client_jc')\n    print('[+] Forum: https://forum.test/u/client_jc')\n")
    w = tmp_path / ("sherlock.cmd" if sys.platform == "win32" else "sherlock")
    w.write_text(f'@echo off\r\n"{sys.executable}" "{py}" %*\r\n' if sys.platform == "win32" else f'#!/bin/sh\nexec "{sys.executable}" "{py}" "$@"\n')
    w.chmod(0o755)
    return str(w)


async def serve(app, s):
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {s.session_token}"})
    c.app = app
    return c


async def test_tp26_consented_client_scenario_end_to_end_then_backup_and_restore(tmp_path, calls):
    s = Settings(data_dir=tmp_path / "live", vault_encryption="off", db_encryption="off", run_scheduler=False, retry_scale=0.001)
    s.ensure_dirs()
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        api = await serve(app, s)
        st = app.state.core
        st.adapters["sherlock"] = SherlockAdapter(binary_path=fake_sherlock(tmp_path))

        # ---- 1. create the engagement
        cid = (await api.post(f"{B}/cases", json={"title": "Client J. Citizen", "category": "people", "purpose": "privacy exposure assessment requested by the client"})).json()["id"]
        sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "J. Citizen", "mode": "client"})).json()["id"]
        user_id = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "username", "value": "client_jc"})).json()["id"]
        dom_id = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "domain", "value": "example.com"})).json()["id"]
        mail_id = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "email", "value": "jc@example.com"})).json()["id"]
        # nothing can be collected yet
        pv = (await api.post(f"{B}/subjects/{sid}/research/preview", json={})).json()
        assert all(not e["runnable"] for e in pv["entries"])

        # ---- 2. verify consent: a self-attestation is refused, the signed engagement is accepted
        consent_body = {"verifier": "Engagement manager", "source_classes": ["public_passive", "public_site_query", "exposure_check"], "permitted_purposes": ["privacy exposure assessment"],
                        "expires_at": soon(60), "identifier_ids": [user_id, dom_id, mail_id]}
        r = await api.post(f"{B}/subjects/{sid}/consent", json={**consent_body, "verification_method": "self_attestation"})
        assert r.status_code == 422 and r.json()["code"] == "proof_required"
        proof = stored_evidence(st, cid, b"SIGNED ENGAGEMENT: J. Citizen authorises the listed checks until the stated date.", "signed engagement")
        r = await api.post(f"{B}/subjects/{sid}/consent", json={**consent_body, "verification_method": "signed_document", "proof_evidence_id": proof})
        assert r.status_code == 201, r.text
        consent_id = (await api.get(f"{B}/subjects/{sid}/consent")).json()["current"]["consent_id"]

        # ---- 3. collect: an approved bounded plan, public-site tool explicitly confirmed
        keys = [f"{dom_id}:rdap", f"{dom_id}:dns", f"{user_id}:sherlock"]
        r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": keys, "wait": True})
        assert r.status_code == 422 and r.json()["code"] == "confirmation_required"
        r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": keys, "confirmed_sources": ["sherlock"], "wait": True})
        assert r.status_code == 202, r.text
        tasks = {t["source_id"]: t["status"] for t in (await api.get(f"{B}/subjects/{sid}/research/runs")).json()["items"]}
        assert tasks == {"rdap": "completed", "dns": "completed", "sherlock": "completed"}

        # ---- 4. review: leads are decided by a person; the client's confirmation is recorded as an attestation
        leads = (await api.get(f"{B}/subjects/{sid}/candidates")).json()["items"]
        assert {c["canonical_url"] for c in leads} == {"https://github.com/client_jc", "https://forum.test/u/client_jc"} and all(c["state"] == "candidate" for c in leads)
        gh = next(c for c in leads if "github" in c["canonical_url"])
        forum = next(c for c in leads if "forum" in c["canonical_url"])
        assert (await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": [gh["id"]], "state": "confirmed", "basis": "same handle"})).status_code == 422
        r = await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": [gh["id"]], "state": "confirmed", "basis": "client confirmed by email on call 2026-02-01", "attestation": "subject"})
        assert r.status_code == 200
        assert (await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": [forum["id"]], "state": "rejected", "basis": "client says this is a different person"})).status_code == 200
        employer_ev = stored_evidence(st, cid, b"<html>J. Citizen, Senior Engineer, Example Ltd</html>", "company bio")
        c = (await api.post(f"{B}/subjects/{sid}/claims", json={"field": "employer", "value": "Example Ltd", "evidence_ids": [employer_ev]})).json()
        assert (await api.post(f"{B}/subjects/{sid}/claims/{c['id']}/verify", json={"state": "verified", "basis": "company staff page", "evidence_ids": [employer_ev]})).status_code == 200

        # ---- 5. exposure and remediation
        x = (await api.post(f"{B}/subjects/{sid}/exposure", json={"cls": "breach_account", "provider": "manual", "status": "confirmed_exposure", "risk": "medium", "verification_basis": "provider_notice",
                                                                  "descriptor": "Breach: ExampleService (2022); data types: email addresses, usernames"})).json()
        t = (await api.post(f"{B}/subjects/{sid}/remediations", json={"issue": "Reused password after the breach", "indicator_id": x["id"], "priority": "high", "due_in_days": 7})).json()
        retest = stored_evidence(st, cid, b"retest 2026-02-08: new unique password, MFA on", "retest note")
        assert (await api.patch(f"{B}/subjects/{sid}/remediations/{t['id']}", json={"state": "resolved", "resolution_evidence_id": retest})).status_code == 200
        assert (await api.get(f"{B}/subjects/{sid}/exposure")).json()["items"][0]["remediation_state"] == "resolved"

        # ---- 6. export the redacted client report; the citation check passes
        rep = await api.post(f"{B}/subjects/{sid}/report/create", json={"audience": "subject", "format": "markdown"})
        assert rep.status_code == 201 and rep.json()["citation_check"]["ok"]
        text = (await api.get(f"{B}/reports/{rep.json()['id']}/download")).text
        assert "Example Ltd (verified)" in text and "https://github.com/client_jc" in text and "forum.test" not in text and "jc@example.com" not in text and "ExampleService" not in text
        assert "resolved" in text

        # ---- 7. a bound scheduled workflow, then revoke: everything stops at once
        tpl = next(t_["slug"] for t_ in (await api.get(f"{B}/subjects/{sid}/templates")).json()["items"] if t_["key"] == "TP-09")
        wf = (await api.post(f"{B}/subjects/{sid}/workflows", json={"slug": tpl, "inputs": {"username": "client_jc"}})).json()
        with st.sm() as db:
            w = db.get(AutomationWorkflow, wf["id"])
            w.state, w.active_version_id = "active", "v-active"
            db.commit()
        n_calls = len(calls)
        r = await api.post(f"{B}/subjects/{sid}/consent/revoke", json={"consent_id": consent_id, "reason": "client withdrew consent"})
        assert r.status_code == 200 and r.json()["status"]["status"] == "revoked"
        with st.sm() as db:
            w = db.get(AutomationWorkflow, wf["id"])
            assert w.state != "active" and w.active_version_id is None
        r = await api.post(f"{B}/subjects/{sid}/research/approve", json={"keys": [f"{dom_id}:rdap"], "wait": True})
        assert r.status_code == 403 and r.json()["code"] == "consent_revoked" and len(calls) == n_calls
        prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
        assert prof["authorization"]["status"] == "revoked" and "Authorization is not current" in prof["next_action"]
        timeline = (await api.get(f"{B}/subjects/{sid}/timeline")).json()["items"]
        assert any("Authorization revoked" in e["text"] for e in timeline) and any(e["kind"] == "review" for e in timeline)

        # ---- 8. encrypted backup and restore keep the whole profile
        b = (await api.post(f"{B}/backups", json={"passphrase": "a-long-passphrase-for-tests"})).json()
        raw = (s.backup_dir / b["file"]).read_bytes()
        assert b"client_jc" not in raw and b"J. Citizen" not in raw and b"Example Ltd" not in raw          # the backup file is encrypted
        assert (await api.post(f"{B}/backups/restore", json={"file": b["file"], "target_name": "restore1", "passphrase": "a-long-passphrase-for-tests", "confirm": True})).status_code == 200
        await api.aclose()
    restored = s.data_dir / "restores" / "restore1"
    s2 = Settings(data_dir=restored, vault_encryption="off", db_encryption="off", run_scheduler=False)
    app2 = create_app(s2, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns), init_db=True)
    async with app2.router.lifespan_context(app2):
        api2 = await serve(app2, s2)
        subs = (await api2.get(f"{B}/cases/{cid}/subjects")).json()
        assert subs["total"] == 1 and subs["items"][0]["id"] == sid and subs["items"][0]["mode"] == "client"
        prof2 = (await api2.get(f"{B}/subjects/{sid}/profile")).json()
        assert prof2["authorization"]["status"] == "revoked" and prof2["counts"]["verified"] == 1
        cand = {c["canonical_url"]: c["state"] for c in (await api2.get(f"{B}/subjects/{sid}/candidates")).json()["items"]}
        assert cand == {"https://github.com/client_jc": "confirmed", "https://forum.test/u/client_jc": "rejected"}
        hist = (await api2.get(f"{B}/subjects/{sid}/review-history")).json()["items"]
        assert {h["to"] for h in hist} >= {"confirmed", "rejected", "verified"} and all(h["reviewer"] for h in hist)
        assert (await api2.get(f"{B}/subjects/{sid}/exposure")).json()["items"][0]["remediation_state"] == "resolved"
        assert len((await api2.get(f"{B}/subjects/{sid}/reports")).json()["items"]) == 1
        cov = (await api2.get(f"{B}/subjects/{sid}/coverage")).json()
        assert cov["completed_tasks"] == 3
        await api2.aclose()

