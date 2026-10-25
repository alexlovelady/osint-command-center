"""Exposure, remediation, corrections, retention (TP5). Acceptance: TP-15 (no secrets can be stored), TP-16 (password check keeps the password and full hash
out of logs, storage and the network), TP-19 (role redaction), plus provider fail-closed behaviour. Provider calls use a mocked transport and are NOT live-verified."""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import AuditEvent, CaseMember, ImageAsset, RetentionAction, Subject, User
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from osintcc.profile import exposure
from sqlalchemy import inspect, text

B = "/api/v1"
SHA1_PASSWORD = hashlib.sha1(b"password").hexdigest().upper()           # 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
PREFIX, SUFFIX = SHA1_PASSWORD[:5], SHA1_PASSWORD[5:]


@pytest.fixture
def provider():
    return {"hibp_key": "test-key", "hibp_status": 200, "hibp_body": [{"Name": "ExampleService", "BreachDate": "2023-05-01", "DataClasses": ["Email addresses", "Passwords"],
                                                                         "Description": "<p>long html that must not be stored</p>", "PwnCount": 123}], "seen": []}


@pytest.fixture
async def api(settings, calls, provider):
    base = make_handler(calls)

    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        provider["seen"].append((u, dict(request.headers)))
        if u.startswith("https://api.pwnedpasswords.com/range/"):
            return httpx.Response(200, text=f"{SUFFIX}:3861493\r\n0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n")
        if u.startswith("https://haveibeenpwned.com/api/v3/breachedaccount/"):
            return httpx.Response(provider["hibp_status"], json=provider["hibp_body"] if provider["hibp_status"] == 200 else None)
        return base(request)

    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(handler))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns, secret=lambda n: provider["hibp_key"] if n == "hibp" else None))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


async def setup(api, classes=("exposure_check",), method="email_confirmation", mode="self"):
    cid = (await api.post(f"{B}/cases", json={"title": "Jane", "category": "people", "purpose": "self audit"})).json()["id"]
    sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Jane Example", "mode": mode})).json()["id"]
    if classes:
        r = await api.post(f"{B}/subjects/{sid}/consent", json={"verification_method": method, "verifier": "Jane", "source_classes": list(classes), "permitted_purposes": ["audit"],
                                                                "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat()})
        assert r.status_code == 201, r.text
    iid = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "email", "value": "jane.doe@example.com"})).json()["id"]
    return cid, sid, iid


GOOD = {"cls": "breach_account", "provider": "manual", "status": "confirmed_exposure", "risk": "high", "verification_basis": "provider_notice",
        "descriptor": "Breach: ExampleService (2023-05); data types: email addresses, passwords"}


# ---- TP-15 -----------------------------------------------------------------------------------------------------------------------------
async def test_tp15_fields_for_secrets_do_not_exist_and_extra_fields_are_refused(api):
    _cid, sid, _iid = await setup(api)
    for extra in ({"password": "hunter2"}, {"ssn": "123-45-6789"}, {"token": "abc"}, {"raw_dump": "a@b.c:pw"}, {"password_hash": "5baa61e4"}, {"national_id": "X"}):
        r = await api.post(f"{B}/subjects/{sid}/exposure", json={**GOOD, **extra})
        assert r.status_code == 422 and r.json()["code"] == "validation_error", extra
    st = api.app.state.core
    cols = {c["name"].lower() for t in ("exposure_indicators", "remediation_tasks", "subjects", "subject_identifiers", "image_assets", "subject_consents")
            for c in inspect(st.sm.kw["bind"]).get_columns(t)}
    assert not [c for c in cols if any(w in c for w in ("password", "passwd", "secret", "ssn", "token", "hash_of_pass", "national", "dump", "cookie", "session"))], cols
    with st.sm() as db:
        assert db.execute(text("SELECT count(*) FROM exposure_indicators")).scalar() == 0


@pytest.mark.parametrize("bad", [
    "password: hunter2", "pwd=Sup3rSecret!", "SSN 123-45-6789", "123456789012345678", "card 4111 1111 1111 1111",
    "hash 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefgh", "Authorization: Bearer abcdef0123456789abcdef",
    "key " + "AK" + "IAABCDEFGHIJKLMNOP", "-----BEGIN RSA PRIVATE KEY-----", "jane.doe@example.com", "jane.doe@example.com:Winter2024!", "https://user:pw12@site.test/",
    "session QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OQ12", "x" * 201,
])
async def test_tp15_secret_shaped_descriptors_are_rejected(api, bad):
    _cid, sid, _iid = await setup(api)
    r = await api.post(f"{B}/subjects/{sid}/exposure", json={**GOOD, "descriptor": bad[:200] if len(bad) <= 200 else bad})
    assert r.status_code == 422, (bad, r.text)
    assert r.json()["code"] in ("secret_rejected", "unmasked_identifier", "validation_error", "descriptor_too_long")
    assert (await api.get(f"{B}/subjects/{sid}/exposure")).json()["total"] == 0


@pytest.mark.parametrize("ok", [
    "Breach: ExampleService (2023-05); data types: email addresses, passwords",
    "Listing on example-people-search.test; opt-out submitted 2026-01-02",
    "Account j***@example.com appears in a 2021 breach (usernames, emails)",
    "Photo geotags disclose a precise home location",
])
async def test_tp15_category_descriptions_are_accepted(api, ok):
    _cid, sid, _iid = await setup(api)
    r = await api.post(f"{B}/subjects/{sid}/exposure", json={**GOOD, "descriptor": ok})
    assert r.status_code == 201, (ok, r.text)


def test_unit_validate_descriptor_never_stores_what_it_rejects():
    with pytest.raises(Exception) as e:
        exposure.validate_descriptor("password: hunter2")
    assert "hunter2" not in str(e.value)                       # the rejection message does not echo the secret


async def test_three_states_stay_distinct_and_risk_rules_hold(api):
    _cid, sid, _iid = await setup(api)
    na = (await api.post(f"{B}/subjects/{sid}/exposure", json={"cls": "breach_account", "status": "not_assessed", "verification_basis": "manual_review", "descriptor": "Not checked yet"})).json()
    nf = (await api.post(f"{B}/subjects/{sid}/exposure", json={"cls": "breach_account", "status": "not_found_in_checked_sources", "verification_basis": "manual_review",
                                                                "descriptor": "Checked one provider"})).json()
    ce = (await api.post(f"{B}/subjects/{sid}/exposure", json=GOOD)).json()
    assert {na["status_label"], nf["status_label"], ce["status_label"]} == {"not assessed", "not found in checked sources", "confirmed exposure"}
    assert "does not show the subject was never exposed" in nf["caveat"] and na["caveat"] == ""
    r = await api.post(f"{B}/subjects/{sid}/exposure", json={**GOOD, "risk": "unknown"})
    assert r.status_code == 422 and r.json()["code"] == "risk_required"
    r = await api.post(f"{B}/subjects/{sid}/exposure", json={**GOOD, "status": "not_found_in_checked_sources", "risk": "high"})
    assert r.status_code == 422 and r.json()["code"] == "risk_not_applicable"
    prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
    assert prof["risk_summary"] == {"confirmed_exposures": 1, "highest_risk": "high", "not_assessed": 1}


async def test_exposure_checks_need_strong_authorization_for_the_mode(api):
    _cid, sid, _iid = await setup(api, classes=("public_passive",), method="self_attestation")
    r = await api.post(f"{B}/subjects/{sid}/exposure", json=GOOD)
    assert r.status_code == 403 and r.json()["code"] == "out_of_scope"
    r = await api.post(f"{B}/subjects/{sid}/consent", json={"verification_method": "self_attestation", "verifier": "me", "source_classes": ["exposure_check"],
                                                            "permitted_purposes": [], "expires_at": (datetime.now(UTC) + timedelta(days=3)).isoformat()})
    assert r.status_code == 422 and r.json()["code"] == "verification_too_weak"
    _cid2, sid2, _ = await setup(api, classes=())
    r = await api.post(f"{B}/subjects/{sid2}/exposure", json=GOOD)
    assert r.status_code == 403 and r.json()["code"] == "consent_required"


# ---- TP-16 -----------------------------------------------------------------------------------------------------------------------------
async def test_tp16_password_check_sees_only_a_five_character_prefix_and_stores_nothing(api, provider, caplog):
    _cid, sid, _iid = await setup(api)
    caplog.set_level(logging.DEBUG)
    for bad in (SHA1_PASSWORD, "password", "ZZZZZ", "5BAA", "5BAA61", ""):
        r = await api.post(f"{B}/subjects/{sid}/exposure/password-range", json={"prefix": bad})
        assert r.status_code == 422, bad                               # a full hash or password is never accepted
    ok = await api.post(f"{B}/subjects/{sid}/exposure/password-range", json={"prefix": PREFIX.lower()})
    assert ok.status_code == 200
    assert f"{SUFFIX}:3861493" in ok.json()["suffixes"] and ok.json()["padded"] is True and "never sees the password" in ok.json()["note"]
    sent = [(u, h) for u, h in provider["seen"] if "pwnedpasswords" in u]
    assert [u for u, _ in sent] == [f"https://api.pwnedpasswords.com/range/{PREFIX}"] and sent[0][1].get("add-padding") == "true"
    assert all(SUFFIX not in u and SHA1_PASSWORD not in u.upper() for u, _ in provider["seen"])
    # nothing about the request was persisted or logged
    st = api.app.state.core
    raw = sqlite3.connect(":memory:")
    with st.sm() as db:
        dump = "\n".join(str(r) for t in inspect(db.get_bind()).get_table_names() for r in db.execute(text(f'SELECT * FROM "{t}"')).all())
        events = db.query(AuditEvent).filter(AuditEvent.action == "exposure.password_check").count()
    raw.close()
    assert events == 1 and PREFIX not in dump.upper().replace("-", "") and SUFFIX not in dump.upper()
    assert PREFIX not in caplog.text.upper() and SUFFIX not in caplog.text.upper() and "hunter" not in caplog.text


async def test_tp16_password_check_requires_authorization_and_fails_visibly(api, provider):
    _cid, sid, _iid = await setup(api, classes=("public_passive",), method="self_attestation")
    assert (await api.post(f"{B}/subjects/{sid}/exposure/password-range", json={"prefix": PREFIX})).status_code == 403
    assert not [u for u, _ in provider["seen"] if "pwnedpasswords" in u]


# ---- provider account check (mocked transport; not live-verified) -----------------------------------------------------------------------------
async def test_account_check_previews_the_exact_data_sent_and_needs_confirmation(api, provider):
    _cid, sid, iid = await setup(api)
    pv = (await api.post(f"{B}/subjects/{sid}/exposure/preview", json={"identifier_id": iid})).json()
    assert pv["will_send"]["data"] == "jane.doe@example.com" and pv["maturity"] == "mocked_only" and "paid API key" in pv["cost"] and pv["allowed"]
    assert "No passwords or leaked records are requested" in pv["will_store"]
    assert not [u for u, _ in provider["seen"] if "haveibeenpwned" in u]                    # preview sent nothing
    r = await api.post(f"{B}/subjects/{sid}/exposure/approve", json={"identifier_id": iid})
    assert r.status_code == 422 and r.json()["code"] == "confirmation_required"
    assert not [u for u, _ in provider["seen"] if "haveibeenpwned" in u]


async def test_account_check_records_only_names_dates_and_categories(api, provider):
    cid, sid, iid = await setup(api)
    r = await api.post(f"{B}/subjects/{sid}/exposure/approve", json={"identifier_id": iid, "confirm": True})
    assert r.status_code == 200 and r.json()["status"] == "confirmed_exposure" and r.json()["created"] == 1
    req = next((u, h) for u, h in provider["seen"] if "haveibeenpwned" in u)
    assert req[1].get("hibp-api-key") == "test-key" and "jane.doe%40example.com" in req[0]
    items = (await api.get(f"{B}/subjects/{sid}/exposure")).json()["items"]
    assert len(items) == 1 and items[0]["status"] == "confirmed_exposure" and items[0]["risk"] in ("high", "medium")
    assert "ExampleService" in items[0]["descriptor"] and "long html" not in json.dumps(items)
    ev = [e for e in (await api.get(f"{B}/cases/{cid}/evidence")).json()["items"] if e["kind"] == "exposure.provider_response"]
    assert len(ev) == 1
    with api.app.state.core.sm() as db:
        body = db.execute(text("SELECT description FROM evidence WHERE kind='exposure.provider_response'")).scalar()
    assert "Description" not in body and "PwnCount" not in body


async def test_account_check_fails_closed_when_the_provider_cannot_answer(api, provider):
    _cid, sid, iid = await setup(api)
    provider["hibp_key"] = None
    r = (await api.post(f"{B}/subjects/{sid}/exposure/approve", json={"identifier_id": iid, "confirm": True})).json()
    assert r["status"] == "requires_key" and r["created"] == 0 and not [u for u, _ in provider["seen"] if "haveibeenpwned" in u]
    provider["hibp_key"] = "k"
    for code, expect in ((404, "not_found_in_checked_sources"), (401, "requires_key"), (429, "rate_limited"), (503, "error")):
        provider["hibp_status"] = code
        out = (await api.post(f"{B}/subjects/{sid}/exposure/approve", json={"identifier_id": iid, "confirm": True})).json()
        assert out["status"] == expect, (code, out)
        if code != 404:
            assert out["created"] == 0 and "not" in out["message"].lower()                    # no record, and no claim of a negative finding
    items = (await api.get(f"{B}/subjects/{sid}/exposure")).json()["items"]
    assert [i["status"] for i in items] == ["not_found_in_checked_sources"]
    nf = items[0]
    assert "Not found by this provider" not in nf["descriptor"] and "No breach found by this provider for the checked address" == nf["descriptor"]


async def test_account_check_refuses_non_email_identifiers_and_missing_authorization(api):
    _cid, sid, _iid = await setup(api)
    u = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "username", "value": "jane_e"})).json()["id"]
    assert (await api.post(f"{B}/subjects/{sid}/exposure/preview", json={"identifier_id": u})).status_code == 422
    _cid2, sid2, iid2 = await setup(api, classes=())
    pv = (await api.post(f"{B}/subjects/{sid2}/exposure/preview", json={"identifier_id": iid2})).json()
    assert pv["allowed"] is False
    assert (await api.post(f"{B}/subjects/{sid2}/exposure/approve", json={"identifier_id": iid2, "confirm": True})).status_code == 403


# ---- TP-19 -----------------------------------------------------------------------------------------------------------------------------
async def test_tp19_only_owners_and_editors_see_exposure_summaries(api):
    cid, sid, _iid = await setup(api)
    await api.post(f"{B}/subjects/{sid}/exposure", json=GOOD)
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="v1", display_name="viewer"))
        db.add(User(id="ed", display_name="editor"))
        db.flush()
        db.add(CaseMember(case_id=cid, user_id="v1", access_role="viewer"))
        db.add(CaseMember(case_id=cid, user_id="ed", access_role="editor"))
        db.commit()
    st.tokens["viewer-token"], st.tokens["editor-token"] = "v1", "ed"
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer viewer-token"})
    e = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer editor-token"})
    vj = (await v.get(f"{B}/subjects/{sid}/exposure")).json()
    assert vj["redacted"] is True and set(vj["items"][0]) == {"id", "class", "class_label", "redacted"}
    ej = (await e.get(f"{B}/subjects/{sid}/exposure")).json()
    assert ej["redacted"] is False and ej["items"][0]["status"] == "confirmed_exposure" and "ExampleService" in ej["items"][0]["descriptor"]
    vp = (await v.get(f"{B}/subjects/{sid}/profile")).json()
    assert vp["risk_summary"]["redacted"] is True and all(x.get("redacted") for x in vp["exposure"]) and vp["remediation"] == []
    assert (await v.post(f"{B}/subjects/{sid}/exposure", json=GOOD)).status_code == 404
    assert (await v.post(f"{B}/subjects/{sid}/exposure/password-range", json={"prefix": PREFIX})).status_code == 404


# ---- remediation -----------------------------------------------------------------------------------------------------------------------
async def test_remediation_uses_class_guidance_and_needs_evidence_to_resolve(api):
    cid, sid, _iid = await setup(api)
    x = (await api.post(f"{B}/subjects/{sid}/exposure", json=GOOD)).json()
    t = (await api.post(f"{B}/subjects/{sid}/remediations", json={"issue": "Breach exposure", "indicator_id": x["id"], "priority": "high", "due_in_days": 7})).json()
    assert "multi-factor" in t["guidance"].lower() and "password" in t["guidance"].lower() and t["state"] == "open" and t["due_at"]
    r = await api.patch(f"{B}/subjects/{sid}/remediations/{t['id']}", json={"state": "resolved"})
    assert r.status_code == 422 and r.json()["code"] == "resolution_evidence_required"
    ev = (await api.post(f"{B}/cases/{cid}/notes", json={"body_markdown": "Changed the password and enabled MFA; retested on 2026-02-01"})).status_code
    assert ev == 201
    with api.app.state.core.sm() as db:
        from osintcc.db.models import Evidence
        h = hashlib.sha256(b"retest").hexdigest()
        e = Evidence(case_id=cid, kind="note", title="retest screenshot", sha256=h, sha512=h * 2, byte_size=1)
        db.add(e)
        db.commit()
        eid = e.id
    r = await api.patch(f"{B}/subjects/{sid}/remediations/{t['id']}", json={"state": "resolved", "resolution_evidence_id": eid})
    assert r.status_code == 200 and r.json()["state"] == "resolved"
    items = (await api.get(f"{B}/subjects/{sid}/exposure")).json()["items"]
    assert items[0]["remediation_state"] == "resolved"
    bad = await api.patch(f"{B}/subjects/{sid}/remediations/{t['id']}", json={"state": "done"})
    assert bad.status_code == 422


# ---- corrections --------------------------------------------------------------------------------------------------------------------
async def test_correction_requests_are_recorded_audited_and_applied_through_normal_paths(api):
    _cid, sid, _iid = await setup(api)
    claim = (await api.post(f"{B}/subjects/{sid}/claims", json={"field": "employer", "value": "Wrong Corp"})).json()
    c = (await api.post(f"{B}/subjects/{sid}/corrections", json={"target_type": "claim", "target_id": claim["id"], "request": "I never worked there", "requested_by": "Jane (subject)"})).json()
    assert c["status"] == "open" and c["audit_seq"]
    r = await api.post(f"{B}/subjects/{sid}/corrections/{c['id']}/resolve", json={"decision": "applied", "resolution": "Marked as conflicting pending new evidence"})
    assert r.status_code == 200 and r.json()["status"] == "applied"
    prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
    work = next(s for s in prof["sections"] if s["key"] == "work")
    assert work["claims"][0]["state"] == "conflicting"
    c2 = (await api.post(f"{B}/subjects/{sid}/corrections", json={"target_type": "other", "request": "Please delete everything"})).json()
    r = await api.post(f"{B}/subjects/{sid}/corrections/{c2['id']}/resolve", json={"decision": "applied", "resolution": "x"})
    assert r.status_code == 422 and r.json()["code"] == "cannot_apply"
    r = await api.post(f"{B}/subjects/{sid}/corrections/{c2['id']}/resolve", json={"decision": "declined", "resolution": "Use the retention purge instead"})
    assert r.json()["status"] == "declined"
    assert len((await api.get(f"{B}/subjects/{sid}/corrections")).json()["items"]) == 2


# ---- retention -------------------------------------------------------------------------------------------------------------------------
async def test_purge_preview_then_purge_removes_profile_data_but_keeps_the_audit_trail(api):
    import io

    import numpy as np
    from PIL import Image
    cid, sid, _iid = await setup(api, classes=("exposure_check", "image_analysis"))
    other_sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Someone else"})).json()["id"]
    await api.post(f"{B}/subjects/{sid}/claims", json={"field": "employer", "value": "Acme"})
    await api.post(f"{B}/subjects/{sid}/exposure", json=GOOD)
    img = Image.fromarray((np.random.default_rng(3).random((12, 16)) * 255).astype("uint8")).resize((320, 240)).convert("RGB")
    b = io.BytesIO()
    img.save(b, "PNG")
    up = await api.post(f"{B}/subjects/{sid}/images", params={"filename": "me.png", "confirm_rights": "true"}, content=b.getvalue())
    assert up.status_code == 201
    st = api.app.state.core
    with st.sm() as db:
        rel = db.execute(text("SELECT vault_relpath FROM evidence WHERE kind='import.image'")).scalar()
    assert (st.vault.root / rel).is_file()
    pv = (await api.get(f"{B}/subjects/{sid}/retention/preview")).json()
    assert pv["will_delete"]["claims"] == 1 and pv["will_delete"]["images"] == 1 and pv["will_delete"]["exposure_indicators"] == 1 and pv["irreversible"] is True
    assert pv["confirm_with"] == "PURGE Jane Example" and any("audit log" in k for k in pv["kept"])
    r = await api.post(f"{B}/subjects/{sid}/retention/purge", json={"confirm": "purge jane"})
    assert r.status_code == 422 and r.json()["code"] == "confirmation_required"
    assert (await api.get(f"{B}/subjects/{sid}/profile")).json()["counts"]["claims"] == 1       # nothing happened
    r = await api.post(f"{B}/subjects/{sid}/retention/purge", json={"confirm": pv["confirm_with"]})
    assert r.status_code == 200 and r.json()["purged"]["images"] == 1 and r.json()["vault_objects_removed"] == 1
    assert not (st.vault.root / rel).exists()
    with st.sm() as db:
        s = db.get(Subject, sid)
        assert s.status == "purged" and s.display_name == "[purged]"
        for t in ("subject_identifiers", "profile_claims", "exposure_indicators", "image_assets", "subject_consents"):
            assert db.execute(text(f"SELECT count(*) FROM {t} WHERE subject_id=:s"), {"s": sid}).scalar() == 0, t
        assert db.execute(text("SELECT title, redacted, vault_relpath FROM evidence WHERE kind='import.image'")).one() == ("[purged]", 1, None)
        assert db.query(AuditEvent).filter(AuditEvent.action == "retention.purge").count() == 1 and db.query(ImageAsset).count() == 0
        assert db.query(RetentionAction).filter(RetentionAction.subject_id == sid, RetentionAction.action == "purge").count() == 1
        assert db.get(Subject, other_sid).status == "active"
    assert (await api.post(f"{B}/subjects/{sid}/research/preview", json={})).json()["entries"] == []     # a purged subject has nothing left to research
    from osintcc.telemetry import audit
    with st.sm() as db:
        assert audit.verify_chain(db)[0] is True


async def test_expired_retention_is_listed_never_deleted_automatically(api):
    _cid, sid, _iid = await setup(api)
    await api.patch(f"{B}/subjects/{sid}", json={"retention_days": 1})
    with api.app.state.core.sm() as db:
        db.get(Subject, sid).created_at = datetime.now(UTC) - timedelta(days=3)
        db.commit()
    due = (await api.get(f"{B}/profile/retention/due")).json()["items"]
    assert [d["subject_id"] for d in due] == [sid] and due[0]["display_name"] == "Jane Example"
    assert (await api.get(f"{B}/subjects/{sid}")).json()["status"] == "active"
