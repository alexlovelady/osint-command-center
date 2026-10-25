"""DARKINT (addendum v1.1 section 14): provider states, consent gate, checks, events, coverage, reviews, monitors, privacy.

Provider answers come from fixtures through a mock transport: nothing here reaches a real service, so every provider is `fixture_tested`, never live-verified.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.darkint import providers as prov
from osintcc.darkint import sanitize
from osintcc.db.models import AuditEvent, ExposureCheck, ExposureEvent, ExposureMonitorConfig, ExposureReview
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import func, select

B = "/api/v1"
HIBP_ROWS = [{"Name": "ExampleForum", "Title": "Example Forum", "BreachDate": "2021-03-14", "DataClasses": ["Email addresses", "Passwords", "Usernames"], "Description": "<p>must not be stored</p>"}]
RWL_ROWS = [{"victim": "Example Holdings", "group": "examplegroup", "attackdate": "2026-02-03", "country": "US", "description": "claimed"}]


def soon(days: int = 30) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


@pytest.fixture
def world():
    return {"hibp_key": "k-test", "hibp_status": 200, "hibp_rows": HIBP_ROWS, "domain_status": 200, "domain_body": {"alice": ["ExampleForum"], "bob": ["ExampleForum"]},
            "rwl_status": 200, "rwl_rows": RWL_ROWS, "seen": []}


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch):
    monkeypatch.setattr(prov, "PACING_SCALE", 0.0)                       # the pacing itself is tested separately


@pytest.fixture(autouse=True)
def _no_real_keyring(monkeypatch):
    from osintcc.secrets_store import SecretStore

    class KR:
        def get_password(self, s, u):
            return None

        def set_password(self, s, u, p):
            return None

        def delete_password(self, s, u):
            return None
    monkeypatch.setattr(SecretStore, "_keyring", staticmethod(lambda: KR()))


@pytest.fixture
async def api(settings, calls, world):
    base = make_handler(calls)

    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        world["seen"].append(u)
        if u.startswith("https://haveibeenpwned.com/api/v3/breachedaccount/"):
            return httpx.Response(world["hibp_status"], json=world["hibp_rows"] if world["hibp_status"] == 200 else {})
        if u.startswith("https://haveibeenpwned.com/api/v3/breacheddomain/"):
            return httpx.Response(world["domain_status"], json=world["domain_body"] if world["domain_status"] == 200 else {})
        if u.startswith("https://api.ransomware.live/v2/searchvictims/"):
            return httpx.Response(world["rwl_status"], json=world["rwl_rows"] if world["rwl_status"] == 200 else [])
        if u.startswith("https://api.pwnedpasswords.com/range/"):
            return httpx.Response(200, text="0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n")
        return base(request)

    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(handler))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns, secret=lambda n: world["hibp_key"] if n == "hibp" else None))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            c.app = app
            yield c


async def enable(api, pid="hibp"):
    r = await api.put(f"{B}/darkint/sources/{pid}", json={"enabled": True, "acknowledge_terms": True})
    assert r.status_code == 200, r.text
    return r.json()


async def person(api, *, classes=("exposure_check",), providers=None, mode="self", kinds=("email",)):
    cid = (await api.post(f"{B}/cases", json={"title": "Jane", "category": "people", "purpose": "self audit"})).json()["id"]
    sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Jane Example", "mode": mode})).json()["id"]
    body = {"verification_method": "email_confirmation", "verifier": "Jane", "source_classes": list(classes), "permitted_purposes": ["self audit"], "expires_at": soon()}
    if providers:
        body["providers"] = providers
    cons = None
    if classes:
        r = await api.post(f"{B}/subjects/{sid}/consent", json=body)
        assert r.status_code == 201, r.text
        cons = r.json()["id"]
    ids = {}
    vals = {"email": "jane.doe@example.com", "domain": "example.com", "organization": "Example Holdings"}
    for k in kinds:
        ids[k] = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": k, "value": vals[k]})).json()["id"]
    return {"cid": cid, "sid": sid, "ids": ids, "consent": cons}


def body_for(p, kind, providers, **kw):
    return {"subject_id": p["sid"], "identifier_ids": [p["ids"][kind]], "provider_ids": providers, **kw}


async def check(api, p, kind, providers, **kw):
    r = await api.post(f"{B}/cases/{p['cid']}/darkint/check", json={**body_for(p, kind, providers, **kw), "confirm": True})
    assert r.status_code == 200, r.text
    return r.json()


# ---- 1. honest provider states, no unapproved traffic -----------------------------------------------------------------------------------------
async def test_providers_report_one_honest_state_and_nothing_is_called_until_enabled(api, world):
    j = (await api.get(f"{B}/darkint/sources")).json()
    by = {s["provider_id"]: s for s in j["items"]}
    assert by["hibp"]["state"] == "disabled" and by["ransomware_live"]["state"] == "disabled"
    assert by["intelligence_x"]["state"] == "manual_only" and by["intelligence_x"]["verification"] == "not_implemented"
    assert by["misp"]["state"] == "manual_only" and by["manual"]["state"] == "manual_only"
    for s in by.values():
        for k in ("provider_id", "licence", "terms_url", "authentication", "scope_policy", "source_type", "cost_tier", "quota", "coverage_limitations", "last_verified"):
            assert k in s
        assert s["last_verified"] is None                                    # never invented: nothing was exercised against a live service
    assert "personal use" in by["ransomware_live"]["terms_note"]
    p = await person(api)
    r = await api.post(f"{B}/cases/{p['cid']}/darkint/preview", json=body_for(p, "email", ["hibp"]))
    assert r.status_code == 200 and r.json()["items"][0]["allowed"] is False and "Not enabled" in r.json()["items"][0]["reason"]
    out = await check(api, p, "email", ["hibp"])
    assert out["all_failed"] and out["results"][0]["outcome"] == "blocked" and not world["seen"]


async def test_enabling_needs_admin_terms_and_an_automated_integration(api):
    assert (await api.put(f"{B}/darkint/sources/hibp", json={"enabled": True})).json()["code"] == "terms_required"
    assert (await api.put(f"{B}/darkint/sources/intelligence_x", json={"enabled": True, "acknowledge_terms": True})).json()["code"] == "unsupported"
    assert (await api.put(f"{B}/darkint/sources/nope", json={"enabled": True, "acknowledge_terms": True})).status_code == 404
    hb = await enable(api)
    assert hb["state"] == "live" and hb["terms_acknowledged_at"] and hb["verification"] == "fixture_tested"


async def test_a_missing_key_is_credential_missing_and_not_a_negative_result(api, world):
    await enable(api)
    world["hibp_key"] = None
    p = await person(api)
    out = await check(api, p, "email", ["hibp"])
    assert out["results"][0]["outcome"] == "credential_missing" and out["results"][0]["code"] == "CREDENTIAL_MISSING" and not world["seen"]
    cov = (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()["coverage"]["items"][0]
    assert cov["state"] == "not_checked" and cov["label"] == "Not checked"


# ---- 2/3. consent and domain control -------------------------------------------------------------------------------------------------------
async def test_no_consent_a_weak_consent_a_provider_outside_the_scope_and_revocation_all_block(api, world):
    await enable(api)
    none = await person(api, classes=())
    r = await api.post(f"{B}/cases/{none['cid']}/darkint/preview", json=body_for(none, "email", ["hibp"]))
    assert r.json()["items"][0]["allowed"] is False and "consent" in r.json()["items"][0]["reason"]
    scoped = await person(api, providers=["ransomware_live"], kinds=("email", "organization"))
    r = await api.post(f"{B}/cases/{scoped['cid']}/darkint/preview", json=body_for(scoped, "email", ["hibp"]))
    assert r.json()["items"][0]["allowed"] is False and "does not permit" in r.json()["items"][0]["reason"]
    ok = await person(api)
    assert (await check(api, ok, "email", ["hibp"]))["results"][0]["outcome"] == "match"
    n = len(world["seen"])
    assert (await api.post(f"{B}/subjects/{ok['sid']}/consent/revoke", json={"consent_id": ok["consent"], "reason": "withdrawn"})).status_code == 200
    out = await check(api, ok, "email", ["hibp"])
    assert out["results"][0]["outcome"] == "blocked" and len(world["seen"]) == n                    # revocation stops the next lookup before any request


async def test_domain_wide_lookup_needs_the_provider_domain_verification_attestation(api, world):
    await enable(api)
    p = await person(api, kinds=("domain",), mode="organization")
    pv = (await api.post(f"{B}/cases/{p['cid']}/darkint/preview", json=body_for(p, "domain", ["hibp"]))).json()["items"][0]
    assert pv["allowed"] is False and "verified with the provider" in pv["reason"]
    assert (await check(api, p, "domain", ["hibp"]))["results"][0]["outcome"] == "blocked" and not world["seen"]
    out = await check(api, p, "domain", ["hibp"], domain_control_attested=True)
    assert out["results"][0]["outcome"] == "match" and any("breacheddomain" in u for u in world["seen"])
    exp = (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()
    txt = json.dumps(exp)
    assert "alice" not in txt and "bob" not in txt and "2 address(es)" in txt                         # the personal part of each address is counted and dropped
    world["domain_status"] = 403
    assert (await check(api, p, "domain", ["hibp"], domain_control_attested=True))["results"][0]["outcome"] == "unsupported"


# ---- 4/5. nothing sensitive is kept ------------------------------------------------------------------------------------------------------
def test_sanitizer_redacts_secret_shaped_values_and_masks_addresses():
    dirty = "leak of jane.doe@example.com password: hunter2 ssn 123-45-6789 card 4111 1111 1111 1111 hash 5f4dcc3b5aa765d61d8327deb882cf99 token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
    clean, red = sanitize.sanitize_text(dirty, 400)
    assert red and "hunter2" not in clean and "123-45-6789" not in clean and "4111" not in clean and "5f4dcc3b" not in clean and "eyJ" not in clean and "jane.doe@" not in clean
    assert sanitize.categorize(["Passwords", "Email addresses", "Weird things"]) == ["credential indicator", "email addresses", "other"]


async def test_manual_intake_and_imports_redact_and_never_keep_the_upload(api, settings):
    p = await person(api)
    r = await api.post(f"{B}/cases/{p['cid']}/darkint/manual", json={"subject_id": p["sid"], "identifier_id": p["ids"]["email"], "title": "Paste with password: hunter2 and jane.doe@example.com",
                                                                       "event_type": "paste", "categories": ["Passwords"], "source_url": "https://news.example.org/story"})
    assert r.status_code == 201 and r.json()["redacted"] is True and "hunter2" not in json.dumps(r.json()) and "jane.doe@" not in json.dumps(r.json())
    csv_text = "title,date,categories,reference\nBreach at ExampleCo 123-45-6789,2024-01-02,Passwords;Email addresses,https://example.org/n\nx,,,\n"
    imp = await api.post(f"{B}/cases/{p['cid']}/darkint/import", json={"subject_id": p["sid"], "kind": "csv", "content": csv_text})
    assert imp.status_code == 200 and imp.json()["created"] == 1 and imp.json()["skipped"] == 1 and imp.json()["redacted"] == 1 and len(imp.json()["upload_sha256"]) == 64
    misp = {"response": [{"Event": {"info": "Phish kit targeting Example", "date": "2025-05-05", "uuid": "11111111-2222-3333-4444-555555555555", "Tag": [{"name": "tlp:amber"}],
                                    "Attribute": [{"type": "password", "value": "hunter2"}]}}]}
    m = await api.post(f"{B}/cases/{p['cid']}/darkint/import", json={"subject_id": p["sid"], "kind": "misp", "content": json.dumps(misp)})
    assert m.status_code == 200 and m.json()["created"] == 1
    dump = json.dumps((await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json())
    assert "hunter2" not in dump and "123-45-6789" not in dump and "tlp:amber" in dump
    assert not list(settings.vault_dir.rglob("*hunter2*"))
    bad = await api.post(f"{B}/cases/{p['cid']}/darkint/manual", json={"subject_id": p["sid"], "title": "x y z", "password": "hunter2"})
    assert bad.status_code == 422                                                                  # unknown fields (password, hash, ssn, token) are refused outright


async def test_password_range_check_keeps_no_password_or_hash_material(api, settings):
    p = await person(api)
    n_audit = None
    r = await api.post(f"{B}/subjects/{p['sid']}/exposure/password-range", json={"prefix": "5BAA6"})
    assert r.status_code == 200 and r.json()["suffixes"]
    st = api.app.state.core
    with st.sm() as db:
        dump = json.dumps([e.metadata_json for e in db.scalars(select(AuditEvent))], default=str)
        n_audit = db.scalar(select(func.count()).select_from(AuditEvent))
    assert "5BAA6" not in dump.upper() and n_audit
    assert (await api.post(f"{B}/subjects/{p['sid']}/exposure/password-range", json={"prefix": "5BAA61E4C9"})).status_code == 422       # a full hash is refused


# ---- 6/7/8. grouping, claims, coverage -----------------------------------------------------------------------------------------------------
async def test_duplicate_reports_group_but_every_original_and_its_provenance_stay(api, world):
    await enable(api)
    p = await person(api)
    await check(api, p, "email", ["hibp"])
    await api.post(f"{B}/cases/{p['cid']}/darkint/manual", json={"subject_id": p["sid"], "identifier_id": p["ids"]["email"], "title": "Example Forum data leak", "event_type": "breach",
                                                                   "categories": ["Email addresses"], "source_url": "https://news.example.org/forum"})
    again = await check(api, p, "email", ["hibp"])
    assert again["results"][0]["new_events"] == 0                                                 # the same report is not stored twice
    j = (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()
    assert len(j["groups"]) == 1 and j["groups"][0]["corroborated"] and sorted(j["groups"][0]["sources"]) == ["hibp", "manual"] and len(j["groups"][0]["events"]) == 2
    assert {e["provider_ref"] for e in j["groups"][0]["events"]} >= {"https://news.example.org/forum"}
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(ExposureEvent)) == 2


async def test_a_ransomware_listing_is_an_unverified_claim_and_says_so(api, world):
    await enable(api, "ransomware_live")
    p = await person(api, kinds=("organization",), mode="organization")
    out = await check(api, p, "organization", ["ransomware_live"])
    assert out["results"][0]["outcome"] == "match"
    g = (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()["groups"][0]["events"][0]
    assert g["claim_label"] == "reported, not independently verified" and "not proof of compromise" in g["caveat"] and "unverified claim by the actor" in g["title"] and g["confidence"] == "low"
    rep = (await api.post(f"{B}/cases/{p['cid']}/darkint/reports/preview", json={"subject_id": p["sid"]})).json()
    assert "not independent proof of compromise" in rep["markdown"] and rep["exports_nothing"] is True


async def test_not_checked_unknown_no_match_and_match_are_four_different_states(api, world):
    await enable(api)
    await enable(api, "ransomware_live")
    p = await person(api, kinds=("email", "organization"))
    async def state():
        return {c["kind"]: c for c in (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()["coverage"]["items"]}
    s0 = await state()
    assert s0["email"]["state"] == "not_checked" and s0["email"]["label"] == "Not checked" and "not the same as no exposure" in s0["email"]["meaning"]
    world["hibp_status"] = 500
    await check(api, p, "email", ["hibp"])
    assert (await state())["email"]["state"] == "unknown"                                          # attempted, nothing learned
    world["hibp_status"] = 404
    await check(api, p, "email", ["hibp"])
    s2 = (await state())["email"]
    assert s2["state"] == "no_match_checked_sources" and s2["label"] == "No match from checked sources"
    assert s2["checked_sources"][0]["provider"] == "Have I Been Pwned" and s2["checked_sources"][0]["checked_at"] and "never exposed" in s2["meaning"]
    world["hibp_status"] = 200
    await check(api, p, "email", ["hibp"])
    assert (await state())["email"]["state"] == "match_reported"
    assert "no universal" in (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()["coverage"]["notice"].lower()


# ---- 10. outages, limits, offline: truthful partial failures, no fallback ----------------------------------------------------------------------
async def test_outage_rate_limit_and_offline_are_reported_as_such_with_partial_accounting(api, world, settings):
    await enable(api)
    await enable(api, "ransomware_live")
    p = await person(api, kinds=("email", "organization"))
    both = {"subject_id": p["sid"], "identifier_ids": list(p["ids"].values()), "provider_ids": ["hibp", "ransomware_live"], "confirm": True}
    world["hibp_status"] = 429
    r = (await api.post(f"{B}/cases/{p['cid']}/darkint/check", json=both)).json()
    got = {(x["provider_id"], x["outcome"]) for x in r["results"]}
    assert ("hibp", "rate_limited") in got and ("ransomware_live", "match") in got and r["partial"] is True and not r["all_failed"]
    world["rwl_status"] = 503
    world["hibp_status"] = 503
    seen_before = list(world["seen"])
    r2 = (await api.post(f"{B}/cases/{p['cid']}/darkint/check", json=both)).json()
    pairs = {(x["provider_id"], x["identifier_id"]): x["outcome"] for x in r2["results"]}
    assert pairs[("hibp", p["ids"]["email"])] == "source_unavailable" and pairs[("ransomware_live", p["ids"]["organization"])] == "source_unavailable"
    assert pairs[("ransomware_live", p["ids"]["email"])] == "unsupported"
    assert all(u.startswith(("https://haveibeenpwned.com/", "https://api.ransomware.live/")) for u in world["seen"][len(seen_before):])       # no other host was tried as a fallback
    settings.offline = True
    off = (await api.post(f"{B}/cases/{p['cid']}/darkint/check", json=both)).json()
    n_online = len(world["seen"])
    off = (await api.post(f"{B}/cases/{p['cid']}/darkint/check", json=both)).json()
    assert {x["outcome"] for x in off["results"]} <= {"offline", "unsupported"} and "offline" in {x["outcome"] for x in off["results"]} and off["all_failed"] and len(world["seen"]) == n_online


# ---- 11. permissions, audit, retention -------------------------------------------------------------------------------------------------
async def test_other_users_and_viewers_cannot_use_or_see_another_cases_exposure_data(api, world):
    from osintcc.db.models import CaseMember, User
    await enable(api)
    p = await person(api)
    await check(api, p, "email", ["hibp"])
    st = api.app.state.core
    with st.sm() as db:
        db.add_all([User(id="v1", display_name="viewer"), User(id="x1", display_name="stranger")])
        db.flush()
        db.add(CaseMember(case_id=p["cid"], user_id="v1", access_role="viewer"))
        db.commit()
    st.tokens["viewer-token"], st.tokens["stranger-token"] = "v1", "x1"
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer viewer-token"})
    s = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer stranger-token"})
    for c in (v, s):
        assert (await c.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).status_code in (403, 404)
        assert (await c.post(f"{B}/cases/{p['cid']}/darkint/check", json={**body_for(p, "email", ["hibp"]), "confirm": True})).status_code in (403, 404)
        assert (await c.post(f"{B}/cases/{p['cid']}/darkint/reports/preview", json={"subject_id": p["sid"]})).status_code in (403, 404)
        d = (await c.get(f"{B}/darkint/dashboard")).json()
        assert d["items"] == []
    dash = (await api.get(f"{B}/darkint/dashboard")).json()
    assert len(dash["items"]) == 1 and dash["items"][0]["states"]["match_reported"] == 1 and "jane" not in json.dumps(dash["items"][0]["states"]).lower()


async def test_audit_records_every_lookup_without_identifier_values(api, world, caplog):
    caplog.set_level(logging.DEBUG)
    await enable(api)
    p = await person(api)
    await check(api, p, "email", ["hibp"])
    await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})
    st = api.app.state.core
    with st.sm() as db:
        acts = [e.action for e in db.scalars(select(AuditEvent))]
        meta = json.dumps([e.metadata_json for e in db.scalars(select(AuditEvent))], default=str)
    assert {"darkint.check", "darkint.view", "darkint.event"} <= set(acts)
    assert "jane.doe" not in meta and "jane.doe" not in caplog.text and "k-test" not in caplog.text and "k-test" not in meta


async def test_purging_the_subject_removes_events_checks_monitors_and_reviews(api, world):
    await enable(api)
    p = await person(api)
    await check(api, p, "email", ["hibp"])
    ev = (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()["groups"][0]["events"][0]
    assert (await api.patch(f"{B}/cases/{p['cid']}/darkint/exposures/{ev['id']}/review", json={"status": "acknowledged", "rationale": "seen"})).status_code == 200
    st = api.app.state.core
    with st.sm() as db:
        s = db.get(__import__("osintcc.db.models", fromlist=["Subject"]).Subject, p["sid"])
        name = s.display_name
    r = await api.post(f"{B}/subjects/{p['sid']}/retention/purge", json={"confirm": f"PURGE {name}"})
    assert r.status_code == 200, r.text
    with st.sm() as db:
        for m in (ExposureEvent, ExposureCheck, ExposureReview, ExposureMonitorConfig):
            assert db.scalar(select(func.count()).select_from(m)) == 0


# ---- reviews, remediation ------------------------------------------------------------------------------------------------------------------
async def test_review_needs_a_reason_not_relevant_removes_it_from_coverage_and_remediation_sends_nothing(api, world):
    await enable(api)
    p = await person(api)
    await check(api, p, "email", ["hibp"])
    j = (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()
    ev = j["groups"][0]["events"][0]
    assert "password_reset" in j["suggested"][ev["id"]] and "mfa" in j["suggested"][ev["id"]]
    assert (await api.patch(f"{B}/cases/{p['cid']}/darkint/exposures/{ev['id']}/review", json={"status": "relevant", "rationale": "x"})).status_code == 422
    rem = await api.post(f"{B}/cases/{p['cid']}/darkint/exposures/{ev['id']}/remediation", json={"action_type": "password_reset"})
    assert rem.status_code == 201 and rem.json()["sends_anything"] is False
    again = await api.post(f"{B}/cases/{p['cid']}/darkint/exposures/{ev['id']}/remediation", json={"action_type": "password_reset"})
    assert again.json()["id"] == rem.json()["id"]                                                  # one open task per action
    assert (await api.patch(f"{B}/cases/{p['cid']}/darkint/exposures/{ev['id']}/review", json={"status": "not_relevant", "rationale": "different person with the same address"})).status_code == 200
    cov = (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()["coverage"]["items"][0]
    assert cov["state"] == "no_match_checked_sources"                    # a reviewer dismissed the only report; the check itself completed


# ---- monitors ---------------------------------------------------------------------------------------------------------------------------
async def test_monitors_need_live_consent_stop_on_revocation_and_exclude_owner_only_checks(api, world):
    await enable(api)
    p = await person(api)
    mk = lambda **kw: api.post(f"{B}/cases/{p['cid']}/darkint/monitors", json={"subject_id": p["sid"], "name": "weekly", "identifier_ids": [p["ids"]["email"]], "provider_ids": ["hibp"],
                                                                               "cadence_hours": 168, "expires_at": soon(60), **kw})
    assert (await mk(provider_ids=["pwned_passwords"])).json()["code"] == "not_monitorable"
    assert (await mk(cadence_hours=1)).status_code == 422
    none = await person(api, classes=())
    r = await api.post(f"{B}/cases/{none['cid']}/darkint/monitors", json={"subject_id": none["sid"], "name": "m", "identifier_ids": [none["ids"]["email"]], "provider_ids": ["hibp"], "cadence_hours": 168, "expires_at": soon(10)})
    assert r.json()["code"] == "consent_required"
    m = (await mk()).json()
    assert m["enabled"] is False
    on = await api.patch(f"{B}/cases/{p['cid']}/darkint/monitors/{m['id']}", json={"enabled": True})
    assert on.status_code == 200 and on.json()["enabled"] is True
    assert (await api.post(f"{B}/subjects/{p['sid']}/consent/revoke", json={"consent_id": p["consent"], "reason": "withdrawn"})).status_code == 200
    mons = (await api.get(f"{B}/cases/{p['cid']}/darkint/monitors")).json()["items"]
    assert mons[0]["enabled"] is False and mons[0]["disabled_reason"]
    assert (await api.patch(f"{B}/cases/{p['cid']}/darkint/monitors/{m['id']}", json={"enabled": True})).json()["code"] == "consent_required"
    # the monitor's expiry never outlives the consent that backs it
    p2 = await person(api)
    m2 = (await api.post(f"{B}/cases/{p2['cid']}/darkint/monitors", json={"subject_id": p2["sid"], "name": "long", "identifier_ids": [p2["ids"]["email"]], "provider_ids": ["hibp"], "cadence_hours": 168, "expires_at": soon(300)})).json()
    assert datetime.fromisoformat(m2["expires_at"].replace("Z", "+00:00")) <= datetime.now(UTC) + timedelta(days=31)


# ---- mock mode, report -------------------------------------------------------------------------------------------------------------------
async def test_mock_mode_is_labelled_uses_synthetic_data_and_never_the_network(api, world):
    await api.put(f"{B}/darkint/mock-mode", json={"enabled": True})
    s = {x["provider_id"]: x for x in (await api.get(f"{B}/darkint/sources")).json()["items"]}
    assert s["hibp"]["state"] == "mocked" and s["ransomware_live"]["state"] == "mocked"
    p = await person(api)
    out = await check(api, p, "email", ["hibp"])
    assert out["mock"] is True and out["results"][0]["outcome"] == "match" and not world["seen"]


async def test_report_cites_evidence_names_sources_and_suggests_practical_steps_without_inventing_contents(api, world):
    await enable(api)
    p = await person(api)
    await check(api, p, "email", ["hibp"])
    ev = (await api.get(f"{B}/cases/{p['cid']}/darkint/exposures", params={"subject_id": p["sid"]})).json()["groups"][0]["events"][0]
    await api.post(f"{B}/cases/{p['cid']}/darkint/exposures/{ev['id']}/remediation", json={"action_type": "password_reset"})
    rep = (await api.post(f"{B}/cases/{p['cid']}/darkint/reports/preview", json={"subject_id": p["sid"]})).json()
    md = rep["markdown"]
    assert "Example Forum" in md and "Match reported" in md and "Change the password" not in md and "Password reset" in md and "not proof" in md
    assert rep["report"]["incidents"][0]["events"][0]["evidence_id"]
    assert "must not be stored" not in md and "jane.doe@" not in md
    made = await api.post(f"{B}/cases/{p['cid']}/darkint/reports", json={"subject_id": p["sid"], "format": "json"})
    assert made.status_code == 201
    dl = await api.get(f"{B}/reports/{made.json()['id']}/download")
    assert dl.status_code == 200 and json.loads(dl.content)["kind"] == "darkint_report"


def test_provider_parsers_keep_categories_only():
    out = prov._hibp_rows(HIBP_ROWS)
    assert out.outcome == "match" and out.events[0].categories == ["email addresses", "credential indicator", "usernames"] and "must not be stored" not in json.dumps([e.__dict__ for e in out.events], default=str)
    rw = prov._ransom_rows(RWL_ROWS + [{"victim": "Unrelated Inc", "group": "g"}], "example")
    assert len(rw.events) == 1 and rw.events[0].claim_status == "reported"


async def test_the_providers_documented_rate_limit_is_paced_locally_before_any_request(api, world, monkeypatch):
    monkeypatch.setattr(prov, "PACING_SCALE", 1.0)
    await enable(api, "ransomware_live")
    p = await person(api, kinds=("organization",), mode="organization")
    assert (await check(api, p, "organization", ["ransomware_live"]))["results"][0]["outcome"] == "match"
    n = len(world["seen"])
    second = (await check(api, p, "organization", ["ransomware_live"]))["results"][0]
    assert second["outcome"] == "rate_limited" and second["code"] == "RATE_LIMITED" and len(world["seen"]) == n
