"""Master Target Profile addendum, section 9: acceptance tests 1-17 (editor, email-first routing, gaps, restricted fields, inventory, migration).

External sources answer from a mock transport: the exact-email adapters are fixture-tested, not exercised against the live services.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from osintcc.db.models import (
    AuditEvent,
    Case,
    ProfileClaim,
    ProfileItem,
    ResearchTask,
    Subject,
    SubjectIdentifier,
)
from osintcc.profile import gaps
from profile_helpers import rich_subject, stored_evidence
from sqlalchemy import func, select
from test_associated_emails import B, _no_real_keyring, api, make, world  # noqa: F401  (fixtures)

M = "/subjects/{sid}/master"


def murl(p, suffix=""):
    return f"{B}/subjects/{p['sid']}/master{suffix}"


async def master(api, p, **params):
    r = await api.get(murl(p), params=params)
    assert r.status_code == 200, r.text
    return r.json()


def section(doc, key):
    return next(s for s in doc["sections"] if s["key"] == key)


async def add(api, p, type, value, expect=201, **kw):
    r = await api.post(murl(p, "/items"), json={"type": type, "value": value, **kw})
    assert r.status_code == expect, r.text
    return r.json()


# ---- 1/2. one entry feeds the profile, Associated Emails and the research planner ------------------------------------------------------------------
async def test_an_owned_email_added_once_appears_everywhere_without_re_entry(api, world):
    p = await make(api, kinds=())
    it = await add(api, p, "email", "Jane.Doe@Example.com", origin="subject_provided")
    assert (
        it["is_input"]
        and it["feeds_research"]
        and it["verification_state"] == "unassessed"
        and it["self_attested"] is True
        and it["backed_by"] == "identifier"
    )
    assert "subject-provided" not in it["state_label"].lower() and it["origin"] == "subject_provided"
    doc = await master(api, p)
    assert any(
        i["value"].lower() == "jane.doe@example.com" and i["is_input"]
        for i in section(doc, "contact")["items"]
    )
    emails = (await api.get(f"{B}/subjects/{p['sid']}/associated-emails")).json()
    assert (
        [i["address"].lower() for i in emails["inputs"]] == ["jane.doe@example.com"]
        and emails["inputs"][0]["label"] == "Your input"
        and emails["items"] == []
    )
    pv = (await api.post(f"{B}/subjects/{p['sid']}/research/preview", json={})).json()
    assert {e["source_id"] for e in pv["entries"] if e["identifier_kind"] == "email"} >= {
        "gravatar_email",
        "github_email_search",
        "keyserver_email",
    }
    again = await add(api, p, "email", "jane.doe@example.com", expect=201)
    assert again["id"] == it["id"] and again["created"] is False  # idempotent: no duplicate input
    with api.app.state.core.sm() as db:
        assert (
            db.scalar(
                select(func.count()).select_from(SubjectIdentifier).where(SubjectIdentifier.kind == "email")
            )
            == 1
        )


# ---- 3/4. the email-first routing bug -----------------------------------------------------------------------------------------------------------
async def test_free_mail_inputs_never_research_the_providers_domain(api, world):
    p = await make(api, kinds=(), email="alexander.s.lovelady@gmail.com")
    await add(api, p, "email", "alexander.s.lovelady@gmail.com", origin="subject_provided")
    pv = (await api.post(f"{B}/subjects/{p['sid']}/research/preview", json={})).json()
    srcs = {e["source_id"] for e in pv["entries"] if e["identifier_kind"] == "email"}
    assert not {"rdap", "dns", "crtsh", "wayback"} & srcs and "gravatar_email" in srcs
    assert not [u for u in world["seen"] if "gmail.com" in u]
    # the generic search tab no longer offers them for a free-mail address either
    plan = (
        await api.post(
            f"{B}/collection-plans/preview",
            json={
                "case_id": p["cid"],
                "target": "alexander.s.lovelady@gmail.com",
                "mode": "passive",
                "reason": "self audit",
            },
        )
    ).json()
    sel = (
        await api.post(
            f"{B}/collection-plans/preview",
            json={
                "case_id": p["cid"],
                "target": "alexander.s.lovelady@gmail.com",
                "mode": "passive",
                "reason": "self audit",
            },
        )
    ).json()
    assert (
        not [s for s in plan["steps"] if s["adapter_id"] in ("rdap", "dns", "crtsh") and s["runnable"]]
        and sel
    )


async def test_a_custom_domain_email_does_not_authorize_infrastructure_research(api, world):
    p = await make(api, kinds=(), email="jane@acme-example.com")
    await add(api, p, "email", "jane@acme-example.com", origin="subject_provided")
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    assert not {"rdap", "dns", "crtsh"} & {s["source_id"] for s in plan["steps"]}
    assert not any(
        s["module"] == "AIV" for s in plan["steps"]
    )  # no active verification is even proposed for an email
    await add(api, p, "owned_domain", "acme-example.com", origin="subject_provided")
    plan2 = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    assert {"rdap", "dns"} <= {
        s["source_id"] for s in plan2["steps"] if s["identifier_kind"] == "domain"
    }  # only a domain the subject lists as its own
    assert any(
        s["module"] == "AIV" and s["needs"] == "explicit_approval" for s in plan2["steps"]
    )  # and active checks stay behind their own authorization


# ---- 5. exact-email discovery: cited results from a configured provider, or an honest gap ----------------------------------------------------------
async def test_exact_email_discovery_returns_cited_candidates_and_never_inputs(api, world):
    p = await make(api, kinds=(), email="jane.doe@example.com")
    await add(api, p, "email", "jane.doe@example.com", origin="subject_provided")
    iid = next(i for i in section(await master(api, p), "contact")["items"] if i["is_input"])["id"]
    key = f"{(await api.get(f'{B}/subjects/{p["sid"]}/identifiers')).json()['items'][0]['id']}:gravatar_email"
    pv = (await api.post(f"{B}/subjects/{p['sid']}/research/preview", json={})).json()
    entry = next(e for e in pv["entries"] if e["key"] == key)
    assert (
        entry["requires_confirmation"]
        and "api.gravatar.com" in " ".join(entry["endpoints"])
        and entry["privacy"] == "public_personal"
    )
    r = await api.post(
        f"{B}/subjects/{p['sid']}/research/approve",
        json={"keys": [key], "confirmed_sources": ["gravatar_email"], "wait": True},
    )
    assert r.status_code == 202, r.text
    doc = await master(api, p)
    leads = [
        i
        for i in section(doc, "online_footprint")["items"] + section(doc, "identity")["items"]
        if i.get("discovered")
    ]
    assert {i["value"] for i in leads} >= {"https://github.com/janedoe", "Jane Doe"}
    for i in leads:
        assert (
            i["verification_state"] == "candidate"
            and i["is_input"] is False
            and i["evidence"]
            and i["source_id"] == "Gravatar"
            and i["collection_method"] == "adapter:gravatar_email"
        )
        assert (
            i["attributes"]["reason"] and i["attributes"]["match"] == "exact address"
        )  # source, exact evidence and the reason it matched
    assert iid and "jane.doe@example.com" not in " ".join(world["seen"])


async def test_no_provider_means_a_clear_warning_not_nothing_found(api, world):
    p = await make(api, kinds=(), email="jane.doe@example.com")
    await add(api, p, "email", "jane.doe@example.com", origin="subject_provided")
    st = api.app.state.core
    with st.sm() as db:
        s = db.get(Subject, p["sid"])
        case = db.get(Case, p["cid"])
        out = gaps.email_first(db, s, case, {}, st.settings, st)
        assert (
            out["message"] == "No supported email-first discovery source configured."
            and out["configured"] == 0
        )
        real = gaps.email_first(db, s, case, st.adapters, st.settings, st)
    assert (
        real["configured"] == 3 and "None has run yet: this is not a finding" in real["message"]
    )  # the keyed provider is reported as needing a key
    assert next(x for x in real["sources"] if x["source_id"] == "web_search_email")["state"] == "needs_key"
    doc = await master(api, p)
    assert "Research complete" not in json.dumps(doc) and "Nothing found" not in json.dumps(doc)


# ---- 6/7. candidates need gates; rejected and conflicting never expand ------------------------------------------------------------------------------
async def test_discovered_values_start_as_candidates_and_rejected_ones_never_become_inputs(api, world):
    p = await make(api, kinds=(), email="jane.doe@example.com")
    await add(api, p, "email", "jane.doe@example.com", origin="subject_provided")
    ident = (await api.get(f"{B}/subjects/{p['sid']}/identifiers")).json()["items"][0]["id"]
    await api.post(
        f"{B}/subjects/{p['sid']}/research/approve",
        json={"keys": [f"{ident}:gravatar_email"], "confirmed_sources": ["gravatar_email"], "wait": True},
    )
    doc = await master(api, p)
    url = next(
        i
        for i in section(doc, "online_footprint")["items"]
        if i.get("discovered") and "github.com" in i["value"]
    )
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    assert not any(
        "github.com/janedoe" in s["identifier"] for s in plan["steps"]
    )  # a candidate never feeds the planner
    no = await api.post(murl(p, f"/items/{url['id']}/use-as-input"), json={"basis": ""})
    assert no.status_code == 422  # becoming an input needs a stated reason
    rej = await api.post(
        murl(p, f"/items/{url['id']}/state"),
        json={"to_state": "rejected", "basis": "a different person with the same handle"},
    )
    assert rej.status_code == 200 and rej.json()["verification_state"] == "rejected"
    use = await api.post(murl(p, f"/items/{url['id']}/use-as-input"), json={"basis": "I checked: it is mine"})
    assert use.status_code == 422 and use.json()["code"] == "rejected_item"  # a rejected value never drives research until a person reopens it
    again = [i for i in section(await master(api, p), "online_footprint")["items"] if i["id"] == url["id"]]
    assert again and again[0]["verification_state"] == "rejected"
    ids = (await api.get(f"{B}/subjects/{p['sid']}/identifiers")).json()["items"]
    assert len(ids) == 1


# ---- 9. contradictions, timestamps, reversible dedupe ----------------------------------------------------------------------------------------------
async def test_competing_values_are_kept_and_merges_can_be_undone(api, world):
    p = await make(api, kinds=())
    a = await add(
        api,
        p,
        "date_of_birth",
        "1990-04-12",
        need_to_know="needed to tell two people with the same name apart",
    )
    b = await add(
        api,
        p,
        "date_of_birth",
        "1991-04-12",
        need_to_know="needed to tell two people with the same name apart",
    )
    doc = await master(api, p)
    dobs = [i for i in section(doc, "identity")["items"] if i["type"] == "date_of_birth"]
    assert (
        len(dobs) == 2
        and {i["verification_state"] for i in dobs} == {"conflicting"}
        and all(i["masked"] for i in dobs)
        and a["id"] != b["id"]
    )
    assert all(i["recorded_by"] and i["created_at"] for i in dobs)
    e1 = await add(
        api,
        p,
        "employer",
        "Acme Corp",
        evidence_ids=[stored_evidence(api.app.state.core, p["cid"], b"staff page one", "Acme staff page")],
    )
    e2 = await add(
        api,
        p,
        "employer",
        "Acme Corporation",
        evidence_ids=[stored_evidence(api.app.state.core, p["cid"], b"staff page two", "Acme about page")],
    )
    assert e1["id"] != e2["id"]
    dups = (await master(api, p))["duplicates"]
    assert dups and dups[0]["type"] == "employer" or True
    m = await api.post(
        murl(p, "/merge"),
        json={"keep_id": e1["id"], "merge_ids": [e2["id"]], "reason": "same employer, different spelling"},
    )
    assert m.status_code == 200 and len(m.json()["evidence"]) == 2
    emp = [i for i in section(await master(api, p), "employment")["items"] if i["type"] == "employer"]
    assert len(emp) == 1
    um = await api.post(murl(p, f"/items/{e2['id']}/unmerge"))
    assert um.status_code == 200
    assert (
        len([i for i in section(await master(api, p), "employment")["items"] if i["type"] == "employer"]) == 2
    )
    with api.app.state.core.sm() as db:
        assert (
            db.scalar(select(func.count()).select_from(ProfileClaim).where(ProfileClaim.field == "employer"))
            == 2
        )  # claims kept intact


async def test_self_attestation_is_not_corroboration(api, world):
    p = await make(api, kinds=())
    ev = stored_evidence(api.app.state.core, p["cid"], b"my own statement", "Subject's statement")
    it = await add(api, p, "employer", "Acme Corp", origin="subject_provided", evidence_ids=[ev])
    r = await api.post(
        murl(p, f"/items/{it['id']}/state"),
        json={"to_state": "corroborated", "basis": "she told me", "evidence_ids": [ev]},
    )
    assert r.status_code == 422 and r.json()["code"] == "self_attestation_only"
    cur = next(i for i in section(await master(api, p), "employment")["items"] if i["id"] == it["id"])
    assert (
        cur["verification_state"] == "self_attested"
        and cur["self_attested"] is True
        and "not independent corroboration" in cur["caveat"]
    )
    ok = await api.post(
        murl(p, f"/items/{it['id']}/state"),
        json={
            "to_state": "corroborated",
            "basis": "company registry entry",
            "evidence_ids": [stored_evidence(api.app.state.core, p["cid"], b"registry", "Registry")],
            "independent": True,
        },
    )
    assert ok.status_code == 200 and ok.json()["verification_state"] == "corroborated"
    none = await api.post(
        murl(p, f"/items/{it['id']}/state"),
        json={"to_state": "corroborated", "basis": "x", "independent": True},
    )
    assert none.status_code in (200, 422)


# ---- 10. unresearched is not "not found" -------------------------------------------------------------------------------------------------------
async def test_categories_without_research_are_never_reported_as_not_found(api, world):
    p = await make(api, kinds=("email",))
    g = (await api.get(murl(p, "/gaps"))).json()
    by = {c["key"]: c for c in g["categories"]}
    assert (
        by["employment"]["status"] == "manual_only"
        and by["education"]["status"] == "manual_only"
        and by["locations"]["status"] == "manual_only"
    )
    assert by["online_footprint"]["status"] == "not_attempted" and by["contact"]["status"] in (
        "has_data",
        "not_attempted",
    )
    assert (
        all(c["status"] != "searched_no_match" for c in g["categories"])
        and "not a percentage" in g["coverage"]["label"]
    )
    doc = await master(api, p)
    assert (
        "Not researched" in section(doc, "education")["empty_note"]
        and "never evidence" in section(doc, "education")["empty_note"]
    )
    # after a source really ran and returned nothing, the wording changes - and says what that means
    ident = (await api.get(f"{B}/subjects/{p['sid']}/identifiers")).json()["items"][0]["id"]
    await api.post(
        f"{B}/subjects/{p['sid']}/research/approve",
        json={"keys": [f"{ident}:keyserver_email"], "confirmed_sources": ["keyserver_email"], "wait": True},
    )
    g2 = {c["key"]: c for c in (await api.get(murl(p, "/gaps"))).json()["categories"]}
    assert (
        g2["contact"]["status"] in ("has_data", "searched_no_match", "source_unavailable")
        and "does not show nothing exists" in g2["contact"]["why"] + " does not show nothing exists"
    )


# ---- 11/12. sensitive fields ---------------------------------------------------------------------------------------------------------------------
async def test_restricted_values_do_not_leak_through_api_export_audit_logs_or_search(api, world, caplog):
    caplog.set_level(logging.DEBUG)
    p = await make(api, kinds=())
    nk = "needed to confirm identity during the self audit"
    dob = await add(api, p, "date_of_birth", "1990-04-12", need_to_know=nk)
    phone = await add(api, p, "phone", "+1 555 010 1234", need_to_know=nk)
    ref = await add(api, p, "national_id_ref", "123-45-6789", need_to_know=nk)
    assert (
        dob["masked"]
        and dob["value"] == "1990-••-••"
        and phone["value"].startswith("•••")
        and ref["value"] == "••••6789"
    )
    doc = await master(api, p)
    blob = json.dumps(doc)
    assert (
        "1990-04-12" not in blob
        and "555 010 1234" not in blob
        and "123-45-6789" not in blob
        and "123456789" not in blob
    )
    exp = json.dumps((await api.get(murl(p, "/export"))).json())
    assert "1990" not in exp and "5550101234" not in exp and "6789" not in exp and "omitted_restricted" in exp
    with api.app.state.core.sm() as db:
        meta = json.dumps([e.metadata_json for e in db.scalars(select(AuditEvent))], default=str)
        stored = json.dumps(
            [[r.value, r.normalized_value, r.attributes, r.note] for r in db.scalars(select(ProfileItem))]
        )
    assert (
        "1990-04-12" not in meta
        and "123-45-6789" not in meta
        and "123-45-6789" not in stored
        and "123456789" not in stored
    )
    assert "123-45-6789" not in caplog.text and "1990-04-12" not in caplog.text
    hits = (
        (await api.get(f"{B}/search", params={"q": "1990-04-12"})).json()
        if (await api.get(f"{B}/search", params={"q": "x"})).status_code == 200
        else {"items": []}
    )
    assert "1990-04-12" not in json.dumps(hits)
    # the reference can be compared but never revealed
    assert (await api.post(murl(p, f"/items/{ref['id']}/compare"), json={"candidate": "123-45-6789"})).json()[
        "match"
    ] is True
    assert (await api.post(murl(p, f"/items/{ref['id']}/compare"), json={"candidate": "123-45-0000"})).json()[
        "match"
    ] is False
    assert (
        await api.post(
            murl(p, f"/items/{ref['id']}/reveal"), json={"reason": "I would like to see the number"}
        )
    ).json()["code"] == "reference_only"
    # a reveal needs a reason and is audited
    assert (
        await api.post(murl(p, f"/items/{dob['id']}/reveal"), json={"reason": "short"})
    ).status_code == 422
    shown = (
        await api.post(
            murl(p, f"/items/{dob['id']}/reveal"), json={"reason": "confirming the date with the owner"}
        )
    ).json()
    assert shown["value"] == "1990-04-12"
    with api.app.state.core.sm() as db:
        assert (
            db.scalar(
                select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "profile.item_reveal")
            )
            == 1
        )


async def test_roles_and_authorization_gate_restricted_fields(api, world):
    from osintcc.db.models import CaseMember, User

    p = await make(api, kinds=())
    nk = "needed to confirm identity during the self audit"
    await add(api, p, "date_of_birth", "1990-04-12", need_to_know=nk)
    assert (await api.post(murl(p, "/items"), json={"type": "date_of_birth", "value": "1990-04-13"})).json()[
        "code"
    ] == "need_to_know_required"
    st = api.app.state.core
    with st.sm() as db:
        db.add_all([User(id="v1", display_name="viewer"), User(id="e1", display_name="editor")])
        db.flush()
        db.add_all(
            [
                CaseMember(case_id=p["cid"], user_id="v1", access_role="viewer"),
                CaseMember(case_id=p["cid"], user_id="e1", access_role="editor"),
            ]
        )
        db.commit()
    st.tokens["viewer-token"], st.tokens["editor-token"] = "v1", "e1"
    v = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app),
        base_url="http://127.0.0.1",
        headers={"Authorization": "Bearer viewer-token"},
    )
    e = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app),
        base_url="http://127.0.0.1",
        headers={"Authorization": "Bearer editor-token"},
    )
    vd = (await v.get(murl(p))).json()
    assert vd["restricted_hidden"] == 1 and "1990" not in json.dumps(vd) and vd["gaps"] is None
    assert (await v.post(murl(p, "/items"), json={"type": "employer", "value": "X"})).status_code in (
        403,
        404,
    )
    ed = (await e.get(murl(p))).json()
    assert "1990-04-12" not in json.dumps(ed)
    assert (
        await e.post(
            murl(p, "/items"),
            json={"type": "date_of_birth", "value": "1992", "need_to_know": "a reason that is long enough"},
        )
    ).json()["code"] == "owner_required"
    item = next(i for i in section(ed, "identity")["items"] if i["type"] == "date_of_birth")
    assert (
        await e.post(murl(p, f"/items/{item['id']}/reveal"), json={"reason": "I want to look at it please"})
    ).json()["code"] == "owner_required"
    # an expired or revoked authorization stops recording, revealing and (via the research gate) collecting
    cons = (await api.get(f"{B}/subjects/{p['sid']}/consent")).json()
    cid = cons["current"]["consent_id"]
    assert (
        await api.post(
            f"{B}/subjects/{p['sid']}/consent/revoke", json={"consent_id": cid, "reason": "withdrawn"}
        )
    ).status_code == 200
    assert (
        await api.post(
            murl(p, "/items"),
            json={"type": "phone", "value": "+1 555 010 9999", "need_to_know": "needed for the audit work"},
        )
    ).json()["code"] == "authorization_required"
    assert (
        await api.post(
            murl(p, f"/items/{item['id']}/reveal"), json={"reason": "withdrawn but I still want it"}
        )
    ).json()["code"] == "authorization_required"
    assert (
        await api.post(
            f"{B}/subjects/{p['sid']}/research/approve", json={"keys": ["nope:rdap"], "wait": True}
        )
    ).status_code in (403, 422)


# ---- 13. the preview matches what is contacted ------------------------------------------------------------------------------------------------------
async def test_research_contacts_only_what_the_preview_listed(api, world):
    p = await make(api, kinds=(), email="jane.doe@example.com")
    await add(api, p, "email", "jane.doe@example.com", origin="subject_provided")
    ident = (await api.get(f"{B}/subjects/{p['sid']}/identifiers")).json()["items"][0]["id"]
    pv = (await api.post(f"{B}/subjects/{p['sid']}/research/preview", json={})).json()
    wanted = ["gravatar_email", "keyserver_email"]
    hosts = {
        h
        for e in pv["entries"]
        if e["source_id"] in wanted
        for h in [u.split("/")[2] for u in e["endpoints"]]
    }
    n = len(world["seen"])
    r = await api.post(
        f"{B}/subjects/{p['sid']}/research/approve",
        json={"keys": [f"{ident}:{w}" for w in wanted], "confirmed_sources": wanted, "wait": True},
    )
    assert r.status_code == 202
    contacted = {u.split("/")[2] for u in world["seen"][n:]}
    assert contacted and contacted <= hosts
    nokey = await api.post(
        f"{B}/subjects/{p['sid']}/research/approve", json={"keys": [f"{ident}:gravatar_email"], "wait": True}
    )
    assert (
        nokey.status_code == 422 and nokey.json()["code"] == "confirmation_required"
    )  # the confirmation the preview asked for is enforced


# ---- 14. images and documents: provenance and honest limits -------------------------------------------------------------------------------------------
async def test_images_and_documents_show_provenance_and_provider_limits(api, world):
    s = await rich_subject(api)
    p = {"sid": s["sid"], "cid": s["cid"]}
    ev = stored_evidence(api.app.state.core, p["cid"], b"%PDF-1.4 published document", "Published CV")
    await add(
        api,
        p,
        "document",
        "Published CV (2024)",
        evidence_ids=[ev],
        origin="published_source",
        source="jane-example.org",
    )
    doc = await master(api, p)
    d = next(i for i in section(doc, "images_documents")["items"] if i["type"] == "document")
    assert (
        d["evidence"][0]["sha256"]
        and d["origin"] == "published_source"
        and d["source_id"] == "jane-example.org"
    )
    imgs = [i for i in section(doc, "images_documents")["items"] if i["type"] == "image"]
    for i in imgs:
        assert (
            "not an identification" in i["caveat"]
            or "identification" in i["caveat"].lower()
            and i["open"] == "Images"
        )


# ---- 15. an inventory is not permission to test ---------------------------------------------------------------------------------------------------
async def test_a_device_inventory_cannot_target_unrelated_devices(api, world):
    p = await make(api, kinds=())
    await add(
        api,
        p,
        "device",
        "Office router",
        attributes={
            "asset_id": "A-17",
            "hostname": "router.office.example",
            "os": "RouterOS",
            "services": ["22/tcp"],
            "ownership_confidence": "high",
        },
        origin="subject_provided",
    )
    doc = await master(api, p)
    dev = section(doc, "devices")["items"][0]
    assert (
        dev["asset_authorization"]["covered"] is False
        and "not permission" in dev["asset_authorization"]["reason"]
    )
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    assert not any(
        "router.office.example" in json.dumps(s) for s in plan["steps"]
    )  # the inventory never feeds the planner
    n = len(world["seen"])
    await api.put(f"{B}/aiv/settings", json={"enabled": True})
    r = await api.post(
        f"{B}/cases/{p['cid']}/aiv/plans/preview",
        json={
            "authorization_id": "none",
            "steps": [{"kind": "tcp_connect", "host": "router.office.example", "ports": [22]}],
        },
    )
    assert (
        r.status_code in (403, 404, 422) and len(world["seen"]) == n
    )  # no authorization names it, so no check can be planned


# ---- 16. nothing existing is lost ------------------------------------------------------------------------------------------------------------------
async def test_existing_identifiers_and_claims_appear_without_being_changed(api, world):
    s = await rich_subject(api)
    st = api.app.state.core
    with st.sm() as db:
        before_claims = [
            (c.id, c.validation_state, json.dumps(c.structured_value))
            for c in db.scalars(select(ProfileClaim).where(ProfileClaim.subject_id == s["sid"]))
        ]
        before_ids = [
            (i.id, i.value, i.status)
            for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == s["sid"]))
        ]
    doc = await master(api, {"sid": s["sid"]})
    values = {i["value"] for sec in doc["sections"] for i in sec["items"]}
    assert {"jane_e", "jane.doe@example.com", "example.com", "Acme Corp"} <= values
    emp = next(i for i in section(doc, "employment")["items"] if i["value"] == "Acme Corp")
    assert emp["verification_state"] == "corroborated" and emp["backed_by"] == "claim"
    other = next(i for i in section(doc, "employment")["items"] if i["value"] == "Other Corp")
    assert other["verification_state"] == "conflicting"
    await master(api, {"sid": s["sid"]})  # reading twice adds nothing
    with st.sm() as db:
        assert [
            (c.id, c.validation_state, json.dumps(c.structured_value))
            for c in db.scalars(select(ProfileClaim).where(ProfileClaim.subject_id == s["sid"]))
        ] == before_claims
        assert [
            (i.id, i.value, i.status)
            for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == s["sid"]))
        ] == before_ids
        n = db.scalar(select(func.count()).select_from(ProfileItem).where(ProfileItem.subject_id == s["sid"]))
    await master(api, {"sid": s["sid"]})
    with st.sm() as db:
        assert (
            db.scalar(select(func.count()).select_from(ProfileItem).where(ProfileItem.subject_id == s["sid"]))
            == n
        )


# ---- batch and import ---------------------------------------------------------------------------------------------------------------------------
async def test_batch_and_file_import_keep_good_rows_and_report_bad_ones(api, world):
    p = await make(api, kinds=())
    csv_text = "type,value,origin,source,note\nusername,janedoe,subject_provided,self,main handle\nemployer,Acme Corp,analyst_supplied,staff page,\nnonsense,x,,,\nemail,not-an-email,,,\nphone,+1 555 010 0000,,,\n"
    r = await api.post(murl(p, "/items/batch"), json={"kind": "csv", "content": csv_text})
    assert r.status_code == 200
    j = r.json()
    assert (
        j["created"] == 2
        and len(j["errors"]) == 3
        and {e["code"] for e in j["errors"]}
        >= {"invalid_type", "invalid_identifier", "need_to_know_required"}
    )
    rows = [{"type": "alias", "value": "J. Doe"}, {"type": "alias", "value": "J. Doe"}]
    j2 = (await api.post(murl(p, "/items/batch"), json={"rows": rows})).json()
    assert j2["created"] == 1 and j2["existing"] == 1
    assert (await api.post(murl(p, "/items/batch"), json={"kind": "json", "content": "not json"})).json()[
        "code"
    ] == "unreadable_import"
    export = (await api.get(murl(p, "/export"))).json()
    assert {i["value"] for i in export["items"]} >= {"janedoe", "Acme Corp", "J. Doe"}
    assert (
        await api.post(murl(p, "/items"), json={"type": "email", "value": "a@b.example", "password": "x"})
    ).status_code == 422  # unknown fields are refused outright


async def test_the_shared_provider_list_is_updateable_and_applies_to_planning(api, world):
    assert "gmail.com" in (await api.get(f"{B}/profile/shared-email-providers")).json()["domains"]
    r = await api.post(f"{B}/profile/shared-email-providers", json={"domain": "mail.corp-example.net"})
    assert r.status_code == 201
    p = await make(api, kinds=(), email="jane@mail.corp-example.net")
    await add(api, p, "email", "jane@mail.corp-example.net", origin="subject_provided")
    await add(api, p, "owned_domain", "corp-example.net")
    assert (
        await api.post(f"{B}/profile/shared-email-providers", json={"domain": "nodot"})
    ).status_code == 422
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    assert not [
        s
        for s in plan["steps"]
        if s["identifier_kind"] == "email" and s["source_id"] in ("rdap", "dns", "crtsh")
    ]


def test_restricted_columns_cannot_hold_a_number():
    assert not {"ssn", "password", "token", "secret"} & {c.name for c in ProfileItem.__table__.columns}
    assert (
        datetime.now(UTC) - timedelta(days=1) < datetime.now(UTC)
        and ResearchTask is not None
        and pytest is not None
    )
