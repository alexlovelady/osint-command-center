"""One-click spec M1: data semantics. FUX-002/003/007/009/011/012/016/020.

A git author called "alexlovelady" is a HANDLE, not a full name; a repository link is not a profile link; an owner's own confirmation is not independent corroboration; evidence
for one site cannot support an account on another; every count can be reconciled. All sources answer from a mock transport (fixture-tested, not live-verified).
"""
from __future__ import annotations

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import ProfileItem
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from profile_helpers import rich_subject, stored_evidence
from sqlalchemy import select
from test_associated_emails import B, _no_real_keyring, make  # noqa: F401  (fixture)

COMMITS = {"items": [{"html_url": "https://github.com/alexlovelady/notes/commit/abc", "repository": {"html_url": "https://github.com/alexlovelady/notes", "full_name": "alexlovelady/notes"},
                      "commit": {"message": "first", "author": {"name": "alexlovelady", "email": "alex@example.org"}}},
                     {"html_url": "https://github.com/alexlovelady/tools/commit/def", "repository": {"html_url": "https://github.com/alexlovelady/tools", "full_name": "alexlovelady/tools"},
                      "commit": {"message": "second", "author": {"name": "Alex Lovelady", "email": "alex@example.org"}}}]}


@pytest.fixture
async def api(settings, calls):
    base = make_handler(calls)

    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if u.startswith("https://api.github.com/search/users"):
            return httpx.Response(200, json={"items": []})
        if u.startswith("https://api.github.com/search/commits"):
            return httpx.Response(200, json=COMMITS)
        if u.startswith(("https://api.gravatar.com/", "https://keys.openpgp.org/")):
            return httpx.Response(404, text="none")
        return base(request)

    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(handler))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            c.app = app
            yield c


def sec(doc, key):
    return next(s for s in doc["sections"] if s["key"] == key)


async def master(api, p):
    r = await api.get(f"{B}/subjects/{p['sid']}/master")
    assert r.status_code == 200, r.text
    return r.json()


async def github_run(api, p):
    ident = p["ids"]["email"]
    r = await api.post(f"{B}/subjects/{p['sid']}/research/approve", json={"keys": [f"{ident}:github_email_search"], "confirmed_sources": ["github_email_search"], "wait": True})
    assert r.status_code == 202, r.text


async def test_a_git_author_handle_is_a_username_and_a_repository_is_not_a_profile(api):
    p = await make(api, kinds=("email",), email="alex@example.org")
    await github_run(api, p)
    doc = await master(api, p)
    foot = [i for i in sec(doc, "online_footprint")["items"] if i.get("discovered")]
    ident = sec(doc, "identity")["items"]
    handle = [i for i in foot if i["value"] == "alexlovelady" and i["type"] == "username"]
    assert handle and handle[0]["verification_state"] == "candidate" and handle[0]["is_input"] is False
    assert not [i for i in ident if i["value"] == "alexlovelady"]                         # FUX-003: a handle is never shown as a full name
    assert any(i["type"] == "full_name" and i["value"] == "Alex Lovelady" for i in ident)  # a real, two-word author name stays a name candidate
    repos = [i for i in foot if i["type"] == "repository"]
    assert {i["value"] for i in repos} == {"https://github.com/alexlovelady/notes", "https://github.com/alexlovelady/tools"}
    assert not [i for i in foot if i["type"] == "profile_url" and "/notes" in i["value"]]


async def test_legacy_mistyped_items_are_corrected_once_and_the_original_is_kept(api):
    p = await make(api, kinds=("email",))
    st = api.app.state.core
    with st.sm() as db:
        ev = stored_evidence(st, p["cid"], b"x", "src")
        db.add(ProfileItem(subject_id=p["sid"], case_id=p["cid"], category="identity", type="full_name", value="alexlovelady", normalized_value="alexlovelady", source_id="GitHub",
                           evidence_ids=[ev], collection_method="adapter:github_email_search", origin="discovered", verification_state="candidate", confidence="low", attributes={"via": ""}))
        db.commit()
    doc = await master(api, p)
    assert not [i for i in sec(doc, "identity")["items"] if i["value"] == "alexlovelady"]
    moved = next(i for i in sec(doc, "online_footprint")["items"] if i["value"] == "alexlovelady")
    assert moved["type"] == "username" and moved["verification_state"] == "candidate" and moved["evidence"]
    with st.sm() as db:
        row = db.scalars(select(ProfileItem).where(ProfileItem.value == "alexlovelady")).one()
        assert row.attributes["classification"]["original"]["type"] == "full_name" and row.attributes["classification"]["history"][0]["automatic"] is True
    iid = moved["id"]
    undo = await api.post(f"{B}/subjects/{p['sid']}/master/items/{iid}/reclassify/undo")
    assert undo.status_code == 200 and undo.json()["type"] == "full_name"
    again = await master(api, p)
    assert [i for i in sec(again, "identity")["items"] if i["value"] == "alexlovelady"]               # the undo sticks: it is not auto-corrected a second time


async def test_an_analyst_can_reclassify_preview_it_and_undo_without_verifying_anything(api):
    p = await make(api, kinds=("email",))
    r = await api.post(f"{B}/subjects/{p['sid']}/master/items", json={"type": "alias", "value": "ghost-writer"})
    assert r.status_code == 201
    r2 = await api.post(f"{B}/subjects/{p['sid']}/master/items", json={"type": "biography", "value": "Maintains the notes repository"})
    iid = r2.json()["id"]
    pv = await api.post(f"{B}/subjects/{p['sid']}/master/items/{iid}/reclassify", json={"to_type": "repository", "preview": True})
    assert pv.status_code == 422 or pv.status_code == 200                                    # the biography text is not a URL: normalization decides
    ok = await api.post(f"{B}/subjects/{p['sid']}/master/items", json={"type": "website", "value": "https://github.com/alexlovelady/notes"})
    wid = ok.json()["id"]
    assert (await api.post(f"{B}/subjects/{p['sid']}/master/items/{wid}/reclassify", json={"to_type": "repository", "reason": "wrong type"})).json()["code"] == "backed_item_fixed"
    # a free-standing note-like item: use a published archived page, then reclassify it to a repository
    a = (await api.post(f"{B}/subjects/{p['sid']}/master/items", json={"type": "archived_profile", "value": "https://github.com/alexlovelady/notes"})).json()
    pv = await api.post(f"{B}/subjects/{p['sid']}/master/items/{a['id']}/reclassify", json={"to_type": "repository", "preview": True})
    assert pv.status_code == 200 and any("not verification" in e for e in pv.json()["effects"])
    assert (await api.post(f"{B}/subjects/{p['sid']}/master/items/{a['id']}/reclassify", json={"to_type": "repository", "reason": ""})).json()["code"] == "reason_required"
    done = await api.post(f"{B}/subjects/{p['sid']}/master/items/{a['id']}/reclassify", json={"to_type": "repository", "reason": "it is the repository page"})
    assert done.status_code == 200 and done.json()["type"] == "repository" and done.json()["verification_state"] == a["verification_state"] and done.json()["evidence"] == a["evidence"]
    assert (await api.post(f"{B}/subjects/{p['sid']}/master/items/{a['id']}/reclassify", json={"to_type": "date_of_birth", "reason": "no way"})).json()["code"] == "restricted_type"
    back = await api.post(f"{B}/subjects/{p['sid']}/master/items/{a['id']}/reclassify/undo")
    assert back.status_code == 200 and back.json()["type"] == "archived_profile"


async def test_owner_attestation_is_never_counted_as_independent_corroboration(api):
    s = await rich_subject(api)
    st = api.app.state.core
    cands = (await api.get(f"{B}/subjects/{s['sid']}/candidates")).json()["items"]
    gh = next(c for c in cands if "github.com" in c["canonical_url"])
    forum = next(c for c in cands if "forum.test" in c["canonical_url"])
    r = await api.post(f"{B}/subjects/{s['sid']}/candidates/bulk-review", json={"candidate_ids": [gh["id"], forum["id"]], "state": "confirmed", "basis": "these are my accounts", "attestation": "subject"})
    assert r.status_code == 200, r.text
    doc = await master(api, {"sid": s["sid"]})
    counts = {k: sec(doc, "online_footprint")["counts"][k] for k in ("self_attested", "corroborated")}
    assert counts["self_attested"] == 2 and counts["corroborated"] == 0
    rows = [i for i in sec(doc, "online_footprint")["items"] if i["type"] == "account_candidate" and i["verification_state"] == "self_attested"]
    assert len(rows) == 2 and all(x["state_label"] == "Self-attested" for x in rows)
    # independent evidence about the SAME site upgrades one account; evidence about another site is refused
    gh_ev = stored_evidence(st, s["cid"], b"profile page text mentioning the owner", "GitHub profile screenshot")
    with st.sm() as db:
        from osintcc.db.models import Evidence
        db.get(Evidence, gh_ev).original_url = "https://github.com/jane_e"
        db.commit()
    bad = await api.post(f"{B}/subjects/{s['sid']}/candidates/bulk-review", json={"candidate_ids": [forum["id"]], "state": "confirmed", "basis": "x", "attestation": "subject", "evidence_ids": [gh_ev]})
    assert bad.status_code == 422 and bad.json()["code"] == "evidence_not_applicable"
    await api.post(f"{B}/subjects/{s['sid']}/candidates/bulk-review", json={"candidate_ids": [gh["id"]], "state": "candidate", "basis": "re-open"})
    good = await api.post(f"{B}/subjects/{s['sid']}/candidates/bulk-review", json={"candidate_ids": [gh["id"]], "state": "confirmed", "basis": "GitHub profile lists the same name", "evidence_ids": [gh_ev]})
    assert good.status_code == 200, good.text
    doc = await master(api, {"sid": s["sid"]})
    states = {i["value"]: i["verification_state"] for i in sec(doc, "online_footprint")["items"] if i["type"] == "account_candidate"}
    assert states["https://github.com/jane_e"] == "corroborated" and states["https://forum.test/u/jane_e"] == "self_attested"


async def test_url_variants_of_one_profile_are_one_account_and_every_count_reconciles(api):
    s = await rich_subject(api)
    from profile_helpers import seed_candidates
    st = api.app.state.core
    seed_candidates(st, s["cid"], "jane_e", [("sherlock", "https://www.youtube.com/@jane_e", "YouTube"), ("maigret", "https://www.youtube.com/@jane_e/about", "YouTube"),
                                             ("sherlock", "https://venmo.com/jane_e", "Venmo"), ("maigret", "https://venmo.com/u/jane_e", "Venmo")])
    acc = (await api.get(f"{B}/subjects/{s['sid']}/master/accounting")).json()
    a = acc["accounts"]
    assert a["unique_accounts"] == len((await api.get(f"{B}/subjects/{s['sid']}/candidates")).json()["items"])
    urls = [c["canonical_url"] for c in (await api.get(f"{B}/subjects/{s['sid']}/candidates")).json()["items"]]
    assert sum("youtube.com" in u for u in urls) == 1 and sum("venmo.com" in u for u in urls) == 1
    assert a["seen_by_more_than_one_tool"] >= 3 and "one signal, not two" in a["explain"]
    assert a["tool_hits"] >= a["unique_accounts"]


async def test_hundreds_of_candidates_stay_fast_and_reconcile(api):
    import time

    from profile_helpers import seed_candidates
    p = await make(api, kinds=("email",))
    await api.post(f"{B}/subjects/{p['sid']}/identifiers", json={"kind": "username", "value": "bulkuser"})
    st = api.app.state.core
    sights = []
    for i in range(300):
        sights.append(("sherlock", f"https://site{i}.example/bulkuser", f"Site{i}"))
        sights.append(("maigret", f"https://site{i}.example/bulkuser/about" if i % 2 else f"https://site{i}.example/bulkuser", f"Site{i}"))
    seed_candidates(st, p["cid"], "bulkuser", sights)
    t0 = time.perf_counter()
    acc = (await api.get(f"{B}/subjects/{p['sid']}/master/accounting")).json()
    inbox = (await api.get(f"{B}/subjects/{p['sid']}/review-inbox")).json()
    doc = await master(api, p)
    took = time.perf_counter() - t0
    assert acc["accounts"]["tool_hits"] == 600 and acc["accounts"]["unique_accounts"] == 450 and acc["accounts"]["seen_by_more_than_one_tool"] == 150
    assert inbox["by_kind"]["account"] == 450 and len(sec(doc, "online_footprint")["items"]) >= 450
    assert took < 20, f"too slow: {took:.1f}s"
    again = (await api.get(f"{B}/subjects/{p['sid']}/master/accounting")).json()                       # repeated refresh adds nothing
    assert again["accounts"]["unique_accounts"] == 450
