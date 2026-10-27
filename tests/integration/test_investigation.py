"""One-click investigation (spec section 10): start from 1+ inputs, run every permitted source, bounded expansion, honest limits, durable and safe.

All sources answer from a mock transport: this proves the orchestration, not the live behaviour of any third-party service.
"""
from __future__ import annotations

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import InvestigationRun, ResearchTask, User
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from osintcc.profile import investigate
from sqlalchemy import func, select
from test_associated_emails import B, _no_real_keyring  # noqa: F401  (fixture)

COMMITS = {"items": [{"html_url": "https://github.com/alexlovelady/notes/commit/abc", "repository": {"html_url": "https://github.com/alexlovelady/notes", "full_name": "alexlovelady/notes"},
                      "commit": {"message": "first", "author": {"name": "alexlovelady", "email": "alex@gmail.com"}}}]}


@pytest.fixture
def world():
    return {"seen": [], "gravatar": 200, "github": "hit"}


@pytest.fixture
async def api(settings, calls, world):
    base = make_handler(calls)

    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        world["seen"].append(u)
        if u.startswith("https://api.gravatar.com/"):
            if world["gravatar"] == 429:
                return httpx.Response(429, headers={"Retry-After": "30"}, text="slow down")
            return httpx.Response(404, text="none")
        if u.startswith("https://api.github.com/search/users"):
            return httpx.Response(200, json={"items": [{"login": "alexlovelady", "html_url": "https://github.com/alexlovelady"}]} if world["github"] == "hit" else {"items": []})
        if u.startswith("https://api.github.com/search/commits"):
            return httpx.Response(200, json=COMMITS if world["github"] == "hit" else {"items": []})
        if u.startswith("https://api.github.com/users/alexlovelady"):
            return httpx.Response(200, json={"login": "alexlovelady", "html_url": "https://github.com/alexlovelady", "name": "Alex Lovelady"})
        if u.startswith("https://keys.openpgp.org/"):
            return httpx.Response(404, text="none")
        return base(request)

    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(handler))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            c.app = app
            yield c


AUTH = {"verification_method": "self_attestation", "verifier": "Alex"}


async def prepare(api, inputs, **kw):
    body = {"kind": "person", "display_name": "Alex", "purpose": "self audit", "inputs": inputs, "authorization": AUTH, **kw}
    r = await api.post(f"{B}/investigations", json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def finish(api, rid, limit=12):
    last = None
    for _ in range(limit):
        r = await api.post(f"{B}/investigations/{rid}/advance")
        assert r.status_code == 200, r.text
        last = r.json()
        if last["finished"]:
            break
    st = (await api.get(f"{B}/investigations/{rid}")).json()
    return st


def rows(man, **want):
    return [r for r in man["rows"] if all(r[k] == v for k, v in want.items())]


async def test_one_free_mail_address_starts_a_run_that_names_every_provider_and_every_gap(api, world):
    p = await prepare(api, [{"kind": "email", "value": "alex@gmail.com"}])
    man = p["manifest"]
    assert {r["source_id"] for r in rows(man, status="needs_approval")} >= {"gravatar_email", "github_email_search", "keyserver_email"}
    assert rows(man, source_id="web_search_email")[0]["status"] == "needs_key" and "Settings" in rows(man, source_id="web_search_email")[0]["reason"]
    assert not [r for r in man["rows"] if r["source_id"] in ("rdap", "dns", "crtsh")]                    # a mailbox provider's domain is never researched
    assert not world["seen"]                                                                           # preparing sends nothing
    assert "api.github.com" in " ".join(man["third_parties"]) or "GitHub" in " ".join(man["third_parties"])
    r = await api.post(f"{B}/subjects/{p['subject_id']}/investigations", json={"approved_sources": "listed"})
    assert r.status_code == 201
    rid = r.json()["id"]
    st = await finish(api, rid)
    assert st["status"] in ("awaiting_review", "complete_with_limits")
    assert any("api.github.com" in u for u in world["seen"]) and not any("gmail.com" in u and "rdap" in u for u in world["seen"])
    summ = (await api.get(f"{B}/investigations/{rid}/summary")).json()
    codes = {x["code"] for x in summ["limits"]}
    assert "needs_key" in codes                                                                        # Brave was not run, and the summary says so instead of "nothing found"
    assert summ["run"]["status"] != "completed"
    acc = summ["accounting"]
    assert acc["profile_items"]["discovered"] >= 1
    users = next(i for i in (await api.get(f"{B}/subjects/{p['subject_id']}/master")).json()["sections"] if i["key"] == "online_footprint")["items"]
    assert any(i["type"] == "username" and i["value"] == "alexlovelady" and i["verification_state"] == "candidate" for i in users)


async def test_providers_that_send_an_input_to_a_third_party_wait_for_the_single_approval(api, world):
    p = await prepare(api, [{"kind": "email", "value": "alex@gmail.com"}], start=True)
    rid = p["run"]["id"]
    st = await finish(api, rid)
    assert st["status"] == "awaiting_review" and st["stop_reason"] == "needs_approval"
    assert not any("api.github.com" in u or "gravatar" in u or "keys.openpgp" in u for u in world["seen"])   # nothing was contacted without the named approval
    ap = await api.post(f"{B}/investigations/{rid}/approve", json={"sources": ["gravatar_email", "keyserver_email"]})
    assert ap.status_code == 200
    st = await finish(api, rid)
    assert any("api.gravatar.com" in u for u in world["seen"]) and not any("api.github.com" in u for u in world["seen"])   # only the providers that were named
    assert (await api.post(f"{B}/investigations/{rid}/approve", json={"sources": ["rdap"]})).status_code == 422
    ev = (await api.get(f"{B}/investigations/{rid}/events")).json()
    assert [e["seq"] for e in ev["events"]] == sorted(e["seq"] for e in ev["events"]) and ev["events"][0]["kind"] == "created"
    assert (await api.get(f"{B}/investigations/{rid}/events", params={"after": ev["last"]})).json()["events"] == []


async def test_name_and_phone_only_never_pretend_to_research(api, world):
    p = await prepare(api, [{"kind": "name", "value": "Alex Lovelady"}, {"kind": "phone", "value": "+1 555 010 4242"}], start=True)
    man = p["manifest"]
    assert {r["status"] for r in man["rows"]} == {"unsupported_input"}
    assert "No approved phone-discovery source" in rows(man, identifier_kind="phone")[0]["reason"]
    assert "4242" not in str(man) and "•••" in rows(man, identifier_kind="phone")[0]["identifier"]
    st = await finish(api, p["run"]["id"])
    assert st["status"] == "complete_with_limits" and not world["seen"]
    summ = (await api.get(f"{B}/investigations/{p['run']['id']}/summary")).json()
    assert {x["code"] for x in summ["limits"]} == {"unsupported_input"}
    assert "4242" not in str(summ)


async def test_a_business_uses_its_organization_and_owned_domain_only(api, world):
    p = await prepare(api, [{"kind": "organization", "value": "Acme Widgets"}, {"kind": "domain", "value": "acme-widgets.example"}], kind="business", mode="organization", start=True, approved_sources="listed")
    man = p["manifest"]
    srcs = {r["source_id"] for r in man["rows"]}
    assert {"rdap", "dns"} <= srcs and not {"gravatar_email", "github_email_search"} & srcs
    assert any(r["module"] == "AIV" and r["status"] == "separate_approval" for r in man["rows"])         # active checks keep their own approval
    await finish(api, p["run"]["id"])
    assert not any("api.gravatar.com" in u for u in world["seen"])


async def test_a_found_handle_is_a_lead_and_only_a_decision_makes_it_a_starting_point(api, world):
    p = await prepare(api, [{"kind": "email", "value": "alex@gmail.com"}], start=True, approved_sources="listed")
    rid = p["run"]["id"]
    await finish(api, rid)
    st = api.app.state.core
    with st.sm() as db:
        assert not db.scalars(select(ResearchTask).where(ResearchTask.source_id == "github_public")).first()      # the handle was NOT researched on its own
    items = [i for s in (await api.get(f"{B}/subjects/{p['subject_id']}/master")).json()["sections"] for i in s["items"] if i["type"] == "username" and i["value"] == "alexlovelady"]
    iid = items[0]["id"]
    promo = await api.post(f"{B}/subjects/{p['subject_id']}/master/items/{iid}/use-as-input", json={"basis": "I checked: it is my handle"})
    assert promo.status_code == 200
    assert (await api.post(f"{B}/investigations/{rid}/resume")).status_code == 200
    man = investigate.build_manifest(api.app.state.core.sm().__enter__(), st, *_subject_case(st, p))
    assert any(r["source_id"] == "github_public" and r["identifier"] == "alexlovelady" for r in man["rows"])       # now available without re-entering it


def _subject_case(st, p):
    from osintcc.db.models import Case, Subject
    db = st.sm()
    return db.get(Subject, p["subject_id"]), db.get(Case, p["case_id"])


async def test_a_rejected_candidate_never_expands(api, world):
    p = await prepare(api, [{"kind": "email", "value": "alex@gmail.com"}], start=True, approved_sources="listed")
    rid = p["run"]["id"]
    await finish(api, rid)
    inbox = (await api.get(f"{B}/subjects/{p['subject_id']}/review-inbox")).json()
    handle = next(i for i in inbox["items"] if i["kind"] == "item" and i["title"] == "alexlovelady")
    out = await api.post(f"{B}/subjects/{p['subject_id']}/review-inbox/decide", json={"ids": [handle["id"]], "action": "not_mine", "basis": "somebody else"})
    assert out.status_code == 200 and out.json()["applied"] == 1
    use = await api.post(f"{B}/subjects/{p['subject_id']}/master/items/{handle['id']}/use-as-input", json={"basis": "I changed my mind"})
    assert use.status_code == 422 and use.json()["code"] == "rejected_item"
    idents = (await api.get(f"{B}/subjects/{p['subject_id']}/identifiers")).json()["items"]
    assert [i["kind"] for i in idents] == ["email"]
    after = [i for i in (await api.get(f"{B}/subjects/{p['subject_id']}/review-inbox")).json()["items"] if i["title"] == "alexlovelady"]
    assert not after                                                                                     # a rejected lead leaves the inbox


async def test_budgets_stop_the_run_and_say_why(api, world):
    p = await prepare(api, [{"kind": "email", "value": "alex@gmail.com"}], start=True, approved_sources="listed", policy={"max_runs": 1})
    st = await finish(api, p["run"]["id"])
    with api.app.state.core.sm() as db:
        n = db.scalar(select(func.count()).select_from(ResearchTask).where(ResearchTask.status != "cancelled"))
    assert n == 1 and st["status"] in ("complete_with_limits", "awaiting_review")
    summ = (await api.get(f"{B}/investigations/{p['run']['id']}/summary")).json()
    assert st["stop_reason"] in ("budget_exhausted", "decisions", "needs_approval", "needs_key") or summ["limits"]
    bad = await api.post(f"{B}/investigations", json={"inputs": [{"kind": "username", "value": "x"}], "purpose": "p", "authorization": AUTH, "policy": {"max_runs": 5000}, "start": True})
    assert bad.status_code == 422 and bad.json()["code"] == "out_of_range"


async def test_rate_limited_provider_does_not_loop_and_is_reported(api, world):
    world["gravatar"] = 429
    p = await prepare(api, [{"kind": "email", "value": "alex@gmail.com"}], start=True, approved_sources="listed")
    st = await finish(api, p["run"]["id"])
    assert st["status"] != "failed"
    assert sum("api.gravatar.com" in u for u in world["seen"]) <= 3                                    # bounded retries, no runaway loop
    summ = (await api.get(f"{B}/investigations/{p['run']['id']}/summary")).json()
    grav = [s for s in summ["accounting"]["sources"] if s["source_id"] == "gravatar_email"]
    assert grav and grav[0]["status"] in ("failed", "partial", "unavailable", "blocked", "completed")


async def test_pause_cancel_resume_and_authorization_loss(api, world):
    p = await prepare(api, [{"kind": "email", "value": "alex@gmail.com"}])
    st = api.app.state.core
    from osintcc.db.models import Case, Subject
    with st.sm() as db:                                                    # create the run without launching the background driver, so the test controls every step
        run = investigate.start(db, st, db.get(Subject, p["subject_id"]), db.get(Case, p["case_id"]), actor="local-user", approved_sources=["gravatar_email"])
        db.commit()
        rid = run.id
    assert (await api.post(f"{B}/investigations/{rid}/pause")).json()["status"] == "paused"
    assert (await api.post(f"{B}/investigations/{rid}/advance")).json()["finished"] is True
    assert not world["seen"]                                                                           # paused: nothing new starts
    cons = (await api.get(f"{B}/subjects/{p['subject_id']}/consent")).json()["current"]["consent_id"]
    assert (await api.post(f"{B}/subjects/{p['subject_id']}/consent/revoke", json={"consent_id": cons, "reason": "withdrawn"})).status_code == 200
    r = await api.post(f"{B}/investigations/{rid}/resume")
    assert r.status_code == 422 and r.json()["code"] == "authorization_required"
    assert (await api.post(f"{B}/investigations/{rid}/cancel")).json()["status"] == "cancelled"
    assert (await api.post(f"{B}/investigations/{rid}/cancel")).status_code == 422


async def test_restart_resumes_without_repeating_finished_checks(api, world):
    p = await prepare(api, [{"kind": "email", "value": "alex@gmail.com"}], start=True, approved_sources="listed")
    rid = p["run"]["id"]
    st = api.app.state.core
    await finish(api, rid, limit=1)
    before = len(world["seen"])
    with st.sm() as db:
        r = db.get(InvestigationRun, rid)
        r.status = "collecting"                                                                            # as if the app stopped mid-run
        db.commit()
        tasks_before = db.scalar(select(func.count()).select_from(ResearchTask))
    assert investigate.recover(st) == 1
    import asyncio
    await asyncio.gather(*list(st.tasks))
    with st.sm() as db:
        assert db.scalar(select(func.count()).select_from(ResearchTask)) == tasks_before                 # no check was started a second time
    assert len(world["seen"]) >= before


async def test_idempotent_start_isolation_and_roles(api, world):
    p = await prepare(api, [{"kind": "email", "value": "alex@gmail.com"}])
    a = await api.post(f"{B}/subjects/{p['subject_id']}/investigations", json={"idempotency_key": "k1"})
    b = await api.post(f"{B}/subjects/{p['subject_id']}/investigations", json={"idempotency_key": "k1"})
    assert a.json()["id"] == b.json()["id"]
    rid = a.json()["id"]
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="out1", display_name="outsider"))
        db.commit()
    st.tokens["out-token"] = "out1"
    o = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer out-token"})
    for path in (f"/investigations/{rid}", f"/investigations/{rid}/summary", f"/investigations/{rid}/events"):
        assert (await o.get(f"{B}{path}")).status_code == 404
    assert (await o.post(f"{B}/investigations/{rid}/cancel")).status_code == 404
    assert (await o.get(f"{B}/investigations")).json()["items"] == []
    assert (await o.post(f"{B}/investigations/{rid}/advance")).status_code == 404


async def test_bulk_review_is_self_attestation_with_a_preview_exceptions_and_undo(api, world):
    from profile_helpers import seed_candidates, stored_evidence
    p = await prepare(api, [{"kind": "username", "value": "jane_e"}])
    st = api.app.state.core
    seed_candidates(st, p["case_id"], "jane_e", [("sherlock", "https://github.com/jane_e", "GitHub"), ("maigret", "https://github.com/jane_e", "GitHub"), ("sherlock", "https://forum.test/u/jane_e", "Forum")])
    inbox = (await api.get(f"{B}/subjects/{p['subject_id']}/review-inbox")).json()
    accs = [i for i in inbox["items"] if i["kind"] == "account"]
    assert len(accs) == 2 and any(a["signals"] == 1 and len(a["tools"]) == 2 for a in accs)           # two tools on one handle = one signal
    ids = [a["id"] for a in accs]
    ev = stored_evidence(st, p["case_id"], b"unrelated github api capture", "GitHub capture")
    with st.sm() as db:
        from osintcc.db.models import Evidence
        db.get(Evidence, ev).original_url = "https://api.github.com/users/jane_e"
        db.commit()
    pv = (await api.post(f"{B}/subjects/{p['subject_id']}/review-inbox/decide", json={"ids": ids, "action": "mine", "preview": True, "evidence_ids": [ev]})).json()
    assert pv["preview"] is True and pv["counts"]["account"] == 1 and len(pv["exceptions"]) == 1 and "not about" in pv["exceptions"][0]["reason"]
    out = (await api.post(f"{B}/subjects/{p['subject_id']}/review-inbox/decide", json={"ids": ids, "action": "mine", "basis": "my accounts"})).json()
    assert out["applied"] == 2
    doc = (await api.get(f"{B}/subjects/{p['subject_id']}/master")).json()
    foot = [i for s in doc["sections"] if s["key"] == "online_footprint" for i in s["items"] if i["type"] == "account_candidate"]
    assert {i["verification_state"] for i in foot} == {"self_attested"}
    back = await api.post(f"{B}/subjects/{p['subject_id']}/review-inbox/undo", json={"bulk_id": out["bulk_id"]})
    assert back.status_code == 200 and back.json()["reversed"] == 2
    assert (await api.post(f"{B}/subjects/{p['subject_id']}/review-inbox/decide", json={"ids": ids, "action": "mine", "basis": ""})).json()["code"] == "basis_required"


async def test_smart_paste_guesses_types_and_phone_is_masked_everywhere(api, world):
    d = (await api.post(f"{B}/investigations/detect", json={"text": "jane@example.org, https://example.org/me; +1 555 010 4242\n@janedoe, Jane Doe, example.org"})).json()["inputs"]
    assert [x["kind"] for x in d] == ["email", "url", "phone", "username", "name", "domain"]
    assert all(x["alternatives"] for x in d)
    p = await prepare(api, [{"kind": "phone", "value": "+1 555 010 4242"}, {"kind": "email", "value": "x@example.org"}])
    master = (await api.get(f"{B}/subjects/{p['subject_id']}/master")).json()
    assert "4242" not in str(master) and "555 010" not in str(master)
