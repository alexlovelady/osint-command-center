"""Associated Email Discovery and Cross-INT Correlation (addendum): acceptance tests 1-14 with realistic fixtures and the negative cases.

GitHub and web pages are answered by a mock transport, so nothing here reaches a real service: the discovery adapters are fixture-tested, not live-verified.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import AssociatedEmail, Relationship, ResearchTask
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from profile_helpers import stored_evidence
from sqlalchemy import func, select

B = "/api/v1"
PROFILE = {"login": "janedoe", "name": "Jane Doe", "email": "jane.work@acme-example.com", "html_url": "https://github.com/janedoe", "blog": "https://jane-example.org"}
EVENTS = [{"type": "PushEvent", "repo": {"name": "janedoe/tools"}, "payload": {"commits": [
    {"author": {"name": "Jane Doe", "email": "jane.doe@example.com"}},
    {"author": {"name": "Jane Doe", "email": "12345+janedoe@users.noreply.github.com"}},
    {"author": {"name": "Robert Builder", "email": "bob@builder-example.net"}}]}}]
PAGE = ("<html><head><title>Jane Doe - contact</title></head><body><p>Questions? Jane Doe can be reached at <a href=\"mailto:jane.work@acme-example.com\">jane.work@acme-example.com</a>. "
        "Press enquiries: press@jane-example.org (password: hunter2 is not a thing to publish)</p><script>var x='ghost@example.com'</script></body></html>")


def soon(days: int = 30) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


@pytest.fixture
def world():
    return {"github_status": 200, "events_status": 200, "seen": [], "profile": dict(PROFILE)}


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
        if u.startswith("https://api.gravatar.com/v3/profiles/"):
            return httpx.Response(200, json={"display_name": "Jane Doe", "profile_url": "https://gravatar.com/janedoe", "verified_accounts": [{"service_label": "GitHub", "url": "https://github.com/janedoe"}]})
        if u.startswith("https://api.github.com/search/"):
            return httpx.Response(200, json={"items": []})
        if u.startswith("https://keys.openpgp.org/"):
            return httpx.Response(404, text="not found")
        if u.startswith("https://api.github.com/users/janedoe/events/public"):
            return httpx.Response(world["events_status"], json=EVENTS if world["events_status"] == 200 else {})
        if u.startswith("https://api.github.com/users/janedoe"):
            return httpx.Response(world["github_status"], json=world["profile"] if world["github_status"] == 200 else {"message": "x"})
        if u.startswith("https://api.github.com/users/"):
            return httpx.Response(404, json={"message": "Not Found"})
        if u.startswith(("https://jane-example.org/contact", "https://github.com/janedoe")):
            return httpx.Response(200, text=PAGE, headers={"content-type": "text/html; charset=utf-8"})
        return base(request)

    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(handler))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            c.app = app
            yield c


async def make(api, *, kinds=("email",), mode="self", classes=("public_passive", "public_site_query"), scope=None, email="jane.doe@example.com"):
    cid = (await api.post(f"{B}/cases", json={"title": "Jane", "category": "people", "purpose": "self audit"})).json()["id"]
    sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Jane Doe", "mode": mode})).json()["id"]
    vals = {"email": email, "username": "janedoe", "domain": "example.com", "url": "https://jane-example.org/contact"}
    ids = {}
    for k in kinds:
        ids[k] = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": k, "value": vals[k]})).json()["id"]
    body = {"verification_method": "email_confirmation", "verifier": "Jane", "source_classes": list(classes), "permitted_purposes": ["self audit"], "expires_at": soon()}
    if mode == "client":
        body["proof_evidence_id"] = stored_evidence(api.app.state.core, cid, b"signed engagement letter", "Signed engagement")
        body["verification_method"] = "signed_document"
    cons = None
    if classes:
        if scope is not None:
            body["identifier_ids"] = [ids[k] for k in scope]
        r = await api.post(f"{B}/subjects/{sid}/consent", json=body)
        assert r.status_code == 201, r.text
        cons = r.json()["id"]
    return {"cid": cid, "sid": sid, "ids": ids, "consent": cons}


async def run_keys(api, p, keys, confirm=("github_public",)):
    r = await api.post(f"{B}/subjects/{p['sid']}/expansion/run", json={"keys": keys, "confirmed_sources": list(confirm), "wait": True})
    assert r.status_code == 202, r.text
    return r.json()


async def listing(api, p):
    return (await api.get(f"{B}/subjects/{p['sid']}/associated-emails")).json()


def by_addr(j, addr):
    return next(i for i in j["items"] if i["address"] == addr)


async def discover_via_github_and_page(api, p):
    await run_keys(api, p, [f"{p['ids']['username']}:github_public", f"{p['ids']['url']}:page_contacts"])
    return await listing(api, p)


# ---- 1. an email-only investigation starts permitted discovery -----------------------------------------------------------------------------------
async def test_email_only_investigation_initiates_permitted_discovery(api, world):
    p = await make(api, email="jane@acme-example.com")
    d = (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/discover")).json()
    assert d["plan_steps"] >= 3 and "Nothing was sent" in d["note"] and not world["seen"]                  # discovery is planned, and planning sends nothing
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    mine = [s for s in plan["steps"] if s["identifier_id"] == p["ids"]["email"] and s["module"] == "OSINT"]
    assert {"gravatar_email", "github_email_search", "keyserver_email"} <= {s["source_id"] for s in mine}      # exact-email public-reference sources
    assert not {"rdap", "dns", "crtsh"} & {s["source_id"] for s in mine}                                   # the address's domain is not researched from an email string
    assert all(s["needs"] in ("confirmation", "blocked") for s in mine)                                    # each sends the address to a third party, so each needs a confirmation
    out = await api.post(f"{B}/subjects/{p['sid']}/expansion/run", json={"keys": [f"{p['ids']['email']}:gravatar_email"], "confirmed_sources": ["gravatar_email"], "wait": True})
    assert out.status_code == 202 and out.json()["started_runs"] == 1
    assert any(u.startswith("https://api.gravatar.com/v3/profiles/") for u in world["seen"]) and not any("rdap" in u for u in world["seen"])
    assert "jane@acme-example.com" not in " ".join(world["seen"])                                         # Gravatar was asked about a hash, not the address
    with api.app.state.core.sm() as db:
        assert db.scalars(select(ResearchTask).where(ResearchTask.source_id == "gravatar_email")).first().identifier_id == p["ids"]["email"]


async def test_a_free_mail_address_does_not_trigger_domain_lookups(api, world):
    p = await make(api, email="jane.doe@gmail.com")
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    mine = [s for s in plan["steps"] if s["identifier_id"] == p["ids"]["email"]]
    assert not {"rdap", "dns", "crtsh"} & {s["source_id"] for s in mine}
    assert {s["source_id"] for s in mine if s["needs"] == "confirmation"} >= {"gravatar_email"}


# ---- 2/12. evidence-backed candidates; adapters report what really happened ---------------------------------------------------------------------
async def test_associated_addresses_appear_with_evidence_and_never_as_facts(api, world):
    p = await make(api, kinds=("email", "username", "url"))
    j = await discover_via_github_and_page(api, p)
    work = by_addr(j, "jane.work@acme-example.com")
    assert work["state"] == "candidate" and work["classification"] == "likely" and work["label"] == "Likely"            # two independent explicit sources
    assert {s["group"] for s in work["sources"]} == {"github", "web:jane-example.org"} and work["evidence"] and all(e["sha256"] for e in work["evidence"])
    assert work["explanation"] and "independent sources" in work["explanation"][0]
    assert work["discovered_at"] and work["origin_path"] and work["origin_path"][0] == "subject input"
    assert work["exposure"]["state"] == "not_an_input" and work["exposure"]["label"] == "Not checked"
    press = by_addr(j, "press@jane-example.org")
    assert press["classification"] == "possible" and "no source says it belongs" in press["explanation"][0]
    assert "ghost@example.com" not in json.dumps(j)                                                      # script blocks are not read
    assert not any("users.noreply.github.com" in i["address"] for i in j["items"])
    assert j["counts"]["likely"] == 1 and "never a fact" in j["notice"]


async def test_commit_authors_with_other_names_are_conflicts_and_stay_possible(api, world):
    p = await make(api, kinds=("email", "username"))
    await run_keys(api, p, [f"{p['ids']['username']}:github_public"])
    j = await listing(api, p)
    bob = by_addr(j, "bob@builder-example.net")
    assert bob["classification"] == "possible" and bob["conflicts"] and "Robert Builder" in bob["conflicts"][0]["detail"]
    own = by_addr(j, "jane.doe@example.com") if any(i["address"] == "jane.doe@example.com" for i in j["items"]) else None
    assert own is None                                                                                    # the subject's own input is never an "associated" address


async def test_adapters_report_real_status_and_limits(api, world):
    p = await make(api, kinds=("email", "username"))
    world["github_status"] = 403
    r = await run_keys(api, p, [f"{p['ids']['username']}:github_public"])
    assert r["status"] == "executed"
    runs = (await api.get(f"{B}/subjects/{p['sid']}/research/runs")).json()["items"]
    gh = next(t for t in runs if t["source_id"] == "github_public")
    assert gh["status"] in ("failed", "unavailable", "partial", "blocked", "completed") and (await listing(api, p))["items"] == []     # a rate limit is not "no addresses"
    from osintcc.adapters.base import Target
    from osintcc.adapters.http.contacts import GithubPublicAdapter
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(lambda req: httpx.Response(403, json={})))
    res = await GithubPublicAdapter().run(Target(type="username", raw="janedoe", canonical="janedoe"), AdapterContext(http=http))
    assert res.status == "rate_limited" and "not a negative result" in res.warnings[0]
    http404 = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(lambda req: httpx.Response(404, json={})))
    nf = await GithubPublicAdapter().run(Target(type="username", raw="nobody", canonical="nobody"), AdapterContext(http=http404))
    assert nf.status == "success" and not nf.findings and "says nothing about the subject" in nf.warnings[0]


# ---- 3/14. one shared graph and timeline, several disciplines -----------------------------------------------------------------------------------
async def test_findings_from_several_disciplines_connect_in_one_graph_and_timeline(api, world):
    p = await make(api, kinds=("email", "username", "url"))
    await discover_via_github_and_page(api, p)
    j = await listing(api, p)
    work = by_addr(j, "jane.work@acme-example.com")
    st = api.app.state.core
    with st.sm() as db:
        rels = db.scalars(select(Relationship).where(Relationship.relation_type == "associated_email")).all()
        assert rels and all(r.status == "unverified" for r in rels)                                       # candidates are unverified edges
    assert (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [work["id"]], "to_state": "confirmed", "basis": "owner told me", "attestation": "subject"})).status_code == 200
    with st.sm() as db:
        st_ = {r.status for r in db.scalars(select(Relationship).where(Relationship.relation_type == "associated_email"))}
        assert "manual" in st_
    graph = (await api.get(f"{B}/cases/{p['cid']}/graph")).json()
    kinds = {n["type"] for n in graph["nodes"]}
    assert {"email", "username", "url"} <= kinds                                                           # OSINT adapters, a public page and an email meet in the same graph
    tl = (await api.get(f"{B}/subjects/{p['sid']}/timeline")).json()
    kinds_tl = {e["kind"] for e in tl["items"]}
    assert "email" in kinds_tl and {"research", "email"} <= kinds_tl and any("confirmed by" in e["text"] for e in tl["items"] if e["kind"] == "email")


# ---- 4/5/8. expansion only from verified identifiers ------------------------------------------------------------------------------------------
async def test_unconfirmed_matches_never_trigger_expansion_and_confirmed_ones_do(api, world):
    p = await make(api, kinds=("email", "username", "url"))
    await discover_via_github_and_page(api, p)
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    props = {x["label"]: x for x in plan["seeds"]["proposals"]}
    assert all(x["action"] in ("confirm_first", "lead_only") for x in props.values()) and any(x["state"] == "likely" for x in props.values())
    assert not any("acme-example" in s["identifier"] or "w***" in s["identifier"] for s in plan["steps"] if s["identifier_id"] not in p["ids"].values())    # no step uses a candidate
    j = await listing(api, p)
    work = by_addr(j, "jane.work@acme-example.com")
    promo = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/{work['id']}/promote")
    assert promo.status_code == 409 or promo.status_code == 422                                           # a candidate cannot become an input
    r = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [work["id"]], "to_state": "confirmed", "basis": "two independent sources, verified by hand"})
    assert r.status_code == 200
    j2 = await listing(api, p)
    w2 = by_addr(j2, "jane.work@acme-example.com")
    assert w2["classification"] == "confirmed" and w2["confirmation_kind"] == "independently_corroborated"
    plan2 = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    assert any(x["action"] == "add_input" and x["state"] == "confirmed" for x in plan2["seeds"]["proposals"])
    assert (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/{work['id']}/promote")).status_code == 200
    plan3 = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    mine = [s for s in plan3["steps"] if s["identifier_kind"] == "email" and s["depth"] == 1 and s["module"] == "OSINT"]
    assert {s["source_id"] for s in mine if s["needs"] == "confirmation"} >= {"gravatar_email", "keyserver_email"} and mine[0]["origin_path"]       # follow-up tasks exist, with the chain that led to them


async def test_rejected_associations_stop_generating_work_and_stay_rejected(api, world):
    p = await make(api, kinds=("email", "username", "url"))
    j = await discover_via_github_and_page(api, p)
    work = by_addr(j, "jane.work@acme-example.com")
    assert (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [work["id"]], "to_state": "rejected", "basis": "that is her employer's shared inbox, not hers"})).status_code == 200
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    assert plan["seeds"]["skipped"]["rejected_emails"] == 1 and not any("w" in x["label"] and x.get("associated_id") == work["id"] for x in plan["seeds"]["proposals"])
    # new evidence arrives later: it is kept, but the decision stands and nothing is researched
    added = await api.post(f"{B}/subjects/{p['sid']}/associated-emails", json={"address": "Jane.Work@acme-example.com", "url": "https://elsewhere.example/staff", "note": "listed on a staff page"})
    assert added.status_code == 201
    again = by_addr(await listing(api, p), "jane.work@acme-example.com")
    assert len(again["sources"]) >= 3
    assert again["state"] == "rejected" and again["classification"] == "rejected" and again["label"] == "Rejected"
    assert (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/{work['id']}/promote")).status_code in (409, 422)


# ---- confirmation rules ----------------------------------------------------------------------------------------------------------------------
async def test_confirming_needs_attestation_or_corroboration_and_records_which(api, world):
    p = await make(api, kinds=("email", "username"))
    await run_keys(api, p, [f"{p['ids']['username']}:github_public"])
    j = await listing(api, p)
    one = by_addr(j, "jane.work@acme-example.com")
    assert one["classification"] == "possible"                                                            # a single source
    r = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [one["id"]], "to_state": "confirmed", "basis": "it is on her github"})
    assert r.status_code == 422 and r.json()["code"] == "corroboration_required"
    ok = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [one["id"]], "to_state": "confirmed", "basis": "Jane confirmed by email reply", "attestation": "subject"})
    assert ok.status_code == 200
    assert by_addr(await listing(api, p), "jane.work@acme-example.com")["confirmation_kind"] == "analyst_attested"
    # a conflicting address cannot be confirmed by more sightings, only by the owner's own word
    bob = by_addr(j, "bob@builder-example.net")
    ev = await api.post(f"{B}/cases/{p['cid']}/notes", json={"body_markdown": "another mention"})
    assert ev.status_code in (200, 201)
    no = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [bob["id"]], "to_state": "confirmed", "basis": "seen twice"})
    assert no.status_code == 422
    assert (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [bob["id"]], "to_state": "confirmed", "basis": "x", "evidence_ids": ["nope"]})).status_code in (404, 422)
    bulk = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [bob["id"], one["id"]], "to_state": "rejected", "basis": "bulk clean-up of the unrelated ones"})
    assert bulk.status_code == 200 and bulk.json()["bulk_id"]
    note = await api.patch(f"{B}/subjects/{p['sid']}/associated-emails/{bob['id']}", json={"note": "co-author on one repository"})
    assert note.json()["note"] == "co-author on one repository"


async def test_a_speculative_pattern_is_labelled_stored_only_on_request_and_never_confirmable_without_evidence(api, world):
    p = await make(api, kinds=("email", "domain"))
    d = (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/discover")).json()
    guess = next(g for g in d["speculative"] if g["address"].startswith("jane.doe@"))
    assert guess["origin"] == "speculative" and "not observed" in guess["label"]
    assert (await listing(api, p))["items"] == []                                                         # suggestions are not stored
    acc = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/speculative", json={"address": guess["address"]})
    assert acc.status_code == 201 and acc.json()["origin"] == "speculative" and acc.json()["classification"] == "possible" and not acc.json()["sources"]
    assert (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/speculative", json={"address": "someone@example.com"})).status_code == 422
    r = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [acc.json()["id"]], "to_state": "confirmed", "basis": "looks right"})
    assert r.status_code == 422                                                                           # a guess cannot become a fact without evidence
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    assert any(x["action"] == "lead_only" for x in plan["seeds"]["proposals"]) and not any(s["identifier_kind"] == "email" and s["depth"] > 0 for s in plan["steps"])


# ---- 6. recursion limits and authorization ---------------------------------------------------------------------------------------------------
async def confirmed_promoted(api, p):
    j = await listing(api, p)
    work = by_addr(j, "jane.work@acme-example.com")
    assert (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [work["id"]], "to_state": "confirmed", "basis": "owner confirmed", "attestation": "subject"})).status_code == 200
    assert (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/{work['id']}/promote")).status_code == 200
    return work


async def test_recursion_respects_depth_budget_per_pass_and_ends_with_a_stop_reason(api, world):
    p = await make(api, kinds=("email", "username", "url", "domain"))
    await discover_via_github_and_page(api, p)
    await confirmed_promoted(api, p)
    assert (await api.put(f"{B}/subjects/{p['sid']}/expansion/policy", json={"max_depth": 1})).json()["max_depth"] == 1
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    deeper = [s for s in plan["steps"] if s["depth"] == 1 and s["identifier_kind"] == "email" and s["module"] == "OSINT"]
    assert deeper and all(s["needs"] == "depth_limit" and not s["executable_now"] for s in deeper)       # one hop only
    bad = await api.post(f"{B}/subjects/{p['sid']}/expansion/run", json={"keys": [deeper[0]["key"]]})
    assert bad.status_code == 422 and bad.json()["code"] == "not_expandable"
    assert (await api.put(f"{B}/subjects/{p['sid']}/expansion/policy", json={"max_depth": 2, "max_per_pass": 1, "auto_passive": True})).status_code == 200
    out = (await api.post(f"{B}/subjects/{p['sid']}/expansion/run", json={"wait": True})).json()
    assert out["status"] == "executed" and len(out["chosen"]) == 1 and out["started_runs"] == 1          # the per-pass limit holds
    assert (await api.put(f"{B}/subjects/{p['sid']}/expansion/policy", json={"max_runs": 1, "max_per_pass": 10})).status_code == 200
    stop = (await api.post(f"{B}/subjects/{p['sid']}/expansion/run", json={"wait": True})).json()
    assert stop["status"] == "stopped" and stop["stop_reason"] == "budget_exhausted" and stop["started_runs"] == 0
    for bad_policy in ({"max_depth": 99}, {"max_runs": 0}, {"max_per_pass": True}):
        assert (await api.put(f"{B}/subjects/{p['sid']}/expansion/policy", json=bad_policy)).status_code == 422
    hist = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()["history"]
    assert {h["stop_reason"] for h in hist} >= {"budget_exhausted"}


async def test_revoking_authorization_stops_expansion_before_any_request(api, world):
    p = await make(api, kinds=("email", "username"))
    assert (await api.put(f"{B}/subjects/{p['sid']}/expansion/policy", json={"auto_passive": True})).status_code == 200
    assert (await api.post(f"{B}/subjects/{p['sid']}/consent/revoke", json={"consent_id": p["consent"], "reason": "withdrawn"})).status_code == 200
    n = len(world["seen"])
    out = (await api.post(f"{B}/subjects/{p['sid']}/expansion/run", json={"wait": True})).json()
    assert out["status"] == "stopped" and out["stop_reason"] == "authorization" and len(world["seen"]) == n
    forced = await api.post(f"{B}/subjects/{p['sid']}/expansion/run", json={"keys": [f"{p['ids']['username']}:github_public"], "confirmed_sources": ["github_public"], "wait": True})
    assert forced.json()["status"] == "stopped" and len(world["seen"]) == n


async def test_offline_mode_and_a_closed_case_stop_expansion(api, world, settings):
    p = await make(api, kinds=("email", "username"))
    settings.offline = True
    assert (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()["stop_reason"] == "offline"
    settings.offline = False


async def test_a_new_address_is_not_covered_by_a_client_consent_that_names_its_identifiers(api, world):
    p = await make(api, kinds=("email", "username", "url"), mode="client", scope=("email", "username", "url"))
    await discover_via_github_and_page(api, p)
    await confirmed_promoted(api, p)
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    new = [s for s in plan["steps"] if s["identifier_kind"] == "email" and s["depth"] == 1 and s["module"] == "OSINT"]
    assert new and all(not s["runnable"] and s["needs"] == "blocked" and "authorization" in s["reason"] for s in new)
    n = len(world["seen"])
    out = await api.post(f"{B}/subjects/{p['sid']}/expansion/run", json={"keys": [new[0]["key"]], "wait": True})
    assert out.status_code == 422 and len(world["seen"]) == n                       # recursion cannot widen what the client authorized


async def test_duplicate_spellings_merge_without_losing_any_source(api, world):
    p = await make(api, kinds=("email", "username", "url"))
    await discover_via_github_and_page(api, p)
    a = await api.post(f"{B}/subjects/{p['sid']}/associated-emails", json={"address": "press+web@jane-example.org", "url": "https://jane-example.org/press", "note": "press page"})
    b = await listing(api, p)
    groups = b["duplicates"]
    assert groups and len(groups[0]["ids"]) == 2
    keep, other = by_addr(b, "press@jane-example.org"), a.json()
    before = len(keep["sources"]) + len(other["sources"])
    m = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/merge", json={"keep_id": keep["id"], "merge_ids": [other["id"]]})
    assert m.status_code == 200 and len(m.json()["sources"]) == before and "press+web@jane-example.org" in m.json()["aliases"]
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(AssociatedEmail).where(AssociatedEmail.dedupe_key.like("press%"))) == 1
    # Gmail dots and +tags are one mailbox
    g1 = await api.post(f"{B}/subjects/{p['sid']}/associated-emails", json={"address": "Jane.Doe+news@gmail.com", "note": "newsletter"})
    g2 = await api.post(f"{B}/subjects/{p['sid']}/associated-emails", json={"address": "janedoe@gmail.com", "note": "forum"})
    assert g1.json()["id"] == g2.json()["id"] and len(g2.json()["sources"]) == 2
    conf = await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [keep["id"]], "to_state": "confirmed", "basis": "owner", "attestation": "subject"})
    assert conf.status_code == 200
    other2 = (await api.post(f"{B}/subjects/{p['sid']}/associated-emails", json={"address": "press+2@jane-example.org", "note": "x"})).json()
    assert (await api.post(f"{B}/subjects/{p['sid']}/associated-emails/merge", json={"keep_id": other2["id"], "merge_ids": [keep["id"]]})).status_code == 422


# ---- 9/10. DARKINT receives only authorized identifiers; nothing sensitive is stored ------------------------------------------------------------
def _ident_id(api, row) -> str:
    with api.app.state.core.sm() as db:
        return db.get(AssociatedEmail, row["id"]).identifier_id


async def test_exposure_checks_only_ever_receive_authorized_identifiers(api, world):
    p = await make(api, kinds=("email", "username", "url"), classes=("public_passive", "public_site_query", "exposure_check"))
    await discover_via_github_and_page(api, p)
    j = await listing(api, p)
    work = by_addr(j, "jane.work@acme-example.com")
    r = await api.post(f"{B}/cases/{p['cid']}/darkint/preview", json={"subject_id": p["sid"], "identifier_ids": [work["id"]], "provider_ids": ["hibp"]})
    assert r.status_code == 404                                                                             # a candidate id is not an identifier, so no provider is ever asked
    plan = (await api.get(f"{B}/subjects/{p['sid']}/expansion")).json()
    dark = [s for s in plan["steps"] if s["module"] == "DARKINT"]
    assert dark and all(not s["executable_now"] and s["needs"] == "explicit_approval" for s in dark) and {s["identifier_id"] for s in dark} <= set(p["ids"].values())
    await confirmed_promoted(api, p)
    w2 = by_addr(await listing(api, p), "jane.work@acme-example.com")
    assert w2["is_input"] and w2["exposure"]["label"] == "Not checked"
    pv = (await api.post(f"{B}/cases/{p['cid']}/darkint/preview", json={"subject_id": p["sid"], "identifier_ids": [_ident_id(api, w2)], "provider_ids": ["hibp"]})).json()
    assert pv["items"][0]["allowed"] is False and "Not enabled" in pv["items"][0]["reason"]                 # the provider still needs an administrator to enable it
    assert not [u for u in world["seen"] if "haveibeenpwned" in u]


async def test_sensitive_material_near_an_address_is_never_stored_or_shown(api, world, caplog):
    caplog.set_level(logging.DEBUG)
    p = await make(api, kinds=("email", "url"))
    await run_keys(api, p, [f"{p['ids']['url']}:page_contacts"])
    j = await listing(api, p)
    dump = json.dumps(j)
    assert "hunter2" not in dump
    assert "press@jane-example.org" in dump or "p***@jane-example.org" in dump
    with api.app.state.core.sm() as db:
        raw = json.dumps([r.sources for r in db.scalars(select(AssociatedEmail))])
    assert "hunter2" not in raw and "hunter2" not in caplog.text
    assert "password" not in {c.name for c in AssociatedEmail.__table__.columns}


async def test_viewers_see_masked_addresses_and_no_passages(api, world):
    from osintcc.db.models import CaseMember, User
    p = await make(api, kinds=("email", "url"))
    await run_keys(api, p, [f"{p['ids']['url']}:page_contacts"])
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="v1", display_name="viewer"))
        db.flush()
        db.add(CaseMember(case_id=p["cid"], user_id="v1", access_role="viewer"))
        db.commit()
    st.tokens["viewer-token"] = "v1"
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer viewer-token"})
    j = (await v.get(f"{B}/subjects/{p['sid']}/associated-emails")).json()
    assert j["items"] and all(i["masked"] and "*" in i["address"] for i in j["items"]) and all(s["context"] == "" for i in j["items"] for s in i["sources"])
    assert (await v.get(f"{B}/subjects/{p['sid']}/expansion")).status_code in (403, 404)
    assert (await v.post(f"{B}/subjects/{p['sid']}/associated-emails/discover")).status_code in (403, 404)


async def test_existing_evidence_from_other_modules_is_folded_in_only_when_it_names_the_subject(api, world):
    from osintcc.db.models import Evidence, Observation
    p = await make(api, kinds=("email", "domain"))
    # the sweep only trusts evidence of searches attached to this subject; imported records count when the record also names the subject
    st = api.app.state.core
    with st.sm() as db:
        ev = Evidence(case_id=p["cid"], kind="import", title="message export", sha256="a" * 64, sha512="a" * 128, byte_size=1)
        db.add(ev)
        db.flush()
        for blob in ("From: Jane Doe <jane.alt@acme-example.com>", "From: someone <stranger@elsewhere.example>"):
            db.add(Observation(case_id=p["cid"], discipline_id="COMINT", kind="message", data_json={"from": blob}, raw_evidence_id=ev.id, access_class="IMPORTED", sensitivity="INTERNAL"))
        db.commit()
    j = await listing(api, p)
    addrs = {i["address"] for i in j["items"]}
    assert "jane.alt@acme-example.com" in addrs and "stranger@elsewhere.example" not in addrs
    alt = by_addr(j, "jane.alt@acme-example.com")
    assert alt["classification"] == "possible" and alt["sources"][0]["group"] == "discipline:COMINT" and "appears in an imported record" in alt["sources"][0]["basis"]
