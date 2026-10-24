from __future__ import annotations

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import User
from osintcc.graph.fusion import confidence_label
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


def pick(evs, kind):
    return next(e for e in evs if e["kind"].startswith(kind))


async def seeded(api):
    cid = (await api.post("/api/v1/cases", json={"title": "F", "purpose": "fusion tests"})).json()["id"]
    await api.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "wait": True})
    ents = (await api.get(f"/api/v1/cases/{cid}/entities?limit=1000")).json()["items"]
    evs = (await api.get(f"/api/v1/cases/{cid}/evidence")).json()["items"]
    return cid, ents, evs


def test_confidence_heuristics_are_labels_with_published_rules():
    assert confidence_label(0, False, False) == "unknown"
    assert confidence_label(1, False, False) == "low"
    assert confidence_label(1, False, True) == "medium"  # single official registry
    assert confidence_label(2, False, False) == "medium"
    assert confidence_label(2, True, False) == "high" and confidence_label(3, False, False) == "high"
    assert confidence_label(5, True, True, "rejected") == "unknown"
    assert confidence_label(5, True, True, "disputed") == "low"  # dispute caps confidence


async def test_claim_needs_evidence_and_rejects_cross_case_citations(api):
    cid, ents, evs = await seeded(api)
    dom = next(e for e in ents if e["key"] == "example.com")
    base = {"case_id": cid, "subject_entity_id": dom["id"], "predicate": "registrar", "value": "Reg A"}
    assert (await api.post("/api/v1/claims", json={**base, "sources": []})).status_code == 422
    assert (await api.post("/api/v1/claims", json={**base, "sources": [{"evidence_id": evs[0]["id"]}],
                                                   "value": None})).status_code == 422  # no object/value
    other = (await api.post("/api/v1/cases", json={"title": "Other", "purpose": "x"})).json()["id"]
    foreign = (await api.post(f"/api/v1/cases/{other}/evidence/import?filename=x.txt&consent_confirmed=true",
                              content=b"foreign")).json()
    bad = await api.post("/api/v1/claims", json={**base, "sources": [{"evidence_id": foreign["id"]}]})
    assert bad.status_code == 422 and bad.json()["code"] == "invalid_citation"
    ok = await api.post("/api/v1/claims", json={**base, "sources": [{"evidence_id": pick(evs, "dns")["id"], "independent_source_group": "g1"}]})
    assert ok.status_code == 201 and ok.json()["confidence_label"] == "low" and ok.json()["verification_status"] == "unverified"


async def test_independence_drives_label_and_verification_is_analyst_only(api):
    cid, ents, evs = await seeded(api)
    dom = next(e for e in ents if e["key"] == "example.com")
    c = (await api.post("/api/v1/claims", json={"case_id": cid, "subject_entity_id": dom["id"], "predicate": "p", "value": 1,
                                                "sources": [{"evidence_id": pick(evs, "dns")["id"], "independent_source_group": "A"}]})).json()
    same_group = (await api.post(f"/api/v1/claims/{c['id']}/sources", json={"evidence_id": pick(evs, "wayback")["id"], "independent_source_group": "A"})).json()
    assert same_group["independent_source_groups"] == 1 and same_group["confidence_label"] == "low"  # copies don't corroborate
    dup = await api.post(f"/api/v1/claims/{c['id']}/sources", json={"evidence_id": pick(evs, "wayback")["id"]})
    assert dup.status_code == 409
    two = (await api.post(f"/api/v1/claims/{c['id']}/sources", json={"evidence_id": pick(evs, "crtsh")["id"], "independent_source_group": "B"})).json()
    assert two["independent_source_groups"] == 2 and two["confidence_label"] == "medium"
    v = (await api.post(f"/api/v1/claims/{c['id']}/verification", json={"status": "analyst_verified"})).json()
    assert v["confidence_label"] == "high"
    d = (await api.post(f"/api/v1/claims/{c['id']}/verification", json={"status": "disputed"})).json()
    assert d["confidence_label"] == "low"
    back = (await api.post(f"/api/v1/claims/{c['id']}/verification", json={"status": "unverified"})).json()
    assert back["confidence_label"] == "medium"  # reversible


async def test_contradictions_preserved_side_by_side(api):
    cid, ents, evs = await seeded(api)
    dom = next(e for e in ents if e["key"] == "example.com")
    mk = lambda v, e: api.post("/api/v1/claims", json={"case_id": cid, "subject_entity_id": dom["id"], "predicate": "registrar",
                                                       "value": v, "sources": [{"evidence_id": e}]})
    a, b = (await mk("Registrar A", evs[0]["id"])).json(), (await mk("Registrar B", evs[1]["id"])).json()
    agree = (await mk("Registrar A", evs[2]["id"])).json()
    items = (await api.get(f"/api/v1/cases/{cid}/contradictions")).json()["items"]
    assert len(items) == 1 and {p["value"] for p in items[0]["positions"]} == {"Registrar A", "Registrar B"}
    assert len(items[0]["positions"]) == 3 and {a["id"], b["id"], agree["id"]} == {p["id"] for p in items[0]["positions"]}
    await api.post(f"/api/v1/claims/{b['id']}/verification", json={"status": "rejected"})
    assert (await api.get(f"/api/v1/cases/{cid}/contradictions")).json()["items"] == []  # resolved by analyst, not deleted
    assert (await api.get(f"/api/v1/claims?case_id={cid}&verification_status=rejected")).json()["total"] == 1


async def test_provenance_chain_reaches_hashed_evidence(api):
    cid, _ents, _ = await seeded(api)
    findings = (await api.get(f"/api/v1/cases/{cid}/findings?limit=500")).json()["items"]
    reg = next(f for f in findings if f["predicate"] == "rdap.registrar")
    c = (await api.post("/api/v1/claims/from-finding", json={"finding_id": reg["id"]})).json()
    assert c["confidence_label"] == "medium"  # one official registry source
    pv = (await api.get(f"/api/v1/claims/{c['id']}/provenance")).json()["provenance"][0]
    assert pv["evidence"]["sha256"] and pv["source"]["adapter"] == "rdap" and pv["group"] == "rdap"
    assert pv["evidence"]["chain_of_custody"][0]["event"] == "captured"


async def test_hypotheses_tally_not_probability_and_case_scoping(api):
    cid, ents, evs = await seeded(api)
    dom = next(e for e in ents if e["key"] == "example.com")
    c = (await api.post("/api/v1/claims", json={"case_id": cid, "subject_entity_id": dom["id"], "predicate": "p", "value": 1,
                                                "sources": [{"evidence_id": evs[0]["id"]}]})).json()
    h = (await api.post("/api/v1/hypotheses", json={"case_id": cid, "statement": "Domain is operated by X"})).json()
    r = (await api.post(f"/api/v1/hypotheses/{h['id']}/claims", json={"claim_id": c["id"], "stance": "contradict"})).json()
    assert r["tally"] == {"support": 0, "contradict": 1, "neutral": 0} and "probability" in r["note"] and r["status"] == "open"
    assert (await api.patch(f"/api/v1/hypotheses/{h['id']}", json={"status": "refuted"})).json()["status"] == "refuted"
    other = (await api.post("/api/v1/cases", json={"title": "O", "purpose": "x"})).json()["id"]
    h2 = (await api.post("/api/v1/hypotheses", json={"case_id": other, "statement": "other case hyp"})).json()
    assert (await api.post(f"/api/v1/hypotheses/{h2['id']}/claims", json={"claim_id": c["id"]})).status_code == 422


async def test_requirements_gap_assessment(api):
    cid, _ents, evs = await seeded(api)
    r = (await api.post("/api/v1/requirements", json={"case_id": cid, "question": "Who hosts example.com?", "objective": "attribution",
                                                      "priority": "high", "collection_constraint": "passive only"})).json()
    gaps = (await api.get(f"/api/v1/cases/{cid}/gaps")).json()
    assert [x["id"] for x in gaps["unanswered_requirements"]] == [r["id"]] and gaps["requirements_without_evidence"] == [r["id"]]
    no = await api.patch(f"/api/v1/requirements/{r['id']}", json={"answer_status": "answered"})
    assert no.status_code == 422 and no.json()["code"] == "no_evidence"
    await api.post(f"/api/v1/requirements/{r['id']}/evidence", json={"evidence_id": evs[0]["id"], "relevance_note": "dns"})
    assert (await api.patch(f"/api/v1/requirements/{r['id']}", json={"answer_status": "answered"})).json()["answer_status"] == "answered"
    gaps = (await api.get(f"/api/v1/cases/{cid}/gaps")).json()
    assert gaps["unanswered_requirements"] == [] and gaps["requirements_without_evidence"] == []


async def test_entity_merge_is_reversible_and_never_touches_underlying_data(api):
    cid, ents, _evs = await seeded(api)
    a = next(e for e in ents if e["key"] == "www.example.com")
    b = next(e for e in ents if e["key"] == "mail.example.com")
    ip = next(e for e in ents if e["type"] == "ip")
    n_before = (await api.get(f"/api/v1/cases/{cid}/entities?limit=1000")).json()["total"]
    g0 = (await api.get(f"/api/v1/cases/{cid}/graph")).json()
    mk = lambda x, y: api.post(f"/api/v1/cases/{cid}/entity-links", json={"entity_id": x["id"], "canonical_entity_id": y["id"], "reason": "same host"})
    assert (await mk(a, a)).status_code == 409 and (await mk(a, ip)).json()["code"] == "type_mismatch"
    link = (await mk(a, b)).json()
    assert (await mk(a, b)).status_code == 409 and (await mk(b, a)).json()["code"] == "merge_cycle"
    merged = (await api.get(f"/api/v1/cases/{cid}/graph?apply_merges=true")).json()
    assert a["id"] not in {n["id"] for n in merged["nodes"]} and b["id"] in {n["id"] for n in merged["nodes"]}
    assert all(e["source"] != a["id"] and e["target"] != a["id"] for e in merged["edges"])
    assert (await api.get(f"/api/v1/cases/{cid}/entities?limit=1000")).json()["total"] == n_before  # data untouched
    assert {n["id"] for n in (await api.get(f"/api/v1/cases/{cid}/graph")).json()["nodes"]} == {n["id"] for n in g0["nodes"]}
    assert (await api.post(f"/api/v1/entity-links/{link['id']}/revert")).json()["status"] == "reverted"
    after = (await api.get(f"/api/v1/cases/{cid}/graph?apply_merges=true")).json()
    assert {n["id"] for n in after["nodes"]} == {n["id"] for n in g0["nodes"]}  # split restores the original view


async def test_collection_plan_preview_approve_cancel_and_policy(api, calls):
    cid = (await api.post("/api/v1/cases", json={"title": "P", "purpose": "plan tests"})).json()["id"]
    body = {"case_id": cid, "target": "example.com", "reason": "baseline passive overview"}
    pv = (await api.post("/api/v1/collection-plans/preview", json=body)).json()
    assert calls == [] and pv["policy_status"] == "allowed" and pv["recursion"].startswith("none") and pv["budget"]["paid_requests"] == 0
    assert (await api.post("/api/v1/collection-plans/preview", json={**body, "reason": ""})).status_code == 422
    plan = (await api.post("/api/v1/collection-plans", json=body)).json()
    assert calls == [] and plan["status"] == "draft"
    ok = await api.post(f"/api/v1/collection-plans/{plan['id']}/approve", json={"wait": True})
    assert ok.status_code == 202 and len(calls) >= 3
    got = (await api.get(f"/api/v1/collection-plans/{plan['id']}")).json()
    assert got["status"] == "approved" and any(s["status"] == "succeeded" for s in got["steps"])
    assert (await api.post(f"/api/v1/collection-plans/{plan['id']}/approve", json={})).status_code == 409  # not draft anymore
    # a username plan needs explicit confirmation and is refused without it; denied plans never start
    u = {"case_id": cid, "target": "someone", "target_type": "username", "adapters": ["sherlock"], "mode": "public_site_query",
         "reason": "brand impersonation check"}
    up = (await api.post("/api/v1/collection-plans", json=u)).json()
    assert up["policy_status"] == "needs_confirmation"
    n = len(calls)
    assert (await api.post(f"/api/v1/collection-plans/{up['id']}/approve", json={})).status_code == 409
    assert len(calls) == n
    d = (await api.post("/api/v1/collection-plans", json={**u, "adapters": ["rdap"]})).json()  # rdap cannot take a username
    assert d["policy_status"] == "denied"
    assert (await api.post(f"/api/v1/collection-plans/{d['id']}/approve", json={})).json()["code"] == "policy_denied"
    assert (await api.post(f"/api/v1/collection-plans/{up['id']}/cancel")).json()["status"] == "cancelled"


async def test_plan_is_reevaluated_at_approval_time(api, calls):
    cid = (await api.post("/api/v1/cases", json={"title": "P2", "purpose": "x"})).json()["id"]
    plan = (await api.post("/api/v1/collection-plans", json={"case_id": cid, "target": "example.com", "reason": "later offline"})).json()
    await api.put("/api/v1/settings", json={"values": {"offline": True}})
    r = await api.post(f"/api/v1/collection-plans/{plan['id']}/approve", json={"wait": True})
    assert r.status_code == 409 and calls == []  # offline now: stale approval cannot start network work


async def test_second_actor_cannot_touch_fusion_objects(api):
    cid, ents, evs = await seeded(api)
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="u9", display_name="x"))
        db.commit()
    st.tokens["t9"] = "u9"
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer t9"})
    dom = next(e for e in ents if e["key"] == "example.com")
    c = (await api.post("/api/v1/claims", json={"case_id": cid, "subject_entity_id": dom["id"], "predicate": "p", "value": 1,
                                                "sources": [{"evidence_id": evs[0]["id"]}]})).json()
    for method, url, body in [("GET", f"/api/v1/claims?case_id={cid}", None), ("GET", f"/api/v1/claims/{c['id']}/provenance", None),
                              ("POST", f"/api/v1/claims/{c['id']}/verification", {"status": "analyst_verified"}),
                              ("GET", f"/api/v1/cases/{cid}/contradictions", None), ("GET", f"/api/v1/cases/{cid}/gaps", None),
                              ("POST", "/api/v1/requirements", {"case_id": cid, "question": "q"}),
                              ("POST", "/api/v1/hypotheses", {"case_id": cid, "statement": "stmt"}),
                              ("POST", "/api/v1/collection-plans", {"case_id": cid, "target": "example.com", "reason": "abc"})]:
        r = await other.request(method, url, json=body)
        assert r.status_code == 404, (method, url, r.status_code)


async def test_heuristics_are_published(api):
    h = (await api.get("/api/v1/fusion/heuristics")).json()
    assert {"unknown", "low", "medium", "high"} <= set(h) and "not probabilities" in h["note"]
