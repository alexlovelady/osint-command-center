"""Target profile (TP1/TP2): migration safety, lazy upgrade, subjects/identifiers/claims, candidate queue, bulk review and reversal.

Acceptance: TP-01, TP-02 (API side), TP-05, TP-06, TP-07, TP-10 (no model path promotes a candidate)."""
from __future__ import annotations

import hashlib
import uuid

import httpx
import pytest
from alembic import command
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db import make_engine
from osintcc.db.migrate import _cfg, current_revision, head_revision, upgrade_to_head
from osintcc.db.models import Entity, Evidence, Finding, Relationship, Target
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import text

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


async def people_case(api, purpose="self-audit of my own public footprint"):
    return (await api.post(f"{B}/cases", json={"title": "Jane Example", "category": "people", "purpose": purpose})).json()["id"]


def mk_evidence(db, case_id, title="e", kind="note"):
    h = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    ev = Evidence(case_id=case_id, kind=kind, title=title, sha256=h, sha512=h * 2, byte_size=1, vault_relpath=None)
    db.add(ev)
    db.flush()
    return ev


def seed_candidates(api, case_id, username, sightings):
    """sightings: list of (adapter_id, url, site). Mirrors what Sherlock/Maigret persist: username entity, url entity,
    candidate_profile relationship and a `profile.candidate` finding with its own evidence."""
    with api.app.state.core.sm() as db:
        user = db.query(Entity).filter_by(case_id=case_id, type="username", canonical_key=username).first()
        if not user:
            user = Entity(case_id=case_id, type="username", canonical_key=username, display_name=username)
            db.add(user)
            db.flush()
        for adapter, url, site in sightings:
            ent = db.query(Entity).filter_by(case_id=case_id, type="url", canonical_key=url).first()
            if not ent:
                ent = Entity(case_id=case_id, type="url", canonical_key=url, display_name=url)
                db.add(ent)
                db.flush()
            if not db.query(Relationship).filter_by(case_id=case_id, from_entity_id=user.id, to_entity_id=ent.id, relation_type="candidate_profile").first():
                db.add(Relationship(case_id=case_id, from_entity_id=user.id, to_entity_id=ent.id, relation_type="candidate_profile", confidence="low"))
            ev = mk_evidence(db, case_id, f"{adapter} hit", kind="adapter_result")
            db.add(Finding(case_id=case_id, subject_entity_id=ent.id, predicate="profile.candidate", value_json={"site": site}, confidence="low",
                           evidence_id=ev.id, adapter_id=adapter, dedup_key=uuid.uuid4().hex))
        db.commit()


async def mk_subject(api, case_id, mode="self"):
    r = await api.post(f"{B}/cases/{case_id}/subjects", json={"display_name": "Jane Example", "mode": mode})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---- TP-01: migrations keep existing data --------------------------------------------------------------------------------------------------
def test_tp01_upgrade_from_0011_keeps_people_case_and_creates_empty_profile_tables(tmp_path):
    p = tmp_path / "old.db"
    eng = make_engine(p)
    with eng.begin() as conn:
        command.upgrade(_cfg(eng, conn), "0011")
        conn.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,created_at,updated_at) "
                          "VALUES ('c1','Old person case','','people','open','my own audit','','{}','2026-01-01','2026-01-01')"))
        conn.execute(text("INSERT INTO targets (id,case_id,type,raw_input,canonical_value,scope_status,created_at) "
                          "VALUES ('t1','c1','username','someone','someone','in_scope','2026-01-01')"))
    assert current_revision(eng) == "0011"
    upgrade_to_head(eng, p)
    assert current_revision(eng) == head_revision()
    with eng.connect() as c:
        assert c.execute(text("SELECT title FROM cases WHERE id='c1'")).scalar() == "Old person case"
        assert c.execute(text("SELECT canonical_value FROM targets WHERE id='t1'")).scalar() == "someone"
        for t in ("subjects", "subject_identifiers", "profile_claims", "profile_candidate_links", "subject_consents", "research_tasks",
                  "image_assets", "image_matches", "exposure_indicators", "remediation_tasks", "subject_corrections", "retention_actions"):
            assert c.execute(text(f"SELECT count(*) FROM {t}")).scalar() == 0, t
    eng.dispose()


async def test_tp01_existing_person_case_is_upgraded_lazily_without_changing_old_rows(api):
    cid = await people_case(api)
    with api.app.state.core.sm() as db:
        db.add(Target(case_id=cid, type="username", raw_input="jane_e", canonical_value="jane_e"))
        db.commit()
        before = db.execute(text("SELECT count(*) FROM targets")).scalar()
    subs = (await api.get(f"{B}/cases/{cid}/subjects")).json()
    assert subs["total"] == 1 and subs["items"][0]["display_name"] == "Jane Example"
    again = (await api.get(f"{B}/cases/{cid}/subjects")).json()  # idempotent
    assert again["total"] == 1 and again["items"][0]["id"] == subs["items"][0]["id"]
    prof = (await api.get(f"{B}/subjects/{subs['items'][0]['id']}/profile")).json()
    assert [i["value"] for i in prof["identifiers"]] == ["jane_e"]
    with api.app.state.core.sm() as db:
        assert db.execute(text("SELECT count(*) FROM targets")).scalar() == before


async def test_non_person_case_is_not_given_a_subject(api):
    cid = (await api.post(f"{B}/cases", json={"title": "corp", "category": "cyber"})).json()["id"]
    assert (await api.get(f"{B}/cases/{cid}/subjects")).json()["total"] == 0


# ---- subjects, identifiers, claims -------------------------------------------------------------------------------------------------------
async def test_subject_requires_purpose_and_identifier_rules(api):
    cid = (await api.post(f"{B}/cases", json={"title": "x", "category": "cyber"})).json()["id"]
    r = await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "No Purpose"})
    assert r.status_code == 422 and r.json()["code"] == "purpose_required"
    pc = await people_case(api)
    sid = await mk_subject(api, pc)
    for kind, val in [("name", "123-45-6789"), ("alias", "my password is hunter2"), ("email", "not-an-email"), ("username", "a b")]:
        r = await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": kind, "value": val})
        assert r.status_code == 422 and r.json()["code"] == "invalid_identifier", (kind, r.text)
    r = await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "phone", "value": "555"})
    assert r.status_code == 422  # no phone / national-ID kind exists
    ok = await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "email", "value": "Jane@Example.com"})
    assert ok.status_code == 201 and ok.json()["value"].endswith("@example.com")


async def test_claims_start_as_candidates_and_need_evidence_to_verify(api):
    cid = await people_case(api)
    sid = await mk_subject(api, cid)
    c = (await api.post(f"{B}/subjects/{sid}/claims", json={"field": "employer", "value": "Acme Corp"})).json()
    assert c["state"] == "candidate" and c["evidence"] == []
    r = await api.post(f"{B}/subjects/{sid}/claims/{c['id']}/verify", json={"state": "verified", "basis": "looks right"})
    assert r.status_code == 422 and r.json()["code"] == "evidence_required"
    with api.app.state.core.sm() as db:
        eid = mk_evidence(db, cid, "company page").id
        db.commit()
    r = await api.post(f"{B}/subjects/{sid}/claims/{c['id']}/verify", json={"state": "verified", "basis": "official staff page", "evidence_ids": [eid]})
    assert r.status_code == 200 and r.json()["state"] == "verified" and r.json()["evidence"][0]["id"] == eid
    r = await api.post(f"{B}/subjects/{sid}/claims/{c['id']}/verify", json={"state": "subject_confirmed", "basis": "told me"})
    assert r.status_code == 422 and r.json()["code"] == "attestation_required"
    # evidence from another case is refused
    other = await people_case(api)
    with api.app.state.core.sm() as db:
        foreign = mk_evidence(db, other).id
        db.commit()
    r = await api.post(f"{B}/subjects/{sid}/claims", json={"field": "education", "value": "State U", "evidence_ids": [foreign]})
    assert r.status_code == 422 and r.json()["code"] == "evidence_not_in_case"
    prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
    work = next(s for s in prof["sections"] if s["key"] == "work")
    assert work["claims"][0]["state_label"] == "verified"
    empty = next(s for s in prof["sections"] if s["key"] == "business")
    assert "Not assessed" in empty["state_note"] and "does not mean" in empty["state_note"]


async def test_viewer_sees_masked_identifiers_and_no_restricted_claims(api):
    from osintcc.db.models import CaseMember, User
    cid = await people_case(api)
    sid = await mk_subject(api, cid)
    await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "email", "value": "jane.doe@example.com"})
    await api.post(f"{B}/subjects/{sid}/claims", json={"field": "location_public", "value": "Springfield"})
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="v1", display_name="viewer"))
        db.flush()
        db.add(CaseMember(case_id=cid, user_id="v1", access_role="viewer"))
        db.commit()
    st.tokens["viewer-token"] = "v1"
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer viewer-token"})
    prof = (await v.get(f"{B}/subjects/{sid}/profile")).json()
    assert prof["identifiers"][0]["value"] != "jane.doe@example.com" and prof["identifiers"][0]["masked"] is True
    assert not any(c["field"] == "location_public" for s in prof["sections"] for c in s["claims"])
    assert (await v.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "alias", "value": "x"})).status_code in (403, 404)


async def test_other_users_cannot_see_a_subject(api):
    from osintcc.db.models import User
    cid = await people_case(api)
    sid = await mk_subject(api, cid)
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="u2", display_name="other"))
        db.commit()
    st.tokens["other-token"] = "u2"
    o = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer other-token"})
    for path in (f"/subjects/{sid}", f"/subjects/{sid}/profile", f"/subjects/{sid}/candidates", f"/subjects/{sid}/consent", f"/subjects/{sid}/timeline"):
        assert (await o.get(f"{B}{path}")).status_code == 404, path


async def test_identifier_values_never_enter_the_audit_log(api):
    cid = await people_case(api)
    sid = await mk_subject(api, cid)
    await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "email", "value": "very.private@example.org"})
    await api.get(f"{B}/subjects/{sid}/profile")
    with api.app.state.core.sm() as db:
        dump = "".join(str(r) for r in db.execute(text("SELECT metadata_json, resource_id, action FROM audit_events")).all())
    assert "very.private" not in dump
    assert "profile.view" in dump


# ---- TP-05 / TP-06 / TP-07: candidate queue ------------------------------------------------------------------------------------------------
async def test_tp05_tp06_overlap_is_clustered_but_stays_a_candidate(api):
    cid = await people_case(api)
    sid = await mk_subject(api, cid)
    await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "username", "value": "jane_e"})
    seed_candidates(api, cid, "jane_e", [
        ("sherlock", "https://github.com/jane_e", "GitHub"), ("maigret", "http://www.github.com/jane_e/?utm_source=x", "GitHub"),
        ("maigret", "https://example-forum.test/u/jane_e", "Forum")])
    q = (await api.get(f"{B}/subjects/{sid}/candidates")).json()
    assert q["total"] == 2  # same canonical URL from two tools = one cluster
    gh = next(c for c in q["items"] if "github.com" in c["canonical_url"])
    assert gh["canonical_url"] == "https://github.com/jane_e"
    assert sorted(gh["adapters"]) == ["maigret", "sherlock"] and gh["observation_count"] == 2
    assert len(gh["evidence"]) == 2  # both observations remain retrievable
    assert gh["independent_signals"] == 1 and "one signal" in gh["note"]
    assert all(c["state"] == "candidate" for c in q["items"])  # TP-05
    prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
    assert prof["counts"]["candidates"] == 2 and len(prof["unresolved_leads"]) == 2
    handles = next(s for s in prof["sections"] if s["key"] == "handles")
    assert [c for c in handles["claims"] if c.get("from") == "candidate_queue"] == []  # nothing verified
    again = (await api.get(f"{B}/subjects/{sid}/candidates")).json()  # sync is idempotent
    assert again["total"] == 2 and sorted(c["observation_count"] for c in again["items"]) == [1, 2]


async def test_tp07_bulk_review_records_reviewer_basis_and_reversal_restores(api):
    cid = await people_case(api)
    sid = await mk_subject(api, cid)
    await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "username", "value": "jane_e"})
    seed_candidates(api, cid, "jane_e", [("sherlock", f"https://site{i}.test/jane_e", f"S{i}") for i in range(3)])
    items = (await api.get(f"{B}/subjects/{sid}/candidates")).json()["items"]
    ids = [c["id"] for c in items]
    r = await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": ids, "state": "rejected", "basis": ""})
    assert r.status_code == 422
    r = await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": ids[:2], "state": "rejected", "basis": "different person, other city"})
    assert r.status_code == 200 and r.json()["updated"] == 2 and r.json()["bulk_id"]
    bulk = r.json()["bulk_id"]
    cur = {c["id"]: c for c in (await api.get(f"{B}/subjects/{sid}/candidates")).json()["items"]}
    assert cur[ids[0]]["state"] == "rejected" and cur[ids[0]]["reviewed_by"] and cur[ids[0]]["review_basis"] and cur[ids[0]]["reviewed_at"]
    assert cur[ids[2]]["state"] == "candidate"
    with api.app.state.core.sm() as db:
        rel = db.query(Relationship).filter_by(relation_type="candidate_profile", status="rejected").count()
    assert rel == 2  # the graph edge follows the decision
    rv = await api.post(f"{B}/subjects/{sid}/candidates/reverse", json={"bulk_id": bulk})
    assert rv.status_code == 200 and rv.json()["reversed"] == 2
    cur = {c["id"]: c for c in (await api.get(f"{B}/subjects/{sid}/candidates")).json()["items"]}
    assert all(cur[i]["state"] == "candidate" for i in ids)
    with api.app.state.core.sm() as db:
        assert db.query(Relationship).filter_by(relation_type="candidate_profile", status="rejected").count() == 0
    hist = (await api.get(f"{B}/subjects/{sid}/review-history")).json()["items"]
    assert len(hist) == 4 and sum(1 for h in hist if h["reverts"]) == 2  # both decisions and both reversals are kept
    assert (await api.post(f"{B}/subjects/{sid}/candidates/reverse", json={"bulk_id": bulk})).json()["reversed"] == 0  # no double reversal


async def test_confirming_needs_attestation_or_independent_evidence_and_later_changes_block_reversal(api):
    cid = await people_case(api)
    sid = await mk_subject(api, cid)
    await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "username", "value": "jane_e"})
    seed_candidates(api, cid, "jane_e", [("sherlock", "https://one.test/jane_e", "One")])
    cand = (await api.get(f"{B}/subjects/{sid}/candidates")).json()["items"][0]
    r = await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": [cand["id"]], "state": "confirmed", "basis": "same handle"})
    assert r.status_code == 422 and r.json()["code"] == "corroboration_required"
    r = await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": [cand["id"]], "state": "confirmed",
                                                                           "basis": "this is my own account", "attestation": "subject"})
    assert r.status_code == 200
    prof = (await api.get(f"{B}/subjects/{sid}/profile")).json()
    handles = next(s for s in prof["sections"] if s["key"] == "handles")
    assert any(c.get("from") == "candidate_queue" for c in handles["claims"])
    first = (await api.get(f"{B}/subjects/{sid}/review-history")).json()["items"][0]["id"]
    await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": [cand["id"]], "state": "unsure", "basis": "second thoughts"})
    r = await api.post(f"{B}/subjects/{sid}/candidates/reverse", json={"event_id": first})
    assert r.status_code == 409 and r.json()["code"] == "changed_since"
    # independent corroborating evidence is also accepted
    with api.app.state.core.sm() as db:
        eid = mk_evidence(db, cid, "bio page lists the same handle").id
        db.commit()
    r = await api.post(f"{B}/subjects/{sid}/candidates/bulk-review", json={"candidate_ids": [cand["id"]], "state": "confirmed",
                                                                           "basis": "linked from their verified site", "evidence_ids": [eid]})
    assert r.status_code == 200


async def test_tp10_no_model_path_can_change_candidate_or_claim_state():
    """The Copilot tool registry and the automation node registry contain no tool that reviews/promotes profile records."""
    from osintcc.automations.registry import SPECS
    from osintcc.copilot.tools import TOOLS
    banned = {"verify", "confirm", "promote", "merge", "attest"}
    for name in list(TOOLS) + list(SPECS):
        assert not banned & set(name.lower().split("_")), name
    # review functions take a human reviewer id and are only referenced by the API layer
    import pathlib

    import osintcc.profile.candidates as cand
    import osintcc.profile.service as svc
    src = pathlib.Path(__file__).resolve().parents[2] / "backend" / "osintcc"
    users = [p.name for p in src.rglob("*.py") if ("candidates.review(" in p.read_text(encoding="utf8") or "review_claim(" in p.read_text(encoding="utf8"))]
    assert set(users) <= {"profile.py", "candidates.py", "service.py", "lifecycle.py"}, users   # lifecycle: a person resolving a subject correction
    assert callable(cand.review) and callable(svc.review_claim)


async def test_timeline_has_basis_and_is_ordered(api):
    cid = await people_case(api)
    sid = await mk_subject(api, cid)
    await api.post(f"{B}/subjects/{sid}/claims", json={"field": "employer", "value": "Acme", "observed_from": "2020-01-01T00:00:00Z"})
    items = (await api.get(f"{B}/subjects/{sid}/timeline")).json()["items"]
    assert [i["at"] for i in items] == sorted(i["at"] for i in items)
    assert any(i["kind"] == "claim" and i["basis"] == "published/observed" for i in items)
