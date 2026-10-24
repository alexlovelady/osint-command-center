from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from osintcc.config import Settings
from osintcc.db.models import AuditEvent, Claim, Evidence, Observation
from osintcc.main import create_app
from sqlalchemy import func, select


@pytest.fixture
async def api(tmp_path):
    s = Settings(data_dir=tmp_path / "data", vault_encryption="required")
    app = create_app(s, vault_key=secrets.token_bytes(32))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {s.session_token}"
            c.app, c.settings = app, s
            yield c


CONSENT = {"basis": "informed_consent", "authorizing_party": "the source (verbal, recorded in field note FN-1)",
           "scope": ["interview", "use in internal report"]}


async def setup(api, alias="Witness A"):
    cid = (await api.post("/api/v1/cases", json={"title": "H", "purpose": "witness corroboration exercise"})).json()["id"]
    r = await api.post(f"/api/v1/cases/{cid}/human-sources", json={"alias": alias, "consent": CONSENT})
    assert r.status_code == 201, r.text
    return cid, r.json()


async def test_source_requires_consent_and_has_no_real_name_fields(api):
    cid = (await api.post("/api/v1/cases", json={"title": "H", "purpose": "x"})).json()["id"]
    assert (await api.post(f"/api/v1/cases/{cid}/human-sources", json={"alias": "W1"})).status_code == 422
    assert (await api.post(f"/api/v1/cases/{cid}/human-sources", json={"alias": "W1", "consent": {**CONSENT, "scope": []}})).status_code == 422
    assert (await api.post(f"/api/v1/cases/{cid}/human-sources", json={"alias": "<script>", "consent": CONSENT})).status_code == 422
    ok = (await api.post(f"/api/v1/cases/{cid}/human-sources", json={"alias": "W1", "consent": CONSENT, "real_name": "Jane Doe"})).json()
    assert "real_name" not in json.dumps(ok) and "Jane" not in json.dumps(ok)  # unknown fields are ignored, never stored
    assert (await api.post(f"/api/v1/cases/{cid}/human-sources", json={"alias": "W1", "consent": CONSENT})).status_code == 409


async def test_reports_are_restricted_encrypted_and_alias_stays_out_of_audit(api):
    _cid, src = await setup(api)
    r = await api.post(f"/api/v1/human-sources/{src['id']}/reports", json={"text": "I saw a grey van at the dock at 9pm.",
                                                                          "information_credibility": 3, "claims": ["grey van at dock"]})
    assert r.status_code == 201
    ev = (await api.get(f"/api/v1/evidence/{r.json()['evidence_id']}")).json()
    assert ev["sensitivity"] == "RESTRICTED" and ev["kind"] == "human.report" and ev["integrity_verified"]
    obj = next(api.settings.vault_dir.rglob(ev["sha256"]))
    assert b"grey van" not in obj.read_bytes()  # encrypted at rest
    with api.app.state.core.sm() as db:
        log = json.dumps([e.metadata_json for e in db.scalars(select(AuditEvent))])
        assert "Witness A" not in log and "grey van" not in log


async def test_no_automatic_trust_score_assessment_is_analyst_set(api):
    cid, src = await setup(api)
    assert src["reliability_assessment"] is None and "never computes" in src["reliability_note"]
    await api.post(f"/api/v1/human-sources/{src['id']}/reports", json={"text": "statement one"})
    after = (await api.get(f"/api/v1/cases/{cid}/human-sources")).json()["items"][0]
    assert after["reliability_assessment"] is None  # adding reports never assigns a score
    assert (await api.post(f"/api/v1/human-sources/{src['id']}/assessment", json={"reliability": "Z"})).status_code == 422
    a = (await api.post(f"/api/v1/human-sources/{src['id']}/assessment", json={"reliability": "B"})).json()
    assert a["reliability_assessment"] == "B"
    assert not any(k in json.dumps(a) for k in ("trust_score", "probability", "score\":"))


async def test_conflicting_witness_notes_stay_independent_until_analyst_verifies(api):
    cid, a = await setup(api, "Witness A")
    b = (await api.post(f"/api/v1/cases/{cid}/human-sources", json={"alias": "Witness B", "consent": CONSENT})).json()
    ra = (await api.post(f"/api/v1/human-sources/{a['id']}/reports", json={"text": "The van was grey."})).json()
    rb = (await api.post(f"/api/v1/human-sources/{b['id']}/reports", json={"text": "The van was white."})).json()
    ent = (await api.post(f"/api/v1/cases/{cid}/notes", json={"body_markdown": "anchor"})).json()
    assert ent
    # an entity to hang claims on: import a tiny file that yields one
    eml = b"From: x@example.com\nTo: y@example.org\nSubject: s\nDate: Tue, 02 Jan 2024 10:30:00 +0000\n\nhi"
    await api.post(f"/api/v1/cases/{cid}/ingest?filename=m.eml&consent_confirmed=true", content=eml)
    subj = (await api.get(f"/api/v1/cases/{cid}/entities")).json()["items"][0]["id"]
    mk = lambda v, e: api.post("/api/v1/claims", json={"case_id": cid, "subject_entity_id": subj, "predicate": "van_colour",
                                                        "value": v, "sources": [{"evidence_id": e}]})
    ca, cb = (await mk("grey", ra["evidence_id"])).json(), (await mk("white", rb["evidence_id"])).json()
    assert ca["confidence_label"] == "low" and cb["confidence_label"] == "low"  # one human source each
    assert ca["sources"][0]["group"] != cb["sources"][0]["group"] and ca["sources"][0]["group"].startswith("human:")
    cons = (await api.get(f"/api/v1/cases/{cid}/contradictions")).json()["items"]
    assert len(cons) == 1 and {p["value"] for p in cons[0]["positions"]} == {"grey", "white"}
    assert all(c["verification_status"] == "unverified" for c in (ca, cb))
    # corroboration matrix flags both as single-source
    m = (await api.get(f"/api/v1/cases/{cid}/humint/corroboration")).json()["items"]
    assert len(m) == 2 and all(x["single_source"] for x in m)
    v = (await api.post(f"/api/v1/claims/{ca['id']}/verification", json={"status": "analyst_verified"})).json()
    assert v["verification_status"] == "analyst_verified"
    assert (await api.get(f"/api/v1/claims?case_id={cid}&verification_status=unverified")).json()["total"] == 1  # B untouched


async def test_consent_withdrawal_blocks_reuse(api):
    cid, src = await setup(api)
    await api.post(f"/api/v1/human-sources/{src['id']}/reports", json={"text": "before withdrawal"})
    r = (await api.post(f"/api/v1/human-sources/{src['id']}/revoke", json={"reason": "source withdrew"})).json()
    assert r["status"] == "revoked" and r["consent"]["revoked_at"]
    blocked = await api.post(f"/api/v1/human-sources/{src['id']}/reports", json={"text": "after withdrawal"})
    assert blocked.status_code == 409 and blocked.json()["code"] == "consent_revoked"
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(Evidence).where(Evidence.kind == "human.report")) == 1
    # content kept (not deleted) but still excluded from default exports
    rep = (await api.post(f"/api/v1/cases/{cid}/reports", json={"format": "json"})).json()
    data = json.loads((await api.get(f"/api/v1/reports/{rep['id']}/download")).content)  # reports are encrypted at rest
    assert not data["observations"] and all(m["kind"] != "human.report" for m in data["evidence_manifest"])


async def test_expired_consent_blocks_new_material(api):
    cid = (await api.post("/api/v1/cases", json={"title": "H", "purpose": "x"})).json()["id"]
    soon = (datetime.now(UTC) + timedelta(milliseconds=1)).isoformat()
    s = (await api.post(f"/api/v1/cases/{cid}/human-sources", json={"alias": "W9", "consent": {**CONSENT, "expires_at": soon}})).json()
    import asyncio
    await asyncio.sleep(0.05)
    r = await api.post(f"/api/v1/human-sources/{s['id']}/reports", json={"text": "late"})
    assert r.status_code == 409 and r.json()["code"] == "consent_expired"
    assert (await api.get(f"/api/v1/cases/{cid}/human-sources")).json()["items"][0]["status"] == "consent_expired"


async def test_revoke_with_delete_removes_content_claims_and_index(api):
    cid, src = await setup(api)
    r1 = (await api.post(f"/api/v1/human-sources/{src['id']}/reports", json={"text": "unique-phrase-quetzal seen near gate"})).json()
    eml = b"From: x@example.com\nTo: y@example.org\nSubject: s\nDate: Tue, 02 Jan 2024 10:30:00 +0000\n\nhi"
    await api.post(f"/api/v1/cases/{cid}/ingest?filename=m.eml&consent_confirmed=true", content=eml)
    subj = (await api.get(f"/api/v1/cases/{cid}/entities")).json()["items"][0]["id"]
    claim = (await api.post("/api/v1/claims", json={"case_id": cid, "subject_entity_id": subj, "predicate": "p", "value": "v",
                                                     "sources": [{"evidence_id": r1["evidence_id"]}]})).json()
    sha = (await api.get(f"/api/v1/evidence/{r1['evidence_id']}")).json()["sha256"]
    assert next(api.settings.vault_dir.rglob(sha))
    no_confirm = await api.post(f"/api/v1/human-sources/{src['id']}/revoke", json={"delete_content": True})
    assert no_confirm.status_code == 422
    out = (await api.post(f"/api/v1/human-sources/{src['id']}/revoke", json={"delete_content": True, "confirm": True})).json()
    assert out["removed"] == {"evidence": 1, "observations": 1, "claims": 1} and out["vault_objects_deleted"] == 1
    assert not list(api.settings.vault_dir.rglob(sha))
    with api.app.state.core.sm() as db:
        assert db.get(Claim, claim["id"]) is None
        assert db.scalar(select(func.count()).select_from(Observation).where(Observation.discipline_id == "HUMINT")) == 0
        assert db.connection().exec_driver_sql("SELECT count(*) FROM search_index WHERE body LIKE '%quetzal%'").scalar() == 0
        ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "humint.revoke")).one()
        assert ev.metadata_json["removed"]["evidence"] == 1 and "quetzal" not in json.dumps(ev.metadata_json)
    assert (await api.get(f"/api/v1/evidence/{r1['evidence_id']}")).status_code == 404


async def test_retention_due_lists_but_never_deletes(api):
    cid, _src = await setup(api)
    s2 = (await api.post(f"/api/v1/cases/{cid}/human-sources", json={"alias": "Old", "consent": CONSENT, "retention_days": 1})).json()
    with api.app.state.core.sm() as db:
        from osintcc.db.models import HumanSource
        row = db.get(HumanSource, s2["id"])
        row.retention_until = datetime.now(UTC) - timedelta(days=1)
        db.commit()
    due = (await api.get("/api/v1/system/retention/due")).json()
    assert [d["source_id"] for d in due["items"]] == [s2["id"]] and "never deletes" in due["note"]
    assert (await api.get(f"/api/v1/cases/{cid}/human-sources")).json()["items"][1]["status"] == "active"


async def test_other_actor_cannot_see_or_use_sources(api):
    cid, src = await setup(api)
    import httpx as hx
    from osintcc.db.models import User
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="u5", display_name="x"))
        db.commit()
    st.tokens["t5"] = "u5"
    other = hx.AsyncClient(transport=hx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer t5"})
    for m, u, b in [("GET", f"/api/v1/cases/{cid}/human-sources", None), ("POST", f"/api/v1/human-sources/{src['id']}/reports", {"text": "x"}),
                    ("POST", f"/api/v1/human-sources/{src['id']}/revoke", {}), ("POST", f"/api/v1/human-sources/{src['id']}/assessment", {"reliability": "A"}),
                    ("GET", f"/api/v1/cases/{cid}/humint/corroboration", None)]:
        assert (await other.request(m, u, json=b)).status_code == 404, (m, u)
