"""Shared builders for the Target Profile tests: a person case with consent, a stored evidence object, Sherlock-style candidates, claims and exposure."""
from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from osintcc.db.models import Entity, Evidence, Finding, Relationship

B = "/api/v1"


def soon(days: int = 30) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def stored_evidence(st, case_id: str, data: bytes, title: str = "source page", kind: str = "document") -> str:
    """A real vault object plus its Evidence row, so integrity checks have something to check."""
    sha256, sha512, rel, size = st.vault.store(data)
    with st.sm() as db:
        ev = Evidence(case_id=case_id, kind=kind, title=title, sha256=sha256, sha512=sha512, byte_size=size, vault_relpath=rel, original_url="https://example.org/page")
        db.add(ev)
        db.commit()
        return ev.id


def reference_evidence(st, case_id: str, title: str = "note") -> str:
    h = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    with st.sm() as db:
        ev = Evidence(case_id=case_id, kind="note", title=title, sha256=h, sha512=h * 2, byte_size=1)
        db.add(ev)
        db.commit()
        return ev.id


def seed_candidates(st, case_id: str, username: str, sightings: list[tuple[str, str, str]]) -> None:
    """sightings: (adapter_id, url, site). Mirrors what Sherlock/Maigret persist."""
    with st.sm() as db:
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
            h = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
            ev = Evidence(case_id=case_id, kind="adapter_result", title=f"{adapter} output", sha256=h, sha512=h * 2, byte_size=1)
            db.add(ev)
            db.flush()
            db.add(Finding(case_id=case_id, subject_entity_id=ent.id, predicate="profile.candidate", value_json={"site": site}, confidence="low", evidence_id=ev.id,
                           adapter_id=adapter, dedup_key=uuid.uuid4().hex))
        db.commit()


async def rich_subject(api, *, classes=("public_passive", "public_site_query", "exposure_check", "image_analysis", "reverse_image"), mode="self"):
    """People case + subject + authorization + identifiers + one verified claim, one conflicting claim, one unverified claim, two leads, one exposure record."""
    st = api.app.state.core
    cid = (await api.post(f"{B}/cases", json={"title": "Jane Example", "category": "people", "purpose": "self audit of my public footprint"})).json()["id"]
    sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Jane Example", "mode": mode})).json()["id"]
    r = await api.post(f"{B}/subjects/{sid}/consent", json={"verification_method": "email_confirmation", "verifier": "Jane (subject)", "source_classes": list(classes),
                                                            "permitted_purposes": ["self audit"], "expires_at": soon()})
    assert r.status_code == 201, r.text
    iid_user = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "username", "value": "jane_e"})).json()["id"]
    iid_mail = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "email", "value": "jane.doe@example.com"})).json()["id"]
    iid_dom = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "domain", "value": "example.com"})).json()["id"]
    page = stored_evidence(st, cid, b"<html>Jane Example works at Acme Corp</html>", "Acme staff page")
    other = stored_evidence(st, cid, b"<html>J. Example, Other Corp</html>", "Other Corp bio")
    c1 = (await api.post(f"{B}/subjects/{sid}/claims", json={"field": "employer", "value": "Acme Corp", "evidence_ids": [page]})).json()
    await api.post(f"{B}/subjects/{sid}/claims/{c1['id']}/verify", json={"state": "verified", "basis": "official staff page", "evidence_ids": [page]})
    c2 = (await api.post(f"{B}/subjects/{sid}/claims", json={"field": "employer", "value": "Other Corp", "evidence_ids": [other]})).json()
    await api.post(f"{B}/subjects/{sid}/claims/{c2['id']}/verify", json={"state": "conflicting", "basis": "a different employer appears in an older bio"})
    c3 = (await api.post(f"{B}/subjects/{sid}/claims", json={"field": "education", "value": "State University"})).json()
    seed_candidates(st, cid, "jane_e", [("sherlock", "https://github.com/jane_e", "GitHub"), ("maigret", "http://www.github.com/jane_e/?utm_source=x", "GitHub"),
                                        ("maigret", "https://forum.test/u/jane_e", "Forum")])
    await api.get(f"{B}/subjects/{sid}/candidates")          # fold the findings into the queue so tests can compare states before and after
    x = {"id": None}
    if "exposure_check" in classes:
        x = (await api.post(f"{B}/subjects/{sid}/exposure", json={"cls": "breach_account", "provider": "manual", "status": "confirmed_exposure", "risk": "high",
                                                                  "verification_basis": "provider_notice", "descriptor": "Breach: ExampleService (2023-05); data types: emails, passwords"})).json()
    return {"cid": cid, "sid": sid, "user": iid_user, "mail": iid_mail, "domain": iid_dom, "page": page, "other": other, "c_verified": c1["id"], "c_conflict": c2["id"], "c_edu": c3["id"],
            "exposure": x["id"]}
