"""Candidate account queue: Sherlock/Maigret (and any `profile.candidate` finding) become *leads* for a person to decide.

Nothing here promotes a candidate by itself. Tools that only test whether a handle string exists at a URL count as ONE signal
(`handle_existence`), however many tools saw it, so overlap never looks like corroboration.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    Entity,
    Evidence,
    Finding,
    ProfileCandidateLink,
    ProfileReviewEvent,
    Relationship,
    Subject,
    SubjectIdentifier,
)
from ..telemetry import audit
from .normalize import canonical_url, cluster_key
from .service import ProfileError, evidence_refs

CANDIDATE_PREDICATE = "profile.candidate"
# Adapters whose only signal is "this handle string resolves at this URL" are a single independent group.
SIGNAL_GROUP = {"sherlock": "handle_existence", "maigret": "handle_existence"}
REL_STATUS = {"confirmed": "manual", "rejected": "rejected", "candidate": "unverified", "unsure": "unverified"}


def _now() -> datetime:
    return datetime.now(UTC)


def sync_from_findings(db: Session, subject: Subject) -> int:
    """Idempotently fold the case's `profile.candidate` findings for this subject's usernames into the queue. Review states are never touched."""
    names = {i.value.casefold(): i for i in db.scalars(select(SubjectIdentifier).where(
        SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.kind == "username", SubjectIdentifier.status == "active"))}
    if not names:
        return 0
    users = {e.id: e for e in db.scalars(select(Entity).where(Entity.case_id == subject.case_id, Entity.type == "username"))
             if e.canonical_key.casefold() in names}
    if not users:
        return 0
    rels = db.scalars(select(Relationship).where(Relationship.case_id == subject.case_id, Relationship.relation_type == "candidate_profile",
                                                 Relationship.from_entity_id.in_(users)))
    changed = 0
    for rel in rels:
        url_ent = db.get(Entity, rel.to_entity_id)
        if not url_ent or url_ent.type != "url":
            continue
        try:
            canon, key = canonical_url(url_ent.canonical_key), cluster_key(url_ent.canonical_key)
        except ValueError:
            continue
        finds = list(db.scalars(select(Finding).where(Finding.case_id == subject.case_id, Finding.subject_entity_id == url_ent.id,
                                                      Finding.predicate == CANDIDATE_PREDICATE)))
        if not finds:
            continue
        link = db.scalars(select(ProfileCandidateLink).where(ProfileCandidateLink.subject_id == subject.id, ProfileCandidateLink.cluster_key == key)).first()
        adapters = sorted({f.adapter_id for f in finds} | set(link.adapters if link else []))
        groups = {SIGNAL_GROUP.get(a, a) for a in adapters}
        evid = sorted({f.evidence_id for f in finds} | set(link.evidence_ids if link else []))
        fids = sorted({f.id for f in finds} | set(link.finding_ids if link else []))
        first = min(_aware(f.observed_at) for f in finds)
        last = max(_aware(f.observed_at) for f in finds)
        site = (finds[0].value_json or {}).get("site", "") if isinstance(finds[0].value_json, dict) else ""
        ident = names[users[rel.from_entity_id].canonical_key.casefold()]
        if link is None:
            link = ProfileCandidateLink(subject_id=subject.id, case_id=subject.case_id, from_identifier_id=ident.id, to_entity_id=url_ent.id,
                                        cluster_key=key, canonical_url=canon, site=site, adapters=adapters, evidence_ids=evid, finding_ids=fids,
                                        source_independence=len(groups), first_seen_at=first, last_seen_at=last,
                                        hypothesis=f"The handle '{ident.value}' exists at this URL. That alone does not show the account belongs to the subject.")
            db.add(link)
            changed += 1
        elif (adapters, evid, fids) != (link.adapters, link.evidence_ids, link.finding_ids) or _aware(link.last_seen_at) != last:
            link.adapters, link.evidence_ids, link.finding_ids = adapters, evid, fids
            link.source_independence = len(groups)
            link.first_seen_at, link.last_seen_at = min(_aware(link.first_seen_at), first), max(_aware(link.last_seen_at), last)
            changed += 1
    db.flush()
    return changed


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def candidate_dict(db: Session, c: ProfileCandidateLink) -> dict:
    return {"id": c.id, "canonical_url": c.canonical_url, "site": c.site, "hypothesis": c.hypothesis, "adapters": c.adapters,
            "independent_signals": c.source_independence, "state": c.state, "reviewed_by": c.reviewed_by, "reviewed_at": c.reviewed_at,
            "review_basis": c.review_basis, "first_seen_at": c.first_seen_at, "last_seen_at": c.last_seen_at, "observation_count": len(c.finding_ids),
            "evidence": evidence_refs(db, c.evidence_ids), "finding_ids": c.finding_ids,
            "note": "Lead only: more than one tool agreeing on a handle is still one signal." if len(c.adapters) > 1 and c.source_independence == 1 else ""}


def list_candidates(db: Session, subject: Subject, state: str | None = None) -> list[dict]:
    sync_from_findings(db, subject)
    q = select(ProfileCandidateLink).where(ProfileCandidateLink.subject_id == subject.id).order_by(ProfileCandidateLink.first_seen_at)
    if state:
        q = q.where(ProfileCandidateLink.state == state)
    return [candidate_dict(db, c) for c in db.scalars(q)]


def _apply_relationship(db: Session, c: ProfileCandidateLink, reviewer: str) -> None:
    ident = db.get(SubjectIdentifier, c.from_identifier_id) if c.from_identifier_id else None
    if not ident or not c.to_entity_id:
        return
    user = db.scalars(select(Entity).where(Entity.case_id == c.case_id, Entity.type == "username", Entity.canonical_key == ident.value)).first()
    if not user:
        return
    rel = db.scalars(select(Relationship).where(Relationship.case_id == c.case_id, Relationship.from_entity_id == user.id,
                                                Relationship.to_entity_id == c.to_entity_id, Relationship.relation_type == "candidate_profile")).first()
    if rel:
        rel.status = REL_STATUS[c.state]
        rel.asserted_by = reviewer if c.state in ("confirmed", "rejected") else "adapter"


def review(db: Session, subject: Subject, candidate_ids: list[str], *, to_state: str, reviewer: str, basis: str, attestation: str = "none",
           evidence_ids: list[str] | None = None) -> dict:
    """Bulk decision by a person. Confirmation needs the subject's own attestation or independent corroborating evidence."""
    if to_state not in ("confirmed", "rejected", "unsure", "candidate"):
        raise ProfileError("invalid_state", "state must be confirmed, rejected, unsure or candidate")
    if not candidate_ids:
        raise ProfileError("nothing_selected", "select at least one candidate")
    if len(candidate_ids) > 200:
        raise ProfileError("too_many", "review at most 200 candidates at a time")
    if not basis.strip():
        raise ProfileError("basis_required", "record the reason or method for this decision")
    extra = list(dict.fromkeys(evidence_ids or []))
    for eid in extra:
        ev = db.get(Evidence, eid)
        if not ev or ev.case_id != subject.case_id:
            raise ProfileError("evidence_not_in_case", f"evidence {eid} is not in this case")
    rows = []
    for cid in candidate_ids:
        c = db.get(ProfileCandidateLink, cid)
        if not c or c.subject_id != subject.id:
            raise ProfileError("not_found", f"candidate {cid} not found")
        rows.append(c)
    if to_state == "confirmed":
        for c in rows:  # evidence that is not just the tool's own handle-existence observation
            independent = [e for e in extra if e not in c.evidence_ids]
            if attestation != "subject" and not independent:
                raise ProfileError("corroboration_required", f"{c.canonical_url}: confirming needs the subject's attestation or independent "
                                   "corroborating evidence; a matching handle alone is not enough")
    bulk = str(uuid.uuid4()) if len(rows) > 1 else None
    for c in rows:
        prev = c.state
        c.state, c.reviewed_by, c.reviewed_at, c.review_basis = to_state, reviewer, _now(), basis.strip()
        if to_state == "confirmed":
            c.evidence_ids = list(dict.fromkeys([*c.evidence_ids, *extra]))
        db.add(ProfileReviewEvent(subject_id=subject.id, case_id=subject.case_id, target_type="candidate", target_id=c.id, from_state=prev,
                                  to_state=to_state, reviewer=reviewer, basis=basis.strip(), attestation=attestation, evidence_ids=extra, bulk_id=bulk))
        _apply_relationship(db, c, reviewer)
    audit.record(db, "profile.candidate_review", actor=reviewer, case_id=subject.case_id, resource_type="subject", resource_id=subject.id,
                 metadata={"count": len(rows), "to": to_state, "bulk_id": bulk or ""})
    db.flush()
    return {"updated": len(rows), "bulk_id": bulk, "state": to_state}


def reverse(db: Session, subject: Subject, *, event_id: str | None = None, bulk_id: str | None = None, reviewer: str) -> dict:
    """Undo a decision (or a whole bulk decision): the candidate returns to the state it had. The history keeps both events."""
    q = select(ProfileReviewEvent).where(ProfileReviewEvent.subject_id == subject.id, ProfileReviewEvent.target_type == "candidate",
                                         ProfileReviewEvent.reverts_event_id.is_(None))
    evs = list(db.scalars(q.where(ProfileReviewEvent.bulk_id == bulk_id) if bulk_id else q.where(ProfileReviewEvent.id == event_id)))
    if not evs:
        raise ProfileError("not_found", "review event not found")
    n = 0
    for ev in evs:
        c = db.get(ProfileCandidateLink, ev.target_id)
        if not c:
            continue
        done = db.scalars(select(ProfileReviewEvent).where(ProfileReviewEvent.reverts_event_id == ev.id)).first()
        if done:
            continue
        if c.state != ev.to_state:
            raise ProfileError("changed_since", "this candidate was reviewed again after that decision; reverse the later decision first")
        c.state, c.reviewed_by, c.reviewed_at = ev.from_state, reviewer, _now()
        c.review_basis = f"reversed decision {ev.id}"
        db.add(ProfileReviewEvent(subject_id=subject.id, case_id=subject.case_id, target_type="candidate", target_id=c.id, from_state=ev.to_state,
                                  to_state=ev.from_state, reviewer=reviewer, basis=f"reversal of {ev.id}", reverts_event_id=ev.id))
        _apply_relationship(db, c, reviewer)
        n += 1
    audit.record(db, "profile.candidate_reverse", actor=reviewer, case_id=subject.case_id, resource_type="subject", resource_id=subject.id,
                 metadata={"count": n})
    db.flush()
    return {"reversed": n}


def history(db: Session, subject: Subject, target_id: str | None = None) -> list[dict[str, Any]]:
    q = select(ProfileReviewEvent).where(ProfileReviewEvent.subject_id == subject.id).order_by(ProfileReviewEvent.created_at)
    if target_id:
        q = q.where(ProfileReviewEvent.target_id == target_id)
    return [{"id": e.id, "target_type": e.target_type, "target_id": e.target_id, "from": e.from_state, "to": e.to_state, "reviewer": e.reviewer,
             "basis": e.basis, "attestation": e.attestation, "evidence_ids": e.evidence_ids, "bulk_id": e.bulk_id,
             "reverts": e.reverts_event_id, "at": e.created_at} for e in db.scalars(q)]
