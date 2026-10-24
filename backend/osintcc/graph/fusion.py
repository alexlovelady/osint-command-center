"""Fusion helpers (spec 8.2, 23.2): claim confidence heuristics, contradictions, gaps, merge views.

Confidence is a *label* from published heuristics, never a probability (no calibration data exists).
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    Claim,
    ClaimSource,
    Entity,
    EntityLink,
    Evidence,
    Finding,
    Requirement,
    RequirementEvidence,
)

OFFICIAL_ADAPTERS = {"rdap", "sec_edgar"}  # authoritative registry sources
STALE_DAYS = 90

HEURISTICS = {
    "unknown": "no evidence attached",
    "low": "one independent source group, not an official registry",
    "medium": "one official registry source, or two independent source groups",
    "high": "three independent source groups, or two plus analyst verification",
    "cap": "disputed or rejected claims are capped at 'low' / 'unknown'",
    "note": "Labels are heuristics, not probabilities. Independence is declared per source group by the analyst "
            "or derived from the adapter; two sources that copy each other should share a group.",
}


def confidence_label(groups: int, verified: bool, official: bool, status: str = "unverified") -> str:
    if status == "rejected":
        return "unknown"
    if groups == 0:
        return "unknown"
    if status == "disputed":
        return "low"
    if groups >= 3 or (groups >= 2 and verified):
        return "high"
    if groups >= 2 or official:
        return "medium"
    return "low"


def recompute_claim(db: Session, claim: Claim) -> Claim:
    rows = db.scalars(select(ClaimSource).where(ClaimSource.claim_id == claim.id)).all()
    groups = {r.independent_source_group or r.evidence_id for r in rows}
    official = False
    for r in rows:
        ev = db.get(Evidence, r.evidence_id)
        if ev and ev.kind.split(".")[0] in OFFICIAL_ADAPTERS:
            official = True
    claim.confidence_label = confidence_label(len(groups), claim.verification_status == "analyst_verified",
                                              official, claim.verification_status)
    return claim


def claim_dict(db: Session, c: Claim) -> dict[str, Any]:
    srcs = db.scalars(select(ClaimSource).where(ClaimSource.claim_id == c.id)).all()
    ents = {e.id: e for e in db.scalars(select(Entity).where(Entity.id.in_([c.subject_entity_id, c.object_entity_id])))}
    return {"id": c.id, "case_id": c.case_id, "subject": ents[c.subject_entity_id].display_name,
            "subject_entity_id": c.subject_entity_id, "predicate": c.predicate,
            "object": ents[c.object_entity_id].display_name if c.object_entity_id else None,
            "object_entity_id": c.object_entity_id, "value": c.value_json, "epistemic_status": c.epistemic_status,
            "confidence_label": c.confidence_label, "verification_status": c.verification_status,
            "observed_at": c.observed_at, "created_by": c.created_by, "created_at": c.created_at,
            "sources": [{"evidence_id": s.evidence_id, "method": s.method, "group": s.independent_source_group}
                        for s in srcs],
            "independent_source_groups": len({s.independent_source_group or s.evidence_id for s in srcs})}


def _value_key(c: Claim) -> str:
    return json.dumps([c.object_entity_id, c.value_json], sort_keys=True, default=str)


def contradictions(db: Session, case_id: str) -> list[dict[str, Any]]:
    """Groups of claims about the same subject+predicate whose values differ. Nothing is overwritten or merged."""
    claims = db.scalars(select(Claim).where(Claim.case_id == case_id, Claim.verification_status != "rejected")).all()
    buckets: dict[tuple[str, str], list[Claim]] = defaultdict(list)
    for c in claims:
        buckets[(c.subject_entity_id, c.predicate)].append(c)
    out = []
    for (subj, pred), cs in buckets.items():
        values = {_value_key(c) for c in cs}
        if len(values) < 2:
            continue
        e = db.get(Entity, subj)
        out.append({"subject": e.display_name if e else subj, "subject_entity_id": subj, "predicate": pred,
                    "positions": [claim_dict(db, c) for c in cs],
                    "note": "Sources disagree; both positions are preserved. Resolve by adding evidence or marking a "
                            "claim disputed/rejected — not by deleting."})
    return out


def gap_assessment(db: Session, case_id: str, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    reqs = db.scalars(select(Requirement).where(Requirement.case_id == case_id)).all()
    unanswered, no_support = [], []
    for r in reqs:
        n = db.scalar(select(func.count()).select_from(RequirementEvidence)
                      .where(RequirementEvidence.requirement_id == r.id)) or 0
        if r.answer_status in ("unanswered", "partial"):
            unanswered.append({"id": r.id, "question": r.question, "priority": r.priority,
                               "answer_status": r.answer_status, "supporting_items": n})
        if n == 0 and r.status != "closed":
            no_support.append(r.id)
    cutoff = now - timedelta(days=STALE_DAYS)
    stale = db.scalar(select(func.count()).select_from(Finding).where(Finding.case_id == case_id,
                                                                      Finding.observed_at < cutoff)) or 0
    disputed = db.scalar(select(func.count()).select_from(Claim).where(
        Claim.case_id == case_id, Claim.verification_status == "disputed")) or 0
    unverified = db.scalar(select(func.count()).select_from(Claim).where(
        Claim.case_id == case_id, Claim.verification_status == "unverified")) or 0
    return {"unanswered_requirements": unanswered, "requirements_without_evidence": no_support,
            "stale_findings": stale, "stale_after_days": STALE_DAYS, "disputed_claims": disputed,
            "unverified_claims": unverified, "contradictions": len(contradictions(db, case_id)),
            "summary": f"{len(unanswered)} open requirement(s), {len(no_support)} without any evidence, "
                       f"{stale} stale finding(s), {disputed} disputed claim(s)."}


def active_merge_map(db: Session, case_id: str) -> dict[str, str]:
    """entity_id -> canonical id after following active links (cycles are impossible by construction)."""
    links = db.scalars(select(EntityLink).where(EntityLink.case_id == case_id, EntityLink.status == "active")).all()
    direct = {link.entity_id: link.canonical_entity_id for link in links}

    def root(i: str) -> str:
        seen = set()
        while i in direct and i not in seen:
            seen.add(i)
            i = direct[i]
        return i
    return {i: root(i) for i in direct}


def would_cycle(db: Session, case_id: str, entity_id: str, canonical_id: str) -> bool:
    m = active_merge_map(db, case_id)
    return m.get(canonical_id, canonical_id) == entity_id or canonical_id == entity_id
