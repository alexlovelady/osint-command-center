"""Result accounting: how one source's raw hits become findings, candidates and profile items, and where every number goes.

The grains differ on purpose and each is named: a task's `result_count` is what the tool returned, a finding is one stored observation, a candidate account is a canonical profile
page (several tools and several URL spellings of the same page count once), a profile item is one entry in the master profile. Nothing here guesses: every figure is counted from
the stored records, and each line says what it is a count OF.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import Finding, ProfileCandidateLink, ProfileItem, ResearchTask, Subject
from . import candidates, research
from .registry import SOURCES


def _label(source_id: str) -> str:
    s = SOURCES.get(source_id)
    return s.label if s else source_id


def pipeline(db: Session, subject: Subject) -> dict[str, Any]:
    research.refresh_tasks(db, subject)
    candidates.sync_from_findings(db, subject)
    tasks = list(db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id).order_by(ResearchTask.created_at)))
    links = list(db.scalars(select(ProfileCandidateLink).where(ProfileCandidateLink.subject_id == subject.id)))
    items = list(db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.status == "active", ProfileItem.origin == "discovered")))
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for t in tasks:
        if t.source_id in seen:
            continue
        seen.add(t.source_id)
        mine = [x for x in tasks if x.source_id == t.source_id]
        run_ids = {x.run_id for x in mine if x.run_id}
        finds = list(db.scalars(select(Finding).where(Finding.case_id == subject.case_id, Finding.adapter_id == t.source_id, Finding.run_id.in_(run_ids)))) if run_ids else []
        cand = [c for c in links if t.source_id in c.adapters]
        its = [i for i in items if i.collection_method == f"adapter:{t.source_id}"]
        retrieved = sum(x.result_count for x in mine)
        rows.append({"source_id": t.source_id, "source": _label(t.source_id), "status": mine[-1].status, "runs": len(mine), "retrieved": retrieved, "findings": len(finds),
                     "evidence": len({f.evidence_id for f in finds}), "candidate_accounts": len(cand), "profile_items": len(its),
                     "shared_with_other_tools": sum(1 for c in cand if len(c.adapters) > 1),
                     "explain": _explain(retrieved, len(finds), len(cand), len(its)), "limitations": mine[-1].limitations})
    raw = sum(len(c.finding_ids) for c in links)               # every stored sighting of a profile page, by any tool
    for aid in sorted({a for c in links for a in c.adapters} - seen):
        cand = [c for c in links if aid in c.adapters]
        rows.append({"source_id": aid, "source": _label(aid), "status": "recorded", "runs": 0, "retrieved": 0, "findings": sum(len(c.finding_ids) for c in cand), "evidence": 0,
                     "candidate_accounts": len(cand), "profile_items": 0, "shared_with_other_tools": sum(1 for c in cand if len(c.adapters) > 1),
                     "explain": f"{len(cand)} unique candidate accounts from stored findings (no research task is recorded for this tool)", "limitations": ""})
    states = {s: sum(1 for c in links if c.state == s) for s in ("candidate", "unsure", "confirmed", "rejected")}
    own = {"self_attested": 0, "independently_corroborated": 0}
    for c in links:
        o = candidates.ownership(db, c)
        if o:
            own[o] += 1
    return {"sources": rows, "accounts": {"tool_hits": raw, "unique_accounts": len(links), "seen_by_more_than_one_tool": sum(1 for c in links if len(c.adapters) > 1),
                                          "by_review_state": states, "confirmed_by": own,
                                          "explain": (f"{raw} stored sightings became {len(links)} unique account pages ({max(0, raw - len(links))} repeats and URL variants merged). Two tools agreeing on a handle "
                                                      "is one signal, not two. Only reviewed accounts count as owned.") if links else "No candidate accounts yet."},
            "profile_items": {"discovered": len(items), "by_type": _by_type(items)}}


def _by_type(items: list[ProfileItem]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        out[i.type] = out.get(i.type, 0) + 1
    return out


def _explain(retrieved: int, findings: int, cands: int, items: int) -> str:
    parts = [f"{retrieved} returned"]
    parts.append(f"{findings} stored as findings")
    if cands:
        parts.append(f"{cands} unique candidate accounts")
    if items:
        parts.append(f"{items} profile entries (duplicates of an existing entry are not added again)")
    return " → ".join(parts)
