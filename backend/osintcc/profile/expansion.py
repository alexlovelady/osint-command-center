"""The shared cross-INT expansion engine: from verified identifiers and credible leads to an inspectable, bounded, authorized research plan.

Every discipline contributes through the same path - the subject's identifiers, the source registry, the consent gate, the research approval and the shared case graph - so there
is one investigation, not separate tool results. This module only DECIDES what could be investigated next and (when allowed) hands passive, authorized steps to the existing
research pipeline (`research.approve`); it never talks to the network itself.

What it will never do:
  * expand from a candidate: only the subject's own inputs and CONFIRMED associations are seeds. "Likely" addresses are listed as proposals that need a person to confirm the
    association first; "possible" ones are listed as leads; "rejected" ones are invisible to it (counted, never planned);
  * use a seed outside the authorization: every step is judged by `consent.check` for that exact identifier and source class, and a client consent that names its identifiers does
    not cover a newly found one until the owner extends it;
  * run active verification or a sensitive check by itself: DARKINT lookups and AIV checks appear as proposals that need their own approval, in their own screens;
  * continue past its limits: depth, total source runs, runs per pass, authorization, offline mode and a closed case all stop it, and the stop reason is recorded.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.base import IntelAdapter
from ..config import Settings
from ..db.models import (
    AssociatedEmail,
    Case,
    ExpansionRun,
    ProfileCandidateLink,
    ResearchTask,
    Setting,
    Subject,
    SubjectIdentifier,
)
from ..telemetry import audit
from . import consent, emails, research
from .normalize import mask_value
from .registry import SOURCES
from .service import ProfileError

DEFAULT_POLICY = {"max_depth": 2, "max_runs": 20, "max_per_pass": 6, "auto_passive": False}
HARD_LIMITS = {"max_depth": (1, 4), "max_runs": (1, 100), "max_per_pass": (1, 20)}
SCORE = {"github_public": 90, "page_contacts": 85, "theharvester": 70, "sherlock": 60, "maigret": 50, "rdap": 40, "dns": 35, "crtsh": 30, "wayback": 20}


def _now() -> datetime:
    return datetime.now(UTC)


# ---- policy ---------------------------------------------------------------------------------------------------------------------------------
def get_policy(db: Session, subject: Subject) -> dict[str, Any]:
    row = db.get(Setting, f"expansion:{subject.id}")
    return {**DEFAULT_POLICY, **(row.value_json if row and isinstance(row.value_json, dict) else {})}


def set_policy(db: Session, subject: Subject, values: dict[str, Any], actor: str) -> dict[str, Any]:
    pol = get_policy(db, subject)
    for k, v in values.items():
        if k not in DEFAULT_POLICY:
            raise ProfileError("unknown_setting", f"unknown expansion setting '{k}'")
        if k == "auto_passive":
            pol[k] = bool(v)
            continue
        lo, hi = HARD_LIMITS[k]
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise ProfileError("out_of_range", f"{k} must be a whole number from {lo} to {hi}")
        pol[k] = v
    db.merge(Setting(key=f"expansion:{subject.id}", value_json=pol))
    audit.record(db, "profile.expansion_policy", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id, metadata=pol)
    return pol


# ---- seeds ----------------------------------------------------------------------------------------------------------------------------------
def seeds(db: Session, subject: Subject) -> dict[str, Any]:
    inputs, proposals, skipped = [], [], {"rejected_emails": 0, "unconfirmed_accounts": 0}
    for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.status == "active")):
        d, path = emails.identifier_depth(db, i)
        inputs.append({"kind": i.kind, "identifier_id": i.id, "label": mask_value(i.kind, i.value) if i.kind in ("email", "name", "alias") else i.value, "depth": d,
                       "origin_path": path or ["subject input"], "state": "input"})
    for r in db.scalars(select(AssociatedEmail).where(AssociatedEmail.subject_id == subject.id).order_by(AssociatedEmail.discovered_at)):
        label = mask_value("email", r.address)
        if r.state == "rejected":
            skipped["rejected_emails"] += 1
        elif r.state == "confirmed" and not r.identifier_id:
            proposals.append({"kind": "email", "associated_id": r.id, "label": label, "depth": r.depth, "state": "confirmed", "origin_path": r.origin_path,
                              "action": "add_input", "reason": "Confirmed. Add it as an input to research it (only inside what the authorization covers)."})
        elif r.state == "candidate" and r.classification == "likely":
            proposals.append({"kind": "email", "associated_id": r.id, "label": label, "depth": r.depth, "state": "likely", "origin_path": r.origin_path, "action": "confirm_first",
                              "reason": "Likely, not confirmed: two sources tie it to the subject, but a person must confirm before anything is researched from it."})
        elif r.state == "candidate":
            proposals.append({"kind": "email", "associated_id": r.id, "label": label, "depth": r.depth, "state": "possible", "origin_path": r.origin_path, "action": "lead_only",
                              "reason": "Possible: " + (r.explanation[0] if r.explanation else "not enough independent evidence") + " No research is planned from it."})
    known_urls = {i["label"] for i in inputs if i["kind"] == "url"}
    for c in db.scalars(select(ProfileCandidateLink).where(ProfileCandidateLink.subject_id == subject.id)):
        if c.state == "confirmed" and c.canonical_url not in known_urls:
            proposals.append({"kind": "url", "candidate_id": c.id, "label": c.canonical_url, "depth": 1, "state": "confirmed", "origin_path": [f"confirmed account on {c.site or 'a site'}"],
                              "action": "add_input", "reason": "A confirmed account page. Add it as an input to read its published contact addresses."})
        elif c.state in ("candidate", "unsure"):
            skipped["unconfirmed_accounts"] += 1
    return {"inputs": inputs, "proposals": proposals, "skipped": skipped}


# ---- plan -----------------------------------------------------------------------------------------------------------------------------------
def _domain(db: Session, identifier_id: str) -> str:
    i = db.get(SubjectIdentifier, identifier_id)
    return i.value.partition("@")[2].lower() if i else ""


def _priority(source_id: str, depth: int) -> int:
    return SCORE.get(source_id, 10) - depth * 5


def plan(db: Session, subject: Subject, case: Case, adapters: dict[str, IntelAdapter], settings: Settings, st: Any = None) -> dict[str, Any]:
    pol = get_policy(db, subject)
    sd = seeds(db, subject)
    done = {(t.identifier_id, t.source_id) for t in db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id, ResearchTask.status != "cancelled"))}
    used = len(done)
    depth_of = {s["identifier_id"]: s for s in sd["inputs"]}
    steps: list[dict[str, Any]] = []
    for e in research._entries(db, subject, case, adapters, settings, None):
        seed = depth_of.get(e["identifier_id"], {"depth": 0, "origin_path": ["subject input"]})
        src = SOURCES.get(e["source_id"])
        ran = (e["identifier_id"], e["source_id"]) in done
        needs = "none"
        if ran:
            needs = "already_done"
        elif not e["runnable"]:
            needs = "blocked"
        elif e["requires_confirmation"]:
            needs = "confirmation"
        beyond = seed["depth"] >= pol["max_depth"]
        if e["identifier_kind"] == "email" and e["runnable"] and src and src.category == "domain_infrastructure" and _domain(db, e["identifier_id"]) in emails.FREEMAIL:
            e = {**e, "runnable": False, "reason": "the address is at a free-mail provider, so records about its domain say nothing about the subject"}
            needs = "blocked"
        steps.append({"key": e["key"], "module": "OSINT" if not src or src.category != "exposure" else "DARKINT", "identifier_id": e["identifier_id"], "identifier": e["identifier"],
                      "identifier_kind": e["identifier_kind"], "source_id": e["source_id"], "source": e["name"], "depth": seed["depth"], "origin_path": seed["origin_path"],
                      "priority": _priority(e["source_id"], seed["depth"]), "runnable": e["runnable"] and not beyond, "needs": "depth_limit" if beyond and needs == "none" else needs,
                      "reason": ("beyond the depth limit" if beyond and needs == "none" else e["reason"]), "warnings": e["warnings"], "privacy": e["privacy"], "consent_class": e["consent_class"],
                      "executable_now": needs == "none" and e["runnable"] and not beyond, "endpoints": e["endpoints"], "maturity": e["maturity"], "data_classes": list(src.data_classes) if src else []})
    # other disciplines: shown as proposals that need their own approval. This engine never starts them.
    for s in sd["inputs"]:
        if s["kind"] in ("email", "domain", "organization"):
            d = consent.check(db, subject, "exposure_check", identifier_id=s["identifier_id"])
            steps.append({"key": f"{s['identifier_id']}:darkint", "module": "DARKINT", "identifier_id": s["identifier_id"], "identifier": s["label"], "identifier_kind": s["kind"], "source_id": "darkint",
                          "source": "Exposure check (breach and mention providers)", "depth": s["depth"], "origin_path": s["origin_path"], "priority": 5 - s["depth"], "runnable": False,
                          "needs": "explicit_approval", "executable_now": False, "reason": ("Needs its own preview and approval in the DARKINT tab." if d.allowed else f"authorization: {d.reason}"),
                          "warnings": [], "privacy": "personal_sensitive", "consent_class": "exposure_check", "endpoints": [], "maturity": "fixture_tested", "data_classes": ["exposure_status"]})
        if s["kind"] == "domain":
            steps.append({"key": f"{s['identifier_id']}:aiv", "module": "AIV", "identifier_id": s["identifier_id"], "identifier": s["label"], "identifier_kind": "domain", "source_id": "aiv",
                          "source": "Active verification (HTTP, TLS, ports)", "depth": s["depth"], "origin_path": s["origin_path"], "priority": 1, "runnable": False, "needs": "explicit_approval",
                          "executable_now": False, "reason": "Needs a written asset authorization and an approved plan in the Verification tab; a person's consent never covers it.",
                          "warnings": [], "privacy": "asset", "consent_class": "asset_authorization", "endpoints": [], "maturity": "fixture_tested", "data_classes": []})
    steps.sort(key=lambda x: (not x["executable_now"], x["depth"], -x["priority"]))
    stop = stop_reason(db, subject, case, settings, pol, steps, used)
    return {"subject_id": subject.id, "policy": pol, "seeds": sd, "steps": steps, "budget": {"used": used, "max_runs": pol["max_runs"], "remaining": max(0, pol["max_runs"] - used),
                                                                                              "max_per_pass": pol["max_per_pass"]},
            "stop_reason": stop, "authorization": consent.current_status(db, subject),
            "rules": ["Only your inputs and addresses a person confirmed are used as starting points.", "Likely and possible addresses are listed, never researched.", "A rejected address is never planned.",
                      "Active verification and exposure checks are proposals; they run only from their own screens after their own approval.",
                      "Limits: depth, total source runs, runs per pass, authorization, offline mode and a closed case each stop the expansion."]}


def stop_reason(db: Session, subject: Subject, case: Case, settings: Settings, pol: dict[str, Any], steps: list[dict[str, Any]], used: int) -> str:
    a = consent.current_status(db, subject)
    if a["status"] not in ("active", "not_required_for_public_org_sources"):
        return "authorization"
    if case.status != "open":
        return "case_not_open"
    if settings.offline:
        return "offline"
    if used >= pol["max_runs"]:
        return "budget_exhausted"
    if not any(s["executable_now"] or s["needs"] == "confirmation" for s in steps):
        return "no_new_leads" if not any(s["needs"] == "depth_limit" for s in steps) else "max_depth"
    return ""


# ---- run one pass ---------------------------------------------------------------------------------------------------------------------------
def promote_confirmed(db: Session, subject: Subject, actor: str) -> int:
    n = 0
    for r in db.scalars(select(AssociatedEmail).where(AssociatedEmail.subject_id == subject.id, AssociatedEmail.state == "confirmed", AssociatedEmail.identifier_id.is_(None))):
        emails.promote(db, subject, r.id, actor)
        n += 1
    return n


def run(db: Session, subject: Subject, case: Case, adapters: dict[str, IntelAdapter], settings: Settings, *, actor: str, keys: list[str] | None = None,
        confirmed_sources: list[str] | None = None, promote: bool = False) -> dict[str, Any]:
    """One bounded pass. Either the keys a person ticked, or - only when the subject's policy allows it - the passive, authorized, confirmation-free steps."""
    research.refresh_tasks(db, subject)
    emails.sweep(db, subject, actor)
    pol = get_policy(db, subject)
    promoted = promote_confirmed(db, subject, actor) if (promote or pol["auto_passive"]) else 0
    p = plan(db, subject, case, adapters, settings)
    reason = p["stop_reason"]
    rec = ExpansionRun(subject_id=subject.id, case_id=subject.case_id, depth=max([s["depth"] for s in p["steps"]] or [0]), policy_json=pol, plan_json=p["steps"][:200], created_by=actor)
    db.add(rec)
    chosen: list[str] = []
    run_ids: list[str] = []
    if reason in ("authorization", "case_not_open", "offline", "budget_exhausted"):
        rec.status, rec.stop_reason = "stopped", reason
    else:
        by_key = {s["key"]: s for s in p["steps"]}
        if keys is not None:
            bad = [k for k in keys if k not in by_key or by_key[k]["needs"] in ("blocked", "already_done", "depth_limit", "explicit_approval")]
            if bad:
                raise ProfileError("not_expandable", "a selected step is not available in the expansion plan (blocked, already done, beyond the depth limit, or needs its own approval)")
            chosen = list(keys)
        elif pol["auto_passive"]:
            chosen = [s["key"] for s in p["steps"] if s["executable_now"]]
        remaining = pol["max_runs"] - p["budget"]["used"]
        chosen = chosen[: max(0, min(pol["max_per_pass"], remaining))]
        if chosen:
            runs = research.approve(db, subject, case, adapters, settings, keys=chosen, confirmed_sources=confirmed_sources or [], actor=actor)
            rec.status, rec.started = "executed", len(runs)
            run_ids = [r.id for r in runs]
        else:
            rec.status, rec.stop_reason = "stopped", reason or "nothing_selected"
    if rec.status == "executed" and pol["max_runs"] - p["budget"]["used"] - len(chosen) <= 0:
        rec.stop_reason = "budget_exhausted"
    audit.record(db, "profile.expansion_run", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id,
                 metadata={"chosen": len(chosen), "status": rec.status, "stop": rec.stop_reason, "promoted": promoted})
    db.flush()
    return {"id": rec.id, "status": rec.status, "stop_reason": rec.stop_reason, "started_runs": rec.started, "promoted_inputs": promoted, "chosen": chosen, "run_ids": run_ids,
            "budget": {"used": p["budget"]["used"] + len(chosen), "max_runs": pol["max_runs"]}, "depth": rec.depth}


def history(db: Session, subject: Subject) -> list[dict[str, Any]]:
    return [{"id": r.id, "status": r.status, "stop_reason": r.stop_reason, "started": r.started, "depth": r.depth, "created_by": r.created_by, "at": r.created_at,
             "steps": len(r.plan_json)} for r in db.scalars(select(ExpansionRun).where(ExpansionRun.subject_id == subject.id).order_by(ExpansionRun.created_at.desc()).limit(50))]
