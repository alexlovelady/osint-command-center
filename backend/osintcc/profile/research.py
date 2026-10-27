"""Bounded, consent-gated research plans for a subject: identifier -> source eligibility -> approval -> existing run pipeline -> coverage.

Nothing here talks to the network. `approve` hands approved (identifier, source) pairs to `search.service.create_run`, so SSRF protection, scope,
rate limits, evidence hashing, provenance and the execution-time policy re-check are exactly the ones every other search uses.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.base import IntelAdapter
from ..config import Settings
from ..db.models import (
    Case,
    ExposureIndicator,
    ImageAsset,
    Job,
    ProfileClaim,
    ResearchTask,
    SearchRun,
    Setting,
    Subject,
    SubjectIdentifier,
)
from ..policy.targets import TargetError, detect_target
from ..search import service as search
from ..telemetry import audit
from . import consent
from .normalize import mask_value
from .registry import CATEGORIES, KIND_TO_TARGET, SOURCES, sources_for
from .service import ProfileError

MAX_TASKS_PER_APPROVAL = 40       # work budget per approval
OUTDATED_DAYS = 30
STOP_RULES = [
    "No automatic recursion here: results never become new research inputs on their own. New addresses are candidates; bounded follow-up from CONFIRMED addresses is planned under Associated emails.",
    f"At most {MAX_TASKS_PER_APPROVAL} source runs per approval; each additional identifier or source needs a fresh approval.",
    "Authorization is re-checked when each source starts, so revoking or expiring it stops queued work.",
    "A source that is unavailable, rate limited or fails is reported as such; it is never reported as 'nothing found'.",
]


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=UTC)


def _entries(db: Session, subject: Subject, case: Case, adapters: dict[str, IntelAdapter], settings: Settings,
             identifier_ids: list[str] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    idents = [i for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.status == "active"))
              if not identifier_ids or i.id in identifier_ids]
    last = {(t.identifier_id, t.source_id): t for t in db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id).order_by(ResearchTask.created_at))}
    for ident in idents:
        for src in sources_for(ident.kind):
            e: dict[str, Any] = {"key": f"{ident.id}:{src.id}", "identifier_id": ident.id, "identifier_kind": ident.kind,
                                 "identifier": mask_value(ident.kind, ident.value) if ident.kind in ("email", "name", "alias") else ident.value,
                                 "source_id": src.id, "name": src.label, "category": src.category, "consent_class": src.source_class,
                                 "privacy": src.privacy, "maturity": src.maturity, "legal_note": src.legal_note, "commercial_use": src.commercial_use,
                                 "runnable": False, "reason": "", "requires_confirmation": False, "warnings": [], "endpoints": [], "rate_limit_per_minute": None,
                                 "cost": "free", "needs_key": None, "previous": None}
            t = last.get((ident.id, src.id))
            if t:
                e["previous"] = {"status": t.status, "last_success": t.last_success, "result_count": t.result_count, "limitations": t.limitations}
            ad = adapters.get(src.id)
            if ad is None:
                e["reason"] = "not installed, disabled or quarantined in this installation"
                out.append(e)
                continue
            m = ad.manifest
            e.update(endpoints=m.endpoints, rate_limit_per_minute=m.rate_limit_per_minute, needs_key=m.api_key_name, cost="key required" if m.api_key_name else "free")
            d = consent.check(db, subject, src.source_class, identifier_id=ident.id)
            e["consent"] = {"allowed": d.allowed, "reason": d.reason, "code": d.code}
            if not d.allowed:
                e["reason"] = f"authorization: {d.reason}"
                out.append(e)
                continue
            if src.id == "sec_edgar" and not ident.value.isdigit():
                e["reason"] = "SEC EDGAR needs a CIK number; this organisation input is a name"
                out.append(e)
                continue
            try:
                parsed = detect_target(ident.value, "cik" if src.id == "sec_edgar" else KIND_TO_TARGET[ident.kind])
                plan = search.build_plan(db, case, parsed, adapters, settings, selected=[src.id],
                                         mode="public_site_query" if m.operation_class == "public_site_query" else "passive")
            except (TargetError, search.PlanError) as exc:
                e["reason"] = str(exc)
                out.append(e)
                continue
            step = plan["steps"][0] if plan["steps"] else None
            if not step or not step["runnable"]:
                e["reason"] = (step or {}).get("reason", "this source does not support that input")
            else:
                e.update(runnable=True, reason=step["reason"], requires_confirmation=bool(step.get("requires_confirmation")) or src.source_class == "public_site_query", warnings=step.get("warnings", []))   # anything that sends the identifier to a third party is approved by name
            out.append(e)
    return out


def preview(db: Session, subject: Subject, case: Case, adapters: dict[str, IntelAdapter], settings: Settings,
            identifier_ids: list[str] | None = None) -> dict[str, Any]:
    """What WOULD be contacted, per identifier and source. Sends nothing and records nothing except the audit entry for the preview."""
    entries = _entries(db, subject, case, adapters, settings, identifier_ids)
    runnable = [e for e in entries if e["runnable"]]
    return {"subject_id": subject.id, "authorization": consent.current_status(db, subject), "entries": entries,
            "budget": {"max_per_approval": MAX_TASKS_PER_APPROVAL, "runnable": len(runnable), "paid_requests": 0},
            "stop_rules": STOP_RULES, "offline": settings.offline,
            "note": "Nothing has been sent. Tick the sources you approve; public-site tools also need their own confirmation."}


def approve(db: Session, subject: Subject, case: Case, adapters: dict[str, IntelAdapter], settings: Settings, *, keys: list[str],
            confirmed_sources: list[str], actor: str) -> list[SearchRun]:
    if not keys:
        raise ProfileError("nothing_selected", "select at least one source to run")
    if len(keys) > MAX_TASKS_PER_APPROVAL:
        raise ProfileError("budget_exceeded", f"at most {MAX_TASKS_PER_APPROVAL} source runs per approval")
    if case.status != "open":
        raise ProfileError("case_not_open", "the case must be open to collect")
    wanted = set(keys)
    entries = {e["key"]: e for e in _entries(db, subject, case, adapters, settings, None)}
    unknown = wanted - set(entries)
    if unknown:
        raise ProfileError("unknown_selection", "a selected source/input pair is not part of this subject's plan")
    blocked = [entries[k] for k in keys if not entries[k]["runnable"]]
    if blocked:
        b = blocked[0]
        audit.record(db, "research.refused", actor=actor, case_id=case.id, resource_type="subject", resource_id=subject.id, decision="deny",
                     metadata={"source": b["source_id"], "reason": b["reason"][:160]})
        code = b.get("consent", {}).get("code", "blocked") if not b.get("consent", {}).get("allowed", True) else "blocked"
        raise ProfileError(code if code != "ok" else "blocked", f"{b['name']}: {b['reason']}")
    need = [entries[k] for k in keys if entries[k]["requires_confirmation"] and entries[k]["source_id"] not in confirmed_sources]
    if need:
        raise ProfileError("confirmation_required", "explicit confirmation required for: " + ", ".join(sorted({e["name"] for e in need})))
    by_ident: dict[str, list[dict[str, Any]]] = {}
    for k in keys:
        by_ident.setdefault(entries[k]["identifier_id"], []).append(entries[k])
    runs: list[SearchRun] = []
    for iid, items in by_ident.items():
        ident = db.get(SubjectIdentifier, iid)
        assert ident is not None
        ids = [e["source_id"] for e in items]
        public_site = any(adapters[i].manifest.operation_class == "public_site_query" for i in ids)
        mode = "public_site_query" if public_site else "passive"
        # sec_edgar needs a CIK-typed target while the others use the identifier's own type: one run per distinct target type
        groups: dict[str, list[str]] = {}
        for e in items:
            groups.setdefault("cik" if e["source_id"] == "sec_edgar" else KIND_TO_TARGET[ident.kind], []).append(e["source_id"])
        for ttype, sids in groups.items():
            parsed = detect_target(ident.value, ttype)
            try:
                plan = search.build_plan(db, case, parsed, adapters, settings, selected=sids, mode=mode)
                run = search.create_run(db, case, parsed, plan, confirmed=[s for s in sids if s in confirmed_sources], mode=mode)
            except search.PlanError as exc:
                raise ProfileError("plan_refused", str(exc)) from exc
            runs.append(run)
            for s in sids:
                db.add(ResearchTask(subject_id=subject.id, case_id=case.id, category=SOURCES[s].category, source_id=s, identifier_id=iid, run_id=run.id,
                                    status="approved", approval_reference=run.id, last_attempt=_now()))
    audit.record(db, "research.approve", actor=actor, case_id=case.id, resource_type="subject", resource_id=subject.id,
                 metadata={"sources": sorted({entries[k]["source_id"] for k in keys}), "tasks": len(keys), "runs": len(runs)})
    db.flush()
    return runs


_JOB_TO_TASK = {"succeeded": "completed", "failed": "failed", "denied": "blocked", "skipped": "unavailable", "cancelled": "cancelled", "interrupted": "failed"}


def refresh_tasks(db: Session, subject: Subject) -> int:
    """Fold finished job outcomes back into the research tasks (idempotent)."""
    n = 0
    for t in db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id, ResearchTask.status.in_(("approved", "running", "waiting_limits")))):
        job = db.scalars(select(Job).where(Job.run_id == t.run_id, Job.adapter_id == t.source_id)).first()
        if job is None:
            continue
        if job.status == "deferred":
            t.status, t.limitations = "waiting_limits", "; ".join(job.warnings_json)[:500] or "Waiting for a provider limit to reset."
            continue
        if job.status == "queued":
            if t.status == "waiting_limits":
                t.status = "approved"
            continue
        if job.status == "running":
            t.status = "running"
            continue
        new = _JOB_TO_TASK.get(job.status, "failed")
        if job.quota_status in ("blocked_credentials", "blocked_plan", "disabled_provider", "awaiting_authorization"):
            new = "blocked"
        if new == "completed" and (job.result_status == "partial" or any("partial" in w.lower() for w in job.warnings_json)):
            new = "partial"
        t.status, t.limitations = new, "; ".join(job.warnings_json)[:500] or (job.last_error_code or "")
        t.result_count = len(job.result_keys_json)
        t.last_attempt = _aware(job.finished_at) or _now()
        if new in ("completed", "partial"):
            t.last_success = t.last_attempt
        n += 1
    db.flush()
    return n


def last_collected(db: Session, subject: Subject) -> datetime | None:
    ts = [t.last_success for t in db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id)) if t.last_success]
    return max(ts, key=lambda d: _aware(d) or _now()) if ts else None


def execution_gate(db: Session, run: SearchRun, job: Job) -> str | None:
    """Called by the job runner immediately before an adapter starts. Returns a refusal reason, or None when this run is not profile research
    or is still fully authorized. This is what makes revocation, expiry, crash recovery and retries fail closed."""
    t = db.scalars(select(ResearchTask).where(ResearchTask.run_id == run.id, ResearchTask.source_id == job.adapter_id)).first()
    if t is None:
        return None
    subject = db.get(Subject, t.subject_id)
    if subject is None or t.status in ("cancelled", "blocked"):
        return "research task was cancelled"
    src = SOURCES.get(job.adapter_id)
    d = consent.check(db, subject, src.source_class if src else "public_passive", identifier_id=t.identifier_id)
    if not d.allowed:
        t.status, t.limitations = "blocked", d.reason
        return d.reason
    if job.adapter_id == "virustotal" and subject.mode != "self":                     # the public API is personal and non-commercial; business or client use needs the operator's licence confirmation
        lic = db.get(Setting, "quota.licensed.virustotal")
        if not (lic and lic.value_json):
            t.status, t.limitations = "blocked", "VirusTotal's public API is for personal, non-commercial use; confirm a covering licence in Settings to use it here."
            return t.limitations
    job.scope_ref = f"task:{t.id}"
    t.status, t.last_attempt = "running", _now()
    return None


# ---- coverage ------------------------------------------------------------------------------------------------------------------------------
def coverage(db: Session, subject: Subject, adapters: dict[str, IntelAdapter], health: dict[str, str] | None = None) -> dict[str, Any]:
    """Completed research methods versus the approved plan. It is NOT a percentage of everything that exists about a person."""
    refresh_tasks(db, subject)
    health = health or {}
    idents = list(db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.status == "active")))
    kinds = {i.kind for i in idents}
    tasks: dict[str, list[ResearchTask]] = {}
    for t in db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id).order_by(ResearchTask.created_at)):
        tasks.setdefault(t.source_id, []).append(t)
    now = _now()
    manual_counts = {
        "manual_professional": db.query(ProfileClaim).filter(ProfileClaim.subject_id == subject.id, ProfileClaim.field.in_(("employer", "role", "education", "business_association"))).count(),
        "manual_documents": db.query(ProfileClaim).filter(ProfileClaim.subject_id == subject.id, ProfileClaim.field.in_(("document", "publication"))).count(),
        "manual_images": db.query(ImageAsset).filter(ImageAsset.subject_id == subject.id).count(),
        "manual_exposure": db.query(ExposureIndicator).filter(ExposureIndicator.subject_id == subject.id).count(),
    }
    cats: list[dict[str, Any]] = []
    totals: dict[str, int] = {}
    for cat, title in CATEGORIES.items():
        cells = []
        for s in (x for x in SOURCES.values() if x.category == cat):
            cell: dict[str, Any] = {"source_id": s.id, "name": s.label, "maturity": s.maturity, "status": "", "detail": "", "last_success": None}
            if s.manual:
                n = manual_counts[s.id]
                cell.update(status="completed" if n else "not_run", detail=f"{n} record(s) entered" if n else "No records entered yet (manual method)")
            elif s.id not in adapters:
                cell.update(status="unavailable", detail="not installed, disabled or quarantined")
            elif not (kinds & set(s.identifier_kinds)):
                cell.update(status="unsupported", detail="needs a " + " or ".join(s.identifier_kinds) + " input, which this subject does not have")
            else:
                ts = tasks.get(s.id, [])
                h = health.get(s.id)
                if ts:
                    t = ts[-1]
                    st = t.status
                    if st in ("completed", "partial") and t.last_success and (_aware(t.last_success) or now) < now - timedelta(days=OUTDATED_DAYS):
                        st = "outdated"
                    cell.update(status=st, detail=t.limitations or (f"{t.result_count} result(s)" if st in ("completed", "partial", "outdated") else ""), last_success=t.last_success)
                elif h and h != "healthy":
                    cell.update(status="unavailable", detail=f"tool state: {h.replace('_', ' ')}")
                else:
                    cell.update(status="not_run", detail="eligible but not yet approved or run")
            totals[cell["status"]] = totals.get(cell["status"], 0) + 1
            cells.append(cell)
        cats.append({"key": cat, "title": title, "cells": cells})
    approved = sum(1 for ts in tasks.values() for t in ts if t.status != "cancelled")
    done = sum(1 for ts in tasks.values() for t in ts if t.status in ("completed", "partial"))
    return {"categories": cats, "totals": totals, "approved_tasks": approved, "completed_tasks": done,
            "label": "Coverage shows which approved research methods have run. It is not a measure of how much information exists about this subject.",
            "legend": ["completed", "partial", "outdated", "not_run", "approved", "running", "failed", "blocked", "cancelled", "unsupported", "unavailable"]}


def next_action(db: Session, subject: Subject, cov: dict[str, Any]) -> str:
    a = consent.current_status(db, subject)
    if a["status"] in ("none",):
        return "Record an authorization before any collection."
    if a["status"] in ("expired", "revoked", "not_yet_valid"):
        return "Authorization is not current: renew it to resume collection."
    from . import candidates
    leads = len(candidates.list_candidates(db, subject, "candidate"))
    if leads:
        return f"Review {leads} unresolved lead(s)."
    if not db.query(SubjectIdentifier).filter_by(subject_id=subject.id, status="active").count():
        return "Add an input (username, email or domain) to research."
    todo = [c["name"] for cat in cov["categories"] for c in cat["cells"] if c["status"] == "not_run" and c["maturity"] != "manual"]
    if todo:
        return f"Approve the next collection ({todo[0]} is eligible and has not run)."
    return "Everything approved has run. Add inputs or refresh outdated checks."
