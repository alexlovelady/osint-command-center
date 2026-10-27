"""One-click investigation: a durable, bounded orchestration over the services that already exist.

It owns NO results and talks to NO network itself. Each step it
  1. builds a manifest from the real adapters, the real authorization and the subject's own inputs (what will run, what cannot and exactly why),
  2. asks the existing expansion planner what is allowed next (inputs and CONFIRMED associations only; a found handle is a lead, never a seed),
  3. hands the chosen steps to the existing research approval (consent gate, SSRF guard, rate limits, evidence vault),
  4. folds the outcome back (emails, leads, candidate accounts) and checkpoints in `investigation_runs` / `investigation_events`.
Providers that send an identifier to a third party run only if the person named them in the single approval made when pressing Investigate; anything else is listed as
"needs approval" while the remaining work continues. Every limit (depth, source runs, runs per identifier, runtime, authorization, offline, closed case) stops it and says why.
Nothing is ever reported complete when a method was unavailable: the finished state is "complete with limits" and the limits are listed.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    AssociatedEmail,
    Case,
    InvestigationEvent,
    InvestigationRun,
    Job,
    ProfileCandidateLink,
    ProfileItem,
    ResearchTask,
    Subject,
    SubjectIdentifier,
)
from ..telemetry import audit
from . import accounting, candidates, consent, emails, expansion, master, research
from .normalize import mask_value
from .registry import SOURCES
from .service import ProfileError

DEFAULT_POLICY = {"max_depth": 2, "max_runs": 100, "per_pass": 10, "per_identifier": 10, "followups_per_pass": 25, "runtime_minutes": 30}
LIMITS = {"max_depth": (1, 4), "max_runs": (1, 100), "per_pass": (1, 20), "per_identifier": (1, 50), "followups_per_pass": (1, 100), "runtime_minutes": (1, 120)}
ACTIVE = ("queued", "collecting", "correlating", "expanding")
WAITING = "waiting_limits"          # parked: every remaining check is waiting for a provider's rate limit or quota to reset; a durable resumer continues it
FINISHED = ("awaiting_review", "complete_with_limits", "completed", "cancelled", "failed")
INPUT_KINDS = {"person": ("name", "email", "phone", "username", "alias", "url", "domain", "organization"), "business": ("organization", "domain", "url", "email", "username", "name", "phone")}
STATUS_LABEL = {"ready": "Ready", "needs_approval": "Sends to a third party (needs your approval)", "needs_key": "Needs an API key", "needs_authorization": "Needs authorization",
                "unsupported_input": "No supported source", "not_installed": "Not installed", "separate_approval": "Needs its own approval", "blocked": "Not allowed here",
                "already_done": "Already done", "over_cap": "Per-identifier cap reached"}


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=UTC)


# ---- reading what a person typed -------------------------------------------------------------------------------------------------------------
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_URL = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
_PHONE = re.compile(r"^\+?[0-9][0-9 ()\-.]{6,22}[0-9]$")
_HANDLE = re.compile(r"^@[A-Za-z0-9_.\-]{2,38}$")


def detect_kind(text: str, investigation: str = "person") -> dict[str, Any]:
    """A guess at what a pasted value is, with the alternatives, so the person can correct it. Never inferred authority: it only labels the input."""
    v = " ".join(text.split())
    if not v:
        return {"value": "", "kind": None, "alternatives": []}
    if _EMAIL.match(v):
        kind = "email"
    elif _URL.match(v):
        kind = "url"
    elif _PHONE.match(v) and sum(c.isdigit() for c in v) >= 7:
        kind = "phone"
    elif _HANDLE.match(v):
        kind = "username"
        v = v.lstrip("@")
    elif _DOMAIN.match(v):
        kind = "domain"
    elif " " in v:
        kind = "organization" if investigation == "business" else "name"
    else:
        kind = "username"
    alts = [k for k in INPUT_KINDS[investigation if investigation in INPUT_KINDS else "person"] if k != kind]
    return {"value": v, "kind": kind, "alternatives": alts}


# ---- policy ------------------------------------------------------------------------------------------------------------------------------------
def clean_policy(values: dict[str, Any] | None) -> dict[str, Any]:
    pol = dict(DEFAULT_POLICY)
    for k, v in (values or {}).items():
        if k not in DEFAULT_POLICY:
            raise ProfileError("unknown_setting", f"unknown investigation setting '{k}'")
        lo, hi = LIMITS[k]
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise ProfileError("out_of_range", f"{k} must be a whole number from {lo} to {hi}")
        pol[k] = v
    return pol


# ---- events --------------------------------------------------------------------------------------------------------------------------------------
def emit(db: Session, run: InvestigationRun, kind: str, message: str, detail: dict[str, Any] | None = None) -> None:
    seq = (db.scalar(select(func.max(InvestigationEvent.seq)).where(InvestigationEvent.run_id == run.id)) or 0) + 1
    db.add(InvestigationEvent(run_id=run.id, seq=seq, kind=kind, message=message[:500], detail_json=detail or {}))
    run.updated_at = _now()


def events(db: Session, run: InvestigationRun, after: int = 0, limit: int = 200) -> list[dict[str, Any]]:
    q = select(InvestigationEvent).where(InvestigationEvent.run_id == run.id, InvestigationEvent.seq > after).order_by(InvestigationEvent.seq).limit(limit)
    return [{"seq": e.seq, "kind": e.kind, "message": e.message, "detail": e.detail_json, "at": e.at} for e in db.scalars(q)]


# ---- manifest -------------------------------------------------------------------------------------------------------------------------------------
def _key_missing(st: Any, ad: Any) -> str | None:
    key = ad.manifest.api_key_name if ad else None
    if key and st is not None and not st.runner.ctx_factory().secret(key):
        return str(key)
    return None


def _classify(step: dict[str, Any], st: Any, subject: Subject | None = None) -> tuple[str, str]:
    ad = st.adapters.get(step["source_id"])
    reason = step.get("reason", "")
    needs = step["needs"]
    if needs == "already_done":
        return "already_done", "This source already ran for this input."
    quota = getattr(st, "quota", None)
    if quota is not None and step["source_id"] == "virustotal" and subject is not None and subject.mode != "self" and not quota.licensed("virustotal"):
        return "blocked", "VirusTotal's public API is limited to personal, non-commercial use, and this investigation is not a personal self-audit. If you hold a VirusTotal licence that covers this use, confirm it in Settings → Provider usage; otherwise this source is not used. Nothing was sent."
    notice = quota.notice(step["source_id"]) if quota is not None else None
    if notice and notice["state"] == "disabled":
        return "blocked", notice["text"]
    if notice and notice["state"] in ("rejected", "plan_restricted", "missing_config"):
        return "needs_key", notice["text"]
    if ad is not None and (k := _key_missing(st, ad)) and needs != "blocked":
        return "needs_key", f"No '{k}' key is stored. Add it in Settings to enable this source; nothing was sent."
    if needs == "blocked":
        low = reason.lower()
        if "authorization" in low:
            return "needs_authorization", reason
        if "not installed" in low or "disabled" in low or "quarantined" in low:
            return "not_installed", reason
        return "blocked", reason
    if needs in ("explicit_approval",):
        return "separate_approval", reason
    if needs == "depth_limit":
        return "blocked", "Beyond the depth limit for this investigation."
    if needs == "confirmation":
        return "needs_approval", "Sends this input to a third-party site, so it needs your approval."
    return "ready", reason


def build_manifest(db: Session, st: Any, subject: Subject, case: Case) -> dict[str, Any]:
    plan = expansion.plan(db, subject, case, st.adapters, st.settings, st)
    rows: list[dict[str, Any]] = []
    covered: set[str] = set()
    for s in plan["steps"]:
        status, why = _classify(s, st, subject)
        src = SOURCES.get(s["source_id"])
        hosts = sorted({u.split("/")[2] for u in s.get("endpoints", []) if u.startswith("http")})
        covered.add(s["identifier_id"])
        rows.append({"key": s["key"], "source_id": s["source_id"], "source": s["source"], "module": s["module"], "identifier_id": s["identifier_id"], "identifier_kind": s["identifier_kind"],
                     "identifier": s["identifier"], "status": status, "status_label": STATUS_LABEL[status], "reason": why, "third_party": bool(hosts) or s["needs"] == "confirmation",
                     "recipients": hosts, "maturity": s.get("maturity", ""), "verified_live": bool(src and src.maturity == "live_tested"), "category": src.category if src else s["module"],
                     "data_classes": s.get("data_classes", []), "depth": s["depth"]})
    for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.status == "active")):
        if i.id not in covered:
            rows.append(_unsupported(i.kind, mask_value(i.kind, i.value) if i.kind in ("email", "name", "alias") else i.value, i.id))
    for it in db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.type == "phone", ProfileItem.status == "active")):
        rows.append(_unsupported("phone", "••• ••• " + re.sub(r"\D", "", it.value)[-2:] if it.value else "•••", it.id))
    rows.sort(key=lambda r: (["ready", "needs_approval", "needs_key", "needs_authorization", "separate_approval", "blocked", "not_installed", "unsupported_input", "already_done"].index(r["status"])
                             if r["status"] in STATUS_LABEL and r["status"] != "over_cap" else 9, r["identifier_kind"], r["source"]))
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    third = sorted({r["source"] for r in rows if r["status"] in ("ready", "needs_approval") and r["third_party"]})
    return {"rows": rows, "counts": counts, "third_parties": third, "authorization": plan["authorization"], "stop_reason": plan["stop_reason"],
            "approvable": sorted({r["source_id"] for r in rows if r["status"] == "needs_approval"})}


def _unsupported(kind: str, label: str, ident_id: str) -> dict[str, Any]:
    if kind == "phone":
        why = "No approved phone-discovery source is configured. The number is stored privately and masked; nothing will be searched with it."
    else:
        why = f"No configured source searches by {kind}. Add an email, username, website or organization for automatic research."
    return {"key": f"{ident_id}:none", "source_id": "", "source": "No supported source", "module": "OSINT", "identifier_id": ident_id, "identifier_kind": kind, "identifier": label,
            "status": "unsupported_input", "status_label": STATUS_LABEL["unsupported_input"], "reason": why, "third_party": False, "recipients": [], "maturity": "", "verified_live": False,
            "category": "none", "data_classes": [], "depth": 0}


# ---- lifecycle ------------------------------------------------------------------------------------------------------------------------------------
def start(db: Session, st: Any, subject: Subject, case: Case, *, actor: str, kind: str = "person", approved_sources: list[str] | None = None, excluded_sources: list[str] | None = None,
          policy: dict[str, Any] | None = None, idempotency_key: str | None = None) -> InvestigationRun:
    if idempotency_key:
        old = db.scalars(select(InvestigationRun).where(InvestigationRun.subject_id == subject.id, InvestigationRun.idempotency_key == idempotency_key)).first()
        if old:
            return old
    pol = clean_policy(policy)
    man = build_manifest(db, st, subject, case)
    approvable = set(man["approvable"])
    asked = set(approved_sources or [])
    if asked - approvable - {r["source_id"] for r in man["rows"] if r["status"] == "ready"}:
        raise ProfileError("unknown_selection", "an approved source is not part of this investigation's plan")
    expansion.set_policy(db, subject, {"max_depth": pol["max_depth"], "max_runs": pol["max_runs"], "max_per_pass": pol["per_pass"]}, actor)
    auth = consent.current_status(db, subject)
    ok = auth["status"] in ("active", "not_required_for_public_org_sources")
    run = InvestigationRun(case_id=case.id, subject_id=subject.id, kind=kind, status="queued" if ok else "draft", phase="", policy_json=pol, approved_sources=sorted(asked & approvable),
                           excluded_sources=sorted(set(excluded_sources or [])), manifest_json={"counts": man["counts"], "rows": man["rows"][:300], "third_parties": man["third_parties"]},
                           requested_by=actor, idempotency_key=idempotency_key, started_at=_now() if ok else None,
                           deadline_at=_now() + timedelta(minutes=pol["runtime_minutes"]) if ok else None, stop_reason="" if ok else "authorization")
    db.add(run)
    db.flush()
    emit(db, run, "created", "Investigation created" + ("" if ok else ": waiting for an authorization"), {"counts": man["counts"], "approved": run.approved_sources})
    audit.record(db, "investigation.start", actor=actor, case_id=case.id, resource_type="subject", resource_id=subject.id,
                 metadata={"run": run.id, "approved_sources": run.approved_sources, "policy": pol, "state": run.status})
    return run


def _tasks(db: Session, subject: Subject) -> list[ResearchTask]:
    return list(db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id)))


def _waiting_jobs(db: Session, tasks: list[ResearchTask]) -> list[Job]:
    out = []
    for t in tasks:
        job = db.scalars(select(Job).where(Job.run_id == t.run_id, Job.adapter_id == t.source_id)).first() if t.run_id else None
        if job is not None and job.status in ("queued", "deferred", "running"):
            out.append(job)
    return out


def _park(db: Session, run: InvestigationRun, waiting: list[ResearchTask]) -> None:
    """Everything that is left is waiting for a provider limit. Say so, remember when it may resume, and stop spending the runtime allowance."""
    jobs = _waiting_jobs(db, waiting)
    times = [j.next_retry_at.replace(tzinfo=UTC) if j.next_retry_at.tzinfo is None else j.next_retry_at for j in jobs if j.next_retry_at]
    nxt = min(times) if times else None
    first = run.status != WAITING
    run.status, run.phase, run.stop_reason = WAITING, WAITING, "provider_limits"
    run.counts_json = {**run.counts_json, "waiting_since": run.counts_json.get("waiting_since") or _now().isoformat() if first else run.counts_json.get("waiting_since"),
                       "next_eligible_at": nxt.isoformat() if nxt else None, "waiting_checks": len(waiting)}
    if first:
        emit(db, run, "waiting", f"{len(waiting)} check(s) are waiting for a provider's limit to reset" + (f"; the next one may run after {nxt.strftime('%H:%M UTC')}." if nxt else "."),
             {"checks": len(waiting), "next_eligible_at": nxt.isoformat() if nxt else None})


def wake(st: Any, run_id: str) -> bool:
    """Continue a parked investigation once none of its checks is still waiting on a provider. Called by the durable resumer; safe to call repeatedly."""
    with st.sm() as db:
        run = db.get(InvestigationRun, run_id)
        if run is None or run.status != WAITING:
            return False
        subject = db.get(Subject, run.subject_id)
        assert subject is not None
        research.refresh_tasks(db, subject)
        if any(t.status in ("waiting_limits", "approved", "running") for t in _tasks(db, subject)):
            db.commit()
            return False
        since = run.counts_json.get("waiting_since")
        if run.deadline_at and since:
            try:
                run.deadline_at = run.deadline_at + (_now() - datetime.fromisoformat(since))     # the runtime allowance counts working time, not time spent waiting for a reset
            except ValueError:
                pass
        run.counts_json = {k: v for k, v in run.counts_json.items() if k not in ("waiting_since", "next_eligible_at", "waiting_checks")}
        run.status, run.phase, run.stop_reason = "collecting", "collecting", ""
        emit(db, run, "resumed", "Provider limits reset; continuing")
        db.commit()
    launch(st, run_id)
    return True


def _finish(db: Session, run: InvestigationRun, status: str, reason: str, message: str) -> None:
    run.status, run.stop_reason, run.finished_at = status, reason, _now()
    run.phase = ""
    emit(db, run, "finished", message, {"status": status, "reason": reason})


def _fresh_since(run: InvestigationRun) -> datetime | None:
    raw = run.counts_json.get("fresh_since")
    try:
        return datetime.fromisoformat(raw) if raw else None
    except (TypeError, ValueError):
        return None


def _pending_decisions(db: Session, subject: Subject) -> int:
    n = db.scalar(select(func.count()).select_from(ProfileCandidateLink).where(ProfileCandidateLink.subject_id == subject.id, ProfileCandidateLink.state.in_(("candidate", "unsure")))) or 0
    n += db.scalar(select(func.count()).select_from(AssociatedEmail).where(AssociatedEmail.subject_id == subject.id, AssociatedEmail.state == "candidate")) or 0
    n += db.scalar(select(func.count()).select_from(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.origin == "discovered", ProfileItem.status == "active",
                                                                       ProfileItem.verification_state == "candidate", ProfileItem.type != "repository")) or 0
    return int(n)


def advance(st: Any, run_id: str) -> dict[str, Any]:
    """One checkpointed step. Returns the research runs to wait for (if any) and whether the investigation has reached a resting state."""
    with st.sm() as db:
        run = db.get(InvestigationRun, run_id)
        if run is None:
            return {"finished": True, "run_ids": [], "wait": False}
        if run.status not in ACTIVE:
            return {"finished": True, "run_ids": [], "wait": False, "status": run.status}
        subject, case = db.get(Subject, run.subject_id), db.get(Case, run.case_id)
        assert subject is not None and case is not None
        pol = run.policy_json
        if run.deadline_at and _aware(run.deadline_at) < _now():  # type: ignore[operator]
            _finish(db, run, "complete_with_limits", "runtime_cap", "Stopped: the runtime limit was reached. Work already collected is kept.")
            db.commit()
            return {"finished": True, "run_ids": [], "wait": False}
        research.refresh_tasks(db, subject)
        if any(t.status in ("approved", "running") for t in _tasks(db, subject)):
            if run.status != "collecting":
                run.status = "collecting"
                emit(db, run, "phase", "Waiting for running checks to finish")
            db.commit()
            return {"finished": False, "run_ids": [], "wait": True}
        run.status, run.phase = "correlating", "correlating"
        emails.sweep(db, subject, run.requested_by)
        master.sweep_leads(db, subject)
        master.repair_lead_types(db, subject)
        candidates.sync_from_findings(db, subject)
        db.flush()
        fresh = _fresh_since(run)
        plan = expansion.plan(db, subject, case, st.adapters, st.settings, st, fresh_since=fresh)
        approved, excluded = set(run.approved_sources), set(run.excluded_sources)
        per_ident: dict[str, int] = {}
        for t in _tasks(db, subject):
            if t.identifier_id and t.status != "cancelled" and (fresh is None or (_aware(t.created_at) or _now()) >= fresh):
                per_ident[t.identifier_id] = per_ident.get(t.identifier_id, 0) + 1
        chosen: list[dict[str, Any]] = []
        waiting_approval: set[str] = set()
        skipped_keys: set[str] = set()
        followups = 0
        for s in plan["steps"]:
            if s["module"] != "OSINT" or s["source_id"] in excluded:
                continue
            status, _why = _classify(s, st, subject)
            if status == "needs_key":
                skipped_keys.add(s["source"])
                continue
            if status == "needs_approval" and s["source_id"] not in approved:
                waiting_approval.add(s["source"])
                continue
            if status not in ("ready", "needs_approval"):
                continue
            if per_ident.get(s["identifier_id"], 0) >= pol["per_identifier"]:
                continue
            if s["depth"] > 0:
                if followups >= pol["followups_per_pass"]:
                    continue
                followups += 1
            chosen.append(s)
            per_ident[s["identifier_id"]] = per_ident.get(s["identifier_id"], 0) + 1
        stop = plan["stop_reason"]
        if stop in ("authorization", "case_not_open", "offline"):
            _finish(db, run, "complete_with_limits", stop, {"authorization": "Stopped: the authorization is not current, so no further sources were contacted.",
                                                            "case_not_open": "Stopped: the case is not open.", "offline": "Stopped: offline mode is on, so nothing can be contacted."}[stop])
            db.commit()
            return {"finished": True, "run_ids": [], "wait": False}
        if chosen and stop != "budget_exhausted":
            try:
                out = expansion.run(db, subject, case, st.adapters, st.settings, actor=run.requested_by, keys=[s["key"] for s in chosen],
                                    confirmed_sources=sorted({s["source_id"] for s in chosen} & approved), fresh_since=fresh)
            except ProfileError as exc:
                run.last_error = exc.message[:300]
                emit(db, run, "error", f"A step could not be started: {exc.message[:160]}")
                _finish(db, run, "complete_with_limits", "step_refused", "Stopped: a planned step was refused by the safety checks. Nothing else was contacted.")
                db.commit()
                return {"finished": True, "run_ids": [], "wait": False}
            run.pass_no += 1
            run.status, run.phase = ("expanding" if run.pass_no > 1 else "collecting"), "expanding" if run.pass_no > 1 else "collecting"
            names = sorted({s["source"] for s in chosen})
            emit(db, run, "pass", f"Pass {run.pass_no}: started {out['started_runs']} research run(s) for {len(chosen)} check(s)", {"sources": names, "keys": len(chosen)})
            db.commit()
            return {"finished": False, "run_ids": out["run_ids"], "wait": False}
        # nothing left that is allowed
        waiting = [t for t in _tasks(db, subject) if t.status == "waiting_limits"]
        if waiting:
            _park(db, run, waiting)
            db.commit()
            return {"finished": True, "run_ids": [], "wait": False}
        pending = _pending_decisions(db, subject)
        limits = []
        if waiting_approval:
            limits.append("needs_approval")
        if skipped_keys:
            limits.append("needs_key")
        if stop in ("budget_exhausted", "max_depth"):
            limits.append(stop)
        end_tasks = _tasks(db, subject)
        if any(t.status == "blocked" for t in end_tasks):
            limits.append("provider_blocked")            # a credential was rejected, a plan does not include the operation, or the provider is switched off
        if any(t.status == "failed" for t in end_tasks):
            limits.append("source_errors")               # a source errored or timed out: that is a gap in coverage, never a clean result
        if any(t.status == "cancelled" for t in end_tasks):
            limits.append("work_cancelled")              # queued checks were cancelled (all provider work, or an authorization that ended): the investigation did not do them
        if any(t.status == "unavailable" for t in end_tasks):
            limits.append("coverage_gaps")               # a source could not run here (not installed, unsupported input): also a gap, reported as such
        man = build_manifest(db, st, subject, case)
        if any(r["status"] in ("unsupported_input", "needs_authorization", "separate_approval", "not_installed") for r in man["rows"]):
            limits.append("coverage_gaps")
        run.counts_json = {"waiting_approval": sorted(waiting_approval), "needs_key": sorted(skipped_keys), "pending_decisions": pending, "limits": limits}
        if waiting_approval:
            _finish(db, run, "awaiting_review", "needs_approval", f"Paused for your approval: {', '.join(sorted(waiting_approval))}. Everything else that was allowed has run.")
        elif pending:
            _finish(db, run, "awaiting_review", "decisions", f"{pending} item(s) wait for your decision. Nothing further runs from them until you confirm.")
        elif limits:
            _finish(db, run, "complete_with_limits", limits[0], "Finished with limits: some methods were unavailable (see Coverage).")
        else:
            _finish(db, run, "completed", "no_new_leads", "Finished: every permitted check ran and no new leads remain.")
        db.commit()
        return {"finished": True, "run_ids": [], "wait": False}


async def drive(st: Any, run_id: str) -> None:
    """Background driver: step, wait for the research runs it started, repeat. A crash or restart resumes from the stored state (finished tasks are never repeated)."""
    for _ in range(400):
        try:
            res = advance(st, run_id)
        except Exception as exc:
            with st.sm() as db:
                run = db.get(InvestigationRun, run_id)
                if run and run.status in ACTIVE:
                    run.last_error = f"{type(exc).__name__}"
                    _finish(db, run, "failed", "internal_error", "The investigation stopped on an internal error. Collected results are kept; you can resume.")
                    db.commit()
            return
        if res["finished"]:
            return
        for rid in res["run_ids"]:
            await st.runner.run_until_idle(rid)
        if res["wait"]:
            await asyncio.sleep(0.5)
        else:
            await asyncio.sleep(0)
    with st.sm() as db:                                                   # the loop ran out: say so instead of leaving the run looking busy forever
        run = db.get(InvestigationRun, run_id)
        if run and run.status in ACTIVE:
            _finish(db, run, "complete_with_limits", "stalled", "Stopped waiting: a check did not finish. Use Check for more to continue.")
            db.commit()


def launch(st: Any, run_id: str) -> None:
    t = asyncio.create_task(drive(st, run_id))
    st.tasks.add(t)
    t.add_done_callback(st.tasks.discard)


def recover(st: Any) -> int:
    """After a restart: pick up runs that were mid-flight. Interrupted jobs were already marked failed, so nothing is repeated."""
    with st.sm() as db:
        ids = [r.id for r in db.scalars(select(InvestigationRun).where(InvestigationRun.status.in_(ACTIVE)))]
        for rid in ids:
            r = db.get(InvestigationRun, rid)
            assert r is not None
            emit(db, r, "recovered", "Resumed after a restart; finished checks are not repeated")
        db.commit()
    for rid in ids:
        launch(st, rid)
    return len(ids)


def pause(db: Session, run: InvestigationRun, actor: str) -> None:
    if run.status not in ACTIVE and run.status != WAITING:
        raise ProfileError("not_running", "only a running investigation can be paused")
    run.status = "paused"
    emit(db, run, "paused", "Paused. Checks already started will finish; nothing new is started.")
    audit.record(db, "investigation.pause", actor=actor, case_id=run.case_id, resource_type="investigation", resource_id=run.id)


def resume(db: Session, run: InvestigationRun, actor: str) -> None:
    if run.status not in ("paused", "awaiting_review", "complete_with_limits", "completed", "failed", "draft"):
        raise ProfileError("not_resumable", "this investigation is running or finished")
    subject = db.get(Subject, run.subject_id)
    assert subject is not None
    auth = consent.current_status(db, subject)
    if auth["status"] not in ("active", "not_required_for_public_org_sources"):
        raise ProfileError("authorization_required", "record or renew the authorization before resuming")
    run.status, run.stop_reason, run.finished_at = "queued", "", None
    run.deadline_at = _now() + timedelta(minutes=run.policy_json.get("runtime_minutes", 30))
    if run.started_at is None:
        run.started_at = _now()
    emit(db, run, "resumed", "Resumed")
    audit.record(db, "investigation.resume", actor=actor, case_id=run.case_id, resource_type="investigation", resource_id=run.id)


def refresh(db: Session, run: InvestigationRun, actor: str) -> None:
    """Run the permitted checks again, now. Earlier results and tasks stay as history; the same limits and approvals apply."""
    if run.status in ACTIVE:
        raise ProfileError("not_resumable", "this investigation is still running")
    if run.status == "cancelled":
        raise ProfileError("not_resumable", "a stopped investigation cannot be refreshed: start a new one")
    run.counts_json = {**run.counts_json, "fresh_since": _now().isoformat()}
    resume(db, run, actor)
    emit(db, run, "refresh", "Refresh requested: permitted checks will run again within the same limits")
    audit.record(db, "investigation.refresh", actor=actor, case_id=run.case_id, resource_type="investigation", resource_id=run.id)


def cancel(db: Session, run: InvestigationRun, actor: str) -> None:
    if run.status in ("cancelled", "completed"):
        raise ProfileError("not_cancellable", "this investigation is already finished")
    run.status, run.finished_at, run.stop_reason = "cancelled", _now(), "cancelled"
    for t in _tasks(db, db.get(Subject, run.subject_id)):  # type: ignore[arg-type]
        if t.status in ("approved", "waiting_limits") and t.run_id:
            t.status = "cancelled"
            for job in db.scalars(select(Job).where(Job.run_id == t.run_id, Job.adapter_id == t.source_id, Job.status.in_(("queued", "deferred")))):
                job.status, job.quota_status, job.finished_at = "cancelled", "cancelled", _now()      # queued provider work does not outlive the investigation
    emit(db, run, "cancelled", "Cancelled. Results already collected are kept.")
    audit.record(db, "investigation.cancel", actor=actor, case_id=run.case_id, resource_type="investigation", resource_id=run.id)


def approve_more(db: Session, st: Any, run: InvestigationRun, sources: list[str], actor: str) -> None:
    subject, case = db.get(Subject, run.subject_id), db.get(Case, run.case_id)
    assert subject is not None and case is not None
    ok = set(build_manifest(db, st, subject, case)["approvable"]) | set(run.approved_sources)
    bad = set(sources) - ok
    if bad:
        raise ProfileError("unknown_selection", "a source is not part of this investigation's plan")
    run.approved_sources = sorted(set(run.approved_sources) | set(sources))
    run.excluded_sources = sorted(set(run.excluded_sources) - set(sources))
    emit(db, run, "approved", "Approved: " + ", ".join(sorted(SOURCES[s].label if s in SOURCES else s for s in sources)))
    audit.record(db, "investigation.approve", actor=actor, case_id=run.case_id, resource_type="investigation", resource_id=run.id, metadata={"sources": sorted(sources)})


# ---- progress and summary --------------------------------------------------------------------------------------------------------------------------
def progress(db: Session, st: Any, run: InvestigationRun) -> dict[str, Any]:
    subject = db.get(Subject, run.subject_id)
    assert subject is not None
    research.refresh_tasks(db, subject)
    tasks = _tasks(db, subject)
    by: dict[str, int] = {}
    for t in tasks:
        by[t.status] = by.get(t.status, 0) + 1
    manifest_rows = run.manifest_json.get("rows", [])
    not_run = [r for r in manifest_rows if r["status"] in ("needs_key", "needs_authorization", "unsupported_input", "not_installed", "separate_approval", "blocked")]
    states = _job_states(db, tasks)
    no_match = states.count("no_match")
    done = by.get("completed", 0) + by.get("partial", 0) - no_match
    queued = by.get("approved", 0) - sum(1 for s in states if s in ("running",))
    running = states.count("running")
    waiting = by.get("waiting_limits", 0)
    blocked = sum(1 for s in states if s in ("blocked_credentials", "blocked_plan", "disabled_provider", "awaiting_authorization"))
    unavailable = by.get("unavailable", 0)                              # skipped: a tool is not installed or the source cannot take this input; a coverage gap, not an error
    failed = by.get("failed", 0) + by.get("blocked", 0) - blocked
    nxt = run.counts_json.get("next_eligible_at") if run.status == WAITING else None
    if nxt is None and waiting:
        times = [j.next_retry_at for j in _waiting_jobs(db, [t for t in tasks if t.status == "waiting_limits"]) if j.next_retry_at]
        nxt = min(times).isoformat() if times else None
    return {"id": run.id, "status": run.status, "phase": run.phase, "pass": run.pass_no, "stop_reason": run.stop_reason, "updated_at": run.updated_at, "started_at": run.started_at,
            "finished_at": run.finished_at, "units": {"done": done, "no_match": no_match, "running": running, "queued": max(0, queued), "waiting_limits": waiting, "blocked": blocked,
                                                       "failed": max(0, failed), "unavailable": unavailable, "remaining": max(0, queued) + running + waiting, "waiting_approval": len(run.counts_json.get("waiting_approval", [])),
                                                       "not_run": len(not_run)},
            "next_eligible_at": nxt,
            "label": "Counts are checks the investigation knows about. They are not a percentage of everything that exists about the subject.",
            "pending_decisions": _pending_decisions(db, subject), "policy": run.policy_json, "last_error": run.last_error}


def _job_states(db: Session, tasks: list[ResearchTask]) -> list[str]:
    """The honest per-check state: the dispatcher's task status for checks that have a job, otherwise the research task's own status."""
    out = []
    for t in tasks:
        job = db.scalars(select(Job).where(Job.run_id == t.run_id, Job.adapter_id == t.source_id)).first() if t.run_id else None
        out.append(job.quota_status if job is not None else t.status)
    return out


def summary(db: Session, st: Any, run: InvestigationRun, role: str = "owner") -> dict[str, Any]:
    from . import gaps
    subject, case = db.get(Subject, run.subject_id), db.get(Case, run.case_id)
    assert subject is not None and case is not None
    prog = progress(db, st, run)
    doc = master.sections(db, st, subject, role=role)
    facts: dict[str, list[dict[str, Any]]] = {"self_provided": [], "self_attested": [], "independently_corroborated": [], "conflicting": []}
    possible = 0
    for sec in doc["sections"]:
        if sec["key"] == "timeline":
            continue
        for i in sec["items"]:
            row = {"category": sec["key"], "type": i["type_label"], "value": i["value"], "state": i["verification_state"], "state_label": i["state_label"], "evidence": len(i.get("evidence") or [])}
            if i["verification_state"] == "corroborated":
                facts["independently_corroborated"].append(row)
            elif i["verification_state"] == "self_attested":
                facts["self_attested"].append(row)
            elif i["verification_state"] == "conflicting":
                facts["conflicting"].append(row)
            elif i.get("is_input"):
                facts["self_provided"].append(row)
            elif i["verification_state"] == "candidate":
                possible += 1
    cov = research.coverage(db, subject, st.adapters)
    analysis = gaps.analyze(db, st, subject, case, st.adapters, st.settings, role=role)
    inbox = review_inbox(db, st, subject, role=role)
    man = build_manifest(db, st, subject, case)
    limits = _limits(run, man) + _task_limits(db, subject)
    return {"run": {"id": run.id, "status": run.status, "kind": run.kind, "policy": run.policy_json, "approved_sources": run.approved_sources, "excluded_sources": run.excluded_sources,
                    "stop_reason": run.stop_reason, "created_at": run.created_at, "requested_by": run.requested_by},
            "subject": {"id": subject.id, "case_id": case.id, "display_name": subject.display_name, "type": subject.type, "mode": subject.mode, "purpose": subject.purpose},
            "authorization": consent.current_status(db, subject), "progress": prog, "facts": {k: v[:12] for k, v in facts.items()}, "fact_counts": {k: len(v) for k, v in facts.items()},
            "possible_associations": possible, "coverage": cov["categories"], "accounting": accounting.pipeline(db, subject), "decisions": {"open": len(inbox["items"]), "top": inbox["items"][:3]},
            "limits": limits, "next_actions": _waiting_actions(prog) + analysis["next_actions"][:5], "email_first": analysis["email_first"],
            "manifest": {"counts": man["counts"], "rows": man["rows"], "third_parties": man["third_parties"], "approvable": man["approvable"]},
            "invite": "Want better coverage? Add another email, username, business name or owned domain. One is enough to start; each extra input gives the sources more to work with."}


def _waiting_actions(prog: dict[str, Any]) -> list[dict[str, str]]:
    u = prog["units"]
    if not u.get("waiting_limits"):
        return []
    when = prog.get("next_eligible_at")
    return [{"kind": "info", "text": f"{u['waiting_limits']} check(s) are waiting for a provider's limit to reset. Nothing needs you; they continue by themselves"
             + (f" (earliest around {str(when)[:16].replace('T', ' ')} UTC, an estimate, not a promise)." if when else "."), "go": "coverage"}]


def _task_limits(db: Session, subject: Subject) -> list[dict[str, str]]:
    """One line per check that did not produce a result, with the provider's reason. Nothing here is a 'no match'."""
    out = []
    for t in _tasks(db, subject):
        if t.status in ("waiting_limits", "blocked", "failed", "unavailable", "cancelled"):
            label = SOURCES[t.source_id].label if t.source_id in SOURCES else t.source_id
            code = {"waiting_limits": "waiting_limits", "blocked": "provider_blocked", "unavailable": "not_available", "cancelled": "work_cancelled"}.get(t.status, "source_error")
            out.append({"code": code, "source": label, "input": "", "text": (t.limitations or {"waiting_limits": "Waiting for a provider limit to reset.", "blocked": "Blocked.", "cancelled": "Cancelled before it ran."}.get(t.status, "The source did not answer."))[:300]})
    return out


def _limits(run: InvestigationRun, man: dict[str, Any]) -> list[dict[str, str]]:
    out = []
    for r in man["rows"]:
        if r["status"] in ("needs_key", "needs_authorization", "unsupported_input", "not_installed", "separate_approval", "needs_approval"):
            out.append({"code": r["status"], "source": r["source"], "input": f"{r['identifier_kind']}: {r['identifier']}", "text": r["reason"]})
    if run.stop_reason in ("budget_exhausted", "max_depth", "runtime_cap", "offline", "authorization", "case_not_open", "step_refused"):
        out.append({"code": run.stop_reason, "source": "", "input": "", "text": {"budget_exhausted": "The source-call budget for this investigation was used up.",
                    "max_depth": "The depth limit was reached; deeper leads were not followed.", "runtime_cap": "The runtime limit was reached.", "offline": "Offline mode was on.",
                    "authorization": "The authorization ended or is missing.", "case_not_open": "The case was not open.", "step_refused": "A step was refused by the safety checks."}[run.stop_reason]})
    return out


# ---- review inbox ----------------------------------------------------------------------------------------------------------------------------------
def review_inbox(db: Session, st: Any, subject: Subject, role: str = "owner") -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for c in candidates.list_candidates(db, subject):
        if c["state"] in ("candidate", "unsure"):
            items.append({"id": f"account:{c['id']}", "kind": "account", "title": c["site"] or c["canonical_url"], "detail": c["canonical_url"], "claim": "This account belongs to the subject",
                          "signals": c["independent_signals"], "tools": c["adapters"], "evidence": len(c["evidence"]), "state": c["state"],
                          "note": "A handle that exists is not the person. More than one tool agreeing is still one signal."})
    for e in emails.list_for(db, st, subject, role=role)["items"]:
        if e["state"] == "candidate":
            items.append({"id": f"email:{e['id']}", "kind": "email", "title": e["address"], "detail": e["label"], "claim": "This address is associated with the subject", "signals": len(e["sources"]),
                          "tools": sorted({s["adapter"] for s in e["sources"] if s.get("adapter")}), "evidence": len(e["evidence"]), "state": e["classification"], "note": "; ".join(e["explanation"])[:200]})
    for it in db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.origin == "discovered", ProfileItem.status == "active", ProfileItem.verification_state == "candidate",
                                                    ProfileItem.type != "repository")):
        items.append({"id": f"item:{it.id}", "kind": "item", "title": it.value, "detail": master.TYPES.get(it.type, master.TYPES["custom"])["label"], "claim": "This is a fact about the subject",
                      "signals": 1, "tools": [it.collection_method.replace("adapter:", "")], "evidence": len(it.evidence_ids), "state": "candidate", "note": str(it.attributes.get("reason", ""))[:200]})
    sd = expansion.seeds(db, subject)
    for pr in sd["proposals"]:
        if pr.get("action") == "add_input":
            items.append({"id": f"seed:{pr.get('associated_id') or pr.get('candidate_id')}", "kind": "seed", "title": pr["label"], "detail": "Confirmed; not yet an input", "claim": "Research from this too",
                          "signals": 0, "tools": [], "evidence": 0, "state": "confirmed", "note": pr["reason"]})
    return {"items": items, "total": len(items), "by_kind": {k: sum(1 for i in items if i["kind"] == k) for k in ("account", "email", "item", "seed")}}


ACTIONS = {"mine": "Mine / confirmed (self-attested)", "not_mine": "Not mine", "unsure": "Unsure", "need_evidence": "Need evidence"}


def apply_reviews(db: Session, subject: Subject, ids: list[str], action: str, *, actor: str, role: str, basis: str, evidence_ids: list[str] | None = None, preview: bool = False) -> dict[str, Any]:
    """Bulk decisions with an impact preview. 'Mine' is recorded as the owner's own attestation, never as independent corroboration; evidence is attached only where it is about that site."""
    if action not in ACTIONS:
        raise ProfileError("invalid_action", "action must be mine, not_mine, unsure or need_evidence")
    if not ids:
        raise ProfileError("nothing_selected", "select at least one item")
    if len(ids) > 200:
        raise ProfileError("too_many", "review at most 200 items at a time")
    if not preview and not basis.strip():
        raise ProfileError("basis_required", "record the reason or method for this decision")
    evidence = list(dict.fromkeys(evidence_ids or []))
    groups: dict[str, list[str]] = {"account": [], "email": [], "item": [], "seed": []}
    for x in ids:
        kind, _, raw = x.partition(":")
        if kind not in groups or not raw:
            raise ProfileError("invalid_selection", f"unknown item '{x}'")
        groups[kind].append(raw)
    exceptions: list[dict[str, str]] = []
    plan: dict[str, list[str]] = {k: list(v) for k, v in groups.items()}
    if evidence and groups["account"]:
        keep = []
        for aid in groups["account"]:
            c = db.get(ProfileCandidateLink, aid)
            if c is None or c.subject_id != subject.id:
                raise ProfileError("not_found", f"account {aid} not found")
            bad = [e for e in evidence if not candidates.evidence_applies(db, e, c)]
            if bad:
                exceptions.append({"id": f"account:{aid}", "reason": f"The selected evidence is not about {c.site or c.canonical_url}, so it was not attached; the decision was not applied."})
            else:
                keep.append(aid)
        plan["account"] = keep
    if action == "need_evidence" and groups["seed"]:
        plan["seed"] = []
    if groups["seed"] and action in ("mine",):
        for sid in groups["seed"]:
            exceptions.append({"id": f"seed:{sid}", "reason": "Adding an input is a separate step: use 'Use as input' so the authorization is checked."})
        plan["seed"] = []
    sites = sorted({(db.get(ProfileCandidateLink, a).site or "site") for a in plan["account"] if db.get(ProfileCandidateLink, a)})  # type: ignore[union-attr]
    impact = {"counts": {k: len(v) for k, v in plan.items()}, "total": sum(len(v) for v in plan.values()), "sites": sites[:30], "exceptions": exceptions,
              "effect": {"mine": "Recorded as the owner's own attestation. It is not independent corroboration and does not make an account verified.",
                         "not_mine": "Rejected: it will not be used as a starting point and stays on record.", "unsure": "Kept as a candidate and marked unsure.",
                         "need_evidence": "Kept as a candidate and marked as waiting for evidence."}[action]}
    if preview:
        return {"preview": True, **impact}
    bulk = str(uuid.uuid4())
    done = 0
    if plan["account"]:
        to = {"mine": "confirmed", "not_mine": "rejected", "unsure": "unsure", "need_evidence": "unsure"}[action]
        out = candidates.review(db, subject, plan["account"], to_state=to, reviewer=actor, basis=basis if action != "need_evidence" else f"needs evidence: {basis}",
                                attestation="subject" if action == "mine" else "none", evidence_ids=evidence if action == "mine" else None, force_bulk=True)
        done += out["updated"]
        bulk = out.get("bulk_id") or bulk
    if plan["email"]:
        to = {"mine": "confirmed", "not_mine": "rejected", "unsure": "candidate", "need_evidence": "candidate"}[action]
        emails.review(db, subject, plan["email"], to_state=to, reviewer=actor, basis=basis, attestation="subject" if action == "mine" else "none", evidence_ids=evidence if action == "mine" else None)
        done += len(plan["email"])
    for iid in plan["item"]:
        try:
            if action == "not_mine":
                master.set_state(db, subject, f"item:{iid}", to_state="rejected", role=role, actor=actor, basis=basis)
            elif action == "mine":
                master.self_attest(db, subject, f"item:{iid}", role=role, actor=actor, basis=basis)
            else:
                master.set_state(db, subject, f"item:{iid}", to_state="candidate", role=role, actor=actor, basis=f"{ACTIONS[action]}: {basis}")
            done += 1
        except ProfileError as exc:
            exceptions.append({"id": f"item:{iid}", "reason": exc.message})
    audit.record(db, "investigation.review", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id, metadata={"action": action, "count": done, "bulk_id": bulk})
    return {"preview": False, "applied": done, "bulk_id": bulk, **impact, "undo": "Accounts decided in this batch can be undone with the bulk id; other items can be reopened one by one."}


def use_as_input(db: Session, subject: Subject, ref: str, *, role: str, actor: str, basis: str) -> dict[str, Any]:
    """A lead (or a confirmed address / account) becomes a starting point only by this deliberate act, with a reason. The authorization still decides what runs from it."""
    if role == "viewer":
        raise ProfileError("forbidden", "viewers cannot change inputs")
    kind, _, raw = ref.partition(":")
    if kind == "item":
        it = master.promote_to_input(db, subject, f"item:{raw}", role=role, actor=actor, basis=basis)
        return {"input": it.type, "id": f"item:{it.id}"}
    if kind == "seed":
        em = db.get(AssociatedEmail, raw)
        if em is not None and em.subject_id == subject.id:
            ident = emails.promote(db, subject, em.id, actor)
            return {"input": "email", "id": ident.id}
        c = db.get(ProfileCandidateLink, raw)
        if c is not None and c.subject_id == subject.id:
            if c.state != "confirmed":
                raise ProfileError("not_confirmed", "only a confirmed account can be used as an input")
            from .service import add_identifier
            ident = add_identifier(db, subject, "url", c.canonical_url, actor=actor)
            return {"input": "url", "id": ident.id}
    raise ProfileError("not_found", "that item cannot be used as an input")
