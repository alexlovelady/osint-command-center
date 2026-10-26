"""Research gaps and next actions for the Master Profile (TPM3): per category, WHY it is empty or uncertain, and what to do about it.

Statuses are about attempted authorized methods, never about what exists in the world:
  has_data                  at least one item that is not rejected
  needs_verification        candidates or conflicting items wait for a person
  searched_no_match         a permitted source ran and returned nothing (this does not show nothing exists)
  source_unavailable        a source that could answer failed, is not installed, or needs a key that is not configured
  awaiting_authorization    the subject has no current authorization for the kind of source that could answer
  not_attempted             sources exist and are allowed, but none has run
  manual_only               only a person can fill this (no automated source applies)
  restricted                only the case owner can see or record it
An empty category is therefore "unknown / not researched", never "not found".
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..adapters.base import IntelAdapter
from ..config import Settings
from ..db.models import Case, Subject
from . import consent, expansion, master, research
from .registry import SOURCES

CATEGORY_SOURCES: dict[str, tuple[str, ...]] = {
    "contact": ("gravatar_email", "github_email_search", "keyserver_email", "web_search_email"),
    "online_footprint": ("sherlock", "maigret", "github_public", "page_contacts", "wayback"),
    "business": ("opencorporates", "sec_edgar", "rdap", "dns", "crtsh", "subfinder"),
    "images_documents": ("manual_documents", "manual_images"),
    "security_exposure": ("manual_exposure",),
}
LABELS = {"has_data": "Has data", "needs_verification": "Needs analyst verification", "searched_no_match": "Searched, no match", "source_unavailable": "Source unavailable",
          "awaiting_authorization": "Awaiting authorization", "not_attempted": "Not attempted", "manual_only": "Needs manual entry", "restricted": "Restricted"}
MANUAL = {"identity": "Add full and alternate names; add a date of birth only if it is needed and authorized.", "locations": "Add general places; exact addresses are owner-only and restricted.",
          "education": "Add institutions, qualifications and cited publications.", "employment": "Add employers and positions with a citation; they stay claimed until corroborated.",
          "devices": "Add devices or assets you own or are explicitly authorized to inventory. Nothing is scanned from an inventory.", "relationships": "Add evidence-backed professional connections only.",
          "custom": "Add typed attributes that do not fit elsewhere."}
EMAIL_FIRST = ("gravatar_email", "github_email_search", "keyserver_email", "web_search_email")


def _cell_status(cell: dict[str, Any]) -> str:
    return str(cell.get("status", ""))


def email_first(db: Session, subject: Subject, case: Case, adapters: dict[str, IntelAdapter], settings: Settings, st: Any = None) -> dict[str, Any]:
    """What exact-email discovery can do for this subject right now, in plain words. It never claims 'nothing found' without a source having run."""
    idents = [i for i in master_inputs(db, subject) if i.kind == "email"]
    if not idents:
        return {"has_email": False, "message": "No email input yet.", "sources": []}
    configured, rows = [], []
    for sid in EMAIL_FIRST:
        ad = adapters.get(sid)
        key = ad.manifest.api_key_name if ad else None
        have_key = True
        if key and st is not None:
            have_key = bool(st.runner.ctx_factory().secret(key))
        state = "not_installed" if ad is None else ("needs_key" if key and not have_key else "configured")
        if state == "configured":
            configured.append(sid)
        rows.append({"source_id": sid, "name": SOURCES[sid].label if sid in SOURCES else sid, "state": state, "needs_key": key,
                     "sends": "the address (or its hash) to a third party after you confirm", "cost": "your own key" if key else "free"})
    done = [t for t in research_tasks(db, subject) if t.source_id in EMAIL_FIRST]
    if not configured:
        msg = "No supported email-first discovery source configured."
    else:
        runnable = 0
        for i in idents:
            from . import consent as c
            runnable += sum(1 for sid in configured if c.check(db, subject, SOURCES[sid].source_class, identifier_id=i.id).allowed)
        if runnable == 0:
            msg = "Email-first sources are configured but this subject's authorization does not allow third-party public-site queries."
        elif not done:
            msg = f"{len(configured)} email-first source(s) are ready. None has run yet: this is not a finding."
        else:
            msg = f"{len(done)} email-first run(s) recorded. See each source's result; nothing here means 'research complete'."
    return {"has_email": True, "message": msg, "configured": len(configured), "sources": rows, "attempted": len(done)}


def master_inputs(db: Session, subject: Subject) -> list[Any]:
    from sqlalchemy import select

    from ..db.models import SubjectIdentifier
    return list(db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.status == "active")))


def research_tasks(db: Session, subject: Subject) -> list[Any]:
    from sqlalchemy import select

    from ..db.models import ResearchTask
    return list(db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id, ResearchTask.status != "cancelled")))


def analyze(db: Session, st: Any, subject: Subject, case: Case, adapters: dict[str, IntelAdapter], settings: Settings, *, role: str) -> dict[str, Any]:
    doc = master.sections(db, st, subject, role=role)
    cov = research.coverage(db, subject, adapters)
    cells = {c["source_id"]: c for cat in cov["categories"] for c in cat["cells"]}
    auth = consent.current_status(db, subject)
    authorized = auth["status"] in ("active", "not_required_for_public_org_sources")
    cats = []
    for s in doc["sections"]:
        key = s["key"]
        live = [i for i in s["items"] if i["verification_state"] != "rejected"]
        pending = [i for i in live if i["verification_state"] in ("candidate", "conflicting")]
        srcs = [{"source": sid, "name": cells[sid]["name"], "status": cells[sid]["status"], "detail": cells[sid]["detail"]} for sid in CATEGORY_SOURCES.get(key, ()) if sid in cells]
        if live and pending:
            status, why = "needs_verification", f"{len(pending)} item(s) wait for a person to confirm, reject or resolve."
        elif live:
            status, why = "has_data", f"{len(live)} item(s) recorded. This is what has been entered or found, not everything that exists."
        elif key == "timeline":
            status, why = "not_attempted", "The timeline fills in as records are added and research runs."
        elif key in ("identity", "locations") and role == "viewer":
            status, why = "restricted", "Some fields in this category are visible only to the case owner."
        else:
            runs = [x for x in srcs if x["status"] in ("completed", "partial", "outdated")]
            bad = [x for x in srcs if x["status"] in ("failed", "blocked", "unavailable")]
            if runs:
                status, why = "searched_no_match", "Permitted sources ran and returned nothing for this category. That does not show nothing exists."
            elif bad:
                status, why = "source_unavailable", "; ".join(f"{x['name']}: {x['detail'] or x['status']}" for x in bad)[:300]
            elif srcs and not authorized:
                status, why = "awaiting_authorization", "Record a current authorization before any source can be asked."
            elif srcs:
                status, why = "not_attempted", "Sources exist for this category and none has run. Preview them in the research plan."
            else:
                status, why = "manual_only", MANUAL.get(key, "Only a person can fill this category.")
        cats.append({"key": key, "title": s["title"], "status": status, "label": LABELS[status], "why": why, "items": len(live), "sources": srcs})
    case_ = db.get(Case, subject.case_id)
    plan = expansion.plan(db, subject, case_ or case, adapters, settings)
    actions: list[dict[str, Any]] = []
    if not authorized:
        actions.append({"priority": 100, "kind": "authorization", "text": "Record a current authorization: nothing can be collected without one.", "go": "Authorization"})
    ef = email_first(db, subject, case, adapters, settings, st)
    if ef["has_email"] and ef.get("configured", 0) == 0:
        actions.append({"priority": 90, "kind": "integration_gap", "text": ef["message"] + " Add a key for a search provider in Settings, or enter what you know by hand.", "go": "Settings"})
    for step in [x for x in plan["steps"] if x["executable_now"] or x["needs"] == "confirmation"][:6]:
        actions.append({"priority": 80 + step["priority"] // 10, "kind": "research", "text": f"{step['source']} on {step['identifier']}" + (" (needs your confirmation)" if step["needs"] == "confirmation" else ""),
                        "key": step["key"], "go": "Associated emails"})
    pend = sum(len([i for i in s["items"] if i["verification_state"] in ("candidate", "conflicting") and i.get("origin") == "discovered"]) for s in doc["sections"])
    if pend:
        actions.append({"priority": 70, "kind": "review", "text": f"Review {pend} discovered lead(s): confirm, reject or keep them as candidates.", "go": "Profile"})
    for c in cats:
        if c["status"] == "manual_only" and c["key"] in ("employment", "education", "identity"):
            actions.append({"priority": 40, "kind": "manual", "text": MANUAL[c["key"]], "go": "Profile", "category": c["key"]})
    actions.sort(key=lambda a: -a["priority"])
    done = sum(1 for c in cats if c["status"] in ("has_data", "searched_no_match", "needs_verification"))
    return {"categories": cats, "next_actions": actions[:12], "email_first": ef, "authorization": auth,
            "coverage": {"attempted_categories": done, "of": len(cats), "label": "Coverage counts categories where an authorized method was attempted or data was entered. It is not a percentage of all information that exists.",
                         "approved_tasks": cov["approved_tasks"], "completed_tasks": cov["completed_tasks"]},
            "plan_stop_reason": plan["stop_reason"]}
