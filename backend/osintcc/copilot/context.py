"""Facts the Copilot may state, read from the application itself: tool health, settings, and a case's stored data.

Everything here is deterministic and works with no model. The chat engine puts these facts in front of the model as data and the
deterministic features (next steps, diagnostics, contradictions, timeline) use them directly, so they are available when no model is.
"""
from __future__ import annotations

import contextlib
import json
import time
import weakref
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    Alert,
    Case,
    Claim,
    CollectionPlan,
    Entity,
    Evidence,
    Finding,
    Hypothesis,
    Job,
    Note,
    Observation,
    Relationship,
    ReportRun,
    Requirement,
    SearchRun,
    Setting,
    Target,
)
from .kb import KnowledgeBase

RESTRICTED = ("RESTRICTED", "SECRET")
ROUTES = {"overview", "cases", "tools", "setup", "settings", "case", "automations"}
AUTO_TABS = ["Library", "My automations", "Runs", "Inbox", "Settings", "Builder"]
TABS = ["Search", "Plans", "Findings", "Graph", "Timeline", "Map", "Evidence", "Imports", "Analysis", "Cross-links", "Workflows", "Verification", "Humint", "AI", "Hardware", "Notes", "Reports"]
CONF_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}


def clean_ctx(raw: Any) -> dict[str, Any]:
    """The client reports where the user is. It is a hint, never trusted for access: case ids are re-checked on use."""
    r = raw if isinstance(raw, dict) else {}
    route = r.get("route") if r.get("route") in ROUTES else "overview"
    tab = r.get("tab") if (r.get("tab") in TABS or (route == "automations" and r.get("tab") in AUTO_TABS)) else None
    cid = r.get("case_id") if isinstance(r.get("case_id"), str) and len(r["case_id"]) <= 64 else None
    tool = r.get("tool_id") if isinstance(r.get("tool_id"), str) and len(r["tool_id"]) <= 80 else None
    return {"route": route, "tab": tab, "case_id": cid, "tool_id": tool}


# ---------------------------------------------------------------------------------------------------------- application
_HEALTH: weakref.WeakKeyDictionary[Any, tuple[float, dict[str, Any]]] = weakref.WeakKeyDictionary()
HEALTH_TTL = 20.0   # command-line tools are smoke-tested by running them; a chat turn should not re-run every one


async def _health(ad: Any) -> dict[str, Any]:
    hit = _HEALTH.get(ad)
    if hit and time.monotonic() - hit[0] < HEALTH_TTL:
        return hit[1]
    try:
        h = await ad.health()
    except Exception as exc:   # a broken adapter must not break the assistant
        h = {"status": "unavailable", "detail": f"health check raised {type(exc).__name__}"}
    with contextlib.suppress(TypeError):
        _HEALTH[ad] = (time.monotonic(), h)
    return h


async def tool_status(st) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for aid, ad in st.adapters.items():
        m = ad.manifest
        h = await _health(ad)
        key_set = st.secrets.exists(m.api_key_name) if (m.api_key_name and st.secrets) else None
        status = h.get("status", "unknown")
        if m.api_key_name and key_set is False and status in ("healthy", "unknown"):
            status = "requires_key"
        out[aid] = {"id": aid, "name": m.name, "class": m.operation_class, "targets": m.supported_target_types, "needs_network": m.needs_network,
                    "endpoints": m.endpoints, "description": m.description, "api_key_name": m.api_key_name, "key_set": key_set,
                    "status": status, "detail": h.get("detail", ""), "version": h.get("version"), "install_hint": m.install_hint}
    return out


def app_state(st, db: Session) -> dict[str, Any]:
    def s(key: str, default: Any = None) -> Any:
        row = db.get(Setting, key)
        return row.value_json if row else default
    from ..db.models import AiProfile
    profiles = [{"id": p.id, "name": p.name, "type": p.provider_type, "model": p.model_id, "local": p.local_only} for p in db.scalars(select(AiProfile))]
    return {"offline": bool(st.settings.offline), "ai_enabled": s("ai_enabled", False) is True, "profiles": profiles,
            "active_module_enabled": bool(st.settings.enable_active_module), "scheduler": bool(st.settings.run_scheduler),
            "setup_complete": bool(s("setup_complete", False)), "update_server_set": bool(st.settings.update_manifest_url or s("update_manifest_url"))}


# -------------------------------------------------------------------------------------------------------------- cases
def case_facts(db: Session, case_id: str) -> dict[str, Any]:
    c = db.get(Case, case_id)
    if not c:
        return {}

    def n(model: Any, *where: Any) -> int:
        return db.scalar(select(func.count()).select_from(model).where(model.case_id == case_id, *where)) or 0

    runs = db.scalars(select(SearchRun).where(SearchRun.case_id == case_id).order_by(SearchRun.started_at.desc()).limit(10)).all()
    return {
        "id": c.id, "title": c.title, "category": c.category, "status": c.status, "purpose": c.purpose, "description": c.description,
        "counts": {"targets": n(Target), "entities": n(Entity), "findings": n(Finding), "relationships": n(Relationship), "evidence": n(Evidence),
                   "observations": n(Observation), "claims": n(Claim), "requirements": n(Requirement), "hypotheses": n(Hypothesis),
                   "notes": n(Note), "runs": n(SearchRun), "reports": n(ReportRun), "plans": n(CollectionPlan)},
        "targets": [{"type": t.type, "value": t.canonical_value} for t in db.scalars(select(Target).where(Target.case_id == case_id).limit(20))],
        "recent_runs": [{"id": r.id, "status": r.status, "adapters": r.selected_adapters_json, "started_at": r.started_at.isoformat() if r.started_at else None,
                         "summary": r.summary_json} for r in runs],
        "open_requirements": [{"id": q.id, "question": q.question, "answer_status": q.answer_status, "priority": q.priority}
                              for q in db.scalars(select(Requirement).where(Requirement.case_id == case_id, Requirement.status == "open"))],
        "unacknowledged_alerts": n(Alert, Alert.acknowledged_at.is_(None)),
    }


def findings_for_reasoning(db: Session, case_id: str, include_restricted: bool = False, limit: int = 400) -> tuple[list[dict[str, Any]], int]:
    """Findings joined to entity and evidence. RESTRICTED/SECRET evidence is withheld unless asked for, and the count of withheld is returned."""
    rows = db.execute(select(Finding, Entity, Evidence).join(Entity, Entity.id == Finding.subject_entity_id).join(Evidence, Evidence.id == Finding.evidence_id)
                      .where(Finding.case_id == case_id).order_by(Finding.observed_at.desc()).limit(limit)).all()
    out, withheld = [], 0
    for f, e, ev in rows:
        if (ev.sensitivity in RESTRICTED or e.sensitivity in RESTRICTED) and not include_restricted:
            withheld += 1
            continue
        out.append({"id": f.id, "entity_id": e.id, "entity": e.display_name, "entity_type": e.type, "predicate": f.predicate, "value": f.value_json,
                    "confidence": f.confidence, "reason": f.confidence_reason, "adapter": f.adapter_id, "evidence_id": f.evidence_id,
                    "observed_at": f.observed_at, "published_at": f.source_published_at, "status": f.status})
    return out, withheld


def contradictions(findings: list[dict[str, Any]], max_groups: int = 20) -> list[dict[str, Any]]:
    """Same subject + predicate with different values. Reported side by side; never resolved here."""
    groups: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for f in findings:
        groups[(f["entity_id"], f["predicate"])][json.dumps(f["value"], sort_keys=True, default=str)].append(f)
    out = []
    for (_, pred), by_val in groups.items():
        if len(by_val) < 2:
            continue
        sides = [{"value": v[0]["value"], "adapters": sorted({x["adapter"] for x in v}), "findings": [x["id"] for x in v],
                  "evidence": sorted({x["evidence_id"] for x in v}), "best_confidence": max((x["confidence"] for x in v), key=lambda c: CONF_RANK.get(c, 0))}
                 for v in by_val.values()]
        first = next(iter(by_val.values()))[0]
        out.append({"entity": first["entity"], "predicate": pred, "sides": sides})
    return out[:max_groups]


def timeline(findings: list[dict[str, Any]], limit: int = 40) -> list[dict[str, Any]]:
    """Ordered by when the source published it when known, otherwise by when we observed it; the basis is always stated."""
    rows = []
    for f in findings:
        when, basis = (f["published_at"], "published") if f.get("published_at") else (f["observed_at"], "observed")
        rows.append({"when": when, "basis": basis, "finding": f["id"], "text": f"{f['entity']} {f['predicate']} = {json.dumps(f['value'], default=str)[:120]}",
                     "adapter": f["adapter"], "evidence": f["evidence_id"]})
    rows.sort(key=lambda r: r["when"] or datetime.min.replace(tzinfo=UTC))
    return rows[-limit:]


def corroboration(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Findings supported by one source family only vs. several. Independence is approximated by distinct adapters."""
    by: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for f in findings:
        by[(f["entity_id"], f["predicate"], json.dumps(f["value"], sort_keys=True, default=str))].add(f["adapter"])
    single = sum(1 for v in by.values() if len(v) == 1)
    return {"distinct_statements": len(by), "single_source": single, "multi_source": len(by) - single}


# ------------------------------------------------------------------------------------------------------- diagnostics
def recent_jobs(db: Session, adapter_id: str, case_id: str | None = None, limit: int = 5) -> list[dict[str, Any]]:
    q = select(Job, SearchRun).join(SearchRun, SearchRun.id == Job.run_id).where(Job.adapter_id == adapter_id)
    if case_id:
        q = q.where(SearchRun.case_id == case_id)
    rows = db.execute(q.order_by(Job.created_at.desc()).limit(limit)).all()
    return [{"job": j.id, "run": r.id, "status": j.status, "result": j.result_status, "error_code": j.last_error_code, "warnings": j.warnings_json[:5],
             "attempts": j.attempts, "when": j.created_at.isoformat() if getattr(j, "created_at", None) else None} for j, r in rows]


def diagnose_tool(db: Session, kb: KnowledgeBase, tools: dict[str, dict[str, Any]], adapter_id: str, case_id: str | None = None) -> dict[str, Any]:
    """Explains one tool's state from real signals: health check, key presence, recent job errors; looks up documented fixes; lists alternatives."""
    t = tools.get(adapter_id)
    if not t:
        return {"found": False, "message": f"No tool with id '{adapter_id}' is registered.", "known": sorted(tools)}
    jobs = recent_jobs(db, adapter_id, case_id)
    causes: list[dict[str, Any]] = []

    def add(code: str, evidence: str) -> None:
        e = kb.get(f"error:{code}")
        causes.append({"code": code, "evidence": evidence, "meaning": e.meta["meaning"] if e else "", "fix": e.meta["fix"] if e else "", "source": f"error:{code}" if e else None})
    if t["status"] in ("not_installed", "requires_key", "disabled", "unsupported", "degraded", "unavailable", "rate_limited"):
        code = {"unsupported": "unsupported_platform"}.get(t["status"], t["status"])
        add(code, f"health check reports '{t['status']}'" + (f": {t['detail']}" if t["detail"] else ""))
    for j in jobs:
        if j["error_code"] and not any(c["code"] == j["error_code"] for c in causes):
            add(j["error_code"], f"job {j['job'][:8]} in run {j['run'][:8]} ended with {j['error_code']}")
    if t["class"] != "local_only" and t["needs_network"]:
        pass
    alternatives = [{"id": a["id"], "name": a["name"], "status": a["status"], "why": "supports the same target type(s) and is available now"}
                    for a in tools.values() if a["id"] != adapter_id and set(a["targets"]) & set(t["targets"]) and a["status"] == "healthy"][:6]
    healthy = t["status"] == "healthy" and not any(j["error_code"] for j in jobs[:1])
    return {"found": True, "tool": {k: t[k] for k in ("id", "name", "class", "status", "detail", "version", "install_hint", "api_key_name", "key_set", "endpoints")},
            "recent_jobs": jobs, "causes": causes, "alternatives": alternatives, "healthy": healthy,
            "note": "Derived from the tool's health check, stored key presence and its most recent jobs. Nothing was run to produce this."}


def diagnose_run(db: Session, kb: KnowledgeBase, tools: dict[str, dict[str, Any]], run_id: str) -> dict[str, Any]:
    run = db.get(SearchRun, run_id)
    if not run:
        return {"found": False, "message": "run not found"}
    jobs = db.scalars(select(Job).where(Job.run_id == run_id)).all()
    items = []
    for j in jobs:
        d = {"adapter": j.adapter_id, "status": j.status, "result": j.result_status, "error_code": j.last_error_code, "warnings": j.warnings_json[:5], "attempts": j.attempts}
        if j.last_error_code or j.status in ("failed", "error"):
            diag = diagnose_tool(db, kb, tools, j.adapter_id, run.case_id)
            d["causes"] = diag.get("causes", [])
            d["alternatives"] = diag.get("alternatives", [])
        items.append(d)
    return {"found": True, "run": {"id": run.id, "status": run.status, "adapters": run.selected_adapters_json, "summary": run.summary_json}, "jobs": items,
            "ok": all(not (i["error_code"]) for i in items)}


# ----------------------------------------------------------------------------------------------------- next steps
def _step(prio: int, title: str, why: str, **extra: Any) -> dict[str, Any]:
    return {"priority": prio, "title": title, "why": why, **extra}


def next_steps(st, db: Session, tools: dict[str, dict[str, Any]], case_id: str, include_restricted: bool = False) -> list[dict[str, Any]]:
    """Prioritised, explained, rule-based recommendations. Every item cites the numbers it is based on. Works with no model."""
    facts = case_facts(db, case_id)
    if not facts:
        return []
    c, steps = facts["counts"], []
    findings, withheld = findings_for_reasoning(db, case_id, include_restricted)
    if facts["status"] != "open":
        steps.append(_step(1, f"Reopen the case (it is {facts['status']})", "Searches only run on an open case.", go={"route": "cases"}))
    if not facts["purpose"].strip():
        steps.append(_step(1, "Write the case purpose", "The purpose is shown on reports and is required for people-focused cases.", go={"route": "case", "tab": "Notes"}))
    if c["targets"] == 0:
        steps.append(_step(1, "Add a first target by running a preview", "The case has no targets yet, so nothing has been collected.", go={"route": "case", "tab": "Search"}))
    failed = [r for r in facts["recent_runs"] if r["status"] in ("failed", "partial")]
    for r in failed[:2]:
        steps.append(_step(1, f"Look into the {r['status']} run {r['id'][:8]}", "Some sources failed or timed out; their errors are listed in the run viewer.", run_id=r["id"], tool="diagnose_run",
                           go={"route": "case", "tab": "Search"}))
    broken = {a for r in facts["recent_runs"][:3] for a in (r.get("adapters") or []) if tools.get(a, {}).get("status") not in (None, "healthy")}
    for a in sorted(broken)[:3]:
        steps.append(_step(2, f"Fix {tools[a]['name']} ({tools[a]['status']})", "It was part of a recent run but its current state is not healthy.", tool="diagnose_tool", tool_id=a,
                           go={"route": "tools"}))
    types = {t["type"] for t in facts["targets"]}
    used = {a for r in facts["recent_runs"] for a in (r.get("adapters") or [])}
    unused = [a for a in tools.values() if a["status"] == "healthy" and a["id"] not in used and set(a["targets"]) & types and a["class"] in ("passive", "local_only")]
    if unused and c["findings"]:
        names = ", ".join(a["name"] for a in unused[:5])
        steps.append(_step(2, f"Run additional sources you have not used: {names}", f"They support your target type(s) ({', '.join(sorted(types))}) and are healthy, but no run included them.",
                           go={"route": "case", "tab": "Search"}))
    for q in [q for q in facts["open_requirements"] if q["answer_status"] in ("unanswered", "partial")][:3]:
        steps.append(_step(2 if q["priority"] == "high" else 3, f"Collect for requirement: {q['question'][:90]}", f"This requirement is {q['answer_status']} (priority {q['priority']}); attach evidence or collect from a relevant source.",
                           go={"route": "case", "tab": "Analysis"}))
    if c["requirements"] == 0 and c["findings"]:
        steps.append(_step(3, "Write down the questions this case must answer", "Without requirements the app cannot list gaps for you.", go={"route": "case", "tab": "Analysis"}))
    conf = contradictions(findings)
    if conf:
        steps.append(_step(2, f"Resolve {len(conf)} conflicting statement(s)", "Different sources reported different values for the same thing: "
                           + "; ".join(f"{x['entity']} {x['predicate']}" for x in conf[:3]), go={"route": "case", "tab": "Findings"}, tool="find_conflicts"))
    corr = corroboration(findings)
    if corr["single_source"] and corr["distinct_statements"]:
        steps.append(_step(3, f"Corroborate {corr['single_source']} single-source statement(s)", f"{corr['single_source']} of {corr['distinct_statements']} distinct statements come from one source only; independent confirmation raises confidence.",
                           go={"route": "case", "tab": "Analysis"}))
    low = sum(1 for f in findings if f["confidence"] in ("low", "unknown"))
    if findings and low / len(findings) > 0.5:
        steps.append(_step(3, "Most findings are low or unknown confidence", f"{low} of {len(findings)} findings. Prefer authoritative sources (registries, filings) to firm them up.", go={"route": "case", "tab": "Findings"}))
    unver = db.scalar(select(func.count()).select_from(Claim).where(Claim.case_id == case_id, Claim.verification_status == "unverified")) or 0
    if unver:
        steps.append(_step(3, f"Review {unver} unverified claim(s)", "Only you can mark a claim verified, disputed or rejected.", go={"route": "case", "tab": "Analysis"}))
    if facts["unacknowledged_alerts"]:
        steps.append(_step(2, f"Review {facts['unacknowledged_alerts']} new alert(s)", "Monitoring found changes.", go={"route": "case", "tab": "Workflows"}))
    if withheld:
        steps.append(_step(4, f"{withheld} restricted item(s) are withheld from this assistant", "Restricted evidence is not shown to the AI unless the case policy and you allow it.", go={"route": "case", "tab": "AI"}))
    last = facts["recent_runs"][0]["started_at"] if facts["recent_runs"] else None
    if last:
        try:
            if datetime.fromisoformat(last).astimezone(UTC) < datetime.now(UTC) - timedelta(days=30):
                steps.append(_step(4, "Collected data is over 30 days old", f"The last run started {last[:10]}. Re-run to check for changes.", go={"route": "case", "tab": "Search"}))
        except ValueError:
            pass
    if c["findings"] and c["reports"] == 0:
        steps.append(_step(4, "Generate a report", "You have findings but no report yet. Preview shows what would be included first.", go={"route": "case", "tab": "Reports"}))
    if not st.settings.offline and not steps:
        steps.append(_step(5, "Nothing urgent found", "No gaps detected by the rules. Consider adding hypotheses or another discipline's data.", go={"route": "case", "tab": "Analysis"}))
    steps.sort(key=lambda s: s["priority"])
    for i, s in enumerate(steps, 1):
        s["rank"] = i
    return steps
