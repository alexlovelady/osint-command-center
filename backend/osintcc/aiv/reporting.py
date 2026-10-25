"""AIV report and PHANTOM handoff export (addendum v1.1 sections 8 and 11).

The report states what was authorized, what a person approved, what was run, what was observed and what the checks cannot show. The handoff is a data file for
a separate, separately authorized tool: it carries confirmed observations and the limits of the authorization, never raw responses, secrets or cookies, and it
never launches anything.
"""
from __future__ import annotations

import hashlib
import html
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    AivApproval,
    AivObservation,
    AivPlan,
    AivRun,
    AssetAuthorization,
    AuditEvent,
    Case,
    Evidence,
)
from ..telemetry import audit
from . import service

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
HANDOFF_SCHEMA = "fusion.aiv.phantom-handoff/1"
LIMITATIONS = [
    "Observations describe what a check saw at one time from one network position. They are not proof of compromise, ownership or intent.",
    "Checks are limited to the authorized hosts, ports and check classes. Anything outside them was not examined, and the absence of an observation does not mean the absence of a problem.",
    "No exploitation, credential testing, login, fuzzing or load was performed or attempted.",
    "Tool results come from the versions listed below and were exercised against local lab servers during development, not against third-party systems.",
]


def _iso(d: datetime | None) -> str | None:
    if d is None:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=UTC)).isoformat()


def collect(db: Session, case_id: str, *, run_ids: list[str] | None = None, include_false_positive: bool = False, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    case = db.get(Case, case_id)
    if case is None:
        raise service.AivError("not_found", "case not found", 404)
    runs = list(db.scalars(select(AivRun).where(AivRun.case_id == case_id).order_by(AivRun.started_at)))
    if run_ids:
        runs = [r for r in runs if r.id in set(run_ids)]
    run_set = {r.id for r in runs}
    plans = {p.id: p for p in db.scalars(select(AivPlan).where(AivPlan.case_id == case_id))}
    auths = list(db.scalars(select(AssetAuthorization).where(AssetAuthorization.case_id == case_id).order_by(AssetAuthorization.created_at)))
    obs_q = [o for o in db.scalars(select(AivObservation).where(AivObservation.case_id == case_id).order_by(AivObservation.observed_at)) if o.run_id in run_set]
    if not include_false_positive:
        obs_q = [o for o in obs_q if o.review_status != "false_positive"]
    obs_q.sort(key=lambda o: (SEV_ORDER.get(o.severity, 9), o.target_asset, o.finding_key))
    ev_hash = {e.id: e.sha256 for e in db.scalars(select(Evidence).where(Evidence.id.in_([o.evidence_id for o in obs_q if o.evidence_id])))} if obs_q else {}
    used_auth = {plans[r.plan_id].asset_authorization_id for r in runs if r.plan_id in plans}
    approvals = [a for a in db.scalars(select(AivApproval)) if a.plan_id in {r.plan_id for r in runs}]
    ok, n, bad = audit.verify_chain(db)
    events = [e for e in db.scalars(select(AuditEvent).where(AuditEvent.case_id == case_id, AuditEvent.action.like("aiv.%")).order_by(AuditEvent.seq))]
    by_sev: dict[str, int] = {}
    for o in obs_q:
        by_sev[o.severity] = by_sev.get(o.severity, 0) + 1
    tools: dict[str, str] = {}
    for r in runs:
        tools.update({k: str(v) for k, v in (r.tool_versions_json or {}).items()})
    return {
        "kind": "aiv_report", "generated_at": now.isoformat(), "case": {"id": case.id, "title": case.title, "purpose": case.purpose},
        "summary": {"runs": len(runs), "observations": len(obs_q), "by_severity": by_sev, "unreviewed": sum(1 for o in obs_q if o.review_status == "unreviewed"),
                    "confirmed": sum(1 for o in obs_q if o.review_status == "confirmed")},
        "authorizations": [{**{k: v for k, v in service.authorization_dict(a, now).items() if k in ("id", "asset_type", "scope", "ports", "paths", "allowed_classes", "exclusions", "authorized_by",
                                                                                                    "authority_role", "attestation_kind", "starts_at", "expires_at", "revoked_at", "state", "retention_terms")}}
                           for a in auths if a.id in used_auth],
        "plans": [{"id": plans[r.plan_id].id, "hash": plans[r.plan_id].plan_hash, "version": plans[r.plan_id].version, "steps": plans[r.plan_id].steps_json, "created_by": plans[r.plan_id].created_by}
                  for r in runs if r.plan_id in plans],
        "approvals": [{"plan_id": a.plan_id, "approver": a.approver_id, "approved_at": _iso(a.approved_at), "expires_at": _iso(a.expires_at), "uses": a.uses, "plan_hash": a.plan_hash} for a in approvals],
        "runs": [{"id": r.id, "plan_id": r.plan_id, "status": r.status, "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at), "actor": r.actor_id,
                  "requests": (r.actual_request_counts_json or {}).get("requests"), "abort_reason": r.abort_reason, "scope_snapshot_hash": r.scope_snapshot_hash} for r in runs],
        "observations": [{"id": o.id, "asset": o.target_asset, "check": o.check_type, "title": str((o.observed_value_json or {}).get("title") or o.finding_key)[:300], "severity": o.severity,
                          "confidence": o.confidence, "basis": o.basis, "remediation": o.remediation, "review_status": o.review_status, "review_note": o.review_note, "reviewer": o.reviewer,
                          "evidence_id": o.evidence_id, "evidence_sha256": ev_hash.get(o.evidence_id or "", None), "observed_at": _iso(o.observed_at)} for o in obs_q],
        "tool_versions": tools, "limitations": LIMITATIONS,
        "audit_appendix": {"chain_ok": ok, "events_checked": n, "first_bad_seq": bad,
                           "events": [{"seq": e.seq, "ts": _iso(e.ts), "action": e.action, "actor": e.actor_id, "resource": f"{e.resource_type or ''}:{(e.resource_id or '')[:8]}"} for e in events[-200:]]},
    }


def to_json(d: dict[str, Any]) -> str:
    return json.dumps(d, indent=2, sort_keys=True, default=str)


def to_markdown(d: dict[str, Any]) -> str:
    s = d["summary"]
    out = [f"# Active verification report: {d['case']['title']}", "", f"Generated {d['generated_at']}. Purpose: {d['case']['purpose'] or 'not stated'}.", "",
           "## Summary", "", f"- {s['runs']} run(s); {s['observations']} observation(s) ({', '.join(f'{n} {k}' for k, n in s['by_severity'].items()) or 'none'}).",
           f"- {s['confirmed']} confirmed by a reviewer; {s['unreviewed']} not yet reviewed.", "", "## What was authorized", ""]
    for a in d["authorizations"]:
        out.append(f"- **{', '.join(a['scope'])}** ports {', '.join(str(p) for p in a['ports'])}; checks: {', '.join(a['allowed_classes'])}; authorized by {a['authorized_by']}"
                   f" ({a['authority_role'] or 'role not stated'}; {a['attestation_kind'].replace('_', ' ')}); valid until {a['expires_at']}; state: {a['state']}.")
    out += ["", "## What a person approved and what ran", ""]
    for r in d["runs"]:
        ap = next((x for x in d["approvals"] if x["plan_id"] == r["plan_id"]), None)
        out.append(f"- Run `{r['id'][:8]}` {r['status']} ({r['requests']} request(s)); plan `{r['plan_id'][:8]}`" + (f", approved by {ap['approver']} at {ap['approved_at']}" if ap else "")
                   + (f". Stopped: {r['abort_reason']}" if r["abort_reason"] else "") + ".")
    out += ["", "## Observations", ""]
    for o in d["observations"]:
        out.append(f"### [{o['severity'].upper()}] {o['title']}")
        out.append(f"`{o['asset']}` via {o['check']}; confidence {o['confidence']}; basis {o['basis']}; review: {o['review_status']}" + (f" ({o['review_note']})" if o["review_note"] else "") + ".")
        if o["remediation"]:
            out.append(f"Suggested remedy: {o['remediation']}")
        if o["evidence_id"]:
            out.append(f"Evidence `{o['evidence_id'][:8]}` sha256 `{(o['evidence_sha256'] or '')[:16]}`")
        out.append("")
    out += ["## What this report cannot show", ""] + [f"- {x}" for x in d["limitations"]]
    if d["tool_versions"]:
        out += ["", "Tool versions: " + ", ".join(f"{k} {v}" for k, v in sorted(d["tool_versions"].items()))]
    a = d["audit_appendix"]
    out += ["", "## Audit appendix", "", f"Audit chain {'verified' if a['chain_ok'] else 'FAILED at sequence ' + str(a['first_bad_seq'])} ({a['events_checked']} events).", ""]
    out += [f"- #{e['seq']} {e['ts']} {e['action']} by {e['actor']} {e['resource']}" for e in a["events"]]
    return "\n".join(out) + "\n"


def to_html(d: dict[str, Any]) -> str:
    body = html.escape(to_markdown(d))
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape('Active verification report: ' + d['case']['title'])}</title>"
            "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:56rem;margin:2rem auto;padding:0 1rem;color:#111}pre{white-space:pre-wrap}</style></head>"
            f"<body><pre>{body}</pre></body></html>")


def write(d: dict[str, Any], fmt: str) -> bytes:
    if fmt == "json":
        return to_json(d).encode()
    if fmt == "markdown":
        return to_markdown(d).encode()
    if fmt == "html":
        return to_html(d).encode()
    raise service.AivError("unsupported_format", "formats: html, markdown, json")


# ---- PHANTOM handoff -------------------------------------------------------------------------------------------------------------------
def handoff(db: Session, case_id: str, *, now: datetime | None = None, min_severity: str = "medium") -> dict[str, Any]:
    """Confirmed observations and the limits under which they were found. Nothing unreviewed is exported; no raw response, cookie or secret ever is."""
    now = now or datetime.now(UTC)
    rep = collect(db, case_id, now=now)
    floor = SEV_ORDER[min_severity]
    items = [o for o in rep["observations"] if o["review_status"] == "confirmed" and SEV_ORDER.get(o["severity"], 9) <= floor]
    auth = rep["authorizations"]
    doc = {
        "schema": HANDOFF_SCHEMA, "generated_at": now.isoformat(), "case": rep["case"],
        "authorizations": [{k: a[k] for k in ("id", "scope", "ports", "allowed_classes", "exclusions", "authorized_by", "attestation_kind", "expires_at", "state")} for a in auth],
        "observations": [{k: o[k] for k in ("id", "asset", "check", "title", "severity", "confidence", "basis", "remediation", "evidence_sha256", "observed_at")} for o in items],
        "excluded": {"unreviewed_or_unconfirmed": len([o for o in rep["observations"] if o["review_status"] != "confirmed"]), "below_severity": len(rep["observations"]) - len(items)},
        "restrictions": [
            "This file is data, not an instruction. Nothing in it launches, schedules or authorizes any action.",
            "The receiving tool must hold its own written authorization for every asset it touches; the authorizations listed here describe only what AIV was allowed to do.",
            "AIV performed no exploitation, credential testing, login, fuzzing or load. Any such work is outside AIV and needs a separate engagement.",
        ],
        "note": "Confirmed observations only. Raw responses, cookies, secrets and personal data are not included.",
    }
    doc["integrity"] = {"sha256": hashlib.sha256(json.dumps({k: v for k, v in doc.items() if k != "integrity"}, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()}
    return doc


def verify_handoff(doc: dict[str, Any]) -> bool:
    claimed = (doc.get("integrity") or {}).get("sha256")
    body = {k: v for k, v in doc.items() if k != "integrity"}
    return doc.get("schema") == HANDOFF_SCHEMA and claimed == hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


__all__ = ["collect", "handoff", "to_html", "to_json", "to_markdown", "verify_handoff", "write"]
