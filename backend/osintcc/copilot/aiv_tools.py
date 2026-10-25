"""Copilot tools for Active Intelligence & Verification. Explain and propose only.

Enforced here, not by the model:
  * no tool approves a plan, starts a run, creates or widens an asset authorization, or contacts anything: the only action is a proposal that, once a person
    accepts the card, stores a DRAFT plan (which still needs its own approval in the Verification workspace before any request can be made);
  * a proposal is judged by the same offline policy as the Verification workspace and is refused if any step is out of scope;
  * with a cloud model only counts and generic text are shown: hosts, URLs, ports and observation details never leave the machine.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..aiv import plans as aplans
from ..aiv import policy
from ..aiv import tools as atools
from ..db.models import (
    AivObservation,
    AivPlan,
    AivRun,
    AssetAuthorization,
    CaseMember,
    Setting,
)
from .profile_tools import Refused

READ_TOOLS = ("aiv_status", "explain_aiv_plan", "explain_aiv_observation")
ACTION_TOOLS = ("propose_aiv_plan",)
ROLE_RANK = {"viewer": 1, "editor": 2, "owner": 3}
SEV_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}

INTENTS = {"aiv_status": "aiv_status", "aiv_plan": "explain_aiv_plan", "aiv_observation": "explain_aiv_observation"}
PATTERNS = [
    ("aiv_plan", re.compile(r"explain (this|the|my) (verification |aiv )?plan|what will (this|the|my) (verification )?plan (do|send)|what (does|would) (this|the) plan do", re.IGNORECASE)),
    ("aiv_observation", re.compile(r"explain (this|the|these) (verification |aiv )?(observation|finding)s?|what does (this|the) (verification )?(observation|finding) mean", re.IGNORECASE)),
    ("aiv_status", re.compile(r"(active )?verification (status|state)|aiv status|what (is|am i) (authorized|authorised) to (verify|test|check)|which assets (are|do i have) authori[sz]ed", re.IGNORECASE)),
]
NOT_PROOF = ("An observation is what a check saw at one moment from one place. It is not proof of compromise, ownership or intent, and the absence of an observation is not "
             "proof that nothing exists.")


def _role(db: Session, user: str, case_id: str) -> str:
    m = db.get(CaseMember, (case_id, user))
    if not m:
        raise Refused("case not found or you do not have the needed role on it")
    return m.access_role


def _need(role: str, need: str, what: str) -> None:
    if ROLE_RANK[role] < ROLE_RANK[need]:
        raise Refused(f"{what} needs the editor or owner role on this case")


def _aware(d: datetime) -> datetime:
    return d.replace(tzinfo=UTC) if d.tzinfo is None else d


def enabled(db: Session) -> bool:
    row = db.get(Setting, "aiv_enabled")
    return bool(row and row.value_json is True)


STEP_WORDS = {
    "http_metadata": "Send one {method} request to {url} and keep the response headers and status (no cookies sent, redirects {follow}).",
    "tls_handshake": "Open one TLS connection to {host}:{port} and read the certificate and protocol settings (nothing is sent after the handshake).",
    "tcp_connect": "Try a plain TCP connection to {host} on port(s) {ports} and record whether each accepts it (nothing is sent).",
    "service_detect": "Run {tool} against {host} on port(s) {ports} in connect-scan mode only to name the service.",
    "signature_check": "Run the approved read-only template(s) {template_ids} against {url} (GET/HEAD requests only).",
}


def _words(step: dict[str, Any]) -> str:
    d = dict(step)
    d["follow"] = "followed only while they stay in scope" if step.get("follow_redirects") else "not followed"
    d["ports"] = ", ".join(str(p) for p in step.get("ports", []))
    d["template_ids"] = ", ".join(step.get("template_ids", []))
    return STEP_WORDS[step["kind"]].format(**{k: d.get(k, "") for k in ("method", "url", "host", "port", "ports", "tool", "template_ids", "follow")})


# ---------------------------------------------------------------------------------------------------------------------------- read tools
def read(db: Session, st: Any, user: str, case_id: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    role = _role(db, user, case_id)
    on = enabled(db)
    if name == "aiv_status":
        return _status(db, case_id, on)
    _need(role, "editor", "verification details")
    if not on:
        return {"enabled": False, "note": "Active verification is switched off, so there are no plans or runs to explain. An administrator can turn it on in Verification > Settings."}
    if name == "explain_aiv_plan":
        return _explain_plan(db, case_id, str(args.get("plan_id") or ""))
    if name == "explain_aiv_observation":
        return _explain_observation(db, case_id, str(args.get("observation_id") or ""))
    raise Refused(f"'{name}' is not a verification tool")


def _status(db: Session, case_id: str, on: bool) -> dict[str, Any]:
    now = datetime.now(UTC)
    week = now + timedelta(days=7)
    auths = list(db.scalars(select(AssetAuthorization).where(AssetAuthorization.case_id == case_id)))
    live = [a for a in auths if policy.authorization_live(a, now)]
    plans = dict(db.execute(select(AivPlan.status, func.count()).where(AivPlan.case_id == case_id).group_by(AivPlan.status)).all())
    runs = dict(db.execute(select(AivRun.status, func.count()).where(AivRun.case_id == case_id).group_by(AivRun.status)).all())
    obs = list(db.scalars(select(AivObservation).where(AivObservation.case_id == case_id)))
    by_sev: dict[str, int] = {}
    for o in obs:
        by_sev[o.severity] = by_sev.get(o.severity, 0) + 1
    return {"enabled": on, "authorizations": {"total": len(auths), "live": len(live), "classes_in_force": sorted({c for a in live for c in (a.allowed_classes_json or [])}),
                                            "expiring_within_7_days": sum(1 for a in live if _aware(a.expires_at) < week)},
            "plans": plans, "runs": runs, "observations": {"total": len(obs), "by_severity": by_sev, "unreviewed": sum(1 for o in obs if o.review_status == "unreviewed")},
            "caveat": "Nothing active runs unless an administrator switched verification on, an asset authorization is live, and a person approved an exact plan. This tool reads state only.",
            "labels": {"checks": "fixture-tested against local lab servers; not verified against third-party systems"}}


def _explain_plan(db: Session, case_id: str, plan_id: str) -> dict[str, Any]:
    if plan_id:
        p = db.get(AivPlan, plan_id)
        if not p or p.case_id != case_id:
            raise Refused("that plan is not part of this case")
    else:
        p = db.scalars(select(AivPlan).where(AivPlan.case_id == case_id).order_by(AivPlan.created_at.desc())).first()
        if p is None:
            raise Refused("this case has no verification plan yet; create one in the Verification workspace or ask me to propose one")
    auth = db.get(AssetAuthorization, p.asset_authorization_id)
    live = policy.authorization_live(auth, datetime.now(UTC)) if auth else policy.deny("auth_missing", "the authorization no longer exists")
    limits = p.projected_limits_json or {}
    return {"plan_id": p.id, "status": p.status, "version": p.version, "hash": p.plan_hash[:16],
            "steps": [{"index": i, "kind": s["kind"], "what_happens": _words(s)} for i, s in enumerate(p.steps_json or [])],
            "authorization": {"id": auth.id if auth else None, "state": "live" if live else live.code, "reason": "" if live else live.reason,
                              "scope": list(auth.canonical_scope) if auth else [], "expires_at": auth.expires_at.isoformat() if auth and auth.expires_at else None},
            "budgets": {k: limits.get(k) for k in ("max_requests", "max_ports", "requests_per_second", "max_runtime_seconds", "max_hosts_per_run", "max_retries") if k in limits},
            "estimated_requests": limits.get("estimated_requests"), "impact": limits.get("impact"),
            "never": ["exploitation or payloads", "password or credential testing", "logging in", "fuzzing or load", "anything outside the authorized hosts, ports and checks"],
            "approval_needed": "A person must approve this exact plan (the approval is single-use and expires) before anything is sent. I cannot approve or run it.",
            "citations": []}


def _explain_observation(db: Session, case_id: str, obs_id: str) -> dict[str, Any]:
    if obs_id:
        o = db.get(AivObservation, obs_id)
        if not o or o.case_id != case_id:
            raise Refused("that observation is not part of this case")
        rows = [o]
    else:
        rows = sorted(db.scalars(select(AivObservation).where(AivObservation.case_id == case_id, AivObservation.review_status == "unreviewed")),
                      key=lambda x: (-SEV_RANK.get(x.severity, 0), x.observed_at or 0))[:5] if False else \
            sorted(db.scalars(select(AivObservation).where(AivObservation.case_id == case_id, AivObservation.review_status == "unreviewed")), key=lambda x: -SEV_RANK.get(x.severity, 0))[:5]
        if not rows:
            raise Refused("there are no unreviewed verification observations in this case")
    items = []
    for o in rows:
        v = o.observed_value_json or {}
        items.append({"id": o.id, "asset": o.target_asset, "check": o.check_type, "title": str(v.get("title") or o.finding_key)[:200], "severity": o.severity, "confidence": o.confidence,
                      "basis": o.basis, "review_status": o.review_status, "remediation": o.remediation, "evidence_id": o.evidence_id,
                      "meaning": "Observed directly by a check." if o.basis == "observed" else "Inferred from what was observed; confirm it before relying on it."})
    return {"observations": items, "not_proof": NOT_PROOF,
            "citations": [{"id": i["evidence_id"], "title": f"AIV {i['check']} {i['asset']}", "sha256": ""} for i in items if i["evidence_id"]]}


# ---------------------------------------------------------------------------------------------------------------------------- cloud view
def cloud_view(name: str, r: dict[str, Any]) -> dict[str, Any]:
    notice = "Verification details are withheld from cloud models; only counts and generic text are shown."
    if name == "aiv_status":
        return {"enabled": r["enabled"], "live_authorizations": r["authorizations"]["live"], "plans": r["plans"], "runs": r["runs"], "observations": r["observations"], "notice": notice}
    if name == "explain_aiv_plan":
        return {"step_count": len(r.get("steps", [])), "status": r.get("status"), "approval_needed": r.get("approval_needed"), "notice": notice}
    if name == "explain_aiv_observation":
        return {"observation_count": len(r.get("observations", [])), "not_proof": r.get("not_proof"), "notice": notice}
    return {"notice": notice}


# ---------------------------------------------------------------------------------------------------------------------------- renderers
def md_status(r: dict[str, Any]) -> str:
    a, o = r["authorizations"], r["observations"]
    if not r["enabled"]:
        return "**Active verification is switched off.** Nothing active can run. An administrator can turn it on in Verification > Settings.\n\n_" + r["caveat"] + "_"
    out = ["**Verification status for this case**", "", f"- Asset authorizations: {a['live']} live of {a['total']} ({', '.join(a['classes_in_force']) or 'no checks permitted'}); {a['expiring_within_7_days']} expire within 7 days.",
           "- Plans: " + (", ".join(f"{n} {k}" for k, n in r["plans"].items()) or "none") + ".",
           "- Runs: " + (", ".join(f"{n} {k}" for k, n in r["runs"].items()) or "none") + ".",
           f"- Observations: {o['total']} ({', '.join(f'{n} {k}' for k, n in o['by_severity'].items()) or 'none'}); {o['unreviewed']} not yet reviewed.", "", f"_{r['caveat']}_"]
    return "\n".join(out)


def md_plan(r: dict[str, Any]) -> str:
    if r.get("enabled") is False:
        return r["note"]
    out = [f"**Plan {r['plan_id'][:8]} (version {r['version']}, {r['status']})**", "", "If you approve this exact plan, the following would happen and nothing else:"]
    out += [f"{s['index'] + 1}. {s['what_happens']}" for s in r["steps"]]
    au = r["authorization"]
    out += ["", f"Authorization: {au['state']}" + (f" ({au['reason']})" if au["reason"] else "") + f"; scope {', '.join(au['scope']) or 'none'}.",
            "Budgets: " + (", ".join(f"{k.replace('_', ' ')} {v}" for k, v in r["budgets"].items()) or "defaults") + f"; about {r['estimated_requests']} request(s), impact {r['impact']}.",
            "It will never: " + "; ".join(r["never"]) + ".", "", r["approval_needed"]]
    return "\n".join(out)


def md_observations(r: dict[str, Any]) -> str:
    if r.get("enabled") is False:
        return r["note"]
    out = ["**Verification observations that still need a review**", ""]
    for i in r["observations"]:
        out.append(f"- **{i['title']}** on `{i['asset']}` ({i['check']}): severity {i['severity']}, confidence {i['confidence']}. {i['meaning']} "
                   + (f"Suggested next step: {i['remediation']} " if i["remediation"] else "") + (f"(evidence `{i['evidence_id'][:8]}`)" if i["evidence_id"] else ""))
    out += ["", f"_{r['not_proof']}_"]
    return "\n".join(out)


RENDERERS = {"aiv_status": md_status, "explain_aiv_plan": md_plan, "explain_aiv_observation": md_observations}


# ---------------------------------------------------------------------------------------------------------------------------- proposal
def propose(db: Session, st: Any, user: str, case_id: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    role = _role(db, user, case_id)
    _need(role, "editor", "proposing a verification plan")
    if not enabled(db):
        raise Refused("not proposed: active verification is switched off (an administrator can turn it on in Verification > Settings)")
    aid = str(args.get("authorization_id") or "")
    auth = db.get(AssetAuthorization, aid)
    if not auth or auth.case_id != case_id:
        raise Refused("name an asset authorization of this case (authorization_id). I cannot create or widen an authorization.")
    try:
        pv = aplans.preview(auth, args.get("steps"), approved_templates=atools.approved_template_ids(db), offline=st.settings.offline)
    except aplans.PlanError as exc:
        raise Refused(f"not proposed: {exc.message}") from exc
    if not pv["ok"]:
        bad = next((r for r in pv["steps"] if not r["allowed"]), None)
        raise Refused("not proposed: " + (f"step {bad['index'] + 1}: {bad['reason']}" if bad else "; ".join(pv["problems"])))
    clean = {"authorization_id": auth.id, "steps": pv["normalized_steps"]}
    preview = {"steps": [{"index": r["index"], "what_happens": _words(pv["normalized_steps"][r["index"]]), "impact": r["impact"]} for r in pv["steps"]],
               "estimated_requests": pv["estimated_requests"], "limits": pv["limits"],
               "stores": "a DRAFT plan only. It is not approved and nothing is sent. You approve (or discard) the exact plan in the Verification workspace.",
               "note": "The plan hash and tool versions are fixed when the draft is created; the workspace shows them before you approve."}
    return clean, preview
