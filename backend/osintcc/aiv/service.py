"""Authorizations, plans, approvals and observations: the records behind AIV. Policy lives in `policy.py`; this module validates input and keeps the audit trail."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    AivApproval,
    AivObservation,
    AivPlan,
    AivRun,
    AssetAuthorization,
    Case,
    Evidence,
    Subject,
)
from ..telemetry import audit
from . import plans as aplans
from . import policy, tools

MAX_DAYS = 180
MAX_SCOPE_ENTRIES = 20


class AivError(Exception):
    def __init__(self, code: str, message: str, status: int = 422):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _now() -> datetime:
    return datetime.now(UTC)


def create_authorization(db: Session, case: Case, *, asset_type: str, scope: list[str], ports: list[int], paths: list[str], classes: list[str], exclusions: list[str],
                         limits: dict[str, Any], authorized_by: str, authority_role: str, source_of_authority: str, attestation_kind: str, attestation_ref: str | None,
                         starts_at: datetime | None, expires_at: datetime, retention_terms: str, notes: str, owner_subject_id: str | None, actor: str,
                         now: datetime | None = None) -> AssetAuthorization:
    now = now or _now()
    if asset_type not in policy.ASSET_TYPES:
        raise AivError("invalid_asset_type", f"asset type must be one of {', '.join(policy.ASSET_TYPES)}")
    if not scope or len(scope) > MAX_SCOPE_ENTRIES:
        raise AivError("invalid_scope", f"list between 1 and {MAX_SCOPE_ENTRIES} exact scope entries")
    try:
        canon = list(dict.fromkeys(policy.canonical_entry(asset_type, e) for e in scope))
        clean_limits = policy.validate_limits(limits or {})
    except ValueError as exc:
        raise AivError("invalid_scope", str(exc)) from exc
    bad = [c for c in classes if c not in (*policy.CLASSES, policy.LAB_CLASS)]
    if not classes or bad:
        raise AivError("invalid_classes", f"choose from: {', '.join(policy.CLASSES)} (and {policy.LAB_CLASS} only for a private lab you own)")
    net_classes = [c for c in classes if c != policy.LAB_CLASS]
    if not net_classes:
        raise AivError("invalid_classes", "authorize at least one check class")
    if not ports or len(ports) > 20 or any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in ports):
        raise AivError("invalid_ports", "list the exact TCP ports (1-65535, at most 20) the checks may touch")
    clean_paths = list(dict.fromkeys(paths or ["/"]))
    if len(clean_paths) > 20 or any(not isinstance(p, str) or not p.startswith("/") or len(p) > 200 or " " in p for p in clean_paths):
        raise AivError("invalid_paths", "paths start with '/' and contain no spaces")
    if len(exclusions or []) > 50 or any(not isinstance(x, str) or len(x) > 300 for x in exclusions or []):
        raise AivError("invalid_exclusions", "too many or too long exclusions")
    if not authorized_by.strip():
        raise AivError("approver_required", "record who authorized this and in what role")
    if attestation_kind not in policy.ATTESTATION_KINDS:
        raise AivError("invalid_attestation", f"attestation must be one of {', '.join(policy.ATTESTATION_KINDS)}")
    if attestation_kind != "owner_statement" and not attestation_ref:
        raise AivError("proof_required", "this kind of attestation needs the document or message attached as case evidence")
    if attestation_kind == "owner_statement" and len(source_of_authority.strip()) < 20:
        raise AivError("source_required", "describe how the authority over this asset was established (at least a sentence)")
    if attestation_ref:
        ev = db.get(Evidence, attestation_ref)
        if not ev or ev.case_id != case.id:
            raise AivError("evidence_not_in_case", "the attestation evidence is not in this case")
    if owner_subject_id:
        s = db.get(Subject, owner_subject_id)
        if not s or s.case_id != case.id:
            raise AivError("subject_not_in_case", "the owner subject is not in this case")
    start = policy.aware(starts_at) or now
    exp = policy.aware(expires_at)
    assert exp is not None
    if exp <= start or exp <= now:
        raise AivError("expiry_invalid", "the authorization must end in the future, after it starts")
    if exp - start > timedelta(days=MAX_DAYS):
        raise AivError("duration_too_long", f"an authorization lasts at most {MAX_DAYS} days; renew it instead")
    a = AssetAuthorization(case_id=case.id, owner_subject_id=owner_subject_id, asset_type=asset_type, canonical_scope=canon, ports_json=sorted(set(ports)), paths_json=clean_paths,
                           allowed_classes_json=list(dict.fromkeys(classes)), exclusions_json=list(dict.fromkeys(exclusions or [])), limits_json=clean_limits,
                           authorized_by=authorized_by.strip()[:200], authority_role=authority_role.strip()[:120], source_of_authority=source_of_authority.strip()[:2000],
                           attestation_kind=attestation_kind, attestation_ref=attestation_ref, starts_at=start, expires_at=exp, retention_terms=retention_terms.strip()[:1000],
                           notes=notes.strip()[:2000], created_by=actor)
    db.add(a)
    db.flush()
    audit.record(db, "aiv.authorization_create", actor=actor, case_id=case.id, resource_type="asset_authorization", resource_id=a.id,
                 metadata={"asset_type": asset_type, "entries": len(canon), "classes": a.allowed_classes_json, "expires": exp.isoformat()})
    return a


def authorization_dict(a: AssetAuthorization, now: datetime | None = None) -> dict[str, Any]:
    now = now or _now()
    live = policy.authorization_live(a, now)
    return {"id": a.id, "case_id": a.case_id, "owner_subject_id": a.owner_subject_id, "asset_type": a.asset_type, "scope": a.canonical_scope, "ports": a.ports_json, "paths": a.paths_json,
            "allowed_classes": a.allowed_classes_json, "exclusions": a.exclusions_json, "limits": policy.effective_limits(a.limits_json), "limits_set": a.limits_json,
            "authorized_by": a.authorized_by, "authority_role": a.authority_role, "source_of_authority": a.source_of_authority, "attestation_kind": a.attestation_kind,
            "attestation_ref": a.attestation_ref, "starts_at": a.starts_at, "expires_at": a.expires_at, "revoked_at": a.revoked_at, "retention_terms": a.retention_terms, "notes": a.notes,
            "state": "live" if live else live.code.replace("auth_", ""), "state_reason": "" if live else live.reason, "created_at": a.created_at,
            "domain_verifications": a.domain_verifications or {}, "scope_snapshot_hash": policy.scope_snapshot(a)}


def revoke_authorization(db: Session, a: AssetAuthorization, executor: Any, actor: str, reason: str) -> dict[str, int]:
    if a.revoked_at is None:
        a.revoked_at = _now()
        a.notes = (a.notes + f"\nRevoked: {reason}").strip()[:2000]
    cancelled = approvals = 0
    for plan in db.scalars(select(AivPlan).where(AivPlan.asset_authorization_id == a.id)):
        for ap in db.scalars(select(AivApproval).where(AivApproval.plan_id == plan.id, AivApproval.revoked_at.is_(None))):
            ap.revoked_at = _now()
            approvals += 1
        for r in db.scalars(select(AivRun).where(AivRun.plan_id == plan.id, AivRun.status.in_(("queued", "running")))):
            if executor is not None:
                executor.cancel(r.id)
            cancelled += 1
    audit.record(db, "aiv.authorization_revoke", actor=actor, case_id=a.case_id, resource_type="asset_authorization", resource_id=a.id, metadata={"approvals_revoked": approvals, "runs_cancelled": cancelled})
    return {"approvals_revoked": approvals, "runs_cancelled": cancelled}


async def preview_plan(db: Session, st: Any, auth: AssetAuthorization, raw_steps: Any) -> dict[str, Any]:
    try:
        return aplans.preview(auth, raw_steps, _now(), tool_versions=await tools.tool_versions(st), approved_templates=tools.approved_template_ids(db), offline=st.settings.offline)
    except aplans.PlanError as exc:
        raise AivError(exc.code, exc.message) from exc


async def create_plan(db: Session, st: Any, case: Case, auth: AssetAuthorization, raw_steps: Any, subject_id: str | None, actor: str, supersedes: str | None = None) -> AivPlan:
    pv = await preview_plan(db, st, auth, raw_steps)
    if not pv["ok"]:
        first = next((r for r in pv["steps"] if not r["allowed"]), None)
        raise AivError(first["code"] if first else "plan_not_ok", first["reason"] if first else "; ".join(pv["problems"]), 422)
    if subject_id:
        s = db.get(Subject, subject_id)
        if not s or s.case_id != case.id:
            raise AivError("subject_not_in_case", "the target profile is not in this case")
    version = 1
    if supersedes:
        old = db.get(AivPlan, supersedes)
        if not old or old.case_id != case.id:
            raise AivError("not_found", "the plan to supersede was not found", 404)
        version = old.version + 1
        old.status = "superseded"
        for ap in db.scalars(select(AivApproval).where(AivApproval.plan_id == old.id, AivApproval.revoked_at.is_(None))):
            ap.revoked_at = _now()                                # a superseded plan can no longer be run
    existing = db.scalars(select(AivPlan).where(AivPlan.case_id == case.id, AivPlan.plan_hash == pv["plan_hash"], AivPlan.version == version)).first()
    if existing:
        return existing
    plan = AivPlan(case_id=case.id, target_profile_id=subject_id, asset_authorization_id=auth.id, plan_hash=pv["plan_hash"], version=version, supersedes_id=supersedes,
                   steps_json=pv["normalized_steps"], projected_limits_json={**pv["limits"], "scope_snapshot_hash": pv["scope_snapshot_hash"], "estimated_requests": pv["estimated_requests"],
                                                                              "impact": pv["impact"], "tools": pv["tools"]}, status="draft", created_by=actor)
    db.add(plan)
    db.flush()
    audit.record(db, "aiv.plan_create", actor=actor, case_id=case.id, resource_type="aiv_plan", resource_id=plan.id, metadata={"hash": plan.plan_hash[:12], "version": version, "steps": len(plan.steps_json)})
    return plan


async def approve_plan(db: Session, st: Any, plan: AivPlan, actor: str, minutes: int) -> AivApproval:
    auth = db.get(AssetAuthorization, plan.asset_authorization_id)
    if auth is None:
        raise AivError("auth_missing", "the authorization no longer exists")
    if plan.status in ("superseded", "running", "cancelled"):
        raise AivError("plan_not_approvable", f"a plan that is {plan.status} cannot be approved")
    pv = await preview_plan(db, st, auth, plan.steps_json)
    if not pv["ok"] or pv["plan_hash"] != plan.plan_hash:
        first = next((r for r in pv["steps"] if not r["allowed"]), None)
        raise AivError(first["code"] if first else "plan_changed", first["reason"] if first else "the plan no longer matches its authorization or tools; create a new plan")
    if not 1 <= minutes <= 240:
        raise AivError("invalid_expiry", "an approval lasts between 1 and 240 minutes")
    ap = AivApproval(plan_id=plan.id, plan_version=plan.version, plan_hash=plan.plan_hash, approver_id=actor, expires_at=_now() + timedelta(minutes=minutes), maximum_uses=1)
    db.add(ap)
    plan.status = "approved"
    db.flush()
    audit.record(db, "aiv.plan_approve", actor=actor, case_id=plan.case_id, resource_type="aiv_plan", resource_id=plan.id, metadata={"approval": ap.id, "minutes": minutes, "hash": plan.plan_hash[:12]})
    return ap


def plan_dict(p: AivPlan) -> dict[str, Any]:
    return {"id": p.id, "case_id": p.case_id, "target_profile_id": p.target_profile_id, "asset_authorization_id": p.asset_authorization_id, "plan_hash": p.plan_hash, "version": p.version,
            "supersedes_id": p.supersedes_id, "steps": p.steps_json, "limits": p.projected_limits_json, "status": p.status, "created_by": p.created_by, "created_at": p.created_at}


def run_dict(r: AivRun) -> dict[str, Any]:
    return {"id": r.id, "plan_id": r.plan_id, "case_id": r.case_id, "actor": r.actor_id, "status": r.status, "started_at": r.started_at, "finished_at": r.finished_at,
            "counts": r.actual_request_counts_json, "abort_reason": r.abort_reason, "scope_snapshot_hash": r.scope_snapshot_hash, "tool_versions": r.tool_versions_json}


def observation_dict(o: AivObservation) -> dict[str, Any]:
    return {"id": o.id, "run_id": o.run_id, "asset_authorization_id": o.asset_authorization_id, "target_asset": o.target_asset, "check_type": o.check_type, "finding_key": o.finding_key,
            "observed": o.observed_value_json, "severity": o.severity, "confidence": o.confidence, "basis": o.basis, "remediation": o.remediation, "evidence_id": o.evidence_id,
            "observed_at": o.observed_at, "review_status": o.review_status, "reviewer": o.reviewer, "review_note": o.review_note}


def review_observation(db: Session, o: AivObservation, status: str, note: str, reviewer: str) -> AivObservation:
    if status not in ("confirmed", "false_positive", "accepted_risk", "unreviewed"):
        raise AivError("invalid_status", "status must be confirmed, false_positive, accepted_risk or unreviewed")
    if status != "unreviewed" and not note.strip():
        raise AivError("note_required", "say why")
    o.review_status, o.review_note, o.reviewer, o.reviewed_at = status, note.strip()[:1000], reviewer, _now()
    audit.record(db, "aiv.observation_review", actor=reviewer, case_id=o.case_id, resource_type="aiv_observation", resource_id=o.id, metadata={"status": status})
    return o


def compare_runs(db: Session, earlier: AivRun, later: AivRun) -> dict[str, Any]:
    """Reverification. A finding counts as RESOLVED only if the later run executed the same kind of check on the same asset and no longer saw it."""
    def seen(run: AivRun) -> dict[str, AivObservation]:
        return {o.finding_key: o for o in db.scalars(select(AivObservation).where(AivObservation.run_id == run.id)) if o.severity != "info" or o.check_type == "signature"}

    def checked(run: AivRun) -> set[tuple[str, str]]:
        return {(a, f) for a, f in (run.actual_request_counts_json or {}).get("checked", [])}
    a, b, rechecked = seen(earlier), seen(later), checked(later)
    new = [observation_dict(o) for k, o in b.items() if k not in a]
    persisting = [observation_dict(o) for k, o in b.items() if k in a]
    resolved: list[dict[str, Any]] = []
    not_rechecked: list[dict[str, Any]] = []
    for k, o in a.items():
        if k in b:
            continue
        (resolved if (o.target_asset, o.check_type) in rechecked else not_rechecked).append(observation_dict(o))
    return {"earlier": earlier.id, "later": later.id, "new": new, "persisting": persisting, "resolved": resolved, "not_rechecked": not_rechecked,
            "note": "'Resolved' means the later run repeated the same check on the same asset and did not observe the finding. Findings not repeated are listed as not rechecked, never as fixed."}
