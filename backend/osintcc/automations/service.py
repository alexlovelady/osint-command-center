"""Workflow lifecycle: draft -> validate -> publish (immutable version) -> approval -> activate. Authorisation is decided HERE and in `permissions`,
never by a model, and every transition is audited. The AI Builder can only create drafts; publishing, approving and activating are people's actions."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    AutomationApproval,
    AutomationTrigger,
    AutomationVersion,
    AutomationWorkflow,
    ScopeAuthorization,
)
from ..policy import engine as policy
from ..telemetry import audit
from . import cron, permissions
from .graph_validator import validate
from .models import CONFIGS, Definition, content_hash


class ServiceError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details or {}


def _now() -> datetime:
    return datetime.now(UTC)


def normalise(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse through the strict model and force the safety defaults: nothing arrives enabled. Raises ServiceError on a malformed definition."""
    try:
        d = Definition.model_validate(raw)
    except Exception as exc:
        errs: list[Any] = getattr(exc, "errors", list)()
        raise ServiceError(422, "INVALID_GRAPH", "the workflow definition is not valid",
                           {"errors": [{"path": ".".join(str(x) for x in e["loc"]), "message": e["msg"]} for e in errs][:20]}) from exc
    d.trigger.enabled = False
    d.status = "draft"
    problems: list[dict[str, Any]] = []
    for n in d.nodes:                                            # unknown or malformed config (a `command`, `sql`, a URL...) never reaches storage
        try:
            n.config = CONFIGS[n.type].model_validate(n.config).model_dump(mode="json")
        except Exception as exc:
            for e in getattr(exc, "errors", list)():
                problems.append({"path": f"nodes.{n.id}.config.{'.'.join(str(x) for x in e['loc'])}", "message": e["msg"]})
    if problems:
        raise ServiceError(422, "INVALID_GRAPH", "a step has settings this application does not support", {"errors": problems[:20]})
    return d.model_dump(mode="json")


def health_map(st: Any) -> dict[str, str]:
    import asyncio

    from ..copilot import context as cx

    async def go() -> dict[str, str]:
        return {a: (await cx._health(ad)).get("status", "unknown") for a, ad in st.adapters.items()}
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(go())
    return {}


def create_workflow(db: Session, *, owner: str, definition: dict[str, Any], case_id: str | None, name: str | None = None, template_slug: str | None = None) -> AutomationWorkflow:
    d = normalise(definition)
    wf = AutomationWorkflow(owner_id=owner, case_id=case_id, name=(name or d["name"])[:200], template_slug=template_slug, draft_json=d, state="draft")
    db.add(wf)
    db.flush()
    audit.record(db, "automation.workflow_created", actor=owner, case_id=case_id, resource_id=wf.id, metadata={"template": template_slug, "after": content_hash(d)[:16]})
    return wf


def update_draft(db: Session, wf: AutomationWorkflow, definition: dict[str, Any], expected_rev: int | None, actor: str, name: str | None = None) -> AutomationWorkflow:
    if expected_rev is not None and expected_rev != wf.draft_rev:
        raise ServiceError(412, "PRECONDITION_FAILED", f"the draft changed (revision {wf.draft_rev}); reload before saving", {"current_rev": wf.draft_rev})
    d = normalise(definition)
    before = content_hash(wf.draft_json or {})
    wf.draft_json, wf.draft_rev = d, wf.draft_rev + 1
    if name:
        wf.name = name[:200]
    audit.record(db, "automation.draft_updated", actor=actor, case_id=wf.case_id, resource_id=wf.id, metadata={"before": before[:16], "after": content_hash(d)[:16]})
    return wf


def latest_version(db: Session, wf_id: str) -> AutomationVersion | None:
    return db.scalars(select(AutomationVersion).where(AutomationVersion.workflow_id == wf_id).order_by(AutomationVersion.revision.desc())).first()


def publish(db: Session, wf: AutomationWorkflow, st: Any, actor: str, health: dict[str, str] | None = None) -> AutomationVersion:
    rep = validate(wf.draft_json, st.adapters, health)
    if not rep["valid"]:
        raise ServiceError(422, "INVALID_GRAPH", "fix the validation errors before publishing", {"errors": rep["errors"][:20]})
    h = content_hash(wf.draft_json)
    last = latest_version(db, wf.id)
    if last is not None and last.content_hash == h:
        return last                                                      # publishing an unchanged draft is a no-op, not a new version
    v = AutomationVersion(workflow_id=wf.id, revision=(last.revision + 1) if last else 1, definition_json=wf.draft_json, content_hash=h, created_by=actor, published_at=_now())
    db.add(v)
    db.flush()
    if wf.state == "draft":
        wf.state = "published"
    audit.record(db, "automation.published", actor=actor, case_id=wf.case_id, resource_id=wf.id,
                 metadata={"revision": v.revision, "hash": h[:16], "active_version_unchanged": bool(wf.active_version_id)})
    return v


def request_approval(db: Session, wf: AutomationWorkflow, version: AutomationVersion, st: Any, actor: str) -> list[AutomationApproval]:
    rep = validate(version.definition_json, st.adapters)
    d = Definition.model_validate(version.definition_json)
    need_confirm = sorted(a for a in rep["permissions"]["adapters"] if a in st.adapters and st.adapters[a].manifest.operation_class in ("public_site_query", "active"))
    scope = {"adapters": rep["permissions"]["adapters"], "network_mode": d.policy.network_mode, "needs_confirmation": need_confirm,
             "trigger": d.trigger.model_dump(), "max_requests": d.policy.max_requests_per_provider_per_run, "risk": "high" if rep["permissions"]["active"] else "medium" if rep["permissions"]["network"] else "low"}
    out = []
    kinds = ["activation"] + (["collection"] if (d.policy.network_mode == "active_with_approval" or need_confirm) else [])
    for kind in kinds:
        existing = db.scalars(select(AutomationApproval).where(AutomationApproval.workflow_id == wf.id, AutomationApproval.version_id == version.id,
                                                               AutomationApproval.kind == kind, AutomationApproval.status == "pending")).first()
        if existing:
            out.append(existing)
            continue
        a = AutomationApproval(workflow_id=wf.id, version_id=version.id, kind=kind, action_scope_json=scope, status="pending")
        db.add(a)
        out.append(a)
    db.flush()
    audit.record(db, "automation.approval_requested", actor=actor, case_id=wf.case_id, resource_id=wf.id, metadata={"version": version.revision, "kinds": kinds})
    return out


def decide_approval(db: Session, a: AutomationApproval, wf: AutomationWorkflow, *, approve: bool, by: str, expires_in_days: int, confirmed_adapters: list[str],
                    authorization_id: str | None) -> AutomationApproval:
    if a.status != "pending":
        raise ServiceError(409, "ALREADY_DECIDED", f"this approval is already {a.status}")
    if not approve:
        a.status, a.approver_id = "rejected", by
        audit.record(db, "automation.approval_rejected", actor=by, case_id=wf.case_id, resource_id=wf.id, metadata={"kind": a.kind})
        return a
    if not 1 <= expires_in_days <= 365:
        raise ServiceError(422, "INVALID", "an approval must expire within 1-365 days")
    scope = dict(a.action_scope_json or {})
    bad = sorted(set(confirmed_adapters) - set(scope.get("needs_confirmation", [])))
    if bad:
        raise ServiceError(422, "INVALID", f"{', '.join(bad)} do not need (or are not part of) this confirmation")
    if a.kind == "collection":
        missing = sorted(set(scope.get("needs_confirmation", [])) - set(confirmed_adapters))
        if missing:
            raise ServiceError(422, "APPROVAL_REQUIRED", f"tick the confirmation for: {', '.join(missing)}")
        if scope.get("network_mode") == "active_with_approval":
            auth = db.get(ScopeAuthorization, authorization_id) if authorization_id else None
            if auth is None or auth.case_id != wf.case_id or auth not in policy.active_authorizations(db, wf.case_id or ""):
                raise ServiceError(422, "SCOPE_DENIED", "active collection needs a current scope authorization for this case")
            a.authorization_id = auth.id
            exp_auth = permissions.aware(auth.expires_at)
            if exp_auth is not None:
                expires = min(_now() + timedelta(days=expires_in_days), exp_auth)         # never outlives the authorization it rests on
                a.expires_at = expires
    a.status, a.approver_id, a.approved_at = "approved", by, _now()
    a.expires_at = a.expires_at or (_now() + timedelta(days=expires_in_days))
    a.action_scope_json = scope | {"confirmed_adapters": sorted(confirmed_adapters)}
    audit.record(db, "automation.approval_granted", actor=by, case_id=wf.case_id, resource_id=wf.id,
                 metadata={"kind": a.kind, "expires": a.expires_at.isoformat() if a.expires_at else None, "version": a.version_id})
    return a


def revoke_approval(db: Session, a: AutomationApproval, wf: AutomationWorkflow, by: str) -> None:
    a.status, a.revoked_at = "revoked", _now()
    if a.kind == "activation" and wf.active_version_id == a.version_id:
        deactivate(db, wf, by, reason="activation approval revoked")
    audit.record(db, "automation.approval_revoked", actor=by, case_id=wf.case_id, resource_id=wf.id, metadata={"kind": a.kind})


def activate(db: Session, wf: AutomationWorkflow, version: AutomationVersion, st: Any, by: str, health: dict[str, str] | None = None) -> AutomationTrigger | None:
    d = Definition.model_validate(version.definition_json)
    if d.trigger.type not in ("schedule", "event"):
        raise ServiceError(422, "INVALID", f"nothing to activate: this workflow's trigger is {d.trigger.type!r}. Run it by hand instead.")
    rep = validate(version.definition_json, st.adapters, health, for_activation=True)
    if not rep["valid"]:
        raise ServiceError(422, rep["errors"][0]["code"], "this version cannot be activated", {"errors": rep["errors"][:10]})
    if permissions.valid_approval(db, wf.id, version.id, "activation") is None:
        raise ServiceError(403, "APPROVAL_REQUIRED", "an unexpired activation approval for this exact version is required")
    needs_collection = d.policy.network_mode == "active_with_approval" or any(
        a in st.adapters and st.adapters[a].manifest.operation_class in ("public_site_query", "active") for a in rep["permissions"]["adapters"])
    if needs_collection and permissions.valid_approval(db, wf.id, version.id, "collection") is None:
        raise ServiceError(403, "APPROVAL_REQUIRED", "this version also needs a separate, unexpired collection approval")
    if wf.case_id is None:
        raise ServiceError(422, "INVALID", "a scheduled workflow must belong to a case (its evidence has to go somewhere)")
    for t in db.scalars(select(AutomationTrigger).where(AutomationTrigger.workflow_id == wf.id, AutomationTrigger.enabled.is_(True))):
        t.enabled = False
    nxt = None
    if d.trigger.type == "schedule":
        spec, tz = cron.validate(d.trigger.schedule or "", d.trigger.timezone)
        nxt = cron.next_fire(spec, _now(), tz)
    trig = AutomationTrigger(workflow_id=wf.id, version_id=version.id, type=d.trigger.type, schedule=d.trigger.schedule, timezone=d.trigger.timezone, enabled=True,
                             missed_run_policy=d.trigger.missed_run_policy, next_due_at=nxt, config_json={"event": d.trigger.event, "last_seen": _now().isoformat()})
    db.add(trig)
    wf.active_version_id, wf.state = version.id, "active"
    audit.record(db, "automation.activated", actor=by, case_id=wf.case_id, resource_id=wf.id, metadata={"revision": version.revision, "next_due": nxt.isoformat() if nxt else None})
    return trig


def deactivate(db: Session, wf: AutomationWorkflow, by: str, reason: str = "user") -> None:
    for t in db.scalars(select(AutomationTrigger).where(AutomationTrigger.workflow_id == wf.id, AutomationTrigger.enabled.is_(True))):
        t.enabled = False
    wf.active_version_id, wf.state = None, "disabled" if latest_version(db, wf.id) else "draft"
    audit.record(db, "automation.deactivated", actor=by, case_id=wf.case_id, resource_id=wf.id, metadata={"reason": reason})
