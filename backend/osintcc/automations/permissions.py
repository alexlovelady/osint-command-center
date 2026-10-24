"""Hard enforcement outside the model: scope, approvals and run gates. Everything here is deterministic and runs at EXECUTION time, for every
network call, not just when a workflow is generated or activated."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AutomationApproval, AutomationWorkflow, Case, ScopeAuthorization
from ..policy import engine as policy
from ..policy.targets import ParsedTarget, TargetError, detect_target, domain_of
from ..search import service
from .registry import NodeError


def aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=UTC) if d is not None and d.tzinfo is None else d


def check_target(db: Session, case: Case, raw: str, type_hint: str | None, settings: Any, *, mode: str = "passive_only",
                 manifest: Any = None, now: datetime | None = None) -> ParsedTarget:
    """Resolve and authorise one target. Raises NodeError(SCOPE_DENIED | SCOPE_EXPIRED | OFFLINE). Never widens: a redirect, a discovered
    subdomain or a rebinding hostname arrives here as a NEW target and is judged on its own."""
    now = now or datetime.now(UTC)
    if not isinstance(raw, str) or not raw.strip():
        raise NodeError("SCOPE_DENIED", "the target is empty")
    try:
        parsed = detect_target(raw, type_hint)
    except TargetError as exc:
        raise NodeError("SCOPE_DENIED", f"invalid target: {exc}") from exc
    dom = domain_of(parsed.type, parsed.canonical)
    authorised = policy.has_active_authorization(db, case.id, parsed.canonical, dom)
    if mode == "active":
        if not authorised:
            expired = [a for a in db.scalars(select(ScopeAuthorization).where(ScopeAuthorization.case_id == case.id))
                       if "active" in (a.allowed_classes_json or []) and (policy.covers(a.scope_value, parsed.canonical) or (dom and policy.covers(a.scope_value, dom)))]
            if expired:
                raise NodeError("SCOPE_EXPIRED", f"the authorization covering {parsed.canonical} has expired or was revoked; renew it before active collection")
            raise NodeError("SCOPE_DENIED", f"no scope authorization permits active collection against {parsed.canonical}")
    if not authorised:
        try:
            service._reject_non_public_target(parsed, dom, settings)
        except service.PlanError as exc:
            raise NodeError("SCOPE_DENIED", str(exc)) from exc
    if manifest is not None and manifest.needs_network and getattr(settings, "offline", False):
        raise NodeError("OFFLINE", "offline mode is on; network steps pause")
    return parsed


def check_public_only(raw: str, type_hint: str | None, settings: Any) -> ParsedTarget:
    """Case-less variant for dry runs: well-formed and public, nothing more."""
    try:
        parsed = detect_target(raw, type_hint)
    except TargetError as exc:
        raise NodeError("SCOPE_DENIED", f"invalid target: {exc}") from exc
    try:
        service._reject_non_public_target(parsed, domain_of(parsed.type, parsed.canonical), settings)
    except service.PlanError as exc:
        raise NodeError("SCOPE_DENIED", str(exc)) from exc
    return parsed


def valid_approval(db: Session, workflow_id: str, version_id: str, kind: str, now: datetime | None = None) -> AutomationApproval | None:
    now = now or datetime.now(UTC)
    for a in db.scalars(select(AutomationApproval).where(AutomationApproval.workflow_id == workflow_id, AutomationApproval.version_id == version_id,
                                                         AutomationApproval.kind == kind, AutomationApproval.status == "approved")
                        .order_by(AutomationApproval.approved_at.desc())):
        exp = aware(a.expires_at)
        if a.revoked_at is None and exp is not None and exp > now:
            return a
    return None


def run_gate(db: Session, wf: AutomationWorkflow, version_id: str | None, trigger_type: str, network_mode: str, case: Case | None,
             now: datetime | None = None) -> dict[str, Any]:
    """Decide whether a (non-dry) run may start. Returns {'confirmed_adapters': [...]} or raises NodeError."""
    now = now or datetime.now(UTC)
    if case is None:
        raise NodeError("SCOPE_DENIED", "the run has no case to put evidence in")
    if case.status != "open":
        raise NodeError("SCOPE_DENIED", f"the case is {case.status}; collection needs an open case")
    out: dict[str, Any] = {"confirmed_adapters": []}
    if version_id is None:
        raise NodeError("APPROVAL_REQUIRED", "only published versions can run for real; dry-run the draft or publish it")
    if trigger_type != "manual":
        if wf.active_version_id != version_id or wf.state != "active":
            raise NodeError("APPROVAL_REQUIRED", "this version is not the active one; scheduled and event runs need an activated version")
        if valid_approval(db, wf.id, version_id, "activation", now) is None:
            raise NodeError("APPROVAL_REQUIRED", "the activation approval for this version is missing or has expired")
    if network_mode == "active_with_approval":
        a = valid_approval(db, wf.id, version_id, "collection", now)
        if a is None:
            raise NodeError("APPROVAL_REQUIRED", "this workflow performs active collection; a separate, unexpired collection approval is required")
        out["confirmed_adapters"] = list((a.action_scope_json or {}).get("confirmed_adapters", []))
    else:
        a = valid_approval(db, wf.id, version_id, "collection", now)
        if a is not None:
            out["confirmed_adapters"] = list((a.action_scope_json or {}).get("confirmed_adapters", []))
    return out
