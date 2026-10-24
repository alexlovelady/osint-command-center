"""Search planning (preview) and run creation. Nothing touches the network here."""
from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.base import IntelAdapter
from ..config import Settings
from ..db.models import Case, Job, SearchRun, Target
from ..policy import engine as policy
from ..policy.ssrf import ip_is_public
from ..policy.targets import ParsedTarget, detect_target, domain_of
from ..telemetry import audit


class PlanError(Exception):
    pass


def get_or_create_target(db: Session, case: Case, parsed: ParsedTarget) -> Target:
    t = db.scalars(select(Target).where(Target.case_id == case.id, Target.type == parsed.type,
                                        Target.canonical_value == parsed.canonical)).first()
    if t:
        return t
    t = Target(case_id=case.id, type=parsed.type, raw_input=parsed.raw, canonical_value=parsed.canonical)
    db.add(t)
    db.flush()
    audit.record(db, "target.create", case_id=case.id, resource_type="target", resource_id=t.id,
                 metadata={"type": parsed.type})
    return t


_LOCAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home.arpa", ".corp")


def _reject_non_public_target(parsed: ParsedTarget, dom: str | None, settings: Settings) -> None:
    """Private/loopback/reserved targets are not valid external collection targets (SSRF defence at plan time)."""
    if settings.allow_private_destinations:
        return
    host = None
    if parsed.type == "ip":
        host = parsed.canonical
    elif parsed.type == "url":
        host = urlsplit(parsed.canonical).hostname
    if host:
        try:
            ipaddress.ip_address(host)
            if not ip_is_public(host):
                raise PlanError(f"{host} is a private/loopback/reserved address and cannot be an external target")
        except ValueError:
            pass
    name = dom or ""
    if name == "localhost" or name.endswith(_LOCAL_SUFFIXES):
        raise PlanError(f"{name} is a local/internal name and cannot be an external target")


def build_plan(db: Session, case: Case, parsed: ParsedTarget, adapters: dict[str, IntelAdapter],
               settings: Settings, selected: list[str] | None = None, mode: str = "passive") -> dict[str, Any]:
    if case.category in ("people", "identity") and not case.purpose.strip():
        raise PlanError("A documented purpose is required for public-identity cases.")
    dom = domain_of(parsed.type, parsed.canonical)
    if not policy.has_active_authorization(db, case.id, parsed.canonical, dom):
        _reject_non_public_target(parsed, dom, settings)  # authorised owners may target their own private ranges
    if selected is not None:
        unknown = [a for a in selected if a not in adapters]
        if unknown:
            raise PlanError(f"unknown adapter(s): {', '.join(unknown)} (not installed, disabled or quarantined)")
    steps, warnings = [], []
    for aid, ad in adapters.items():
        m = ad.manifest
        if selected is not None and aid not in selected:
            continue
        if parsed.type not in m.supported_target_types:
            if selected is not None:
                steps.append({"adapter_id": aid, "name": m.name, "runnable": False,
                              "reason": f"does not support target type {parsed.type}"})
            continue
        d = policy.evaluate(db, case_id=case.id, manifest=m, target_canonical=parsed.canonical, target_domain=dom,
                            mode=mode, offline=settings.offline)
        if selected is None and (m.operation_class in ("public_site_query", "active") or not d.allowed):
            continue  # shown only when asked for explicitly (they need confirmation / authorization)
        steps.append({"adapter_id": aid, "name": m.name, "operation_class": m.operation_class,
                      "runnable": d.allowed, "reason": d.reason, "requires_confirmation": d.requires_confirmation,
                      "endpoints": m.endpoints, "needs_network": m.needs_network, "license": m.license,
                      "rate_limit_per_minute": m.rate_limit_per_minute, "warnings": d.warnings, "cost": "free", "default_selected": m.default_selected})
        warnings.extend(d.warnings)
    return {"target": parsed.as_dict(), "mode": mode, "steps": steps, "warnings": sorted(set(warnings)),
            "explicit": selected is not None,
            "offline": settings.offline,
            "note": "Nothing has been sent. Confirm to launch; each request is recorded with provenance."}


def create_run(db: Session, case: Case, parsed: ParsedTarget, plan: dict, *, confirmed: list[str],
               mode: str = "passive") -> SearchRun:
    runnable = [s for s in plan["steps"] if s["runnable"] and (plan.get("explicit") or s.get("default_selected", True))]
    unconfirmed = [s["adapter_id"] for s in runnable if s.get("requires_confirmation")
                   and s["adapter_id"] not in confirmed]
    if unconfirmed:
        raise PlanError(f"explicit confirmation required for: {', '.join(unconfirmed)}")
    if not runnable:
        raise PlanError("no runnable adapters in this plan")
    target = get_or_create_target(db, case, parsed)
    run = SearchRun(case_id=case.id, target_id=target.id, mode=mode,
                    selected_adapters_json=[s["adapter_id"] for s in runnable], status="queued",
                    permission_snapshot_json={"steps": [{k: s[k] for k in ("adapter_id", "operation_class", "reason")}
                                                        for s in runnable], "confirmed": confirmed})
    db.add(run)
    db.flush()
    for s in runnable:
        db.add(Job(run_id=run.id, adapter_id=s["adapter_id"], idempotency_key=f"{run.id}:{s['adapter_id']}"))
    audit.record(db, "search.launch", case_id=case.id, resource_type="search_run", resource_id=run.id,
                 metadata={"adapters": run.selected_adapters_json, "target_type": parsed.type})
    db.flush()
    return run


def preview(db: Session, case: Case, raw: str, explicit_type: str | None, adapters, settings, selected=None,
            mode="passive"):
    parsed = detect_target(raw, explicit_type)
    return parsed, build_plan(db, case, parsed, adapters, settings, selected, mode)
