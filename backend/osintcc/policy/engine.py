"""Policy engine: decides, independently of any UI or AI, whether an adapter may run on a target (spec 12.2)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import ScopeAuthorization

PASSIVE_CLASSES = {"passive", "local_only"}


@dataclass
class Decision:
    allowed: bool
    reason: str
    requires_confirmation: bool = False
    warnings: list[str] = field(default_factory=list)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def active_authorizations(db: Session, case_id: str, now: datetime | None = None) -> list[ScopeAuthorization]:
    now = now or datetime.now(UTC)
    rows = db.scalars(select(ScopeAuthorization).where(ScopeAuthorization.case_id == case_id)).all()
    out = []
    for r in rows:
        exp = _aware(r.expires_at)
        if r.revoked_at is None and (exp is None or exp > now):
            out.append(r)
    return out


def covers(scope_value: str, domain_or_value: str) -> bool:
    import ipaddress
    s, v = scope_value.lower().lstrip("*."), domain_or_value.lower()
    try:  # IP / CIDR scopes
        net = ipaddress.ip_network(s, strict=False)
        return ipaddress.ip_address(v) in net
    except ValueError:
        pass
    return v == s or v.endswith("." + s)


def has_active_authorization(db: Session, case_id: str, target_canonical: str, target_domain: str | None) -> bool:
    return any("active" in (a.allowed_classes_json or []) and (covers(a.scope_value, target_canonical)
                                                               or (target_domain and covers(a.scope_value, target_domain)))
               for a in active_authorizations(db, case_id))


def evaluate(db: Session, *, case_id: str, manifest, target_canonical: str, target_domain: str | None,
             mode: str, offline: bool) -> Decision:
    """`manifest` is an AdapterManifest. Enforced at plan time AND again at execution time."""
    if manifest.needs_network and offline:
        return Decision(False, "offline mode: network adapters are paused")
    cls = manifest.operation_class
    if cls in PASSIVE_CLASSES:
        return Decision(True, "passive source")
    if cls == "public_site_query":
        if mode not in ("passive", "public_site_query", "active"):
            return Decision(False, "mode does not allow public-site queries")
        return Decision(True, "queries third-party public sites; explicit confirmation required",
                        requires_confirmation=True,
                        warnings=["Tool contacts many public websites using the supplied handle."])
    if cls == "active":
        if mode != "active":
            return Decision(False, "active adapters need mode=active")
        auths = [a for a in active_authorizations(db, case_id)
                 if "active" in (a.allowed_classes_json or [])
                 and (covers(a.scope_value, target_canonical)
                      or (target_domain and covers(a.scope_value, target_domain)))]
        if not auths:
            return Decision(False, "no valid scope authorization covers this target for active assessment")
        return Decision(True, f"authorized by {auths[0].authorized_by}", requires_confirmation=True)
    return Decision(False, f"unknown operation class {cls}")
