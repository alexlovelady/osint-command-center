"""DARKINT service: gate, preview, check, events, coverage, reviews, monitors, remediation, reports.

It reuses what exists: `profile.consent` (who may be researched, for which source class, until when), `profile.exposure` (indicators, descriptor screening),
`profile.lifecycle` (remediation tasks, retention) and the audit chain. It adds a provider framework and an incident/event layer, not a second breach database.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    Case,
    CaseMember,
    Evidence,
    ExposureCheck,
    ExposureEvent,
    ExposureMonitorConfig,
    ExposureReview,
    ExposureSource,
    RemediationTask,
    Setting,
    Subject,
    SubjectConsent,
    SubjectIdentifier,
)
from ..profile import consent, lifecycle
from ..profile.exposure import risk_for, validate_descriptor
from ..profile.normalize import mask_value
from ..telemetry import audit
from . import providers as prov
from .sanitize import CATEGORIES, categorize, group_key, parse_date, sanitize_text

STATES = ("unknown", "not_checked", "no_match_checked_sources", "match_reported")
STATE_LABEL = {"unknown": "Unknown", "not_checked": "Not checked", "no_match_checked_sources": "No match from checked sources", "match_reported": "Match reported"}
STATE_MEANING = {
    "unknown": "Checks were attempted but none completed, so nothing can be said.",
    "not_checked": "No provider has been asked about this identifier yet. This is not the same as no exposure.",
    "no_match_checked_sources": "The providers named below reported nothing at the times shown. That does not show the identifier was never exposed.",
    "match_reported": "At least one provider or source reported it. A report is a lead, not proof that data exists, is accurate or is still reachable.",
}
NOT_ASKED = ("blocked", "offline", "credential_missing", "unsupported")      # refusals before the provider was asked do not make a state "unknown": it is still "not checked"
REVIEW_STATUSES = ("acknowledged", "relevant", "not_relevant", "corroborated", "resolved", "accepted_risk")
ACTION_TYPES = ("mfa", "password_reset", "domain_hygiene", "takedown", "notify", "follow_up_check")
ACTION_TEXT = {
    "mfa": ("Turn on multi-factor authentication or passkeys on the affected accounts.", "high"),
    "password_reset": ("Change the password on the affected service and anywhere it was reused; use a unique password per account.", "high"),
    "domain_hygiene": ("Review the domain's email authentication (SPF, DKIM, DMARC), mailbox access and who can send as the domain.", "medium"),
    "takedown": ("Ask the host or the publisher to remove the material. Keep the request and any reply. Nothing is sent from this application.", "medium"),
    "notify": ("Tell the people or customers affected, following your legal duties. Nothing is sent from this application.", "medium"),
    "follow_up_check": ("Re-run the provider checks after the remediation to see whether the report persists.", "low"),
}
MAX_IMPORT_BYTES = 2 * 1024 * 1024
MAX_IMPORT_ROWS = 500


class DarkError(Exception):
    def __init__(self, code: str, message: str, status: int = 422):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=UTC)


# ---- keyed token (events are grouped by identifier without copying it) ------------------------------------------------------------------------
def _token(db: Session, kind: str, value: str) -> str:
    row = db.get(Setting, "darkint_token_key")
    if row is None:
        row = Setting(key="darkint_token_key", value_json=secrets.token_hex(32))
        db.add(row)
        db.flush()
    return hmac.new(bytes.fromhex(str(row.value_json)), f"{kind}\x00{value.casefold()}".encode(), hashlib.sha256).hexdigest()[:24]


# ---- providers ------------------------------------------------------------------------------------------------------------------------------
def mock_mode(db: Session) -> bool:
    row = db.get(Setting, "darkint_mock_mode")
    return bool(row and row.value_json is True)


def set_mock_mode(db: Session, on: bool, actor: str) -> None:
    db.merge(Setting(key="darkint_mock_mode", value_json=on))
    audit.record(db, "darkint.mock_mode", actor=actor, metadata={"on": on})


def source_view(db: Session, st: Any, spec: prov.ProviderSpec) -> dict[str, Any]:
    row = db.scalars(select(ExposureSource).where(ExposureSource.provider_id == spec.provider_id)).first()
    have_secret = bool(spec.secret_name and st.runner.ctx_factory().secret(spec.secret_name))
    s = prov.state_for(spec, enabled=bool(row and row.enabled), terms_ok=bool(row and row.terms_acknowledged_at), have_secret=have_secret, mock=mock_mode(db))
    return {**spec.public(), **s, "enabled": bool(row and row.enabled), "terms_acknowledged_at": row.terms_acknowledged_at if row else None, "credential_present": have_secret if spec.secret_name else None,
            "offline": st.settings.offline, "last_check": row.last_verification_json if row else {}}


def sources(db: Session, st: Any) -> list[dict[str, Any]]:
    return [source_view(db, st, s) for s in prov.PROVIDERS.values()]


def set_source(db: Session, provider_id: str, *, enabled: bool, acknowledge_terms: bool, actor: str) -> ExposureSource:
    spec = prov.PROVIDERS.get(provider_id)
    if spec is None:
        raise DarkError("not_found", "unknown provider", 404)
    if enabled and not spec.automated:
        raise DarkError("unsupported", f"{spec.name} has no automated integration here; use manual intake")
    row = db.scalars(select(ExposureSource).where(ExposureSource.provider_id == provider_id)).first() or ExposureSource(provider_id=provider_id)
    db.add(row)
    if enabled and not (acknowledge_terms or row.terms_acknowledged_at):
        raise DarkError("terms_required", f"read {spec.terms_url or 'the provider terms'} and confirm you may use {spec.name} this way ({spec.terms_note or 'terms apply'})")
    if acknowledge_terms and not row.terms_acknowledged_at:
        row.terms_acknowledged_at, row.terms_acknowledged_by = _now(), actor
    row.enabled, row.updated_at = enabled, _now()
    db.flush()
    audit.record(db, "darkint.source", actor=actor, resource_type="exposure_source", resource_id=provider_id, metadata={"enabled": enabled})
    return row


# ---- the gate -------------------------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Gate:
    allowed: bool
    code: str
    reason: str


def _live_consent(db: Session, subject: Subject, ident: SubjectIdentifier, now: datetime | None = None) -> SubjectConsent | None:
    d = consent.check(db, subject, "exposure_check", identifier_id=ident.id, now=now)
    return db.get(SubjectConsent, d.consent_id) if d.allowed and d.consent_id else None


def authorize(db: Session, st: Any, subject: Subject, ident: SubjectIdentifier, provider_id: str, *, domain_attested: bool = False, now: datetime | None = None) -> Gate:
    """Fail closed. Order: provider known -> operation exists for this kind -> provider usable -> person's consent for this class, identifier and provider -> domain control."""
    spec = prov.PROVIDERS.get(provider_id)
    if spec is None:
        return Gate(False, "UNSUPPORTED", "unknown provider")
    if ident.subject_id != subject.id or ident.status != "active":
        return Gate(False, "SCOPE_DENIED", "that identifier is not an active input of this subject")
    op = prov.operation_for(provider_id, ident.kind)
    if op is None:
        return Gate(False, "UNSUPPORTED", f"{spec.name} cannot check a {ident.kind} identifier")
    sv = source_view(db, st, spec)
    if sv["state"] == "manual_only":
        return Gate(False, "UNSUPPORTED", "this provider is manual only")
    if sv["state"] == "disabled":
        return Gate(False, "CREDENTIAL_MISSING" if "CREDENTIAL_MISSING" in sv["reason"] else "SCOPE_DENIED", sv["reason"])
    if st.settings.offline and sv["state"] == "live":
        return Gate(False, "OFFLINE", "offline mode is on: no provider is contacted")
    c = _live_consent(db, subject, ident, now)
    if c is None:
        d = consent.check(db, subject, "exposure_check", identifier_id=ident.id, now=now)
        return Gate(False, "SCOPE_DENIED", f"consent: {d.reason}")
    allowed_providers = (c.scope_json or {}).get("providers") or []
    if allowed_providers and provider_id not in allowed_providers:
        return Gate(False, "SCOPE_DENIED", f"the authorization does not permit {spec.name}")
    if op == "domain_breaches" and not domain_attested:
        return Gate(False, "SCOPE_DENIED", "a domain-wide lookup needs the domain to be verified with the provider first; confirm that you completed that verification")
    return Gate(True, "ok", "allowed")


def _ident(db: Session, subject: Subject, identifier_id: str) -> SubjectIdentifier:
    ident = db.get(SubjectIdentifier, identifier_id)
    if ident is None or ident.subject_id != subject.id:
        raise DarkError("not_found", "identifier not found on this subject", 404)
    return ident


def preview(db: Session, st: Any, subject: Subject, identifier_ids: list[str], provider_ids: list[str], *, domain_attested: bool = False) -> dict[str, Any]:
    rows = []
    for iid in identifier_ids[:20]:
        ident = _ident(db, subject, iid)
        for pid in provider_ids[:8]:
            spec = prov.PROVIDERS.get(pid)
            g = authorize(db, st, subject, ident, pid, domain_attested=domain_attested)
            op = prov.operation_for(pid, ident.kind)
            rows.append({"identifier_id": iid, "kind": ident.kind, "identifier": mask_value(ident.kind, ident.value), "provider_id": pid, "provider": spec.name if spec else pid, "operation": op,
                         "allowed": g.allowed, "code": g.code, "reason": g.reason,
                         "will_send": {"to": (spec.endpoints[0] if spec and spec.endpoints else "nothing (manual)"), "data": f"the {ident.kind} (shown masked here)", "credentials": "the provider API key is sent as a header" if spec and spec.secret_name else "none"},
                         "will_store": "Provider incident names, dates and data categories only. No passwords, hashes, tokens or leaked records are requested or kept.",
                         "terms_url": spec.terms_url if spec else "", "cost": spec.cost_tier if spec else "", "quota": spec.quota if spec else "", "terms_note": spec.terms_note if spec else "",
                         "mocked": mock_mode(db)})
    return {"items": rows, "runnable": sum(1 for r in rows if r["allowed"]), "note": "Nothing has been sent. 'Not checked' is never reported as 'no exposure'."}


# ---- events ---------------------------------------------------------------------------------------------------------------------------------
def _store_event(db: Session, subject: Subject, ident: SubjectIdentifier | None, provider_id: str, ev: prov.ProviderEvent, evidence_id: str | None, token: str, actor: str) -> tuple[ExposureEvent, bool]:
    title, red = sanitize_text(ev.title)
    dedupe = hashlib.sha256(f"{subject.case_id}|{subject.id}|{token}|{provider_id}|{ev.event_type}|{ev.incident_key}".encode()).hexdigest()
    cur = db.scalars(select(ExposureEvent).where(ExposureEvent.case_id == subject.case_id, ExposureEvent.dedupe_key == dedupe)).first()
    if cur is not None:
        cur.reported_last_seen = ev.last_seen or cur.reported_last_seen
        if evidence_id:
            cur.evidence_id = evidence_id
        return cur, False
    row = ExposureEvent(case_id=subject.case_id, subject_id=subject.id, identifier_id=ident.id if ident else None, identifier_token=token, provider_id=provider_id, event_type=ev.event_type,
                        incident_key=ev.incident_key[:160], group_key=group_key(title.removeprefix("Breach: ")), title=title, categories_json=[c for c in ev.categories if c in CATEGORIES],
                        reported_first_seen=ev.first_seen, reported_last_seen=ev.last_seen, claim_status=ev.claim_status, confidence=ev.confidence, evidence_id=evidence_id,
                        provider_ref=sanitize_text(ev.provider_ref, 300)[0], redacted=red or ev.redacted, dedupe_key=dedupe)
    db.add(row)
    db.flush()
    audit.record(db, "darkint.event", actor=actor, case_id=subject.case_id, resource_type="exposure_event", resource_id=row.id, metadata={"provider": provider_id, "type": ev.event_type})
    return row, True


def _evidence(db: Session, subject: Subject, provider_id: str, summary: list[dict[str, Any]], actor: str) -> str:
    raw = json.dumps(summary, sort_keys=True).encode()
    ev = Evidence(case_id=subject.case_id, kind="darkint.provider_summary", title=f"{prov.PROVIDERS[provider_id].name}: incident names, dates and data categories only",
                  sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest(), byte_size=len(raw), mime_type="application/json", retrieved_at=_now(), observed_at=_now(),
                  capture_method="provider_api", sensitivity="RESTRICTED", created_by=actor, description="Trimmed provider response. No leaked records, secrets or addresses.")
    db.add(ev)
    db.flush()
    return ev.id


def _mirror_indicator(db: Session, subject: Subject, ev_row: ExposureEvent, ev: prov.ProviderEvent, actor: str) -> None:
    """Breach events also appear as exposure indicators, so the existing Exposure tab, remediation and reports show them. One record per event."""
    if ev_row.indicator_id or ev.event_type != "breach":
        return
    try:
        from ..profile import exposure
        desc = validate_descriptor(f"{ev_row.title} ({(ev.first_seen or _now()).date()}); data types: {', '.join(ev_row.categories_json[:6])}"[:200])
        x = exposure.record(db, subject, cls="breach_account", provider="hibp" if ev_row.provider_id == "hibp" else "manual", status="confirmed_exposure",
                            risk=risk_for([c.replace("credential indicator", "passwords") for c in ev_row.categories_json], str(ev.first_seen.date()) if ev.first_seen else None),
                            descriptor=desc, basis="provider_api", actor=actor, exposure_date=ev.first_seen, evidence_id=ev_row.evidence_id)
        ev_row.indicator_id = x.id
    except Exception:       # a descriptor that cannot be screened is not mirrored; the event itself is already stored and redacted
        return


async def run_check(db: Session, st: Any, subject: Subject, identifier_ids: list[str], provider_ids: list[str], actor: str, *, domain_attested: bool = False, ctx: Any = None) -> dict[str, Any]:
    """Runs the allowed (identifier, provider) pairs one at a time. Every pair gets an ExposureCheck row, including refusals, so coverage is never inferred."""
    ctx = ctx or st.runner.ctx_factory()
    mock = mock_mode(db)
    results = []
    for iid in identifier_ids[:20]:
        ident = _ident(db, subject, iid)
        for pid in provider_ids[:8]:
            spec = prov.PROVIDERS.get(pid)
            g = authorize(db, st, subject, ident, pid, domain_attested=domain_attested)
            op = prov.operation_for(pid, ident.kind) or "none"
            if not g.allowed:
                outcome = {"CREDENTIAL_MISSING": "credential_missing", "OFFLINE": "offline", "UNSUPPORTED": "unsupported"}.get(g.code, "blocked")
                db.add(ExposureCheck(case_id=subject.case_id, subject_id=subject.id, identifier_id=ident.id, provider_id=pid, operation=op, outcome=outcome, detail=g.reason[:300], actor=actor))
                results.append({"identifier_id": iid, "provider_id": pid, "outcome": outcome, "code": g.code, "detail": g.reason, "events": 0})
                continue
            assert spec is not None
            last = db.scalars(select(ExposureCheck).where(ExposureCheck.subject_id == subject.id, ExposureCheck.provider_id == pid, ExposureCheck.outcome.in_(("match", "no_match", "rate_limited"))).order_by(ExposureCheck.checked_at.desc())).first()
            if spec.min_interval_s and not mock and last and (_now() - _aware(last.checked_at)).total_seconds() < spec.min_interval_s * prov.PACING_SCALE:   # type: ignore[operator]
                db.add(ExposureCheck(case_id=subject.case_id, subject_id=subject.id, identifier_id=ident.id, provider_id=pid, operation=op, outcome="rate_limited", detail="local pacing for this provider's rate limit", actor=actor))
                results.append({"identifier_id": iid, "provider_id": pid, "outcome": "rate_limited", "code": "RATE_LIMITED", "detail": f"{spec.name} allows about one request per {spec.min_interval_s}s; try again shortly.", "events": 0})
                continue
            out = await prov.run_provider(pid, op, ident.value, ctx, mock)
            ev_id = _evidence(db, subject, pid, out.summary, actor) if out.summary and out.outcome == "match" else None
            token = _token(db, ident.kind, ident.value)
            created = 0
            for pe in out.events:
                row, new = _store_event(db, subject, ident, pid, pe, ev_id, token, actor)
                created += int(new)
                if new:
                    _mirror_indicator(db, subject, row, pe, actor)
            db.add(ExposureCheck(case_id=subject.case_id, subject_id=subject.id, identifier_id=ident.id, provider_id=pid, operation=op, outcome=out.outcome, events_found=len(out.events), evidence_id=ev_id,
                                 detail=out.detail[:300], actor=actor))
            audit.record(db, "darkint.check", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id, metadata={"provider": pid, "outcome": out.outcome, "events": len(out.events), "mock": mock})
            results.append({"identifier_id": iid, "provider_id": pid, "outcome": out.outcome, "code": {"credential_missing": "CREDENTIAL_MISSING", "source_unavailable": "SOURCE_UNAVAILABLE", "rate_limited": "RATE_LIMITED",
                                                                                                   "unsupported": "UNSUPPORTED"}.get(out.outcome, "ok"), "detail": out.detail, "events": len(out.events), "new_events": created})
    db.flush()
    failed = [r for r in results if r["outcome"] not in ("match", "no_match")]
    return {"results": results, "partial": bool(failed) and len(failed) < len(results), "all_failed": bool(results) and len(failed) == len(results), "mock": mock,
            "note": "A failed or blocked check is not a negative result."}


# ---- coverage: four distinct states ---------------------------------------------------------------------------------------------------------
def event_dict(e: ExposureEvent, *, redact: bool = False) -> dict[str, Any]:
    out = {"id": e.id, "provider_id": e.provider_id, "provider": prov.PROVIDERS[e.provider_id].name if e.provider_id in prov.PROVIDERS else e.provider_id, "event_type": e.event_type,
           "title": "" if redact else e.title, "categories": e.categories_json, "first_seen": e.reported_first_seen, "last_seen": e.reported_last_seen, "claim_status": e.claim_status,
           "claim_label": {"reported": "reported, not independently verified", "corroborated": "corroborated by a second source", "disputed": "disputed", "retracted": "retracted"}.get(e.claim_status, e.claim_status),
           "confidence": e.confidence, "provider_ref": "" if redact else e.provider_ref, "evidence_id": e.evidence_id, "redacted": e.redacted, "group_key": e.group_key, "identifier_id": e.identifier_id,
           "caveat": "A reported listing is not proof of compromise." if e.event_type == "ransomware_listing" else "A report that data leaked is a lead, not proof the record exists, is accurate or is still reachable."}
    return out


def _live_events(db: Session, subject: Subject, identifier_id: str) -> list[ExposureEvent]:
    out = []
    for e in db.scalars(select(ExposureEvent).where(ExposureEvent.subject_id == subject.id, ExposureEvent.identifier_id == identifier_id)):
        if e.claim_status == "retracted":
            continue
        latest = db.scalars(select(ExposureReview).where(ExposureReview.event_id == e.id).order_by(ExposureReview.created_at.desc())).first()
        if latest and latest.status == "not_relevant":
            continue
        out.append(e)
    return out


def coverage(db: Session, st: Any, subject: Subject) -> dict[str, Any]:
    items = []
    idents = list(db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.status == "active")))
    for ident in idents:
        applicable = [p for p in prov.PROVIDERS.values() if prov.operation_for(p.provider_id, ident.kind)]
        if not applicable:
            continue
        evs = _live_events(db, subject, ident.id)
        per = []
        for spec in applicable:
            checks = list(db.scalars(select(ExposureCheck).where(ExposureCheck.subject_id == subject.id, ExposureCheck.identifier_id == ident.id, ExposureCheck.provider_id == spec.provider_id).order_by(ExposureCheck.checked_at.desc())))
            done = next((c for c in checks if c.outcome in ("match", "no_match")), None)
            n_events = sum(1 for e in evs if e.provider_id == spec.provider_id)
            if n_events:
                s = "match_reported"
            elif done:                                   # completed, and nothing reported remains relevant (either none was reported, or a reviewer dismissed it)
                s = "no_match_checked_sources"
            elif any(c.outcome not in NOT_ASKED for c in checks):
                s = "unknown"
            else:
                s = "not_checked"
            per.append({"provider_id": spec.provider_id, "provider": spec.name, "state": s, "checked_at": done.checked_at if done else (checks[0].checked_at if checks else None),
                        "last_outcome": checks[0].outcome if checks else None, "events": n_events})
        overall = ("match_reported" if any(p["state"] == "match_reported" for p in per) else "no_match_checked_sources" if any(p["state"] == "no_match_checked_sources" for p in per)
                   else "unknown" if any(p["state"] == "unknown" for p in per) else "not_checked")
        checked = [p for p in per if p["state"] == "no_match_checked_sources"]
        items.append({"identifier_id": ident.id, "kind": ident.kind, "identifier": mask_value(ident.kind, ident.value), "state": overall, "label": STATE_LABEL[overall], "meaning": STATE_MEANING[overall],
                      "providers": per, "checked_sources": [{"provider": p["provider"], "checked_at": p["checked_at"]} for p in checked] if overall == "no_match_checked_sources" else []})
    return {"items": items, "states": list(STATES), "labels": STATE_LABEL,
            "notice": "There is no universal 'not leaked' indicator: source opacity, indexing bias and reporting delays mean an absent report is not evidence of safety."}


def grouped_events(db: Session, subject: Subject, *, redact: bool = False) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[ExposureEvent]] = {}
    for e in db.scalars(select(ExposureEvent).where(ExposureEvent.subject_id == subject.id).order_by(ExposureEvent.created_at)):
        groups.setdefault((e.identifier_token, e.group_key or e.id), []).append(e)
    out = []
    for (_tok, key), evs in groups.items():
        firsts = [d for e in evs if (d := _aware(e.reported_first_seen))]
        lasts = [d for e in evs if (d := _aware(e.reported_last_seen))]
        first, last = (min(firsts) if firsts else None), (max(lasts) if lasts else None)
        latest = [db.scalars(select(ExposureReview).where(ExposureReview.event_id == e.id).order_by(ExposureReview.created_at.desc())).first() for e in evs]
        out.append({"group": key, "sources": sorted({e.provider_id for e in evs}), "events": [event_dict(e, redact=redact) for e in evs], "first_seen": first, "last_seen": last,
                    "categories": sorted({c for e in evs for c in e.categories_json}), "corroborated": len({e.provider_id for e in evs}) > 1,
                    "review_status": next((r.status for r in latest if r), "unreviewed"),
                    "note": "Reports from several sources are grouped for reading; each original report and its provenance is kept and auditable."})
    return out


# ---- reviews --------------------------------------------------------------------------------------------------------------------------------
def review(db: Session, event: ExposureEvent, *, status: str, rationale: str, action_items: list[str], reviewer: str) -> ExposureReview:
    if status not in REVIEW_STATUSES:
        raise DarkError("invalid_status", f"status must be one of {', '.join(REVIEW_STATUSES)}")
    if len(rationale.strip()) < 3:
        raise DarkError("rationale_required", "say why (it is recorded)")
    clean, _ = sanitize_text(rationale, 1000)
    items = [sanitize_text(a, 200)[0] for a in action_items[:10]]
    r = ExposureReview(event_id=event.id, reviewer=reviewer, status=status, rationale=clean, action_items_json=items)
    db.add(r)
    if status == "corroborated":
        event.claim_status = "corroborated"
    audit.record(db, "darkint.review", actor=reviewer, case_id=event.case_id, resource_type="exposure_event", resource_id=event.id, metadata={"status": status})
    db.flush()
    return r


# ---- manual intake and file import --------------------------------------------------------------------------------------------------------
def manual_event(db: Session, subject: Subject, *, identifier_id: str | None, title: str, event_type: str, categories: list[str], reported_at: str | None, source_url: str,
                 claim_status: str, provider: str, actor: str) -> ExposureEvent:
    if event_type not in ("breach", "paste", "darkweb_mention", "ransomware_listing", "advisory", "manual_report"):
        raise DarkError("invalid_event_type", "unknown event type")
    ident = _ident(db, subject, identifier_id) if identifier_id else None
    clean_title, red = sanitize_text(title)
    if len(clean_title) < 3:
        raise DarkError("title_required", "give the report a short title")
    url, _ = sanitize_text(source_url, 300)
    when = parse_date(reported_at)
    token = _token(db, ident.kind, ident.value) if ident else ""
    pe = prov.ProviderEvent(event_type, f"manual:{hashlib.sha256((clean_title + url).encode()).hexdigest()[:16]}", clean_title, categorize(categories), when, when, claim_status if claim_status in ("reported", "corroborated", "disputed") else "reported",
                            "low", url, red)
    row, _new = _store_event(db, subject, ident, provider if provider in prov.PROVIDERS else "manual", pe, None, token, actor)
    if red:
        row.redacted = True
    return row


def import_events(db: Session, subject: Subject, kind: str, content: bytes, identifier_id: str | None, actor: str) -> dict[str, Any]:
    """CSV (title,date,categories,reference), generic JSON list, or a MISP event export. The upload itself is never stored: only its hash, counts and the redacted events."""
    if len(content) > MAX_IMPORT_BYTES:
        raise DarkError("too_large", f"imports are limited to {MAX_IMPORT_BYTES // 1024} KiB")
    sha = hashlib.sha256(content).hexdigest()
    rows: list[dict[str, Any]] = []
    try:
        if kind == "csv":
            rows = list(csv.DictReader(io.StringIO(content.decode("utf-8", "replace"))))[:MAX_IMPORT_ROWS]
        elif kind == "json":
            data = json.loads(content)
            rows = [r for r in (data if isinstance(data, list) else data.get("items", [])) if isinstance(r, dict)][:MAX_IMPORT_ROWS]
        elif kind == "misp":
            data = json.loads(content)
            evs = data.get("response", data if isinstance(data, list) else [data])
            for e in evs[:MAX_IMPORT_ROWS]:
                ev = e.get("Event", e) if isinstance(e, dict) else {}
                tags = [t.get("name", "") for t in (ev.get("Tag") or []) if isinstance(t, dict)]
                tlp = next((t for t in tags if t.lower().startswith("tlp:")), "tlp:unspecified")
                # attributes are dropped: only the event's own title, date, info and TLP survive, so no indicator value can carry a secret into the case
                rows.append({"title": ev.get("info", ""), "date": ev.get("date", ""), "categories": [], "reference": f"misp:{str(ev.get('uuid', ''))[:36]}", "tlp": tlp})
        else:
            raise DarkError("invalid_kind", "kind must be csv, json or misp")
    except (ValueError, AttributeError) as exc:
        raise DarkError("unreadable_import", "the file could not be read as that format") from exc
    created = skipped = redacted = 0
    for r in rows:
        title = str(r.get("title") or r.get("name") or "")
        if len(title.strip()) < 3:
            skipped += 1
            continue
        cats = r.get("categories") or r.get("data_classes") or []
        cats = [c.strip() for c in cats.split(";")] if isinstance(cats, str) else [str(c) for c in cats]
        row = manual_event(db, subject, identifier_id=identifier_id, title=title if kind != "misp" else f"{title} [{r.get('tlp')}]", event_type="advisory" if kind == "misp" else "manual_report", categories=cats,
                           reported_at=str(r.get("date") or r.get("reported") or "") or None, source_url=str(r.get("reference") or r.get("url") or ""), claim_status="reported",
                           provider="misp" if kind == "misp" else "manual", actor=actor)
        created += 1
        redacted += int(row.redacted)
    audit.record(db, "darkint.import", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id, metadata={"kind": kind, "rows": len(rows), "created": created, "sha256": sha[:16]})
    return {"rows": len(rows), "created": created, "skipped": skipped, "redacted": redacted, "upload_sha256": sha,
            "note": "The uploaded file was not stored. Anything that looked like a secret, a number or an address was redacted before indexing."}


# ---- monitors ---------------------------------------------------------------------------------------------------------------------------------
def create_monitor(db: Session, st: Any, subject: Subject, *, name: str, identifier_ids: list[str], provider_ids: list[str], cadence_hours: int, expires_at: datetime, actor: str) -> ExposureMonitorConfig:
    if not 24 <= cadence_hours <= 720:
        raise DarkError("invalid_cadence", "cadence is between 24 hours and 30 days")
    if not identifier_ids or not provider_ids:
        raise DarkError("scope_required", "name at least one identifier and one provider")
    exp = _aware(expires_at)
    assert exp is not None
    if exp <= _now() or exp > _now() + timedelta(days=365):
        raise DarkError("invalid_expiry", "a monitor must expire in the future and within 365 days")
    cid = None
    for iid in identifier_ids:
        ident = _ident(db, subject, iid)
        for pid in provider_ids:
            spec = prov.PROVIDERS.get(pid)
            if spec is None or not spec.monitorable:
                raise DarkError("not_monitorable", f"{pid} cannot be scheduled (password checks and manual sources are owner-initiated only)")
            if prov.operation_for(pid, ident.kind) is None:
                raise DarkError("unsupported", f"{spec.name} cannot check a {ident.kind} identifier")
            c = _live_consent(db, subject, ident)
            if c is None:
                raise DarkError("consent_required", "scheduled monitoring needs a live, verified authorization that covers this identifier")
            if (c.scope_json or {}).get("providers") and pid not in c.scope_json["providers"]:
                raise DarkError("provider_not_permitted", f"the authorization does not permit {spec.name}")
            if prov.operation_for(pid, ident.kind) == "domain_breaches":
                raise DarkError("domain_monitor_unsupported", "domain-wide breach lookups are run by hand after domain verification, not scheduled")
            cid = c.id
            if _aware(c.expires_at) and exp > _aware(c.expires_at):    # type: ignore[operator]
                exp = _aware(c.expires_at)
    m = ExposureMonitorConfig(case_id=subject.case_id, subject_id=subject.id, name=name.strip()[:120] or "Monitor", identifier_ids_json=list(identifier_ids), providers_json=list(provider_ids),
                              cadence_hours=cadence_hours, consent_id=cid, expires_at=exp, enabled=False, created_by=actor)
    db.add(m)
    db.flush()
    audit.record(db, "darkint.monitor_create", actor=actor, case_id=subject.case_id, resource_type="exposure_monitor", resource_id=m.id, metadata={"providers": provider_ids, "cadence_hours": cadence_hours})
    return m


def set_monitor(db: Session, st: Any, m: ExposureMonitorConfig, subject: Subject, enabled: bool, actor: str) -> ExposureMonitorConfig:
    if enabled:
        if _aware(m.expires_at) <= _now():      # type: ignore[operator]
            raise DarkError("monitor_expired", "this monitor has expired; create a new one")
        for iid in m.identifier_ids_json:
            ident = _ident(db, subject, iid)
            for pid in m.providers_json:
                g = authorize(db, st, subject, ident, pid)
                if not g.allowed and g.code != "OFFLINE":
                    raise DarkError("consent_required" if g.code == "SCOPE_DENIED" else "unavailable", g.reason)
        m.disabled_reason = ""
    else:
        m.disabled_reason = "turned off by a person"
    m.enabled = enabled
    audit.record(db, "darkint.monitor_set", actor=actor, case_id=m.case_id, resource_type="exposure_monitor", resource_id=m.id, metadata={"enabled": enabled})
    return m


def disable_monitors(db: Session, subject: Subject, why: str) -> int:
    """Registered on consent revocation/expiry: monitors stop at once and say why."""
    n = 0
    for m in db.scalars(select(ExposureMonitorConfig).where(ExposureMonitorConfig.subject_id == subject.id, ExposureMonitorConfig.enabled.is_(True))):
        m.enabled, m.disabled_reason = False, why[:200]
        n += 1
    return n


consent.REVOKE_HOOKS.append(disable_monitors)


async def run_monitor(db: Session, st: Any, m: ExposureMonitorConfig, actor: str, *, force: bool = False, ctx: Any = None) -> dict[str, Any]:
    subject = db.get(Subject, m.subject_id)
    if subject is None:
        return {"ran": False, "reason": "SCOPE_DENIED: the subject no longer exists", "results": []}
    if not m.enabled:
        return {"ran": False, "reason": "SCOPE_DENIED: this monitor is switched off" + (f" ({m.disabled_reason})" if m.disabled_reason else ""), "results": []}
    if _aware(m.expires_at) <= _now():      # type: ignore[operator]
        m.enabled, m.disabled_reason = False, "expired"
        return {"ran": False, "reason": "SCOPE_DENIED: this monitor has expired", "results": []}
    if not force and m.last_run_at and _now() - _aware(m.last_run_at) < timedelta(hours=m.cadence_hours):    # type: ignore[operator]
        return {"ran": False, "reason": f"not due yet (cadence {m.cadence_hours}h)", "results": []}
    out = await run_check(db, st, subject, list(m.identifier_ids_json), list(m.providers_json), actor, ctx=ctx)
    m.last_run_at, m.last_outcome_json = _now(), {"results": [{k: r[k] for k in ("provider_id", "outcome", "events")} for r in out["results"]]}
    if any(r["code"] == "SCOPE_DENIED" for r in out["results"]):
        m.enabled, m.disabled_reason = False, "authorization no longer covers this scope"
    return {"ran": True, **out}


# ---- remediation ------------------------------------------------------------------------------------------------------------------------------
def suggest_actions(e: ExposureEvent) -> list[str]:
    acts: list[str] = []
    cats = set(e.categories_json)
    if "credential indicator" in cats:
        acts += ["password_reset", "mfa"]
    if e.event_type == "ransomware_listing":
        acts += ["notify", "domain_hygiene"]
    if e.event_type in ("paste", "darkweb_mention", "manual_report"):
        acts.append("takedown")
    if cats & {"email addresses", "phone numbers", "physical addresses", "names"} and "notify" not in acts:
        acts.append("notify")
    acts.append("follow_up_check")
    return list(dict.fromkeys(acts))


def create_remediation(db: Session, subject: Subject, event: ExposureEvent, action_type: str, actor: str) -> RemediationTask:
    if action_type not in ACTION_TYPES:
        raise DarkError("invalid_action", f"action must be one of {', '.join(ACTION_TYPES)}")
    dup = db.scalars(select(RemediationTask).where(RemediationTask.exposure_event_id == event.id, RemediationTask.action_type == action_type, RemediationTask.state.in_(("open", "in_progress")))).first()
    if dup:
        return dup
    text, prio = ACTION_TEXT[action_type]
    t = lifecycle.create_remediation(db, subject, issue=f"{action_type.replace('_', ' ').capitalize()}: {event.title}"[:300], priority=prio, guidance=text, owner=None,
                                     due_in_days=14, indicator_id=event.indicator_id, actor=actor)
    t.exposure_event_id, t.action_type = event.id, action_type
    return t


# ---- dashboard and report -----------------------------------------------------------------------------------------------------------------
def dashboard(db: Session, user: str) -> dict[str, Any]:
    """Across the cases this person may edit. Counts and labels only: no identifier, title or reference leaves its case here."""
    cases = [m.case_id for m in db.scalars(select(CaseMember).where(CaseMember.user_id == user, CaseMember.access_role.in_(("owner", "editor"))))]
    rows = []
    totals = {s: 0 for s in STATES}
    for cid in cases:
        case = db.get(Case, cid)
        for s in db.scalars(select(Subject).where(Subject.case_id == cid, Subject.status == "active")):
            ids = list(db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == s.id, SubjectIdentifier.status == "active")))
            if not ids and not db.scalar(select(func.count()).select_from(ExposureEvent).where(ExposureEvent.subject_id == s.id)):
                continue
            states = {k: 0 for k in STATES}
            for ident in ids:
                if not any(prov.operation_for(p, ident.kind) for p in prov.PROVIDERS):
                    continue
                evs = _live_events(db, s, ident.id)
                checks = list(db.scalars(select(ExposureCheck).where(ExposureCheck.subject_id == s.id, ExposureCheck.identifier_id == ident.id)))
                st_ = "match_reported" if evs else "no_match_checked_sources" if any(c.outcome in ("match", "no_match") for c in checks) else "unknown" if any(c.outcome not in NOT_ASKED for c in checks) else "not_checked"
                states[st_] += 1
                totals[st_] += 1
            unreviewed = 0
            for e in db.scalars(select(ExposureEvent).where(ExposureEvent.subject_id == s.id)):
                if db.scalar(select(func.count()).select_from(ExposureReview).where(ExposureReview.event_id == e.id)) == 0:
                    unreviewed += 1
            mons = list(db.scalars(select(ExposureMonitorConfig).where(ExposureMonitorConfig.subject_id == s.id)))
            last = db.scalar(select(func.max(ExposureCheck.checked_at)).where(ExposureCheck.subject_id == s.id))
            rows.append({"case_id": cid, "case": case.title if case else "", "subject_id": s.id, "subject": s.display_name, "mode": s.mode, "states": states, "unreviewed_events": unreviewed,
                         "open_remediation": db.scalar(select(func.count()).select_from(RemediationTask).where(RemediationTask.subject_id == s.id, RemediationTask.exposure_event_id.is_not(None), RemediationTask.state.in_(("open", "in_progress")))) or 0,
                         "monitors_active": sum(1 for m in mons if m.enabled), "monitors_stopped": sum(1 for m in mons if not m.enabled and m.disabled_reason), "last_checked": last})
    return {"items": rows, "totals": totals, "labels": STATE_LABEL, "notice": "'Not checked' and 'Unknown' are not 'No exposure'. Open a profile to see which providers were asked and when."}


def report(db: Session, st: Any, subject: Subject) -> dict[str, Any]:
    case = db.get(Case, subject.case_id)
    cov = coverage(db, st, subject)
    groups = grouped_events(db, subject)
    tasks = [t for t in db.scalars(select(RemediationTask).where(RemediationTask.subject_id == subject.id, RemediationTask.exposure_event_id.is_not(None)))]
    return {"kind": "darkint_report", "generated_at": _now().isoformat(), "case": case.title if case else "", "subject": {"label": subject.display_name, "mode": subject.mode},
            "coverage": cov["items"], "incidents": groups, "remediation": [{"action": t.action_type, "issue": t.issue, "state": t.state, "priority": t.priority, "due_at": t.due_at} for t in tasks],
            "limitations": ["Reports describe what providers said, not what exists. A report that data leaked is a lead, not proof that the full record exists, is accurate or remains accessible.",
                            "Absence of a report is not evidence of safety: sources are opaque, indexing is biased and reporting is delayed.",
                            "A ransomware-victim listing is a claim by the actor and is not independent proof of compromise.",
                            "No passwords, hashes, tokens, identity documents, card numbers or leaked records are held or shown here."],
            "sources": [{"provider": p["name"], "terms": p["terms_url"], "verification": p["verification"]} for p in (prov.PROVIDERS[k].public() for k in prov.PROVIDERS)]}


def report_markdown(r: dict[str, Any]) -> str:
    out = [f"# Exposure assessment: {r['subject']['label']}", "", f"Case: {r['case']}. Generated {r['generated_at']}. Mode: {r['subject']['mode']}.", "", "## Coverage", ""]
    for c in r["coverage"]:
        out.append(f"- **{c['identifier']}** ({c['kind']}): **{c['label']}**. {c['meaning']}")
        for p in c["providers"]:
            out.append(f"  - {p['provider']}: {STATE_LABEL[p['state']]}" + (f" (checked {p['checked_at']})" if p["checked_at"] else ""))
    out += ["", "## Reported incidents", ""]
    for g in r["incidents"]:
        out.append(f"- {', '.join(g['categories']) or 'category not stated'}; sources: {', '.join(g['sources'])}; first reported {g['first_seen'] or 'unknown'}; review: {g['review_status']}")
        for e in g["events"]:
            out.append(f"  - {e['title']} ({e['provider']}; {e['claim_label']}; confidence {e['confidence']}) {e['provider_ref']}")
    if not r["incidents"]:
        out.append("- No incidents were reported by the sources that were checked.")
    out += ["", "## Suggested actions", ""] + ([f"- [{t['state']}] {t['issue']} (priority {t['priority']})" for t in r["remediation"]] or ["- None recorded."])
    out += ["", "## Limitations", ""] + [f"- {x}" for x in r["limitations"]]
    return "\n".join(out) + "\n"
