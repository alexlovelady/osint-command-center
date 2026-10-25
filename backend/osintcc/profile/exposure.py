"""Privacy-exposure indicators: STATUS, CLASS, PROVIDER, DATE, risk, masked descriptor and remediation, never the exposed secret itself.

Nothing in this module can store a plaintext password, a password hash, a session token, a recovery secret, a full government identifier or a
breach dump: the table has no column for one, the API model rejects unknown fields, and the free-text descriptor is screened by `validate_descriptor`.
Three states are kept distinct on purpose: `not_assessed`, `not_found_in_checked_sources` and `confirmed_exposure`.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import Evidence, ExposureIndicator, Subject, SubjectIdentifier
from ..telemetry import audit
from . import consent
from .service import ProfileError

CLASSES: dict[str, dict[str, Any]] = {
    "breach_account": {"label": "Account found in a known data breach", "guidance": [
        "Change the password on the affected service, and anywhere the same password was reused.",
        "Turn on multi-factor authentication or passkeys for the account.",
        "Use a password manager so every account has a unique password.",
        "Subscribe to breach notifications for this address.",
        "Where available in your country, consider a credit freeze or fraud alert if financial data was involved."]},
    "password_exposure": {"label": "Password seen in a breach corpus", "guidance": [
        "Stop using that password everywhere and replace it with a unique one.",
        "Turn on multi-factor authentication for accounts that used it."]},
    "data_broker_listing": {"label": "Listing on a data-broker or people-search site", "guidance": [
        "Submit the site's opt-out or removal request and keep the confirmation.",
        "Recheck after the site's stated processing time; repeat if the listing returns."]},
    "public_document_disclosure": {"label": "Personal details disclosed in a public document", "guidance": [
        "Remove document metadata (author, software, location) and republish a clean copy.",
        "Ask the host to remove the old version and request a search-engine cache refresh."]},
    "precise_location_disclosure": {"label": "Precise location disclosed (for example photo geotags)", "guidance": [
        "Remove location data from published photos and turn off geotagging on the device.",
        "Review who can see the original files."]},
    "social_oversharing": {"label": "Profile shows more personal detail than intended", "guidance": [
        "Review the profile's privacy settings and remove details that are not needed.",
        "Check linked accounts and old posts."]},
}
STATUSES = ("not_assessed", "not_found_in_checked_sources", "confirmed_exposure")
RISKS = ("unknown", "low", "medium", "high", "critical")
BASES = ("provider_api", "owner_confirmed", "provider_notice", "manual_review")
PROVIDERS: dict[str, dict[str, Any]] = {
    "hibp": {"name": "Have I Been Pwned", "needs_key": "hibp", "cost": "paid API key (per-month subscription)",
             "terms": "https://haveibeenpwned.com/API/v3#AcceptableUse",
             "note": "Account lookups need the account owner's consent and a paid key. Searching a whole domain additionally needs domain verification with the provider, which this application does not perform.",
             "maturity": "mocked_only"},
    "pwned_passwords": {"name": "Pwned Passwords (k-anonymity range)", "needs_key": None, "cost": "free",
                        "terms": "https://haveibeenpwned.com/API/v3#PwnedPasswords",
                        "note": "Only the first five characters of the password's SHA-1 are ever sent. The comparison happens in your browser.", "maturity": "mocked_only"},
    "manual": {"name": "Manual / provider notice", "needs_key": None, "cost": "free", "terms": "", "note": "Recorded by a person from a notice, a portal or a visual check.",
               "maturity": "manual"},
}

_SECRET_PATTERNS = [
    (re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b"), "a government identifier"),
    (re.compile(r"(?<!\d)\d{9,}(?!\d)"), "a long number"),
    (re.compile(r"(?<!\d)(?:\d[ -]?){12,19}(?!\d)"), "a card or account number"),
    (re.compile(r"(?i)\b(pass(word|wd)?|pwd|secret|token|api[_-]?key|bearer)\b\s*[:=]\s*\S+"), "a credential assignment"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"), "a bearer token"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), "a JWT"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "a cloud access key"),
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "a hash or key"),
    (re.compile(r"(?<![A-Za-z0-9+/_-])(?=[A-Za-z0-9+/_-]*\d)(?=[A-Za-z0-9+/_-]*[A-Za-z])[A-Za-z0-9+/_-]{28,}={0,2}(?![A-Za-z0-9+/_-])"), "a long opaque string"),
    (re.compile(r"[^\s:]{1,64}:[^\s:]{4,64}@"), "credentials in an address"),
    (re.compile(r"[\w.+-]{1,64}@[\w.-]{1,200}\.[A-Za-z]{2,24}\s*[:;|]\s*\S{4,}"), "an address:password pair"),
]
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,200}\.[A-Za-z]{2,24}")


def validate_descriptor(text: str) -> str:
    """The free-text descriptor must read like 'Breach: ExampleService (2023-05); data types: email addresses, passwords' and nothing more."""
    t = " ".join((text or "").split())
    if len(t) > 200:
        raise ProfileError("descriptor_too_long", "keep the descriptor under 200 characters")
    for pat, what in _SECRET_PATTERNS:
        m = pat.search(t)
        if not m:
            continue
        raise ProfileError("secret_rejected", f"the descriptor looks like it contains {what}; exposure records never hold secrets, dumps or identifiers. Describe the category instead")
    for m in _EMAIL.finditer(t):
        local = m.group(0).split("@")[0]
        if "*" not in local:
            raise ProfileError("unmasked_identifier", "mask email addresses (for example j***@example.com)")
    return t


def _now() -> datetime:
    return datetime.now(UTC)


def risk_for(data_classes: list[str], breach_date: str | None) -> str:
    """Deterministic and explainable: passwords or financial data in a recent breach rank highest."""
    dc = {d.lower() for d in data_classes}
    recent = False
    if breach_date:
        try:
            recent = (_now() - datetime.fromisoformat(breach_date).replace(tzinfo=UTC)).days < 5 * 365
        except ValueError:
            recent = False
    if dc & {"passwords", "password hints", "credit cards", "bank account numbers", "social security numbers", "government issued ids"}:
        return "high" if recent else "medium"
    if dc & {"physical addresses", "phone numbers", "dates of birth", "ip addresses"}:
        return "medium" if recent else "low"
    return "low"


def record(db: Session, subject: Subject, *, cls: str, provider: str, status: str, risk: str, descriptor: str, basis: str, actor: str,
           exposure_date: datetime | None = None, evidence_id: str | None = None) -> ExposureIndicator:
    consent.require(db, subject, "exposure_check")
    if cls not in CLASSES:
        raise ProfileError("invalid_class", f"class must be one of {', '.join(CLASSES)}")
    if provider not in PROVIDERS:
        raise ProfileError("invalid_provider", f"provider must be one of {', '.join(PROVIDERS)}")
    if status not in STATUSES:
        raise ProfileError("invalid_status", f"status must be one of {', '.join(STATUSES)}")
    if risk not in RISKS:
        raise ProfileError("invalid_risk", f"risk must be one of {', '.join(RISKS)}")
    if basis not in BASES:
        raise ProfileError("invalid_basis", f"verification basis must be one of {', '.join(BASES)}")
    if status == "confirmed_exposure" and risk == "unknown":
        raise ProfileError("risk_required", "state a risk level for a confirmed exposure")
    if status != "confirmed_exposure" and risk not in ("unknown",):
        raise ProfileError("risk_not_applicable", "only a confirmed exposure has a risk level; use 'unknown' otherwise")
    desc = validate_descriptor(descriptor)
    if evidence_id:
        ev = db.get(Evidence, evidence_id)
        if not ev or ev.case_id != subject.case_id:
            raise ProfileError("evidence_not_in_case", "evidence is not in this case")
    x = ExposureIndicator(subject_id=subject.id, case_id=subject.case_id, cls=cls, provider=provider, status=status, risk=risk, masked_descriptor=desc,
                          verification_basis=basis, exposure_date=exposure_date, last_checked=_now(), evidence_id=evidence_id,
                          remediation_state="open" if status == "confirmed_exposure" else "not_applicable")
    db.add(x)
    db.flush()
    audit.record(db, "exposure.record", actor=actor, case_id=subject.case_id, resource_type="exposure_indicator", resource_id=x.id,
                 metadata={"class": cls, "status": status, "provider": provider})
    return x


def indicator_dict(x: ExposureIndicator, *, redact: bool) -> dict[str, Any]:
    out = {"id": x.id, "class": x.cls, "class_label": CLASSES.get(x.cls, {}).get("label", x.cls), "provider": x.provider, "status": x.status,
           "status_label": {"not_assessed": "not assessed", "not_found_in_checked_sources": "not found in checked sources", "confirmed_exposure": "confirmed exposure"}[x.status],
           "risk": x.risk, "exposure_date": x.exposure_date, "last_checked": x.last_checked, "verification_basis": x.verification_basis,
           "remediation_state": x.remediation_state, "evidence_id": x.evidence_id,
           "caveat": "'Not found in checked sources' only describes the sources that were checked. It does not show the subject was never exposed."
           if x.status == "not_found_in_checked_sources" else ""}
    out["descriptor"] = "" if redact else x.masked_descriptor
    return out


def list_for(db: Session, subject: Subject, *, role: str) -> list[dict[str, Any]]:
    """Owners and editors see the full indicator. Viewers (and anything built from this for them) see only that an indicator of a class exists."""
    rows = db.scalars(select(ExposureIndicator).where(ExposureIndicator.subject_id == subject.id).order_by(ExposureIndicator.last_checked.desc()))
    if role in ("owner", "editor"):
        return [indicator_dict(x, redact=False) for x in rows]
    return [{"id": x.id, "class": x.cls, "class_label": CLASSES.get(x.cls, {}).get("label", x.cls), "redacted": True} for x in rows]


# ---- provider flows ---------------------------------------------------------------------------------------------------------------------
def account_check_preview(db: Session, subject: Subject, identifier_id: str) -> dict[str, Any]:
    ident = db.get(SubjectIdentifier, identifier_id)
    if not ident or ident.subject_id != subject.id or ident.kind != "email" or ident.status != "active":
        raise ProfileError("invalid_identifier", "choose one of this subject's email inputs")
    d = consent.check(db, subject, "exposure_check", identifier_id=identifier_id)
    p = PROVIDERS["hibp"]
    return {"provider": "hibp", "provider_name": p["name"], "allowed": d.allowed, "reason": d.reason, "cost": p["cost"], "terms": p["terms"], "note": p["note"],
            "will_send": {"to": "https://haveibeenpwned.com/api/v3/breachedaccount/", "data": ident.value, "also_sent": "your API key (header) and this application's user agent"},
            "will_store": "For each breach: its name, date and the data categories it exposed, as masked indicators. No passwords or leaked records are requested or stored.",
            "maturity": p["maturity"], "requires_key": p["needs_key"]}


async def run_account_check(db: Session, ctx: Any, subject: Subject, identifier_id: str, actor: str) -> dict[str, Any]:
    pv = account_check_preview(db, subject, identifier_id)
    if not pv["allowed"]:
        raise ProfileError("consent_required" if "no authorization" in pv["reason"] else "out_of_scope", pv["reason"])
    ident = db.get(SubjectIdentifier, identifier_id)
    assert ident is not None
    key = ctx.secret("hibp")
    if not key:
        return {"status": "requires_key", "created": 0, "message": "No 'hibp' API key is stored, so no request was made. Add one in Settings, or record the result of a manual check instead."}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(ident.value, safe='')}?truncateResponse=false"
    try:
        res = await ctx.http.get(url, headers={"hibp-api-key": key, "Accept": "application/json"})
    except Exception as exc:
        return {"status": "error", "created": 0, "message": f"The provider could not be reached ({type(exc).__name__}). Nothing was recorded; this is not a negative result."}
    audit.record(db, "exposure.account_check", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id, metadata={"provider": "hibp", "http": res.status})
    if res.status == 404:
        x = record(db, subject, cls="breach_account", provider="hibp", status="not_found_in_checked_sources", risk="unknown", basis="provider_api", actor=actor,
                   descriptor="No breach found by this provider for the checked address")
        return {"status": "not_found_in_checked_sources", "created": 1, "indicator_ids": [x.id], "message": "Not found by this provider. That does not prove the address was never exposed."}
    if res.status in (401, 403):
        return {"status": "requires_key", "created": 0, "message": "The provider rejected the API key (wrong, expired or not permitted). Nothing was recorded."}
    if res.status == 429:
        return {"status": "rate_limited", "created": 0, "message": "The provider is rate limiting requests. Try again later; nothing was recorded."}
    if res.status != 200:
        return {"status": "error", "created": 0, "message": f"The provider answered HTTP {res.status}. Nothing was recorded."}
    try:
        rows = json.loads(res.body)
        assert isinstance(rows, list)
    except (ValueError, AssertionError):
        return {"status": "error", "created": 0, "message": "The provider's answer could not be read. Nothing was recorded."}
    trimmed: list[dict[str, Any]] = [{"Name": str(r.get("Name", ""))[:80], "BreachDate": str(r.get("BreachDate", ""))[:10], "DataClasses": [str(c)[:60] for c in (r.get("DataClasses") or [])][:30]} for r in rows[:100]]
    raw = json.dumps(trimmed, sort_keys=True).encode()
    from hashlib import sha256, sha512
    sh = sha256(raw).hexdigest()
    ev = Evidence(case_id=subject.case_id, kind="exposure.provider_response", title="Breach summary (names, dates, data categories only)", sha256=sh, sha512=sha512(raw).hexdigest(),
                  byte_size=len(raw), mime_type="application/json", retrieved_at=_now(), observed_at=_now(), capture_method="provider_api", sensitivity="RESTRICTED",
                  original_url="https://haveibeenpwned.com/api/v3/breachedaccount/", created_by=actor,
                  description="Trimmed provider response: breach names, dates and data categories. No leaked records.")
    db.add(ev)
    db.flush()
    ids = []
    for r in trimmed:
        classes = ", ".join(r["DataClasses"][:6]).lower()
        desc = validate_descriptor(f"Breach: {r['Name']} ({r['BreachDate']}); data types: {classes}"[:200])
        try:
            when = datetime.fromisoformat(r["BreachDate"]).replace(tzinfo=UTC) if r["BreachDate"] else None
        except ValueError:
            when = None
        x = record(db, subject, cls="breach_account", provider="hibp", status="confirmed_exposure", risk=risk_for(r["DataClasses"], r["BreachDate"] or None), basis="provider_api",
                   descriptor=desc, exposure_date=when, evidence_id=ev.id, actor=actor)
        ids.append(x.id)
    return {"status": "confirmed_exposure" if ids else "not_found_in_checked_sources", "created": len(ids), "indicator_ids": ids,
            "message": f"{len(ids)} breach record(s) summarised. Only names, dates and data categories were kept."}


_PREFIX = re.compile(r"^[0-9A-Fa-f]{5}$")


async def password_range(db: Session, ctx: Any, subject: Subject, prefix: str, actor: str) -> dict[str, Any]:
    """k-anonymity relay. The browser hashed the password locally and sends ONLY five hex characters. Nothing about the request is stored,
    logged or audited beyond the fact that a check happened; the answer is returned to the caller and forgotten."""
    if not _PREFIX.match(prefix or ""):
        raise ProfileError("invalid_prefix", "send exactly the first five hexadecimal characters of the SHA-1 hash, nothing more")
    consent.require(db, subject, "exposure_check")
    audit.record(db, "exposure.password_check", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id)
    try:
        res = await ctx.http.get(f"https://api.pwnedpasswords.com/range/{prefix.upper()}", headers={"Add-Padding": "true"})
    except Exception as exc:
        raise ProfileError("provider_unreachable", f"the range service could not be reached ({type(exc).__name__}); this is not a negative result") from exc
    if res.status != 200:
        raise ProfileError("provider_error", f"the range service answered HTTP {res.status}; this is not a negative result")
    lines = [ln.strip() for ln in res.body.decode("ascii", "replace").splitlines() if re.fullmatch(r"[0-9A-Fa-f]{35}:\d{1,10}", ln.strip())]
    return {"suffixes": lines, "padded": True, "note": "Compare the rest of your hash with this list in your browser. This application never sees the password or the full hash."}
