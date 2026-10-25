"""DARKINT provider registry and adapters (addendum v1.1 section 14.2).

Every provider exposes the same facts and one honest operational state:
  live         the operator enabled it, accepted its terms, and any credential it needs is present: the next check WILL call the provider's documented API
  mocked       fixture mode is on: answers are synthetic, no network is used
  manual_only  no permitted automation exists or was built: a person records results by hand
  disabled     not enabled, terms not accepted, or a credential is missing (the reason is returned)
`verification` is separate and never overstated: no provider here has been exercised against its live service in this build, so each says `fixture_tested`.
Nothing scrapes a page that has no documented interface, and nothing falls back to an unauthorized source when a provider is unavailable.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote

from ..policy.ssrf import DestinationDenied
from .sanitize import categorize, parse_date, sanitize_text

PACING_SCALE = 1.0            # tests set 0; real runs always honour the provider's documented rate limit
CHECKED_ON = "2026-10-25"      # when the terms below were read; they change, so re-read them before relying on this


@dataclass(frozen=True)
class ProviderSpec:
    provider_id: str
    name: str
    capabilities: tuple[str, ...]
    identifier_kinds: tuple[str, ...]          # kinds a check can be run for
    licence: str
    terms_url: str
    authentication: str
    scope_policy: str
    source_type: str
    cost_tier: str
    quota: str
    coverage_limitations: str
    secret_name: str | None = None             # name in the secret store
    automated: bool = True                     # a coded, permitted API integration exists
    monitorable: bool = False
    min_interval_s: int = 0
    terms_note: str = ""
    verification: str = "fixture_tested"
    last_verified: str | None = None           # null until a real call succeeded; never invented
    terms_read_on: str = CHECKED_ON
    endpoints: tuple[str, ...] = field(default_factory=tuple)

    def public(self) -> dict[str, Any]:
        return {"provider_id": self.provider_id, "name": self.name, "capabilities": list(self.capabilities), "identifier_kinds": list(self.identifier_kinds), "licence": self.licence,
                "terms_url": self.terms_url, "authentication": self.authentication, "scope_policy": self.scope_policy, "source_type": self.source_type, "cost_tier": self.cost_tier,
                "quota": self.quota, "coverage_limitations": self.coverage_limitations, "last_verified": self.last_verified, "verification": self.verification,
                "terms_read_on": self.terms_read_on, "terms_note": self.terms_note, "automated": self.automated, "monitorable": self.monitorable, "endpoints": list(self.endpoints)}


PROVIDERS: dict[str, ProviderSpec] = {p.provider_id: p for p in [
    ProviderSpec("hibp", "Have I Been Pwned", ("account_breaches", "domain_breaches"), ("email", "domain"), "Data CC BY 4.0 (attribution required); API per provider terms",
                 "https://haveibeenpwned.com/API/v3#AcceptableUse", "API key in the hibp-api-key header (paid plan)",
                 "Account lookups need the account owner's verified consent. Domain-wide lookups need the domain verified with the provider first; this application cannot perform that verification, so you attest to it.",
                 "breach_aggregator", "paid subscription", "Requests per minute depend on the plan; 429 with Retry-After on excess",
                 "Covers only breaches the provider has loaded. Sensitive and retired breaches are never returned for account lookups. No result is not proof of no exposure.",
                 secret_name="hibp", monitorable=True, min_interval_s=2, endpoints=("https://haveibeenpwned.com/api/v3/",),
                 terms_note="Show HIBP as the source wherever its data is displayed. Do not automate undocumented APIs or evade usage controls."),
    ProviderSpec("pwned_passwords", "Pwned Passwords (k-anonymity)", ("password_range",), (), "Free; no attribution required", "https://haveibeenpwned.com/API/v3#PwnedPasswords",
                 "none", "Owner-initiated only, one intentional password at a time; never scheduled, never bulk, never stored", "breach_aggregator", "free", "No stated rate limit",
                 "Answers whether a password appears in known breach corpora, not whose it was. Only five characters of a hash leave the browser.",
                 automated=False, monitorable=False, endpoints=("https://api.pwnedpasswords.com/range/",),
                 terms_note="Runs from the Exposure screen in your browser. The application relays five hex characters and keeps nothing."),
    ProviderSpec("ransomware_live", "Ransomware.live", ("victim_search",), ("organization", "domain"), "Free v2 API is stated to be for personal use; PRO needs a free key and its own terms",
                 "https://www.ransomware.live/api", "none for the v2 API", "Public reporting about organizations the operator is authorized to assess",
                 "threat_feed", "free", "v2: about one request per minute per endpoint; results are delayed compared with PRO",
                 "Lists what ransomware groups claimed on leak sites. A listing is an unverified claim by the actor, not independent proof of compromise. Coverage and timeliness are limited.",
                 monitorable=True, min_interval_s=60, endpoints=("https://api.ransomware.live/v2/",),
                 terms_note="The free v2 interface is labelled personal use only. Do not use it for corporate or commercial work unless the provider's terms allow it; read /t&c and use the PRO interface if they require it."),
    ProviderSpec("intelligence_x", "Intelligence X", ("metadata_search",), ("email", "domain", "organization"), "Commercial licence required", "https://intelx.io/terms",
                 "API key tied to a paid plan", "Metadata only, with a valid entitlement; raw leaked content is never retrieved", "darkweb_index", "paid subscription",
                 "Plan dependent; the provider asks for one request per second at most", "No automated integration was built because its response format could not be verified here. Record results by hand.",
                 automated=False, verification="not_implemented", endpoints=(),
                 terms_note="Use the provider's own interface under your licence, then record the category, date and reference with manual intake."),
    ProviderSpec("misp", "MISP (file import)", ("sanitized_import",), ("organization", "domain", "email"), "Per the exporting organization's terms and TLP markings",
                 "https://www.misp-project.org/", "none (a file you exported from a server you are authorized to use)", "Sanitized events only; attributes that look like secrets are dropped",
                 "threat_intel_platform", "free (self-hosted)", "n/a", "Reflects only what the exporting organization chose to share. A live server connector is not implemented.",
                 automated=False, endpoints=(), terms_note="Respect the TLP and distribution markings; they are kept with each imported event."),
    ProviderSpec("manual", "Manual intake (reports, notices, exports)", ("manual_report",), ("email", "domain", "organization", "name", "username"), "Whatever licence the source carries",
                 "", "none", "A person records a public report, provider notice, customer incident notice or provider-supported export, with its source link", "analyst_supplied",
                 "free", "n/a", "Only as complete as what was entered. Nothing is crawled and no illicit destination is ever visited.", automated=False),
]}

# Synthetic answers for mock mode. They use reserved example domains only and exist so the whole flow can be demonstrated without any network.
MOCK_ROWS: dict[str, list[dict[str, Any]]] = {
    "hibp": [{"Name": "ExampleForum", "Title": "Example Forum", "BreachDate": "2021-03-14", "DataClasses": ["Email addresses", "Passwords", "Usernames"]},
             {"Name": "SampleShop", "Title": "Sample Shop", "BreachDate": "2023-08-02", "DataClasses": ["Email addresses", "Names", "Phone numbers"]}],
    "ransomware_live": [{"victim": "Example Holdings", "group": "examplegroup", "attackdate": "2026-02-03", "country": "US"}],
}


@dataclass
class ProviderEvent:
    event_type: str
    incident_key: str
    title: str
    categories: list[str]
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    claim_status: str = "reported"
    confidence: str = "low"
    provider_ref: str = ""
    redacted: bool = False


@dataclass
class ProviderOutcome:
    outcome: str                               # match | no_match | credential_missing | source_unavailable | rate_limited | unsupported | error
    events: list[ProviderEvent] = field(default_factory=list)
    detail: str = ""
    summary: list[dict[str, Any]] = field(default_factory=list)      # the trimmed, non-sensitive record kept as evidence


def state_for(spec: ProviderSpec, *, enabled: bool, terms_ok: bool, have_secret: bool, mock: bool) -> dict[str, str]:
    """The single place that decides what a provider's state is."""
    if mock and spec.automated:
        return {"state": "mocked", "reason": "Fixture mode is on: answers are synthetic and nothing leaves this machine."}
    if not spec.automated:
        return {"state": "manual_only", "reason": spec.coverage_limitations if spec.verification == "not_implemented" else "No permitted automation: record results by hand or import a file."}
    if not enabled:
        return {"state": "disabled", "reason": "Not enabled. An administrator must enable it and accept its terms."}
    if not terms_ok:
        return {"state": "disabled", "reason": "Its terms have not been accepted yet."}
    if spec.secret_name and not have_secret:
        return {"state": "disabled", "reason": f"CREDENTIAL_MISSING: add the '{spec.secret_name}' API key in Settings."}
    return {"state": "live", "reason": "Enabled. The next check will call the provider's documented API."}


# ---- adapters -----------------------------------------------------------------------------------------------------------------------------
async def hibp_account(ctx: Any, email: str) -> ProviderOutcome:
    key = ctx.secret("hibp")
    if not key:
        return ProviderOutcome("credential_missing", detail="No 'hibp' API key is stored, so no request was made.")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}?truncateResponse=false"
    try:
        res = await ctx.http.get(url, headers={"hibp-api-key": key, "Accept": "application/json"})
    except DestinationDenied as exc:
        return ProviderOutcome("source_unavailable", detail=f"blocked by network policy: {exc}")
    except Exception as exc:
        return ProviderOutcome("source_unavailable", detail=f"the provider could not be reached ({type(exc).__name__}); this is not a negative result")
    if res.status == 404:
        return ProviderOutcome("no_match", detail="Not found by this provider. That does not prove the address was never exposed.")
    if res.status in (401, 403):
        return ProviderOutcome("credential_missing", detail=f"The provider rejected the API key or the request (HTTP {res.status}). Nothing was recorded.")
    if res.status == 429:
        return ProviderOutcome("rate_limited", detail=f"The provider is rate limiting requests (Retry-After {res.headers.get('retry-after', 'unknown')}).")
    if res.status != 200:
        return ProviderOutcome("source_unavailable", detail=f"The provider answered HTTP {res.status}.")
    try:
        rows = json.loads(res.body)
        assert isinstance(rows, list)
    except (ValueError, AssertionError):
        return ProviderOutcome("error", detail="The provider's answer could not be read.")
    return _hibp_rows(rows)


def _hibp_rows(rows: list[Any]) -> ProviderOutcome:
    events, summary = [], []
    for r in rows[:100]:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or r.get("Title") or "")[:80]
        if not name:
            continue
        cats = categorize([str(c) for c in (r.get("DataClasses") or [])][:30])
        when = parse_date(r.get("BreachDate"))
        title, red = sanitize_text(f"Breach: {r.get('Title') or name}"[:120])
        events.append(ProviderEvent("breach", f"hibp:{name}", title, cats, when, when, "reported", "medium", f"https://haveibeenpwned.com/PwnedWebsites#{quote(name)}", red))
        summary.append({"name": name, "date": str(r.get("BreachDate") or "")[:10], "categories": cats})
    return ProviderOutcome("match" if events else "no_match", events, summary=summary)


async def hibp_domain(ctx: Any, domain: str) -> ProviderOutcome:
    key = ctx.secret("hibp")
    if not key:
        return ProviderOutcome("credential_missing", detail="No 'hibp' API key is stored, so no request was made.")
    try:
        res = await ctx.http.get(f"https://haveibeenpwned.com/api/v3/breacheddomain/{quote(domain, safe='')}", headers={"hibp-api-key": key, "Accept": "application/json"})
    except DestinationDenied as exc:
        return ProviderOutcome("source_unavailable", detail=f"blocked by network policy: {exc}")
    except Exception as exc:
        return ProviderOutcome("source_unavailable", detail=f"the provider could not be reached ({type(exc).__name__})")
    if res.status == 403:
        return ProviderOutcome("unsupported", detail="The provider refused: the domain is not verified to your account with the provider. Verify it there first.")
    if res.status == 404:
        return ProviderOutcome("no_match", detail="No breached addresses at this domain were reported by this provider.")
    if res.status in (401,):
        return ProviderOutcome("credential_missing", detail="The provider rejected the API key.")
    if res.status == 429:
        return ProviderOutcome("rate_limited", detail="The provider is rate limiting requests.")
    if res.status != 200:
        return ProviderOutcome("source_unavailable", detail=f"The provider answered HTTP {res.status}.")
    try:
        body = json.loads(res.body)
        assert isinstance(body, dict)
    except (ValueError, AssertionError):
        return ProviderOutcome("error", detail="The provider's answer could not be read.")
    counts: dict[str, int] = {}
    for _alias, breaches in body.items():                    # the alias (the part before the @) is personal data: it is counted and dropped
        for b in (breaches or [])[:200]:
            counts[str(b)[:80]] = counts.get(str(b)[:80], 0) + 1
    events, summary = [], []
    for name, n in sorted(counts.items())[:100]:
        title, red = sanitize_text(f"Breach: {name} ({n} address(es) at this domain)")
        events.append(ProviderEvent("breach", f"hibp:{name}", title, ["email addresses"], None, None, "reported", "medium", f"https://haveibeenpwned.com/PwnedWebsites#{quote(name)}", red))
        summary.append({"name": name, "addresses_at_domain": n})
    return ProviderOutcome("match" if events else "no_match", events, summary=summary)


async def ransomware_search(ctx: Any, keyword: str) -> ProviderOutcome:
    try:
        res = await ctx.http.get(f"https://api.ransomware.live/v2/searchvictims/{quote(keyword, safe='')}", headers={"Accept": "application/json"})
    except DestinationDenied as exc:
        return ProviderOutcome("source_unavailable", detail=f"blocked by network policy: {exc}")
    except Exception as exc:
        return ProviderOutcome("source_unavailable", detail=f"the provider could not be reached ({type(exc).__name__}); this is not a negative result")
    if res.status == 404:
        return ProviderOutcome("no_match", detail="The provider reported no listing for this name. Coverage is limited and delayed.")
    if res.status == 429:
        return ProviderOutcome("rate_limited", detail="The provider is rate limiting requests (the free interface allows about one per minute).")
    if res.status != 200:
        return ProviderOutcome("source_unavailable", detail=f"The provider answered HTTP {res.status}.")
    try:
        rows = json.loads(res.body)
        assert isinstance(rows, list)
    except (ValueError, AssertionError):
        return ProviderOutcome("error", detail="The provider's answer could not be read.")
    return _ransom_rows(rows, keyword)


def _ransom_rows(rows: list[Any], keyword: str) -> ProviderOutcome:
    kw = keyword.casefold()
    events, summary = [], []
    for r in rows[:100]:
        if not isinstance(r, dict):
            continue
        victim, group = str(r.get("victim") or r.get("post_title") or "")[:120], str(r.get("group") or r.get("group_name") or "")[:60]
        if not victim or kw not in victim.casefold() and kw not in str(r.get("website") or r.get("domain") or "").casefold():
            continue
        when = parse_date(r.get("attackdate") or r.get("discovered"))
        title, red = sanitize_text(f"Named on a leak site by group {group or 'unknown'} (an unverified claim by the actor)")
        events.append(ProviderEvent("ransomware_listing", f"rwl:{group}:{victim.casefold()}:{str(r.get('attackdate') or r.get('discovered') or '')[:10]}", title,
                                    ["organization named on a leak site"], when, when, "reported", "low", f"ransomware.live:{group or 'unknown'}:{str(r.get('attackdate') or '')[:10]}", red))
        summary.append({"group": group, "date": str(r.get("attackdate") or r.get("discovered") or "")[:10], "country": str(r.get("country") or "")[:2]})
    return ProviderOutcome("match" if events else "no_match", events, summary=summary)


def mock_outcome(provider_id: str, op: str, value: str) -> ProviderOutcome:
    """Synthetic only: matches just addresses/names under reserved example domains so a demo never implies a real person was exposed."""
    v = value.casefold()
    demo = v.endswith(("example.com", "example.org", "example.net")) or "example" in v
    rows = MOCK_ROWS.get(provider_id, [])
    if not demo or not rows:
        return ProviderOutcome("no_match", detail="Fixture mode: no synthetic record for this value.")
    return _hibp_rows(rows) if provider_id == "hibp" else _ransom_rows([{**r, "victim": r["victim"]} for r in rows], "example")


async def run_provider(provider_id: str, op: str, value: str, ctx: Any, mock: bool) -> ProviderOutcome:
    if mock:
        return mock_outcome(provider_id, op, value)
    if provider_id == "hibp" and op == "account_breaches":
        return await hibp_account(ctx, value)
    if provider_id == "hibp" and op == "domain_breaches":
        return await hibp_domain(ctx, value)
    if provider_id == "ransomware_live" and op == "victim_search":
        return await ransomware_search(ctx, value)
    return ProviderOutcome("unsupported", detail="There is no permitted automation for this provider and operation.")


def operation_for(provider_id: str, kind: str) -> str | None:
    if provider_id == "hibp":
        return {"email": "account_breaches", "domain": "domain_breaches"}.get(kind)
    if provider_id == "ransomware_live":
        return "victim_search" if kind in ("organization", "domain") else None
    return None
