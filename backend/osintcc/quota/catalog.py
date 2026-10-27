"""Provider limit catalogue (addendum PQ-1.0): which outbound requests are metered, against which budget, and what is known about each limit.

Every number here is a DEFAULT. A limit is only as good as its `basis`:
  documented    the provider publishes it
  operator      read from the operator's own account screen (it can differ for another account or change later)
  assumption    a conservative value chosen here because the provider publishes none; it is replaced by whatever the provider's response headers say
Nothing in this module spends money: there is no purchase, upgrade or overage path anywhere in the application.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# window kinds
ROLLING = "rolling"        # the last `seconds` seconds
FIXED_MINUTE, FIXED_HOUR, FIXED_DAY, FIXED_MONTH = "utc_minute", "utc_hour", "utc_day", "utc_month"   # calendar windows that reset on a UTC boundary

# task statuses (addendum section 2); `disabled_provider` is an addition for an operator switch / paid provider
TASK_STATUSES = ("planned", "queued", "running", "completed", "no_match", "partial", "deferred_rate_limit", "deferred_daily_quota", "deferred_credits", "blocked_credentials",
                 "blocked_plan", "awaiting_authorization", "transient_error", "permanent_error", "cancelled", "disabled_provider")
WAITING_STATUSES = ("deferred_rate_limit", "deferred_daily_quota", "deferred_credits")
BLOCKED_STATUSES = ("blocked_credentials", "blocked_plan", "disabled_provider", "awaiting_authorization")
FINISHED_STATUSES = ("completed", "no_match", "partial")


@dataclass(frozen=True)
class Window:
    kind: str
    limit: float
    seconds: int = 0           # only for ROLLING
    unit: str = "requests"     # requests | credits
    basis: str = "assumption"

    @property
    def wid(self) -> str:
        return f"{ROLLING}:{self.seconds}" if self.kind == ROLLING else self.kind

    @property
    def status(self) -> str:
        """The deferral status a full window produces."""
        if self.kind == FIXED_MONTH or self.unit == "credits":
            return "deferred_credits"
        if self.kind == FIXED_DAY:
            return "deferred_daily_quota"
        return "deferred_rate_limit"


@dataclass(frozen=True)
class Operation:
    id: str
    label: str
    windows: tuple[Window, ...] = ()
    cost: float = 1.0                  # charged to a `credits` window per request
    concurrency: int | None = None     # simultaneous in-flight requests allowed for one credential
    min_spacing: float = 0.0           # seconds between two requests of this operation
    blocked: str = ""                  # non-empty: never dispatched; the text is the reason (e.g. a paid-only operation)


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    hosts: tuple[str, ...]
    ops: dict[str, Operation]
    route: Callable[[str, str], str]           # (path, query) -> operation id
    credential: str | None = None              # secret name in the credential store
    plan: str = "free / public"
    disabled: str = ""                         # non-empty: switched off by default; the text is the reason shown in the interface
    paid_only: bool = False
    terms: str = ""
    reset_note: str = ""
    limitations: tuple[str, ...] = ()
    verified_live: bool = False                # no provider here was exercised live in this build


def _op(pid: str, oid: str, label: str, *windows: Window, **kw) -> Operation:
    return Operation(oid, label, tuple(windows), **kw)


def _only(op_id: str) -> Callable[[str, str], str]:
    return lambda path, query: op_id


def _urlscan_route(path: str, query: str) -> str:
    p = path.rstrip("/")
    if p.startswith("/api/v1/search"):
        return "search"
    if p.startswith(("/api/v1/result", "/api/v1/screenshots", "/api/v1/dom")):
        return "result"
    if p.startswith("/api/v1/scan"):
        return "scan_public"             # Fusion never submits scans; classified defensively as the most visible kind so it is never allowed by accident
    if p.startswith("/api/v1/quotas"):
        return "quotas"
    return "other"


def _censys_route(path: str, query: str) -> str:
    p = path.rstrip("/")
    if p.startswith(("/v3/global/asset/host/", "/v3/global/asset/certificate/", "/v3/global/asset/webproperty/")):
        return "asset_lookup"
    if p.startswith("/api/v2/hosts/"):
        return "legacy_lookup"
    return "search"                      # search, aggregate, tracking and every other path: unavailable on the Free plan


def _github_route(path: str, query: str) -> str:
    return "search" if path.startswith("/search/") else "core"


US, UD, UM = FIXED_MINUTE, FIXED_DAY, FIXED_MONTH
W = Window


def _build() -> dict[str, Provider]:
    P: dict[str, Provider] = {}

    def add(p: Provider) -> None:
        P[p.id] = p

    add(Provider(
        "virustotal", "VirusTotal", ("www.virustotal.com",),
        {"lookup": _op("virustotal", "lookup", "Reputation lookup", W(ROLLING, 4, 60, basis="documented"), W(FIXED_DAY, 500, basis="documented"), W(FIXED_MONTH, 15500, basis="documented"),
                       min_spacing=16.0)},
        _only("lookup"), credential="virustotal", plan="public (free) API",
        terms="https://docs.virustotal.com/reference/public-vs-premium-api",
        reset_note="Daily quota resets at 00:00 UTC. Requests are spaced at least 16 seconds apart so four never go out at once.",
        limitations=("The public API is for personal, non-commercial use only; it is not suitable for a business workflow.",
                     "These are the documented public-API limits. A real account may have less; a 429 or a quota error from VirusTotal overrides them.")))
    add(Provider(
        "urlscan", "urlscan.io", ("urlscan.io",),
        {"search": _op("urlscan", "search", "Search", W(FIXED_MINUTE, 120, basis="operator"), W(FIXED_HOUR, 1000, basis="operator"), W(FIXED_DAY, 1000, basis="operator")),
         "result": _op("urlscan", "result", "Result retrieval", W(FIXED_MINUTE, 120, basis="operator"), W(FIXED_HOUR, 5000, basis="operator"), W(FIXED_DAY, 10000, basis="operator")),
         "scan_public": _op("urlscan", "scan_public", "Public scan", W(FIXED_MINUTE, 60, basis="operator"), W(FIXED_HOUR, 500, basis="operator"), W(FIXED_DAY, 5000, basis="operator"),
                            blocked="Fusion never submits a scan: a scan is visible to others and is a separate action that needs its own approval."),
         "scan_unlisted": _op("urlscan", "scan_unlisted", "Unlisted scan", W(FIXED_MINUTE, 60, basis="operator"), W(FIXED_HOUR, 100, basis="operator"), W(FIXED_DAY, 1000, basis="operator"),
                              blocked="Fusion never submits a scan."),
         "scan_private": _op("urlscan", "scan_private", "Private scan", W(FIXED_MINUTE, 5, basis="operator"), W(FIXED_HOUR, 50, basis="operator"), W(FIXED_DAY, 50, basis="operator"),
                             blocked="Fusion never submits a scan."),
         "quotas": _op("urlscan", "quotas", "Quota check", W(FIXED_MINUTE, 6, basis="assumption")),
         "other": _op("urlscan", "other", "Other", W(FIXED_MINUTE, 20, basis="assumption"))},
        _urlscan_route, credential="urlscan", plan="free account (limits read from the operator's account screen)",
        terms="https://docs.urlscan.io/pages/api-rate-limits",
        reset_note="Fixed windows: they reset at the full minute, the full hour and 00:00 UTC. Each action (search, result retrieval, each kind of scan) has its own budget. Only successful (HTTP 200) requests count.",
        limitations=("The figures are from the operator's own account screen and can differ on another account; Fusion reads the real limits from the quotas endpoint and from response headers when it can.",
                     "Without a key urlscan applies much smaller limits to the address; the budgets above assume a key.")))
    add(Provider(
        "censys", "Censys", ("api.platform.censys.io", "search.censys.io"),
        {"asset_lookup": _op("censys", "asset_lookup", "Asset lookup (host, certificate, web property)", W(FIXED_MONTH, 100, unit="credits", basis="operator"), cost=1.0, concurrency=1, min_spacing=1.0),
         "legacy_lookup": _op("censys", "legacy_lookup", "Legacy host lookup (API ID and secret)", W(FIXED_MONTH, 100, unit="credits", basis="assumption"), W(ROLLING, 10, 60, basis="assumption"),
                              cost=1.0, concurrency=1, min_spacing=2.0),
         "search": _op("censys", "search", "Search and aggregate", blocked="Search is not part of the Censys Free plan (lookups only). Fusion does not call it.")},
        _censys_route, credential="censys", plan="Free (100 credits per month, one concurrent action, lookup endpoints only)",
        terms="https://docs.censys.com/docs/platform-credits-free-starter",
        reset_note="Credits reset monthly (the first of the month, UTC, is assumed; confirm on the Censys account page). Each host, certificate or web-property lookup costs 1 credit.",
        limitations=("Authentication is a Personal Access Token sent as a bearer token to api.platform.censys.io. A token is never converted into an API-ID:secret pair.",
                     "Exceeding the one-concurrent-action limit returns 429; the request rate limit returns 503. Both are treated as 'try again later', never as 'no result'.")))
    add(Provider(
        "brave", "Brave Search", ("api.search.brave.com",),
        {"search": _op("brave", "search", "Web search", W(ROLLING, 1, 1, basis="assumption"), min_spacing=1.1)},
        _only("search"), credential="brave_search", plan="read from the provider's response headers",
        terms="https://brave.com/search/api/",
        reset_note="Brave reports the plan's per-second and per-month limits, what is left and when each resets in the response headers of every call. Until the first call the monthly limit is unknown, so only the per-second pace is enforced.",
        limitations=("There is no endpoint that reports the plan before the first call. 'Quota available' therefore stays unknown until a request has been made.",
                     "Only successful requests are counted by Brave. Paid overflow is never enabled by Fusion.")))
    add(Provider(
        "sec_edgar", "SEC EDGAR", ("data.sec.gov", "www.sec.gov"),
        {"fetch": _op("sec_edgar", "fetch", "Filing data", W(ROLLING, 5, 1, basis="documented"), W(ROLLING, 30, 10, basis="assumption"), min_spacing=0.25)},
        _only("fetch"), credential=None, plan="public (no key); contact string required",
        terms="https://www.sec.gov/os/accessing-edgar-data",
        reset_note="The SEC allows at most 10 requests per second; Fusion paces itself to 5 per second across the whole application.",
        limitations=("A contact (name and email) is required in the User-Agent. Without a valid one no request is sent.",)))
    add(Provider(
        "shodan", "Shodan", ("api.shodan.io",), {"host": _op("shodan", "host", "Host lookup")}, _only("host"), credential="shodan", plan="not used",
        disabled="Disabled — paid provider", paid_only=True, terms="https://www.shodan.io/",
        reset_note="Not used. Turning it on later needs your explicit confirmation after you have verified the account's entitlements.",
        limitations=("The capability Fusion would need is paid. It is excluded from automatic investigation planning.",)))
    add(Provider(
        "github", "GitHub", ("api.github.com",),
        {"search": _op("github", "search", "Search", W(ROLLING, 8, 60, basis="documented")), "core": _op("github", "core", "Public API", W(ROLLING, 50, 3600, basis="documented"))},
        _github_route, plan="anonymous", terms="https://docs.github.com/en/rest/rate-limit",
        reset_note="Anonymous search is limited to 10 per minute and other calls to 60 per hour per address; the response headers say exactly when each resets.",
        limitations=("Fusion does not send a GitHub token.",)))
    add(Provider(
        "gravatar", "Gravatar", ("api.gravatar.com",), {"profile": _op("gravatar", "profile", "Profile lookup", W(ROLLING, 80, 3600, basis="documented"))},
        _only("profile"), plan="anonymous", terms="https://docs.gravatar.com/", reset_note="Unauthenticated: 100 requests per hour; Fusion stays at 80."))
    add(Provider(
        "keyserver", "OpenPGP keyserver", ("keys.openpgp.org",), {"lookup": _op("keyserver", "lookup", "Key lookup", W(ROLLING, 1, 60, basis="documented"))},
        _only("lookup"), plan="anonymous", terms="https://keys.openpgp.org/about/api", reset_note="One lookup per minute."))
    add(Provider(
        "hibp", "Have I Been Pwned", ("haveibeenpwned.com",), {"breach": _op("hibp", "breach", "Breach lookup", W(ROLLING, 8, 60, basis="assumption"))},
        _only("breach"), credential="hibp", plan="paid key (operator's own)", terms="https://haveibeenpwned.com/API/v3",
        reset_note="The rate depends on the key's plan; the provider's 429 response says how long to wait."))
    add(Provider(
        "opencorporates", "OpenCorporates", ("api.opencorporates.com",), {"search": _op("opencorporates", "search", "Company search", W(ROLLING, 5, 60, basis="assumption"))},
        _only("search"), credential="opencorporates", plan="unknown", terms="https://opencorporates.com/info/licence",
        reset_note="No quota is assumed for a free token; it is reported as unknown until the provider says otherwise.",
        limitations=("Commercial use needs a paid licence tier; Fusion cannot tell which tier a token is on.",)))
    add(Provider(
        "wayback", "Internet Archive", ("web.archive.org", "archive.org"), {"cdx": _op("wayback", "cdx", "Index lookup", W(ROLLING, 12, 60, basis="assumption"))},
        _only("cdx"), plan="public", terms="https://archive.org/details/toc"))
    add(Provider(
        "crtsh", "crt.sh", ("crt.sh",), {"query": _op("crtsh", "query", "Certificate search", W(ROLLING, 10, 60, basis="assumption"))},
        _only("query"), plan="public", terms="https://crt.sh/"))
    add(Provider(
        "gdelt", "GDELT", ("api.gdeltproject.org",), {"doc": _op("gdelt", "doc", "News search", W(ROLLING, 12, 60, basis="assumption"))},
        _only("doc"), plan="public", terms="https://www.gdeltproject.org/about.html"))
    return P


PROVIDERS: dict[str, Provider] = _build()
# which provider budget each adapter spends from (the adapters themselves are unchanged)
ADAPTER_PROVIDER = {"virustotal": "virustotal", "urlscan": "urlscan", "censys": "censys", "shodan": "shodan", "web_search_email": "brave", "sec_edgar": "sec_edgar",
                    "github_public": "github", "github_email_search": "github", "gravatar_email": "gravatar", "keyserver_email": "keyserver", "opencorporates": "opencorporates",
                    "wayback": "wayback", "crtsh": "crtsh", "gdelt": "gdelt"}
_HOSTS: dict[str, Provider] = {h: p for p in PROVIDERS.values() for h in p.hosts}


@dataclass(frozen=True)
class Route:
    provider: Provider
    operation: Operation


def classify(url: str) -> Route | None:
    """Which provider budget an outbound URL is charged to. None means the destination is not a metered provider (it is still checked by the SSRF policy)."""
    parts = urlsplit(url)
    prov = _HOSTS.get((parts.hostname or "").lower())
    if prov is None:
        return None
    op_id = prov.route(parts.path or "/", parts.query or "")
    op = prov.ops.get(op_id) or next(iter(prov.ops.values()))
    return Route(prov, op)


@dataclass
class Facts:
    """What the interface may say about a provider without contacting it."""
    provider: str
    label: str
    plan: str
    operations: list[dict] = field(default_factory=list)
