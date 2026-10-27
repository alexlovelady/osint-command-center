"""Provider quotas, the durable queue, credentials and the EDGAR save (addendum PQ-1.0).

Every provider answers from a mock transport and the clock is a fake one, so this proves the dispatcher's arithmetic, its persistence and the states it reports. It does not prove
what any real provider does: see docs/provider-quotas.md for which behaviours are fixture-only.
"""
from __future__ import annotations

import asyncio
import itertools
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import fake_dns, fake_resolver
from conftest import make_handler as fixture_handler
from osintcc.adapters.base import AdapterContext
from osintcc.config import Settings
from osintcc.db.models import Job, ProviderLedger, ProviderState
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from osintcc.quota import PROVIDERS, QuotaService
from osintcc.quota.catalog import classify
from osintcc.quota.credentials import censys_kind, validate_contact, validate_credential
from osintcc.quota.service import Denial, Reservation
from sqlalchemy import func, select
from test_associated_emails import B, _no_real_keyring  # noqa: F401  (fixture)

T0 = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
VT_KEY = "a" * 64
URLSCAN_KEY = "0b1c2d3e-aaaa-bbbb-cccc-1234567890ab"
PAT = "censys_" + "x" * 32
LEGACY = "0b1c2d3e-aaaa-bbbb-cccc-1234567890ab:s3cr3tS3cr3tS3cr3tS3cr3tAA"
SECRETS = {"virustotal": VT_KEY, "urlscan": URLSCAN_KEY, "censys": PAT, "brave_search": "BSA-brave-key-123", "shodan": "SHODANSECRET99"}


class Clock:
    def __init__(self, t: datetime = T0):
        self.t = t

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)


def vt_body(malicious: int = 0) -> dict:
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "suspicious": 0, "harmless": 70}, "reputation": 3, "last_analysis_date": 1700000000}}}


class Env:
    def __init__(self, app, clock: Clock, world: dict):
        self.app, self.clock, self.world = app, clock, world
        self.st = app.state.core
        self.quota = self.st.quota

    def jobs(self, adapter: str | None = None) -> list[Job]:
        with self.st.sm() as db:
            q = select(Job).order_by(Job.created_at)
            if adapter:
                q = q.where(Job.adapter_id == adapter)
            rows = list(db.scalars(q))
            for r in rows:
                db.expunge(r)
            return rows

    def seen(self, host: str) -> list[httpx.Request]:
        return [r for r in self.world["requests"] if r.url.host == host]


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def world():
    return {"requests": [], "vt": (200, vt_body()), "urlscan": 200, "censys": 200, "brave": 200, "edgar": 200, "shodan": 200, "raise": None, "secrets": dict(SECRETS)}


def make_handler(world):
    others = fixture_handler([])                                    # RDAP, crt.sh, Wayback and friends answer from the shared fixtures

    def handler(req: httpx.Request) -> httpx.Response:
        world["requests"].append(req)
        if world["raise"] is not None and req.url.host == world["raise"]:
            raise httpx.ReadTimeout("slow", request=req)
        h = req.url.host
        if h == "www.virustotal.com":
            code, body = world["vt"]
            hdr = {"Retry-After": str(world.get("vt_retry_after", 5))} if code == 429 else {}
            return httpx.Response(code, json=body if code != 404 else {"error": {"code": "NotFoundError"}}, headers=hdr)
        if h == "urlscan.io":
            if req.url.path.startswith("/api/v1/quotas"):
                return httpx.Response(200, json={"limits": {"search": {"minute": {"limit": 30, "used": 0, "remaining": 30}, "hour": {"limit": 500, "used": 0, "remaining": 500},
                                                            "day": {"limit": 800, "used": 0, "remaining": 800}}}})
            code = world["urlscan"]
            if code == 429:
                return httpx.Response(429, headers={"X-Rate-Limit-Scope": "user", "X-Rate-Limit-Action": "search", "X-Rate-Limit-Window": world.get("urlscan_window", "minute"),
                                                    "X-Rate-Limit-Limit": "120", "X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset-After": "40"})
            return httpx.Response(code, json={"results": [{"page": {"ip": "93.184.216.34", "country": "US"}, "task": {"time": "2026-01-01T00:00:00Z"}}], "total": 1},
                                  headers={"X-Rate-Limit-Action": "search", "X-Rate-Limit-Window": "minute", "X-Rate-Limit-Limit": "120", "X-Rate-Limit-Remaining": "119",
                                           "X-Rate-Limit-Reset-After": "30"})
        if h == "api.platform.censys.io":
            code = world["censys"]
            return httpx.Response(code, json={"result": {"resource": {"ip": "93.184.216.34", "services": [{"port": 443, "protocol": "HTTPS", "transport_protocol": "TCP"}],
                                                                       "autonomous_system": {"asn": 15133, "name": "EDGECAST"}, "location": {"country_code": "US"}}}} if code == 200 else {})
        if h == "api.search.brave.com":
            return httpx.Response(world["brave"], json={"web": {"results": []}}, headers={"X-RateLimit-Limit": "1, 2000", "X-RateLimit-Remaining": "0, 1990", "X-RateLimit-Reset": "1, 2000000",
                                                                                           "X-RateLimit-Policy": "1;w=1, 2000;w=2592000"})
        if h == "data.sec.gov":
            return httpx.Response(world["edgar"], json={"name": "ACME CORP", "sic": "7372", "sicDescription": "Services", "stateOfIncorporation": "DE", "tickers": ["ACME"],
                                                        "filings": {"recent": {"accessionNumber": ["0000000000-26-000001"], "form": ["10-K"], "filingDate": ["2026-01-01"],
                                                                               "primaryDocument": ["a.htm"]}}})
        if h == "api.gdeltproject.org":
            return httpx.Response(world.get("gdelt", 200), json={"articles": []})
        if h == "api.shodan.io":
            return httpx.Response(world["shodan"], json={"ports": [443]})
        return others(req)
    return handler


@pytest.fixture
async def env(settings: Settings, clock, world, monkeypatch):
    settings.retry_scale = 1.0                                       # real delays: the clock below is the fake one
    monkeypatch.setattr("osintcc.jobs.runner._now", clock)
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(world)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns, secret=world["secrets"].get, config=_cfg(app)))
    app.state.core.quota.now = clock
    app.state.core.secrets.get = lambda name: world["secrets"].get(name)          # the credential store the dispatcher and the adapters both read
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            e = Env(app, clock, world)
            for n in ("app", "st", "quota", "jobs", "seen", "clock", "world"):
                setattr(c, n, getattr(e, n))
            yield c


def _cfg(app) -> dict:
    st = getattr(app.state, "core", None)
    if st is None:
        return {}
    from osintcc.db.models import Setting
    with st.sm() as db:
        row = db.get(Setting, "edgar_contact")
        return {"edgar_user_agent": row.value_json if row else None}


async def new_case(c) -> str:
    return (await c.post("/api/v1/cases", json={"title": "Q", "purpose": "quota tests"})).json()["id"]


async def search(c, cid: str, target: str, adapter: str) -> dict:
    r = await c.post(f"/api/v1/cases/{cid}/searches", json={"target": target, "adapters": [adapter], "wait": True})
    assert r.status_code == 202, r.text
    return r.json()


def at(actual, expected):
    """The dispatcher adds 50 ms of margin after a reset so a request is never made a hair early."""
    return actual is not None and expected <= actual <= expected + timedelta(seconds=1)


def vt_route():
    return classify("https://www.virustotal.com/api/v3/domains/example.org")


# =============================================================================================== catalogue and credential shapes
def test_every_provider_url_is_classified_into_its_own_budget():
    assert classify("https://urlscan.io/api/v1/search/?q=domain:x").operation.id == "search"
    assert classify("https://urlscan.io/api/v1/result/abc/").operation.id == "result"
    assert classify("https://urlscan.io/api/v1/scan/").operation.id == "scan_public" and classify("https://urlscan.io/api/v1/scan/").operation.blocked
    assert classify("https://api.platform.censys.io/v3/global/asset/host/8.8.8.8").operation.id == "asset_lookup"
    assert classify("https://api.platform.censys.io/v3/global/search/query").operation.blocked                       # search is not part of the Free plan
    assert classify("https://api.shodan.io/shodan/host/1.2.3.4").provider.disabled == "Disabled — paid provider"
    assert classify("https://example.org/anything") is None


def test_credential_shapes_distinguish_a_censys_token_from_the_legacy_pair_and_never_convert_one_to_the_other():
    assert censys_kind(PAT) == "pat" and censys_kind(LEGACY) == "legacy"
    assert censys_kind("short") == "wrong_format" and censys_kind("ID:SECRET") == "wrong_format" and censys_kind("a b") == "wrong_format"
    assert validate_credential("censys", PAT) is None and validate_credential("censys", LEGACY) is None and "Personal Access Token" in (validate_credential("censys", "nope") or "")
    assert validate_credential("virustotal", VT_KEY) is None and validate_credential("virustotal", "line\nbreak") and validate_credential("virustotal", "  ")
    assert validate_contact("Jane Analyst jane@example.org") == (None, "Jane Analyst jane@example.org")
    assert validate_contact("jane@example.org")[0] and validate_contact("Jane Analyst")[0] and validate_contact("Jane Analyst jane@@example")[0] and validate_contact("")[0]


# =============================================================================================== the arithmetic of the budgets (no network)
class Rig:
    """A QuotaService on the real encrypted-schema database with a fake clock and no HTTP at all."""

    def __init__(self, st, clock, secrets):
        self.q = QuotaService(st.sm, secrets.get, now=clock, rng=lambda: 0.0)
        self.clock, self.sm = clock, st.sm

    def take(self, url: str) -> Reservation | Denial:
        return self.q.reserve(classify(url))

    def settle_ok(self, r: Reservation, status: int = 200, headers: dict | None = None) -> None:
        self.q.settle(r, status=status, headers=headers or {})


@pytest.fixture
async def rig(env, clock):
    return Rig(env.st, clock, dict(SECRETS))


VT_URL = "https://www.virustotal.com/api/v3/domains/example.org"


async def test_twelve_virustotal_lookups_are_spread_over_successive_windows_never_four_at_once(rig, clock):
    sent = []
    for _ in range(12):
        while True:
            r = rig.take(VT_URL)
            if isinstance(r, Reservation):
                rig.settle_ok(r)
                sent.append(clock())
                break
            assert r.status == "deferred_rate_limit" and r.eligible_at is not None and r.eligible_at > clock()
            clock.t = r.eligible_at
    assert len(sent) == 12
    gaps = [(b - a).total_seconds() for a, b in itertools.pairwise(sent)]
    assert min(gaps) >= 16 - 1e-6                                                                    # at least 16 seconds apart: never a burst of four
    for i, t in enumerate(sent):                                                                     # and never more than 4 in any rolling 60 seconds
        assert sum(1 for u in sent if t - timedelta(seconds=60) < u <= t) <= 4, i
    assert (sent[-1] - sent[0]).total_seconds() >= 11 * 16 - 1e-6                                    # twelve lookups take about three minutes, not an instant


async def test_the_501st_daily_virustotal_request_waits_for_the_utc_reset_and_counters_survive_a_restart(rig, env, clock):
    with env.st.sm() as db:                                                                          # 500 requests already made today (spread out so no per-minute window is full)
        for i in range(500):
            db.add(ProviderLedger(provider="virustotal", operation="lookup", account_key=rig.q.account_key(PROVIDERS["virustotal"]), state="settled", cost=1.0,
                                  reserved_at=T0 - timedelta(minutes=5 + i * 0.01), consumption_known=True, classification="ok", error_code="", url_host=""))
        db.commit()
    d = rig.take(VT_URL)
    assert isinstance(d, Denial) and d.status == "deferred_daily_quota"
    midnight = datetime(2026, 10, 28, 0, 0, 0, tzinfo=UTC)
    assert at(d.eligible_at, midnight)                                                                # the UTC day boundary, from the persisted ledger
    again = QuotaService(env.st.sm, SECRETS.get, now=clock, rng=lambda: 0.0)                         # "restart": a brand-new service object, same database
    d2 = again.reserve(classify(VT_URL))
    assert isinstance(d2, Denial) and d2.status == "deferred_daily_quota" and at(d2.eligible_at, midnight)
    clock.t = midnight + timedelta(seconds=1)
    assert isinstance(again.reserve(classify(VT_URL)), Reservation)


async def test_two_investigations_sharing_one_credential_cannot_oversubscribe_the_budget(env, clock):
    results: list = []
    q = env.quota

    def grab():
        return q.reserve(classify(VT_URL))
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: grab(), range(8)))
    granted = [r for r in results if isinstance(r, Reservation)]
    denied = [r for r in results if isinstance(r, Denial)]
    assert len(granted) == 1 and len(denied) == 7                                                    # one slot, eight racers: exactly one wins
    assert all(d.status == "deferred_rate_limit" for d in denied)
    with env.st.sm() as db:
        assert db.scalar(select(func.count()).select_from(ProviderLedger).where(ProviderLedger.provider == "virustotal")) == 1


async def test_urlscan_actions_have_independent_budgets_and_headers_reconcile(rig, env, clock):
    acct = rig.q.account_key(PROVIDERS["urlscan"])
    clock.advance(30)                                                                                # 12:00:30
    with env.st.sm() as db:                                                                          # 120 searches in this minute: the search budget for the minute is full
        for i in range(120):
            db.add(ProviderLedger(provider="urlscan", operation="search", account_key=acct, state="settled", cost=1.0, reserved_at=clock() - timedelta(seconds=1 + i * 0.1),
                                  consumption_known=True, classification="ok", error_code="", url_host=""))
        db.commit()
    s = rig.take("https://urlscan.io/api/v1/search/?q=domain:example.org")
    assert isinstance(s, Denial) and s.status == "deferred_rate_limit" and at(s.eligible_at, datetime(2026, 10, 27, 12, 1, 0, tzinfo=UTC))
    assert isinstance(rig.take("https://urlscan.io/api/v1/result/abc/"), Reservation)                # result retrieval is a different action with its own budget
    scan = rig.take("https://urlscan.io/api/v1/scan/")
    assert isinstance(scan, Denial) and scan.status == "blocked_plan"                                # a scan is never dispatched
    clock.advance(61)
    r = rig.take("https://urlscan.io/api/v1/search/?q=domain:example.org")
    assert isinstance(r, Reservation)
    out = rig.q.settle(r, status=429, headers={"X-Rate-Limit-Action": "search", "X-Rate-Limit-Window": "day", "X-Rate-Limit-Limit": "1000", "X-Rate-Limit-Remaining": "0",
                                                "X-Rate-Limit-Reset-After": "3600"})
    assert out.quota_status == "deferred_daily_quota" and out.eligible_at is not None and out.eligible_at >= clock() + timedelta(hours=1)
    blocked = rig.take("https://urlscan.io/api/v1/search/?q=domain:example.org")
    assert isinstance(blocked, Denial) and blocked.status == "deferred_daily_quota"                  # the provider's own 429 is honoured, not retried


async def test_urlscan_headers_on_a_success_lower_the_effective_limit(rig, env, clock):
    r = rig.take("https://urlscan.io/api/v1/search/?q=domain:example.org")
    assert isinstance(r, Reservation)
    rig.q.settle(r, status=200, headers={"X-Rate-Limit-Action": "search", "X-Rate-Limit-Window": "minute", "X-Rate-Limit-Limit": "120", "X-Rate-Limit-Remaining": "0",
                                          "X-Rate-Limit-Reset-After": "25"})
    d = rig.take("https://urlscan.io/api/v1/search/?q=domain:example.org")
    assert isinstance(d, Denial) and d.status == "deferred_rate_limit"                               # the provider says 0 left this minute, whatever Fusion thought
    assert d.eligible_at is not None and 24 <= (d.eligible_at - clock()).total_seconds() <= 26


async def test_censys_allows_one_concurrent_action_and_stops_at_100_credits(rig, env, clock):
    url = "https://api.platform.censys.io/v3/global/asset/host/8.8.8.8"
    first = rig.take(url)
    assert isinstance(first, Reservation)
    second = rig.take(url)
    assert isinstance(second, Denial) and second.status == "deferred_rate_limit" and "one request at a time" in second.reason or "at a time" in second.reason   # one in flight at a time
    rig.settle_ok(first)
    clock.advance(2)
    acct = rig.q.account_key(PROVIDERS["censys"])
    with env.st.sm() as db:                                                                          # 99 more credits used this month (100 in total with the one above)
        for i in range(99):
            db.add(ProviderLedger(provider="censys", operation="asset_lookup", account_key=acct, state="settled", cost=1.0, reserved_at=T0 - timedelta(hours=1 + i), consumption_known=True,
                                  classification="ok", error_code="", url_host=""))
        db.commit()
    d = rig.take(url)
    assert isinstance(d, Denial) and d.status == "deferred_credits" and at(d.eligible_at, datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC))   # no overage: wait for the monthly reset
    s = rig.take("https://api.platform.censys.io/v3/global/search/query")
    assert isinstance(s, Denial) and s.status == "blocked_plan"                                      # a paid-only operation is never attempted


async def test_a_busy_ledger_is_never_read_as_permission(rig, monkeypatch):
    from sqlalchemy.exc import OperationalError

    def boom(*a, **k):
        raise OperationalError("x", {}, Exception("database is locked"))
    monkeypatch.setattr(rig.q, "_reserve", boom)
    d = rig.take(VT_URL)
    assert isinstance(d, Denial) and d.status == "deferred_rate_limit"


# =============================================================================================== statuses: a refusal is never a result
@pytest.mark.parametrize("code,expect,requests", [
    (200, "completed", 1), (404, "no_match", 1), (401, "blocked_credentials", 1), (403, "blocked_plan", 1), (402, "deferred_credits", 1), (429, "deferred_rate_limit", 1),
])
async def test_each_virustotal_answer_becomes_its_own_task_status(env, world, code, expect, requests):
    world["vt"] = (code, vt_body())
    cid = await new_case(env)
    await search(env, cid, "example.org", "virustotal")
    job = env.jobs("virustotal")[0]
    assert job.quota_status == expect, (code, job.status, job.quota_status)
    assert len(env.seen("www.virustotal.com")) == requests                                           # no retry loop on any of them
    if expect in ("blocked_credentials", "blocked_plan"):
        assert job.status in ("failed", "skipped") and job.finished_at is not None                  # final, not queued for a retry
    if expect.startswith("deferred"):
        assert job.status == "deferred" and job.next_retry_at is not None and job.finished_at is None
    if expect == "completed":
        assert job.status == "succeeded"


async def test_virustotal_quota_error_in_the_body_waits_until_the_utc_day_rolls_over(env, world, clock):
    world["vt"] = (429, {"error": {"code": "QuotaExceededError", "message": "Quota exceeded"}})
    cid = await new_case(env)
    await search(env, cid, "example.org", "virustotal")
    job = env.jobs("virustotal")[0]
    assert job.quota_status == "deferred_daily_quota"
    nra = job.next_retry_at.replace(tzinfo=UTC) if job.next_retry_at.tzinfo is None else job.next_retry_at
    assert datetime(2026, 10, 28, 0, 0, tzinfo=UTC) <= nra < datetime(2026, 10, 28, 0, 0, 5, tzinfo=UTC)


async def test_a_rejected_key_is_never_retried_until_it_is_replaced(env, world):
    world["vt"] = (401, {"error": {"code": "WrongCredentialsError"}})
    cid = await new_case(env)
    await search(env, cid, "example.org", "virustotal")
    await search(env, cid, "example2.org", "virustotal")
    await search(env, cid, "example3.org", "virustotal")
    assert len(env.seen("www.virustotal.com")) == 1                                                   # the second and third searches were refused locally, nothing was sent
    assert [j.quota_status for j in env.jobs("virustotal")] == ["blocked_credentials"] * 3
    u = (await env.get("/api/v1/providers/usage")).json()
    vt = next(p for p in u["providers"] if p["provider"] == "virustotal")
    assert vt["state"]["code"] == "rejected" and vt["axes"]["live_authentication"] == "rejected"
    world["secrets"]["virustotal"] = "b" * 64                                                         # a new key is a new identity: it is tried
    world["vt"] = (200, vt_body())
    await search(env, cid, "example4.org", "virustotal")
    assert env.jobs("virustotal")[-1].quota_status == "completed"


@pytest.mark.parametrize("failure,expect", [("timeout", "transient_error"), ("500", "transient_error")])
async def test_timeouts_and_server_errors_are_transient_errors_with_bounded_retries(env, world, failure, expect, monkeypatch):
    real = lambda: datetime.now(UTC)
    monkeypatch.setattr("osintcc.jobs.runner._now", real)
    env.quota.now = real
    env.st.settings.retry_scale = 0.001
    if failure == "timeout":
        world["raise"] = "api.gdeltproject.org"
    else:
        world["gdelt"] = 500
    cid = await new_case(env)
    await search(env, cid, "example.org", "gdelt")
    job = env.jobs("gdelt")[0]
    assert job.quota_status == expect and job.status == "failed"
    assert 1 <= len(env.seen("api.gdeltproject.org")) <= job.max_attempts                           # bounded: never an infinite retry loop
    assert job.quota_status not in ("completed", "no_match")


async def test_a_provider_the_operator_turned_off_sends_nothing_and_says_so(env, world):
    env.quota.set_disabled("virustotal", True)
    cid = await new_case(env)
    await search(env, cid, "example.org", "virustotal")
    assert env.jobs("virustotal")[0].quota_status == "disabled_provider" and not env.seen("www.virustotal.com")
    assert env.jobs("virustotal")[0].status != "succeeded"


async def test_shodan_is_disabled_by_default_is_not_planned_and_is_never_contacted(env, world):
    cid = await new_case(env)
    await search(env, cid, "93.184.216.34", "shodan")
    job = env.jobs("shodan")[0]
    assert job.quota_status == "disabled_provider" and not env.seen("api.shodan.io")                 # even with a key stored, no request leaves
    assert "Disabled — paid provider" in " ".join(job.warnings_json)
    r = await env.post("/api/v1/providers/shodan/enable", json={"confirm": True})
    assert r.status_code == 409 and r.json()["code"] == "paid_provider"                               # re-enabling needs explicit entitlement confirmation
    u = (await env.get("/api/v1/providers/usage")).json()
    sh = next(p for p in u["providers"] if p["provider"] == "shodan")
    assert sh["state"]["label"] == "Disabled — paid provider" and sh["paid_only"] is True
    from osintcc.profile.registry import SOURCES
    assert "shodan" not in SOURCES and "censys" not in SOURCES                                        # automatic investigation planning never offers them


async def test_pause_holds_every_queued_job_and_resume_releases_them(env, world, clock):
    world["vt"] = (429, {})
    cid = await new_case(env)
    await search(env, cid, "example.org", "virustotal")
    assert env.jobs("virustotal")[0].status == "deferred"
    world["vt"] = (200, vt_body())
    assert (await env.post("/api/v1/providers/pause")).json()["paused"] is True
    clock.advance(24 * 3600)
    assert (await env.st.quota_resumer.tick())["paused"] == 1 and env.jobs("virustotal")[0].status == "deferred"       # held while paused, not lost
    await env.post("/api/v1/providers/resume")
    await env.st.quota_resumer.tick()
    assert env.jobs("virustotal")[0].quota_status == "completed"


async def test_deferred_work_resumes_by_itself_after_a_restart_without_repeating_finished_work(settings, world, clock, monkeypatch):
    settings.retry_scale = 1.0
    monkeypatch.setattr("osintcc.jobs.runner._now", clock)
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(world)))

    def build():
        a = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns, secret=world["secrets"].get))
        a.state.core.quota.now = clock
        return a
    world["vt"] = (429, {})
    app = build()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            cid = await new_case(c)
            await search(c, cid, "example.org", "virustotal")
            before = len(world["requests"])
    world["vt"] = (200, vt_body())
    app2 = build()                                                                                    # the process "restarted": new objects, same encrypted database
    async with app2.router.lifespan_context(app2):
        env2 = Env(app2, clock, world)
        assert env2.jobs("virustotal")[0].status == "deferred"                                        # the queue survived
        await app2.state.core.quota_resumer.tick()
        assert env2.jobs("virustotal")[0].status == "deferred"                                        # not yet: the reset time has not come
        clock.advance(600)
        await app2.state.core.quota_resumer.tick()
        assert env2.jobs("virustotal")[0].quota_status == "completed"
        assert len(world["requests"]) == before + 1                                                   # exactly one new request: no duplicate submission


# =============================================================================================== credentials in use
async def test_censys_pat_is_sent_as_a_bearer_token_to_the_platform_api_and_is_never_stored(env, world):
    cid = await new_case(env)
    await search(env, cid, "93.184.216.34", "censys")
    req = env.seen("api.platform.censys.io")[0]
    assert req.headers["authorization"] == f"Bearer {PAT}" and req.url.path == "/v3/global/asset/host/93.184.216.34"
    assert req.headers["accept"] == "application/vnd.censys.api.v3.host.v1+json"
    job = env.jobs("censys")[0]
    assert job.quota_status == "completed" and job.provider == "censys"
    with env.st.sm() as db:
        dump = json.dumps([r.__dict__ for r in db.scalars(select(ProviderLedger)) if r.provider == "censys"], default=str) + json.dumps(
            [(s.provider, s.account_key, s.learned_json) for s in db.scalars(select(ProviderState))], default=str)
    assert PAT not in dump and "xxxxxxxx" not in dump                                                 # the ledger and state hold a fingerprint, never the token


async def test_a_censys_free_plan_403_marks_the_operation_plan_restricted_and_is_not_retried(env, world):
    world["censys"] = 403
    cid = await new_case(env)
    await search(env, cid, "93.184.216.34", "censys")
    await search(env, cid, "1.1.1.1", "censys")
    assert [j.quota_status for j in env.jobs("censys")] == ["blocked_plan", "blocked_plan"] and len(env.seen("api.platform.censys.io")) == 1


async def test_a_wrong_format_censys_credential_is_caught_on_save_and_at_dispatch(env, world):
    r = await env.post("/api/v1/secrets/censys", json={"value": "ID:SECRET"})
    assert r.status_code == 422 and r.json()["code"] == "wrong_format"
    world["secrets"]["censys"] = "ID:SECRET"                                                          # something stored earlier by an older version
    cid = await new_case(env)
    await search(env, cid, "93.184.216.34", "censys")
    assert env.jobs("censys")[0].quota_status == "blocked_credentials" and not env.seen("api.platform.censys.io")


async def test_brave_limits_are_learned_from_its_headers_and_overflow_is_never_requested(env, world, clock):
    from osintcc.adapters.http.email_first import WebSearchEmailAdapter
    ctx = env.st.runner.ctx_factory()
    res = await WebSearchEmailAdapter().run(__import__("osintcc.adapters.base", fromlist=["Target"]).Target(type="email", raw="a@b.org", canonical="a@b.org"), ctx)
    assert res.status in ("success", "partial")
    u = (await env.get("/api/v1/providers/usage")).json()
    brave = next(p for p in u["providers"] if p["provider"] == "brave")
    wins = {w["window"]: w for o in brave["operations"] for w in o["windows"]}
    assert any(w["basis"] == "provider headers" for w in wins.values())
    assert brave["axes"]["quota_available"] in ("no", "yes", "unknown") and brave["state"]["code"] in ("stored", "verified", "quota_exhausted")


# =============================================================================================== SEC EDGAR contact
async def test_edgar_contact_validates_saves_reads_back_and_survives_a_restart(settings, world, clock):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(world)))

    def build():
        return create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns, secret=world["secrets"].get))
    app = build()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            for bad in ("", "jane@example.org", "Jane Analyst", "Jane Analyst jane@@example.org", "Jane <script> jane@example.org"):
                if bad == "":
                    continue
                r = await c.put("/api/v1/settings", json={"values": {"edgar_contact": bad}})
                assert r.status_code == 422 and r.json()["code"] == "invalid_contact", bad
            assert (await c.get("/api/v1/settings")).json()["edgar_contact"] in (None, "")
            r = await c.put("/api/v1/settings", json={"values": {"edgar_contact": "  Jane   Analyst  jane@example.org "}})
            body = r.json()
            assert r.status_code == 200 and body["edgar_contact"] == "Jane Analyst jane@example.org" and body["edgar_contact_verified_readback"] is True
            assert body["edgar_contact_saved_at"]
    app2 = build()                                                                                    # restart
    async with app2.router.lifespan_context(app2):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app2), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            again = (await c.get("/api/v1/settings")).json()
            assert again["edgar_contact"] == "Jane Analyst jane@example.org" and again["edgar_contact_saved_at"]


async def test_edgar_without_a_valid_contact_is_blocked_visibly_and_with_one_sends_it_as_the_user_agent(env, world):
    from osintcc.adapters.base import Target
    from osintcc.adapters.http.edgar import EdgarAdapter
    from osintcc.quota.gate import JobScope
    from osintcc.quota.outcome import job_outcome
    t = Target(type="cik", raw="320193", canonical="cik:0000320193")
    ctx = env.st.runner.ctx_factory()
    ctx.config = _cfg(env.app)
    res = await EdgarAdapter().run(t, ctx)
    assert res.status == "skipped" and res.error_code == "requires_config" and not env.seen("data.sec.gov")        # nothing was sent
    o = job_outcome(res, JobScope(), env.clock())
    assert o.quota_status == "blocked_credentials" and "contact" in o.reason.lower()                                  # blocked and said so: not completed, not "no match"
    assert (await env.put("/api/v1/settings", json={"values": {"edgar_contact": "Jane Analyst jane@example.org"}})).status_code == 200
    ctx.config = _cfg(env.app)
    ok = await EdgarAdapter().run(t, ctx)
    assert ok.status == "success"
    sent = env.seen("data.sec.gov")
    assert sent and sent[0].headers["user-agent"] == "Jane Analyst jane@example.org"


async def test_edgar_requests_are_paced_below_the_sec_limit_for_the_whole_application(rig, env, clock):
    got = 0
    for _ in range(12):
        r = rig.take("https://data.sec.gov/submissions/CIK0000320193.json")
        if isinstance(r, Reservation):
            got += 1
            rig.settle_ok(r)
    assert got == 1                                                                                   # 0.25 s spacing: the rest wait, nothing is sent in a burst
    clock.advance(0.3)
    assert isinstance(rig.take("https://data.sec.gov/submissions/CIK0000320193.json"), Reservation)


async def test_edgar_save_failures_are_reported_not_swallowed(env, monkeypatch):
    bad = await env.put("/api/v1/settings", json={"values": {"edgar_contact": "nonsense"}})
    assert bad.status_code == 422 and "email" in bad.json()["message"].lower()
    cleared = await env.put("/api/v1/settings", json={"values": {"edgar_contact": ""}})
    assert cleared.status_code == 200 and cleared.json()["edgar_contact"] == ""


# =============================================================================================== usage, queue and ledger views
async def test_usage_view_separates_stored_verified_supported_and_available_and_never_contains_a_secret(env, world):
    cid = await new_case(env)
    await search(env, cid, "example.org", "virustotal")
    u = (await env.get("/api/v1/providers/usage")).json()
    text = json.dumps(u)
    for secret in (*SECRETS.values(),):
        assert secret not in text
    vt = next(p for p in u["providers"] if p["provider"] == "virustotal")
    assert vt["axes"] == {"stored_credential": "yes", "live_authentication": "yes", "endpoint_supported": "yes", "quota_available": "yes"}
    assert vt["state"]["code"] == "verified" and vt["verified_at"] and u["timezone"] == "UTC" and u["spend_guard"]["paid_spend_usd"] == 0
    minute = next(w for o in vt["operations"] for w in o["windows"] if w["window"] == "rolling:60")
    assert minute["limit"] == 4 and minute["used"] == 1 and minute["remaining"] == 3 and u["note"].startswith("Counts are Fusion's own estimate")
    ce = next(p for p in u["providers"] if p["provider"] == "censys")
    assert ce["state"]["code"] == "stored" and ce["axes"]["live_authentication"] == "not_tested"       # a stored key is not a verified key
    ed = (await env.get("/api/v1/secrets")).json()["items"]
    assert next(i for i in ed if i["provider"] == "censys")["state"]["code"] == "stored"


async def test_queue_and_ledger_are_audit_friendly_and_contain_no_keys_or_targets(env, world, clock):
    world["vt"] = (429, {})
    cid = await new_case(env)
    await search(env, cid, "secret-target.example.org", "virustotal")
    q = (await env.get("/api/v1/providers/queue")).json()
    assert q["items"] and q["items"][0]["status"] == "deferred_rate_limit" and q["items"][0]["next_eligible_at"] and q["items"][0]["source"] == "virustotal"
    led = (await env.get("/api/v1/providers/ledger")).json()
    blob = json.dumps(q) + json.dumps(led, default=str)
    assert VT_KEY not in blob and "secret-target" not in blob
    assert led["items"][0]["provider"] == "virustotal" and led["items"][0]["classification"] == "rate_limited" and led["items"][0]["http_status"] == 429


async def test_the_test_button_needs_confirmation_is_accounted_and_reads_the_urlscan_quota_table(env, world):
    r = await env.post("/api/v1/providers/urlscan/test", json={})
    assert r.status_code == 409 and r.json()["code"] == "confirmation_required"
    assert not env.seen("urlscan.io")
    ok = await env.post("/api/v1/providers/urlscan/test", json={"confirm": True})
    assert ok.status_code == 200 and ok.json()["state"] == "verified"
    snap = next(p for p in (await env.get("/api/v1/providers/usage")).json()["providers"] if p["provider"] == "urlscan")
    search_min = next(w for o in snap["operations"] if o["id"] == "search" for w in o["windows"] if w["window"] == "utc_minute")
    assert search_min["limit"] == 30 and search_min["basis"] == "provider headers"                   # the account's real limit replaced the default
    with env.st.sm() as db:
        assert db.scalar(select(func.count()).select_from(ProviderLedger).where(ProviderLedger.provider == "urlscan")) == 1


# =============================================================================================== one-click: partial, queued, resumed
async def test_one_click_investigation_shows_why_it_is_partial_what_waits_and_when_it_resumes(env, world, clock):
    from test_investigation import AUTH, finish, prepare
    env.quota.set_licensed("virustotal", True)                                                        # a business investigation: the operator confirmed a covering VirusTotal licence
    inputs = [{"kind": "domain", "value": f"{n}.example.org"} for n in ("alpha", "beta", "gamma")]
    p = await prepare(env, inputs, kind="business", start=True, approved_sources="listed")
    rid = p["run"]["id"]
    vt_rows = [r for r in p["manifest"]["rows"] if r["source_id"] == "virustotal"]
    assert vt_rows and all(r["status"] == "needs_approval" for r in vt_rows)
    st = await finish(env, rid, limit=20)
    for _ in range(30):                                                                               # let the background driver settle
        st = (await env.get(f"{B}/investigations/{rid}")).json()
        if st["status"] not in ("queued", "collecting", "correlating", "expanding"):
            break
        await asyncio.sleep(0.05)
    assert st["status"] == "waiting_limits", st                                                       # not complete, not failed: waiting for a rate limit
    u = st["units"]
    assert u["waiting_limits"] >= 1 and u["remaining"] >= 1 and u["done"] + u["no_match"] >= 1
    assert st["next_eligible_at"]
    summ = (await env.get(f"{B}/investigations/{rid}/summary")).json()
    assert summ["run"]["status"] == "waiting_limits" and any(a["kind"] == "info" and "waiting" in a["text"] for a in summ["next_actions"])
    assert any(x["code"] == "waiting_limits" for x in summ["limits"])
    assert summ["progress"]["status"] != "completed"
    sent_so_far = len(env.seen("www.virustotal.com"))
    assert 1 <= sent_so_far <= 3
    for _ in range(40):                                                                               # the clock moves on; the durable resumer finishes the queue
        clock.advance(20)
        await env.st.quota_resumer.tick()
        await asyncio.sleep(0.05)
        st = (await env.get(f"{B}/investigations/{rid}")).json()
        if st["status"] not in ("waiting_limits", "queued", "collecting", "correlating", "expanding"):
            break
    assert st["status"] in ("complete_with_limits", "awaiting_review", "completed") and st["units"]["waiting_limits"] == 0
    assert len(env.seen("www.virustotal.com")) == 3                                                   # every allowed lookup was made exactly once
    assert AUTH


async def test_authorization_is_checked_again_when_deferred_work_resumes(env, world, clock):
    from test_investigation import prepare
    env.quota.set_licensed("virustotal", True)
    world["vt"] = (429, {})
    p = await prepare(env, [{"kind": "domain", "value": "alpha.example.org"}], kind="business", start=True, approved_sources="listed")
    rid = p["run"]["id"]
    for _ in range(40):
        st = (await env.get(f"{B}/investigations/{rid}")).json()
        if st["status"] == "waiting_limits":
            break
        await asyncio.sleep(0.05)
    assert st["status"] == "waiting_limits"
    from osintcc.db.models import SubjectConsent
    with env.st.sm() as db:                                                                           # the authorization is withdrawn while the work waits
        from osintcc.db.models import Subject
        from osintcc.profile import consent as _consent
        for sub in db.scalars(select(Subject)):
            for cns in db.scalars(select(SubjectConsent).where(SubjectConsent.subject_id == sub.id)):
                _consent.revoke(db, sub, cns.id, reason="withdrawn while queued")
        db.commit()
    world["vt"] = (200, vt_body())
    before = len(env.seen("www.virustotal.com"))
    clock.advance(3600)
    await env.st.quota_resumer.tick()
    assert len(env.seen("www.virustotal.com")) == before                                              # nothing was sent after the withdrawal
    assert all(j.quota_status == "awaiting_authorization" and j.status == "denied" for j in env.jobs("virustotal"))   # held back and labelled: neither sent nor "completed"


def test_the_ledger_and_state_tables_have_no_column_that_could_hold_a_secret():
    cols = {c.name for t in (ProviderLedger.__table__, ProviderState.__table__) for c in t.columns}
    assert not [c for c in cols if any(w in c for w in ("key", "token", "secret", "password", "pin")) and c != "account_key"]


# =============================================================================================== no bypass
METERED_HOSTS = ("virustotal.com", "urlscan.io", "censys.io", "platform.censys.io", "api.search.brave.com", "sec.gov", "shodan.io")
DIRECT_CLIENT = ("httpx.AsyncClient(", "httpx.Client(", "SafeHttp(", "urllib.request", "requests.get", "requests.post", "aiohttp")


def test_no_code_path_names_a_metered_provider_and_also_builds_its_own_http_client():
    """Inventory of provider call sites: the only code that mentions a metered provider's host talks through ctx.http (the dispatcher), never through a client of its own."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "backend" / "osintcc"
    offenders = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if any(h in text for h in METERED_HOSTS) and any(d in text for d in DIRECT_CLIENT):
            offenders.append(str(path.relative_to(root)))
    assert offenders == [], offenders


def test_the_only_modules_that_build_http_clients_are_known_and_none_is_a_metered_provider():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "backend" / "osintcc"
    known = {"policy/ssrf.py": "the SSRF-safe client that the dispatcher wraps", "main.py": "wraps it in the dispatcher", "adapters/active/http_metadata.py": "AIV check of the operator's own asset",
             "ai/providers.py": "LLM endpoints (local Ollama, optional cloud model), not an OSINT data provider", "api/v1/updates.py": "signed update manifest and download",
             "automations/notifications.py": "operator-approved webhooks", "setup/installer.py": "pinned tool and model downloads"}
    found = {str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*.py") if any(d in p.read_text(encoding="utf-8") for d in ("httpx.AsyncClient(", "SafeHttp(", "httpx.Client("))}
    assert found - set(known) == set(), found - set(known)


async def test_every_context_handed_to_an_adapter_goes_through_the_dispatcher(env):
    from osintcc.quota import GatedHttp
    assert isinstance(env.st.runner.ctx_factory().http, GatedHttp)
    assert env.st.runner.quota is env.quota


# =============================================================================================== migration 0018 rehearsal
def test_migration_0018_is_additive_keeps_existing_jobs_and_downgrades_cleanly(tmp_path):
    from alembic import command
    from osintcc.db import make_engine
    from osintcc.db.migrate import _cfg, current_revision, upgrade_to_head
    from sqlalchemy import inspect, text
    p = tmp_path / "m.db"
    eng = make_engine(p)
    with eng.begin() as conn:
        command.upgrade(_cfg(eng, conn), "0017")
    assert current_revision(eng) == "0017"
    with eng.begin() as conn:                                                                         # a database that already holds a case, a search run and a finished job
        conn.execute(text("INSERT INTO cases (id, title, description, category, status, purpose, legal_basis_notes, scope_json, created_at, updated_at) "
                          "VALUES ('c1','Old case','','general','open','p','','{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO targets (id, case_id, type, raw_input, canonical_value, scope_status, created_at) VALUES ('t1','c1','domain','example.org','example.org','in_scope', CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO search_runs (id, case_id, target_id, mode, selected_adapters_json, permission_snapshot_json, status, started_at, summary_json) "
                          "VALUES ('r1','c1','t1','passive','[]','{}','succeeded', CURRENT_TIMESTAMP, '{}')"))
        conn.execute(text("INSERT INTO jobs (id, run_id, adapter_id, status, idempotency_key, attempts, max_attempts, warnings_json, result_keys_json, created_at) "
                          "VALUES ('j1','r1','rdap','succeeded','k1',1,3,'[]','[]', CURRENT_TIMESTAMP)"))
    upgrade_to_head(eng, p)
    assert current_revision(eng) >= "0018"
    assert p.with_suffix(".pre-0017.bak").exists()                                                    # the automatic safety copy
    cols = {c["name"] for c in inspect(eng).get_columns("jobs")}
    assert {"quota_status", "provider", "operation", "priority", "consumption_known", "scope_ref", "deferrals"} <= cols
    with eng.begin() as conn:
        row = conn.execute(text("SELECT status, quota_status, provider, priority, deferrals FROM jobs WHERE id='j1'")).one()
    assert tuple(row) == ("succeeded", "queued", "", 5, 0)                                            # untouched data, neutral defaults for the new columns
    assert {"provider_ledger", "provider_state"} <= set(inspect(eng).get_table_names())
    with eng.begin() as conn:
        command.downgrade(_cfg(eng, conn), "0017")
    assert current_revision(eng) == "0017" and "quota_status" not in {c["name"] for c in inspect(eng).get_columns("jobs")}
    with eng.begin() as conn:
        assert conn.execute(text("SELECT count(*) FROM jobs")).scalar() == 1                          # rollback keeps the work
    eng.dispose()


# =============================================================================================== licensing, global cancel, scope reference
async def test_virustotal_public_api_is_blocked_for_business_use_until_a_licence_is_confirmed_and_rechecked_when_work_resumes(env, world, clock):
    from test_investigation import prepare
    biz = await prepare(env, [{"kind": "domain", "value": "alpha.example.org"}], kind="business")
    row = next(r for r in biz["manifest"]["rows"] if r["source_id"] == "virustotal")
    assert row["status"] == "blocked" and "non-commercial" in row["reason"]                           # the plan says so; nothing is sent
    me = await prepare(env, [{"kind": "domain", "value": "mine.example.org"}], kind="person")
    assert next(r for r in me["manifest"]["rows"] if r["source_id"] == "virustotal")["status"] == "needs_approval"   # a personal self-audit is the licensed use
    u = (await env.post("/api/v1/providers/virustotal/licence", json={"commercial_licensed": True})).json()
    assert next(p for p in u["providers"] if p["provider"] == "virustotal")["licence"]["confirmed"] is True
    assert (await env.post("/api/v1/providers/shodan/licence", json={"commercial_licensed": True})).status_code == 404
    again = await prepare(env, [{"kind": "domain", "value": "beta.example.org"}], kind="business")
    assert next(r for r in again["manifest"]["rows"] if r["source_id"] == "virustotal")["status"] == "needs_approval"
    world["vt"] = (429, {})
    p = await prepare(env, [{"kind": "domain", "value": "gamma.example.org"}], kind="business", start=True, approved_sources="listed")
    for _ in range(40):
        st = (await env.get(f"{B}/investigations/{p['run']['id']}")).json()
        if st["status"] == "waiting_limits":
            break
        await asyncio.sleep(0.05)
    assert st["status"] == "waiting_limits"
    env.quota.set_licensed("virustotal", False)                                                       # withdrawn while the work waits
    world["vt"] = (200, vt_body())
    sent = len(env.seen("www.virustotal.com"))
    clock.advance(3600)
    await env.st.quota_resumer.tick()
    assert len(env.seen("www.virustotal.com")) == sent                                                # re-checked at dispatch: nothing was sent
    assert [j.quota_status for j in env.jobs("virustotal") if j.status != "succeeded"][-1] == "awaiting_authorization"


async def test_cancel_queued_work_cancels_every_waiting_check_and_the_investigation_says_so(env, world, clock):
    from test_investigation import prepare
    env.quota.set_licensed("virustotal", True)
    world["vt"] = (429, {})
    p = await prepare(env, [{"kind": "domain", "value": "alpha.example.org"}], kind="business", start=True, approved_sources="listed")
    rid = p["run"]["id"]
    for _ in range(40):
        st = (await env.get(f"{B}/investigations/{rid}")).json()
        if st["status"] == "waiting_limits":
            break
        await asyncio.sleep(0.05)
    assert st["status"] == "waiting_limits"
    r = await env.post("/api/v1/providers/cancel-queued")
    assert r.status_code == 200 and r.json()["cancelled"] >= 1
    assert all(j.status in ("cancelled", "succeeded", "failed", "skipped", "denied") for j in env.jobs())
    world["vt"] = (200, vt_body())
    before = len(env.seen("www.virustotal.com"))
    for _ in range(30):
        clock.advance(60)
        await env.st.quota_resumer.tick()
        await asyncio.sleep(0.05)
        st = (await env.get(f"{B}/investigations/{rid}")).json()
        if st["status"] not in ("waiting_limits", "queued", "collecting", "correlating", "expanding"):
            break
    assert len(env.seen("www.virustotal.com")) == before                                              # cancelled work never runs
    summ = (await env.get(f"{B}/investigations/{rid}/summary")).json()
    assert st["status"] in ("complete_with_limits", "awaiting_review") and any(x["code"] == "work_cancelled" for x in summ["limits"])   # not "complete"


async def test_a_job_records_what_it_ran_under_and_the_sec_plan_row_needs_a_valid_contact(env, world):
    from test_investigation import prepare
    env.quota.set_licensed("virustotal", True)
    p = await prepare(env, [{"kind": "domain", "value": "alpha.example.org"}], kind="business", start=True, approved_sources="listed")
    for _ in range(40):
        await env.post(f"{B}/investigations/{p['run']['id']}/advance")
        if all(j.finished_at or j.status == "deferred" for j in env.jobs()):
            break
        await asyncio.sleep(0.05)
    assert env.jobs() and all(j.scope_ref for j in env.jobs() if j.attempts)                           # every job that ran says which consent or run it ran under
    assert any(j.scope_ref.startswith("task:") for j in env.jobs())
    notice = env.quota.notice("sec_edgar")
    assert notice and notice["state"] == "missing_config" and "contact" in notice["text"].lower()
    assert (await env.put("/api/v1/settings", json={"values": {"edgar_contact": "Jane Analyst jane@example.org"}})).status_code == 200
    assert env.quota.notice("sec_edgar") is None
