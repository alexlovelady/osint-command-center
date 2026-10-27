"""The shared provider dispatcher (addendum PQ-1.0).

Every outbound request to a metered provider is reserved here BEFORE it is sent and settled after it returns. Reservations are made under one lock and committed to the
encrypted database, so two investigations that share a credential can never both spend the last slot, and the counters survive a restart because they are computed from the
persisted ledger. Nothing in this module reads or stores a key: a credential is represented only by a short one-way fingerprint.
"""
from __future__ import annotations

import hashlib
import json
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from ..db.models import Job, ProviderLedger, ProviderState, Setting
from .catalog import (
    ADAPTER_PROVIDER,
    FIXED_DAY,
    FIXED_HOUR,
    FIXED_MINUTE,
    FIXED_MONTH,
    PROVIDERS,
    ROLLING,
    WAITING_STATUSES,
    Operation,
    Provider,
    Route,
    Window,
    classify,
)

LEASE_SECONDS = 90
MAX_BACKOFF = 3600
PAUSE_KEY = "quota.paused"


def _now() -> datetime:
    return datetime.now(UTC)


def _aw(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=UTC) if d is not None and d.tzinfo is None else d


def window_start(kind: str, seconds: int, now: datetime) -> datetime:
    if kind == ROLLING:
        return now - timedelta(seconds=seconds)
    if kind == FIXED_MINUTE:
        return now.replace(second=0, microsecond=0)
    if kind == FIXED_HOUR:
        return now.replace(minute=0, second=0, microsecond=0)
    if kind == FIXED_DAY:
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)        # FIXED_MONTH


def window_end(kind: str, now: datetime) -> datetime:
    """The next reset of a calendar window (UTC)."""
    start = window_start(kind, 0, now)
    if kind == FIXED_MINUTE:
        return start + timedelta(minutes=1)
    if kind == FIXED_HOUR:
        return start + timedelta(hours=1)
    if kind == FIXED_DAY:
        return start + timedelta(days=1)
    return (start.replace(day=28) + timedelta(days=4)).replace(day=1)             # first of the next month


@dataclass
class Reservation:
    id: str
    provider: str
    operation: str
    account_key: str
    reserved_at: datetime


@dataclass
class Denial:
    status: str                 # one of catalog.TASK_STATUSES
    reason: str
    eligible_at: datetime | None = None
    provider: str = ""
    operation: str = ""
    window: str = ""

    @property
    def retry_after(self) -> int:
        return max(1, int((self.eligible_at - _now()).total_seconds()) + 1) if self.eligible_at else 60


@dataclass
class Outcome:
    classification: str                     # ok | no_record | rejected_credentials | plan_restricted | insufficient_credits | rate_limited | server_error | timeout | client_error
    quota_status: str | None = None         # the task status this response implies, when it is not a plain success
    eligible_at: datetime | None = None
    reason: str = ""
    http_status: int | None = None
    provider: str = ""
    operation: str = ""
    consumption_known: bool | None = None


@dataclass
class _Eff:
    """A window as it applies right now: the default limit tightened by anything the provider has told us."""
    wid: str
    kind: str
    seconds: int
    limit: float
    unit: str
    status: str
    basis: str
    authoritative_remaining: float | None = None
    reset_at: datetime | None = None
    observed_at: datetime | None = None
    ledger: bool = True


def fingerprint(provider: str, secret: str | None) -> str:
    """A short one-way identifier for 'which account'. It is not reversible to the credential and is never shown."""
    return hashlib.sha256(f"osintcc-account:{provider}:{secret}".encode()).hexdigest()[:12] if secret else "anon"


def _parse_retry_after(v: str | None, now: datetime) -> float | None:
    if not v:
        return None
    v = v.strip()
    if v.isdigit():
        return float(v)
    try:
        return max(0.0, (parsedate_to_datetime(v) - now).total_seconds())
    except (TypeError, ValueError):
        return None


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def _from_iso(s: Any) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(s))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


class QuotaService:
    def __init__(self, sm: sessionmaker, secret: Callable[[str], str | None], *, now: Callable[[], datetime] = _now, rng: Callable[[], float] = random.random,
                 enforce: bool = True, contact: Callable[[], str | None] = lambda: None):
        self.sm, self._secret, self.now, self.rng, self.enforce, self._contact = sm, secret, now, rng, enforce, contact
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ identity and switches
    def account_key(self, prov: Provider) -> str:
        if prov.id == "sec_edgar":                   # the SEC identifies you by the contact in the User-Agent, so changing it starts a clean slate
            return fingerprint(prov.id, " ".join((self._contact() or "").split()).lower() or None)
        return fingerprint(prov.id, self._secret(prov.credential)) if prov.credential else "anon"

    def classify(self, url: str) -> Route | None:
        return classify(url)

    def is_paused(self) -> bool:
        with self.sm() as db:
            row = db.get(Setting, PAUSE_KEY)
            return bool(row and row.value_json)

    def set_paused(self, paused: bool) -> None:
        with self.sm() as db:
            db.merge(Setting(key=PAUSE_KEY, value_json=bool(paused)))
            db.commit()

    def set_disabled(self, provider: str, disabled: bool, reason: str = "Turned off by you") -> None:
        prov = PROVIDERS[provider]
        with self._lock, self.sm() as db:
            st = self._state(db, provider, self.account_key(prov))
            if prov.paid_only and not disabled:
                # Re-enabling a paid provider is a deliberate act that Fusion records; it never buys anything and never turns on by itself.
                st.learned_json = {**st.learned_json, "_paid_opt_in": _iso(self.now())}
            elif prov.paid_only:
                st.learned_json = {k: v for k, v in st.learned_json.items() if k != "_paid_opt_in"}
            st.disabled, st.disabled_reason = bool(disabled), reason if disabled else ""
            st.updated_at = self.now()
            db.commit()

    def clear_restrictions(self, provider: str) -> None:
        """The operator changed plan or key and wants a fresh try: forget 'rejected' and 'plan restricted' marks and any backoff."""
        prov = PROVIDERS[provider]
        with self._lock, self.sm() as db:
            st = self._state(db, provider, self.account_key(prov))
            st.learned_json = {k: v for k, v in st.learned_json.items() if k not in ("_restricted_ops", "_backoff")}
            st.verified_state, st.blocked_until, st.blocked_status, st.last_error = "", None, "", ""
            db.commit()

    # ------------------------------------------------------------------ state rows
    def _state(self, db: Session, provider: str, acct: str) -> ProviderState:
        st = db.get(ProviderState, (provider, acct))
        if st is None:
            st = ProviderState(provider=provider, account_key=acct, learned_json={}, blocked_status="", disabled=False, disabled_reason="", verified_state="",
                               last_error="", updated_at=self.now())
            db.add(st)
            db.flush()
        return st

    def _peek(self, db: Session, provider: str, acct: str) -> ProviderState:
        """Read-only view of the state row: never writes, so it is safe to call while another transaction of the caller is open."""
        return db.get(ProviderState, (provider, acct)) or ProviderState(provider=provider, account_key=acct, learned_json={}, blocked_status="", disabled=False,
                                                                       disabled_reason="", verified_state="", last_error="", updated_at=self.now())

    def _effective(self, prov: Provider, op: Operation, st: ProviderState, now: datetime) -> list[_Eff]:
        learned = {e["wid"]: e for e in (st.learned_json.get("ops", {}).get(op.id, []) if isinstance(st.learned_json.get("ops"), dict) else []) if isinstance(e, dict)}
        out: list[_Eff] = []
        seen: set[str] = set()
        for w in op.windows:
            e = learned.get(w.wid)
            seen.add(w.wid)
            lim = w.limit
            eff = _Eff(w.wid, w.kind, w.seconds, lim, w.unit, w.status, w.basis)
            if e:
                reset = _from_iso(e.get("reset_at"))
                if e.get("limit") and (reset is None or reset > now):
                    eff.limit, eff.basis = min(w.limit, float(e["limit"])), "provider headers"
                if e.get("remaining") is not None and reset and reset > now:
                    eff.authoritative_remaining, eff.reset_at, eff.observed_at = float(e["remaining"]), reset, _from_iso(e.get("observed_at"))
            out.append(eff)
        for wid, e in learned.items():                      # a window the provider reports that we have no default for (e.g. a monthly plan limit)
            if wid in seen:
                continue
            reset = _from_iso(e.get("reset_at"))
            if reset is None or reset <= now or e.get("remaining") is None:
                continue
            kind = FIXED_MONTH if e.get("seconds", 0) >= 20 * 86400 else FIXED_DAY if e.get("seconds", 0) >= 80000 else ROLLING
            status = "deferred_credits" if kind == FIXED_MONTH else "deferred_daily_quota" if kind == FIXED_DAY else "deferred_rate_limit"
            out.append(_Eff(wid, kind, int(e.get("seconds", 0)), float(e.get("limit") or 0), "requests", status, "provider headers", float(e["remaining"]), reset,
                            _from_iso(e.get("observed_at")), ledger=False))
        return out

    def _rows(self, db: Session, prov: str, op: str, acct: str, since: datetime, now: datetime) -> list[ProviderLedger]:
        q = select(ProviderLedger).where(ProviderLedger.provider == prov, ProviderLedger.operation == op, ProviderLedger.account_key == acct,
                                         ProviderLedger.reserved_at >= since, ProviderLedger.state.in_(("inflight", "settled", "expired")))
        return list(db.scalars(q))

    # ------------------------------------------------------------------ reserve
    def reserve(self, route: Route, *, case_id: str | None = None, job_id: str | None = None) -> Reservation | Denial:
        """Atomically check every budget and, only if all have room, record the reservation. If the database is busy the answer is 'not now', never 'go ahead'."""
        try:
            return self._reserve(route, case_id=case_id, job_id=job_id)
        except OperationalError:
            return Denial("deferred_rate_limit", "The usage ledger was busy; trying again in a moment.", self.now() + timedelta(seconds=2), route.provider.id, route.operation.id, "ledger")

    def _reserve(self, route: Route, *, case_id: str | None = None, job_id: str | None = None) -> Reservation | Denial:
        prov, op = route.provider, route.operation
        with self._lock, self.sm() as db:
            now = self.now()
            acct = self.account_key(prov)
            st = self._state(db, prov.id, acct)

            def deny(status: str, reason: str, eligible: datetime | None = None, window: str = "") -> Denial:
                return Denial(status, reason, eligible, prov.id, op.id, window)

            if prov.disabled and not st.learned_json.get("_paid_opt_in"):
                return deny("disabled_provider", prov.disabled)
            if st.disabled:
                return deny("disabled_provider", st.disabled_reason or "Turned off by you")
            if op.blocked:
                return deny("blocked_plan", op.blocked)
            if st.verified_state == "rejected":
                return deny("blocked_credentials", f"{prov.label} rejected the stored credential earlier. Replace it in Settings; Fusion will not keep retrying it.")
            if op.id in (st.learned_json.get("_restricted_ops") or []):
                return deny("blocked_plan", f"{prov.label} says this account's plan does not include this operation. Fusion will not retry it until the plan or key changes.")
            bu = _aw(st.blocked_until)
            if bu and bu > now:
                return deny(st.blocked_status or "deferred_rate_limit", f"{prov.label} asked Fusion to wait.", bu)
            if not self.enforce:
                return self._take(db, prov, op, acct, case_id, job_id, now)
            effs = self._effective(prov, op, st, now)
            eligible: datetime | None = None
            blocking: _Eff | None = None
            horizon = now - timedelta(days=1)
            if any(e.kind == FIXED_MONTH for e in effs):
                horizon = window_start(FIXED_MONTH, 0, now)
            for e in effs:
                if e.kind == ROLLING:
                    horizon = min(horizon, now - timedelta(seconds=e.seconds))
            rows = self._rows(db, prov.id, op.id, acct, horizon, now)
            live = [r for r in rows if r.state != "inflight" or (_aw(r.lease_until) or now) > now]
            for e in effs:
                start = window_start(e.kind, e.seconds, now)
                used = sum(r.cost for r in live if (_aw(r.reserved_at) or now) >= start) if e.ledger else 0.0
                need = op.cost if e.unit == "credits" else 1.0
                at: datetime | None = None
                if e.authoritative_remaining is not None and e.reset_at:
                    since_obs = sum(r.cost for r in live if (e.observed_at is None or (_aw(r.reserved_at) or now) > e.observed_at))
                    if e.authoritative_remaining - since_obs < need:
                        at = e.reset_at
                if at is None and e.ledger and e.limit and used + need > e.limit:
                    if e.kind == ROLLING:
                        inwin = sorted((r for r in live if (_aw(r.reserved_at) or now) >= start), key=lambda r: r.reserved_at)
                        freed = 0.0
                        at = now + timedelta(seconds=e.seconds)
                        for r in inwin:
                            freed += r.cost
                            if used - freed + need <= e.limit:
                                at = (_aw(r.reserved_at) or now) + timedelta(seconds=e.seconds)
                                break
                    else:
                        at = window_end(e.kind, now)
                if at is not None and (eligible is None or at > eligible):
                    eligible, blocking = at, e
            if op.min_spacing and live:
                last = max((_aw(r.reserved_at) or now) for r in live)
                at = last + timedelta(seconds=op.min_spacing)
                if at > now and (eligible is None or at > eligible):
                    eligible, blocking = at, _Eff("spacing", ROLLING, int(op.min_spacing), 0, "requests", "deferred_rate_limit", "assumption")
            if op.concurrency:
                inflight = [r for r in live if r.state == "inflight"]
                if len(inflight) >= op.concurrency:
                    at = now + timedelta(seconds=2)
                    if eligible is None or at > eligible:
                        eligible, blocking = at, _Eff("concurrency", ROLLING, 2, 0, "requests", "deferred_rate_limit", "documented")
            if eligible is not None and blocking is not None:
                why = {"deferred_credits": "No credits are left in this window (Fusion never buys more).", "deferred_daily_quota": "The daily quota is used up.",
                       "deferred_rate_limit": "The rate limit is reached."}[blocking.status]
                if blocking.wid == "concurrency":
                    why = f"{prov.label} allows {op.concurrency} request at a time; another is in progress."
                elif blocking.wid == "spacing":
                    why = f"Requests to {prov.label} are spaced at least {op.min_spacing:g} seconds apart."
                return deny(blocking.status, why, eligible + timedelta(seconds=0.05 + self.rng() * 0.5), blocking.wid)
            return self._take(db, prov, op, acct, case_id, job_id, now)

    def _take(self, db: Session, prov: Provider, op: Operation, acct: str, case_id: str | None, job_id: str | None, now: datetime) -> Reservation:
        row = ProviderLedger(provider=prov.id, operation=op.id, account_key=acct, case_id=case_id, job_id=job_id, state="inflight", cost=op.cost, reserved_at=now,
                             lease_until=now + timedelta(seconds=LEASE_SECONDS), classification="", error_code="", url_host="")
        db.add(row)
        db.commit()
        return Reservation(row.id, prov.id, op.id, acct, now)

    # ------------------------------------------------------------------ settle
    def release(self, res: Reservation, reason: str = "not sent") -> None:
        with self._lock, self.sm() as db:
            row = db.get(ProviderLedger, res.id)
            if row and row.state == "inflight":
                row.state, row.finished_at, row.classification, row.consumption_known, row.error_code = "released", self.now(), "not_sent", False, reason[:40]
                db.commit()

    def settle(self, res: Reservation, *, status: int | None, headers: dict[str, str] | None = None, body: bytes | None = None, error: str | None = None,
               host: str = "") -> Outcome:
        """Record what the provider said. A request that has already left must be accounted for, so a busy database is retried before giving up."""
        for attempt in range(4):
            try:
                return self._settle(res, status=status, headers=headers, body=body, error=error, host=host)
            except OperationalError:
                if attempt == 3:
                    break
                time.sleep(0.25 * (attempt + 1))
        return Outcome("server_error" if (status or 0) >= 500 else "ok", None, None, "The usage ledger could not be updated; the count is an estimate.", status, res.provider, res.operation, None)

    def _settle(self, res: Reservation, *, status: int | None, headers: dict[str, str] | None = None, body: bytes | None = None, error: str | None = None,
                host: str = "") -> Outcome:
        prov = PROVIDERS[res.provider]
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        with self._lock, self.sm() as db:
            now = self.now()
            row = db.get(ProviderLedger, res.id)
            st = self._state(db, res.provider, res.account_key)
            out = Outcome("ok", provider=res.provider, operation=res.operation, http_status=status)
            if row is not None:
                row.finished_at, row.http_status, row.lease_until, row.url_host = now, status, None, host[:120]
            st.last_status, st.last_response_at, st.updated_at = status, now, now
            if status is None:
                out.classification, out.quota_status, out.consumption_known = "timeout", "transient_error", None
                st.last_error = (error or "no response")[:200]
                if row is not None:
                    row.state, row.classification, row.error_code = "settled", "timeout", (error or "")[:40]
            elif 200 <= status < 300:
                self._learn(prov, res.operation, st, headers, now)
                bo = st.learned_json.get("_backoff")
                if bo:
                    st.learned_json = {k: v for k, v in st.learned_json.items() if k != "_backoff"}
                st.blocked_until, st.blocked_status, st.last_error = None, "", ""
                if (prov.credential or prov.id == "sec_edgar") and res.account_key != "anon":
                    st.verified_state, st.verified_at = "verified", now
                out.consumption_known = True
                if row is not None:
                    row.state, row.classification, row.consumption_known = "settled", "ok", True
            elif status == 404:
                out.classification, out.consumption_known = "no_record", None
                self._learn(prov, res.operation, st, headers, now)
                if row is not None:
                    row.state, row.classification, row.consumption_known = "settled", "no_record", None
            elif status == 401:
                out.classification, out.quota_status, out.consumption_known = "rejected_credentials", "blocked_credentials", False
                out.reason = f"{prov.label} rejected the credential (HTTP 401)."
                if prov.credential and res.account_key != "anon":
                    st.verified_state = "rejected"
                st.last_error = out.reason
                if row is not None:
                    row.state, row.classification, row.consumption_known = "released", "rejected_credentials", False
            elif status == 403 and res.provider == "sec_edgar":
                out.classification, out.quota_status, out.consumption_known = "rejected_credentials", "blocked_credentials", False
                out.reason = "The SEC refused the request (HTTP 403). It needs a real name and email in the User-Agent; check the contact in Settings."
                st.verified_state, st.last_error = "rejected", out.reason
                if row is not None:
                    row.state, row.classification, row.consumption_known = "released", "rejected_credentials", False
            elif status == 403:
                out.classification, out.quota_status, out.consumption_known = "plan_restricted", "blocked_plan", False
                out.reason = f"{prov.label} refused this operation for the account (HTTP 403): the plan or permissions do not allow it."
                lj = dict(st.learned_json)
                lj["_restricted_ops"] = sorted({*lj.get("_restricted_ops", []), res.operation})
                st.learned_json, st.verified_state = lj, "plan_restricted"
                st.last_error = out.reason
                if row is not None:
                    row.state, row.classification, row.consumption_known = "released", "plan_restricted", False
            elif status == 402:
                out.classification, out.quota_status, out.consumption_known = "insufficient_credits", "deferred_credits", False
                out.eligible_at = window_end(FIXED_MONTH, now)
                out.reason = f"{prov.label} reports no credits left (HTTP 402). Fusion does not buy credits; it waits for the next reset."
                st.blocked_until, st.blocked_status, st.last_error = out.eligible_at, "deferred_credits", out.reason
                if row is not None:
                    row.state, row.classification, row.consumption_known = "released", "insufficient_credits", False
            elif status == 429 or (status == 503 and res.provider == "censys"):
                status_name, at, why = self._rate_limited(prov, res.operation, st, headers, body, now, concurrency=(res.provider == "censys"))
                out.classification, out.quota_status, out.eligible_at, out.reason, out.consumption_known = "rate_limited", status_name, at, why, False
                st.blocked_until, st.blocked_status, st.last_error = at, status_name, why[:200]
                if row is not None:
                    row.state, row.classification, row.consumption_known = "released", "rate_limited", False
            elif status >= 500:
                out.classification, out.quota_status, out.consumption_known = "server_error", "transient_error", None
                out.reason = f"{prov.label} had a server problem (HTTP {status})."
                st.last_error = out.reason
                if row is not None:
                    row.state, row.classification = "settled", "server_error"
            else:
                out.classification, out.consumption_known = "client_error", None
                st.last_error = f"HTTP {status}"
                if row is not None:
                    row.state, row.classification = "settled", "client_error"
            if row is not None:
                out.consumption_known = row.consumption_known if row.consumption_known is not None else out.consumption_known
            db.commit()
            return out

    # ------------------------------------------------------------------ learning from the provider
    def _learn(self, prov: Provider, op: str, st: ProviderState, headers: dict[str, str], now: datetime) -> None:
        entries: list[dict[str, Any]] = []
        if prov.id == "urlscan" and "x-rate-limit-limit" in headers:
            win = headers.get("x-rate-limit-window", "")
            wid = {"minute": FIXED_MINUTE, "hour": FIXED_HOUR, "day": FIXED_DAY}.get(win)
            action = headers.get("x-rate-limit-action", op)
            if wid:
                reset = _from_iso(headers.get("x-rate-limit-reset")) or (now + timedelta(seconds=float(headers.get("x-rate-limit-reset-after", "60") or 60)))
                op = action if action in prov.ops else op
                entries.append({"wid": wid, "limit": _num(headers.get("x-rate-limit-limit")), "remaining": _num(headers.get("x-rate-limit-remaining")),
                                "reset_at": _iso(reset), "observed_at": _iso(now), "seconds": 0})
        elif prov.id == "brave" and "x-ratelimit-limit" in headers:
            lim, rem, rst = (_nums(headers.get(h)) for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"))
            pol = [p.strip() for p in headers.get("x-ratelimit-policy", "").split(",") if p.strip()]
            wins = []
            for p in pol:
                try:
                    wins.append(int(p.split("w=")[1]))
                except (IndexError, ValueError):
                    wins.append(0)
            for i, lv in enumerate(lim):
                secs = wins[i] if i < len(wins) else (1 if i == 0 else 2592000)
                reset_s = rst[i] if i < len(rst) else float(secs)
                entries.append({"wid": f"{ROLLING}:{secs}", "limit": lv, "remaining": rem[i] if i < len(rem) else None, "reset_at": _iso(now + timedelta(seconds=reset_s)),
                                "observed_at": _iso(now), "seconds": secs})
        elif prov.id == "github" and "x-ratelimit-limit" in headers:
            gh_reset: datetime | None = datetime.fromtimestamp(int(headers["x-ratelimit-reset"]), UTC) if headers.get("x-ratelimit-reset", "").isdigit() else None
            res_name = headers.get("x-ratelimit-resource", "")
            if gh_reset:
                secs = 60 if res_name == "search" else 3600
                entries.append({"wid": f"{ROLLING}:{secs}", "limit": _num(headers.get("x-ratelimit-limit")), "remaining": _num(headers.get("x-ratelimit-remaining")),
                                "reset_at": _iso(gh_reset), "observed_at": _iso(now), "seconds": secs})
                op = "search" if res_name == "search" else "core"
        if not entries:
            return
        lj = dict(st.learned_json)
        ops = dict(lj.get("ops") or {})
        cur = {e["wid"]: e for e in ops.get(op, []) if isinstance(e, dict)}
        for e in entries:
            cur[e["wid"]] = e
        ops[op] = list(cur.values())
        lj["ops"] = ops
        st.learned_json = lj

    def _rate_limited(self, prov: Provider, op: str, st: ProviderState, headers: dict[str, str], body: bytes | None, now: datetime, *, concurrency: bool
                      ) -> tuple[str, datetime, str]:
        status_name, at, why = "deferred_rate_limit", None, f"{prov.label} is rate limiting requests."
        ra = _parse_retry_after(headers.get("retry-after"), now)
        if prov.id == "urlscan":
            self._learn(prov, op, st, headers, now)
            win = headers.get("x-rate-limit-window", "")
            reset = _from_iso(headers.get("x-rate-limit-reset"))
            after = _num(headers.get("x-rate-limit-reset-after"))
            if reset is None and after is not None:
                reset = now + timedelta(seconds=after)
            if reset:
                at = reset
            status_name = {"day": "deferred_daily_quota"}.get(win, "deferred_rate_limit")
            why = f"urlscan.io {headers.get('x-rate-limit-action', op)} limit reached for this {win or 'window'}."
        elif prov.id == "virustotal":
            code = ""
            try:
                code = str(json.loads(body or b"{}").get("error", {}).get("code", ""))
            except (ValueError, AttributeError):
                pass
            if code == "QuotaExceededError":
                status_name, at, why = "deferred_daily_quota", window_end(FIXED_DAY, now), "VirusTotal says the request quota is used up; it resets at 00:00 UTC."
        elif concurrency:
            at, why = now + timedelta(seconds=3 + self.rng() * 2), f"{prov.label} allows one request at a time (or its request rate was exceeded); trying again shortly."
        if at is None and ra is not None:
            at = now + timedelta(seconds=ra)
        if at is None:                                                # nothing authoritative: bounded exponential backoff with jitter
            bo = dict(st.learned_json.get("_backoff") or {})
            n = int(bo.get("n", 0)) + 1
            lj = dict(st.learned_json)
            lj["_backoff"] = {"n": n, "at": _iso(now)}
            st.learned_json = lj
            delay = min(MAX_BACKOFF, 30 * 2 ** (n - 1)) * (0.75 + self.rng() * 0.5)
            at = now + timedelta(seconds=delay)
        return status_name, at + timedelta(seconds=self.rng()), why

    def notice(self, adapter_id: str) -> dict[str, str] | None:
        """Why the provider behind an adapter cannot be used right now, in plain words (None when nothing is wrong). Used by the plan, before anything is queued."""
        pid = ADAPTER_PROVIDER.get(adapter_id)
        if pid is None:
            return None
        prov = PROVIDERS[pid]
        with self.sm() as db:
            st = self._peek(db, pid, self.account_key(prov))
            if prov.disabled and not st.learned_json.get("_paid_opt_in"):
                return {"state": "disabled", "text": prov.disabled}
            if st.disabled:
                return {"state": "disabled", "text": st.disabled_reason or "Turned off by you"}
            if st.verified_state == "rejected":
                return {"state": "rejected", "text": f"{prov.label} rejected the stored key. Replace it in Settings; nothing was sent."}
            if st.verified_state == "plan_restricted":
                return {"state": "plan_restricted", "text": f"{prov.label} says this account's plan does not include the operation. Nothing was sent."}
        return None

    # ------------------------------------------------------------------ housekeeping
    def expire_stale(self) -> int:
        """Reservations whose request never reported back (a crash): they stay counted (the request may have been spent) but no longer hold a concurrency slot."""
        n = 0
        with self._lock, self.sm() as db:
            now = self.now()
            for r in db.scalars(select(ProviderLedger).where(ProviderLedger.state == "inflight")):
                if (_aw(r.lease_until) or now) <= now:
                    r.state, r.finished_at, r.classification, r.consumption_known = "expired", now, "interrupted", None
                    n += 1
            db.commit()
        return n

    # ------------------------------------------------------------------ read model
    def snapshot(self) -> list[dict[str, Any]]:
        now = self.now()
        out = []
        with self.sm() as db:
            for prov in PROVIDERS.values():
                acct = self.account_key(prov)
                st = self._peek(db, prov.id, acct)
                ops = []
                for op in prov.ops.values():
                    if op.blocked and prov.paid_only:
                        continue
                    effs = self._effective(prov, op, st, now)
                    rows = self._rows(db, prov.id, op.id, acct, now - timedelta(days=32), now)
                    wins = []
                    for e in effs:
                        start = window_start(e.kind, e.seconds, now)
                        used = sum(r.cost for r in rows if (_aw(r.reserved_at) or now) >= start and (r.state != "inflight" or (_aw(r.lease_until) or now) > now)) if e.ledger else None
                        rem = None if used is None else max(0.0, e.limit - used)
                        if e.authoritative_remaining is not None and e.reset_at:
                            since = sum(r.cost for r in rows if e.observed_at is None or (_aw(r.reserved_at) or now) > e.observed_at)
                            auth = max(0.0, e.authoritative_remaining - since)
                            rem = auth if rem is None else min(rem, auth)
                        reset = e.reset_at or (window_end(e.kind, now) if e.kind != ROLLING else None)
                        wins.append({"window": e.wid, "unit": e.unit, "limit": e.limit or None, "used": used, "remaining": rem, "resets_at": _iso(reset), "basis": e.basis})
                    ops.append({"id": op.id, "label": op.label, "windows": wins, "concurrency": op.concurrency, "blocked": op.blocked,
                                "restricted": op.id in (st.learned_json.get("_restricted_ops") or [])})
                queued = {}
                for status, n in db.execute(select(Job.quota_status, func.count()).where(Job.provider == prov.id, Job.status.in_(("queued", "deferred", "running"))).group_by(Job.quota_status)):
                    queued[status] = n
                out.append({"provider": prov.id, "label": prov.label, "plan": prov.plan, "credential_name": prov.credential, "stored": bool(prov.credential and self._secret(prov.credential)),
                            "paid_only": prov.paid_only, "disabled": bool(st.disabled or (prov.disabled and not st.learned_json.get("_paid_opt_in"))),
                            "disabled_reason": st.disabled_reason or prov.disabled, "verified_state": st.verified_state, "verified_at": _iso(_aw(st.verified_at)),
                            "last_status": st.last_status, "last_error": st.last_error, "last_response_at": _iso(_aw(st.last_response_at)),
                            "blocked_until": _iso(bu) if (bu := _aw(st.blocked_until)) is not None and bu > now else None,
                            "operations": ops, "queued": queued, "reset_note": prov.reset_note, "limitations": list(prov.limitations), "terms": prov.terms,
                            "verified_live": prov.verified_live, "local_estimate": True})
        return out


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _nums(v: Any) -> list[float]:
    return [x for x in (_num(p.strip()) for p in str(v or "").split(",")) if x is not None]


__all__ = ["WAITING_STATUSES", "Denial", "Outcome", "QuotaService", "Reservation", "Window", "fingerprint", "window_end", "window_start"]

