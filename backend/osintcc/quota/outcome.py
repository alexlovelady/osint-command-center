"""Turn 'what the adapter returned' plus 'what the dispatcher saw' into one honest task status.

The rule this module exists to enforce: a refusal, a rate limit, a rejected credential, a missing credit or a timeout is NEVER reported as completed and NEVER as 'no match'.
Only a source that really answered (and answered with nothing) is a no match.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..adapters.base import AdapterResult
from .gate import JobScope

MAX_PROVIDER_DEFERRALS = 8      # consecutive 'rate limited, reset unknown' deferrals before the job is reported as a transient error (still resumable by the operator)


@dataclass
class JobOutcome:
    quota_status: str
    defer_until: datetime | None = None
    reason: str = ""
    provider: str = ""
    operation: str = ""
    consumption_known: bool | None = None
    retry: bool = False             # a transient error that the runner may retry (bounded by max_attempts)


def job_outcome(result: AdapterResult, scope: JobScope, now: datetime, *, deferrals: int = 0) -> JobOutcome:
    first = (scope.denials[0] if scope.denials else None)
    prov = first.provider if first else (scope.outcomes[0].provider if scope.outcomes else "")
    op = first.operation if first else (scope.outcomes[0].operation if scope.outcomes else "")
    cons = next((o.consumption_known for o in reversed(scope.outcomes) if o.consumption_known is not None), None)

    def out(status: str, reason: str = "", defer: datetime | None = None, retry: bool = False) -> JobOutcome:
        return JobOutcome(status, defer, reason, prov, op, cons, retry)

    if (d := scope.deferral) is not None:
        return out(d.status, d.reason, d.eligible_at or now + timedelta(seconds=60))
    if (b := scope.blocked) is not None:
        return out(b.status, b.reason)
    for o in reversed(scope.outcomes):                         # something the provider itself said during the run
        if o.quota_status in ("blocked_credentials", "blocked_plan"):
            return out(o.quota_status, o.reason)
        if o.quota_status in ("deferred_rate_limit", "deferred_daily_quota", "deferred_credits"):
            if deferrals >= MAX_PROVIDER_DEFERRALS and o.quota_status == "deferred_rate_limit":
                return out("transient_error", f"{o.reason} Gave up after {deferrals} waits; press Check for more to try again.")
            return out(o.quota_status, o.reason, o.eligible_at or now + timedelta(seconds=120))
    code = result.error_code or ""
    if result.status in ("success", "partial"):
        if result.status == "partial":
            return out("partial", "; ".join(result.warnings)[:300])
        return out("completed" if (result.findings or result.relationships) else "no_match", "")
    if result.status == "skipped":
        if code in ("requires_key", "requires_config"):
            return out("blocked_credentials", result.warnings[0] if result.warnings else "A credential or setting is missing.")
        return out("permanent_error", result.warnings[0] if result.warnings else code)
    if result.status == "rate_limited":
        if deferrals >= MAX_PROVIDER_DEFERRALS:
            return out("transient_error", "The source kept asking for a pause; press Check for more to try again.")
        return out("deferred_rate_limit", "The source asked for a pause.", now + timedelta(seconds=result.retry_after_seconds or 120))
    if code in ("timeout", "network_error") or code.startswith("http_5"):
        return out("transient_error", "; ".join(result.warnings)[:300] or code, retry=True)
    return out("permanent_error", "; ".join(result.warnings)[:300] or code)
