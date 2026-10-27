"""The enforcement point: an HTTP client every adapter already uses (`ctx.http`) that asks the dispatcher before each request to a metered provider.

Adapters are not edited to cooperate. When the dispatcher refuses a request this client returns a synthetic response (429 for 'wait', 401/403 for 'blocked') with an
`x-osintcc-deferred` or `x-osintcc-blocked` header, and records the real reason on the job's scope. The job runner reads that scope after the adapter returns, so a refusal
becomes a `deferred_*` or `blocked_*` task, never a completed one and never a 'no match'.
"""
from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..policy.ssrf import DestinationDenied, HttpClient, HttpResult
from .service import Denial, Outcome, QuotaService, Reservation


@dataclass
class JobScope:
    job_id: str | None = None
    case_id: str | None = None
    denials: list[Denial] = field(default_factory=list)
    outcomes: list[Outcome] = field(default_factory=list)
    sent: int = 0

    @property
    def deferral(self) -> Denial | None:
        return next((d for d in self.denials if d.status.startswith("deferred_")), None)

    @property
    def blocked(self) -> Denial | None:
        return next((d for d in self.denials if not d.status.startswith("deferred_")), None)


current_scope: contextvars.ContextVar[JobScope | None] = contextvars.ContextVar("osintcc_job_scope", default=None)

_BLOCK_HTTP = {"blocked_credentials": 401, "blocked_plan": 403, "disabled_provider": 403}


class GatedHttp:
    """Drop-in for SafeHttp.get with provider budgets."""

    def __init__(self, inner: HttpClient, quota: QuotaService):
        self.inner, self.quota = inner, quota

    def __getattr__(self, name: str):        # SafeHttp attributes (resolver, transport, user_agent ...) stay reachable for tests and for callers that tune them
        return getattr(self.inner, name)

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResult:
        route = self.quota.classify(url)
        if route is None:
            return await self.inner.get(url, headers=headers)
        scope = current_scope.get()
        res = self.quota.reserve(route, case_id=scope.case_id if scope else None, job_id=scope.job_id if scope else None)
        if isinstance(res, Denial):
            if scope is not None:
                scope.denials.append(res)
            hdr = {"x-osintcc-deferred": res.status, "retry-after": str(res.retry_after)} if res.status.startswith("deferred_") or res.status == "queued" \
                else {"x-osintcc-blocked": res.status}
            return HttpResult(429 if "retry-after" in hdr else _BLOCK_HTTP.get(res.status, 403), hdr, b"", url)
        return await self._send(res, url, headers, scope)

    async def _send(self, res: Reservation, url: str, headers: dict[str, str] | None, scope: JobScope | None) -> HttpResult:
        host = urlsplit(url).hostname or ""
        settled = False
        try:
            try:
                out = await self.inner.get(url, headers=headers)
            except DestinationDenied:
                self.quota.release(res, "policy_denied")      # nothing left the machine
                settled = True
                raise
            except Exception as exc:
                o = self.quota.settle(res, status=None, error=type(exc).__name__, host=host)
                settled = True
                if scope is not None:
                    scope.outcomes.append(o)
                    scope.sent += 1
                raise
            o = self.quota.settle(res, status=out.status, headers=out.headers, body=out.body, host=host)
            settled = True
            if scope is not None:
                scope.outcomes.append(o)
                scope.sent += 1
            return out
        finally:
            if not settled:                                    # cancelled mid-flight (timeout, shutdown): the request may have left, so it stays counted as unknown
                o = self.quota.settle(res, status=None, error="cancelled", host=host)
                if scope is not None:
                    scope.outcomes.append(o)
