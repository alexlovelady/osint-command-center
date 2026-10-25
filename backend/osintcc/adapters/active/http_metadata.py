"""Scope-enforcing HTTP metadata check (HEAD/GET, headers only). One hop at a time: every request, including each redirect, is re-judged.

Not ProjectDiscovery httpx and not a crawler: it never follows links, never submits forms, sends no cookies, no credentials and no custom headers, and reads
at most a small body to measure it. The connection is pinned to an address that has just been checked against the authorization.
"""
from __future__ import annotations

import asyncio
import ssl
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from ...aiv import policy
from ...aiv.policy import Budget, BudgetExceeded
from ...policy.ssrf import system_resolver

Resolver = Callable[[str], Awaitable[list[str]]]
USER_AGENT = "osintcc-aiv/1.0 (authorized verification; contact the asset owner)"
MAX_BODY_READ = 32 * 1024
TIMEOUT = httpx.Timeout(8.0, connect=5.0)


class ScopedHttp:
    def __init__(self, auth: Any, budget: Budget, *, resolver: Resolver = system_resolver, ssl_context: ssl.SSLContext | bool = True,
                 transport: httpx.AsyncBaseTransport | None = None, now: Callable[[], datetime] = lambda: datetime.now(UTC),
                 emit: Callable[[str, dict[str, Any]], None] | None = None, cancelled: Callable[[], bool] | None = None):
        self.auth, self.budget, self.resolver, self.ssl_context, self.transport = auth, budget, resolver, ssl_context, transport
        self.now, self.emit, self.cancelled = now, emit or (lambda k, p: None), cancelled or (lambda: False)

    async def _pin(self, host: str) -> tuple[list[str], policy.Decision]:
        try:
            ips = [host] if _is_ip(host) else await self.resolver(host)
        except OSError:
            ips = []
        return ips, policy.check_resolved(self.auth, host, ips)

    async def fetch(self, url: str, method: str = "HEAD", follow_redirects: bool = False) -> dict[str, Any]:
        """Returns a plain dict (serialisable evidence): hops, final status/headers, blocked info, tls info. Never raises for policy: policy is a result."""
        if method not in ("HEAD", "GET"):
            return {"requested_url": url, "blocked": {"code": "method_denied", "reason": "only HEAD and GET are allowed"}, "hops": []}
        hops: list[dict[str, Any]] = []
        current = url
        res: dict[str, Any] = {"requested_url": url, "method": method, "hops": hops, "blocked": None, "error": None}
        for hop in range(self.budget.limits["max_redirects"] + 1):
            if self.cancelled():
                res["error"] = "cancelled"
                return res
            gate = policy.check_url(self.auth, "http_metadata", current, self.now()) if hop == 0 else None
            if gate is not None and not gate:
                res["blocked"] = {"code": gate.code, "reason": gate.reason, "url": current}
                self.emit("blocked", res["blocked"])
                return res
            p = urlsplit(current)
            host, port = p.hostname or "", p.port or (443 if p.scheme == "https" else 80)
            ips, rd = await self._pin(host)
            if not rd:
                res["blocked"] = {"code": rd.code, "reason": rd.reason, "url": current}
                self.emit("blocked", res["blocked"])
                return res
            try:
                wait = self.budget.charge("http_metadata", host)
            except BudgetExceeded as exc:
                res["blocked"] = {"code": "budget_exceeded", "reason": f"the {exc.what} budget is used up", "url": current}
                self.emit("blocked", res["blocked"])
                return res
            if wait:
                await asyncio.sleep(wait)
            attempt = await self._one(current, method, ips[0], host, port, p.scheme)
            hops.append({k: attempt[k] for k in ("url", "status", "elapsed_ms", "error") if k in attempt})
            if attempt.get("error") == "timeout" and self.budget.limits["max_retries"] >= 1:
                try:
                    self.budget.charge("http_metadata", host)
                    attempt = await self._one(current, method, ips[0], host, port, p.scheme)
                    hops[-1] = {k: attempt[k] for k in ("url", "status", "elapsed_ms", "error") if k in attempt} | {"retried": True}
                except BudgetExceeded:
                    pass
            if attempt.get("status") in (405, 501) and method == "HEAD":      # some servers refuse HEAD; one GET is within the same authorization class
                try:
                    wait = self.budget.charge("http_metadata", host)
                    if wait:
                        await asyncio.sleep(wait)
                    attempt = await self._one(current, "GET", ips[0], host, port, p.scheme)
                    hops[-1] = {k: attempt[k] for k in ("url", "status", "elapsed_ms", "error") if k in attempt} | {"method_fallback": "GET"}
                except BudgetExceeded:
                    pass
            self.emit("request", {"url": current, "status": attempt.get("status"), "error": attempt.get("error")})
            if attempt.get("error"):
                res["error"], res["final_url"] = attempt["error"], current
                res["tls_error"] = attempt.get("tls_error")
                return res
            res.update(final_url=current, status=attempt["status"], headers=attempt["headers"], set_cookies=attempt["set_cookies"], tls=attempt.get("tls"), body_bytes=attempt["body_bytes"],
                       resolved_ips=ips)
            loc = attempt["headers"].get("location")
            if attempt["status"] in (301, 302, 303, 307, 308) and loc:
                if not follow_redirects:
                    res["redirect_not_followed"] = urljoin(current, loc)
                    return res
                rg = policy.check_redirect(self.auth, "http_metadata", current, loc, self.now(), hop, self.budget.limits["max_redirects"])
                if not rg:
                    res["blocked"] = {"code": rg.code, "reason": rg.reason, "url": urljoin(current, loc)}
                    self.emit("blocked", res["blocked"])
                    return res
                current = urljoin(current, loc)
                continue
            return res
        res["blocked"] = {"code": "redirect_limit", "reason": "too many redirects", "url": current}
        return res

    async def _one(self, url: str, method: str, ip: str, host: str, port: int, scheme: str) -> dict[str, Any]:
        t0 = time.perf_counter()
        pinned = url
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        ext: dict[str, Any] = {}
        if self.transport is None:
            netloc = f"[{ip}]" if ":" in ip else ip
            pinned = urlsplit(url)._replace(netloc=f"{netloc}:{port}").geturl()
            headers["Host"] = host if port in (80, 443) else f"{host}:{port}"
            if scheme == "https":
                ext["sni_hostname"] = host
        out: dict[str, Any] = {"url": url}
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=TIMEOUT, follow_redirects=False, verify=self.ssl_context, trust_env=False) as client:
                async with client.stream(method, pinned, headers=headers, extensions=ext) as r:
                    body = 0
                    if method == "GET":
                        async for chunk in r.aiter_bytes():
                            body += len(chunk)
                            if body >= MAX_BODY_READ:
                                break
                    self.budget.add_bytes(body + sum(len(k) + len(v) for k, v in r.headers.items()))
                    hdrs: dict[str, str] = {}
                    for k, v in r.headers.items():
                        hdrs[k.lower()] = v if k.lower() not in hdrs else hdrs[k.lower()] + ", " + v
                    out.update(status=r.status_code, headers={k: v[:1000] for k, v in hdrs.items() if k != "set-cookie"},
                               set_cookies=[v[:500] for k, v in r.headers.multi_items() if k.lower() == "set-cookie"][:20], body_bytes=body)
                    stream = r.extensions.get("network_stream")
                    ssl_obj = stream.get_extra_info("ssl_object") if stream is not None else None
                    if ssl_obj is not None:
                        out["tls"] = {"version": ssl_obj.version(), "cipher": (ssl_obj.cipher() or ("", "", 0))[0]}
        except httpx.ConnectTimeout:
            out["error"] = "timeout"
        except httpx.ReadTimeout:
            out["error"] = "timeout"
        except BudgetExceeded as exc:
            out["error"] = f"budget_exceeded:{exc.what}"
        except httpx.ConnectError as exc:
            msg = str(exc)
            out["error"] = "tls_error" if "CERTIFICATE_VERIFY_FAILED" in msg or "SSL" in msg.upper() else "connect_error"
            out["tls_error"] = msg[:200] if out["error"] == "tls_error" else None
        except (httpx.HTTPError, ssl.SSLError, OSError) as exc:
            out["error"] = type(exc).__name__
        out["elapsed_ms"] = round((time.perf_counter() - t0) * 1000)
        return out


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
