"""Bounded TCP connect check: an explicit short list of ports, connect only, nothing sent, nothing read. No banner grabbing, no scanning profiles."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from ...aiv import policy
from ...aiv.policy import Budget, BudgetExceeded
from ...policy.ssrf import system_resolver
from .http_metadata import _is_ip

Resolver = Callable[[str], Awaitable[list[str]]]


async def check_ports(auth: Any, host: str, ports: list[int], budget: Budget, *, resolver: Resolver = system_resolver, connect_timeout: float = 3.0,
                      now: Callable[[], datetime] = lambda: datetime.now(UTC), emit: Callable[[str, dict[str, Any]], None] | None = None,
                      cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
    emit = emit or (lambda k, p: None)
    out: dict[str, Any] = {"host": host, "ports": {}, "blocked": None, "skipped": {}}
    pv = policy.validate_ports(ports, budget.limits["max_ports"])
    if not pv:
        out["blocked"] = {"code": pv.code, "reason": pv.reason}
        return out
    try:
        ips = [host] if _is_ip(host) else await resolver(host)
    except OSError:
        ips = []
    rd = policy.check_resolved(auth, host, ips)
    if not rd:
        out["blocked"] = {"code": rd.code, "reason": rd.reason}
        emit("blocked", out["blocked"])
        return out
    ip = ips[0]
    for port in ports:
        if cancelled and cancelled():
            out["skipped"][port] = "cancelled"
            continue
        gate = policy.check_host_port(auth, "tcp_connect", host, port, now())
        if not gate:
            out["skipped"][port] = f"{gate.code}: {gate.reason}"           # one unauthorized port skips that port only
            emit("blocked", {"port": port, "code": gate.code})
            continue
        try:
            wait = budget.charge("tcp_connect", host)
        except BudgetExceeded as exc:
            out["skipped"][port] = f"budget_exceeded: {exc.what}"
            continue
        if wait:
            await asyncio.sleep(wait)
        try:
            _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=connect_timeout)
            w.close()
            try:
                await w.wait_closed()
            except (ConnectionError, OSError):
                pass
            state = "open"
        except ConnectionRefusedError:
            state = "closed"
        except (TimeoutError, OSError):
            state = "filtered_or_unreachable"
        out["ports"][port] = state
        emit("port", {"port": port, "state": state})
    return out
