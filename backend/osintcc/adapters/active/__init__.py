"""Optional ACTIVE-assessment module (spec 12.2). Absent from the registry unless OSINTCC_ENABLE_ACTIVE=1.

Even when enabled it never runs without (a) a scope authorization row covering the target with the 'active' class and
(b) per-run confirmation; the policy engine checks both at plan time and again immediately before execution.
It is a bounded TCP connect check (no payloads, no banner grabbing, no exploitation).
"""
from __future__ import annotations

import asyncio
import json
import socket

from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    Target,
)

MAX_PORTS = 20
DEFAULT_PORTS = (80, 443)


class TcpConnectAdapter:
    manifest = AdapterManifest(
        id="tcp_connect", name="TCP connect check (active)", version="1.0.0", supported_target_types=["domain", "ip"],
        operation_class="active", needs_network=True, timeout_seconds=60, rate_limit_per_minute=10,
        license="in-house", endpoints=["TCP connect to the authorised target on the listed ports"],
        description="Checks whether a few TCP ports accept a connection on a target you are authorised to assess. "
                    "Sends no data. Requires a scope authorization and per-run confirmation.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "active module enabled by the owner"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        ports = [int(p) for p in ctx.config.get("ports", DEFAULT_PORTS)][:MAX_PORTS]
        if not ports or any(not 0 < p < 65536 for p in ports):
            return AdapterResult(adapter_id=aid, status="error", error_code="invalid_ports", warnings=["invalid port list"])
        host = target.canonical
        results: dict[int, str] = {}
        sem = asyncio.Semaphore(3)

        async def probe(port: int) -> None:
            async with sem:
                try:
                    _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
                    w.close()
                    try:
                        await w.wait_closed()
                    except (ConnectionError, OSError):
                        pass
                    results[port] = "open"
                except ConnectionRefusedError:
                    results[port] = "closed"
                except (TimeoutError, OSError, socket.gaierror):
                    results[port] = "filtered_or_unreachable"
        await asyncio.gather(*(probe(p) for p in ports))
        art = RawArtifact(name=f"tcp-{host}.json", content=json.dumps({"host": host, "ports": results}, sort_keys=True).encode())
        subj = EntityRef(type=target.type, key=host, display=host)
        f = [FindingDraft(subject=subj, predicate="net.tcp_port", value={"port": p, "state": s}, confidence="medium",
                          confidence_reason="Direct connection attempt from this machine at the stated time; results can vary by path")
             for p, s in sorted(results.items())]
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=f,
                             warnings=["Active check performed under a recorded scope authorization."])
