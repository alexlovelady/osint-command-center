"""Opt-in: run one installed CLI adapter against the REAL tool for a reserved domain and show what came back.

    uv run python scripts/tool_live_check.py theharvester example.com
    uv run python scripts/tool_live_check.py subfinder example.com

Passive sources only, one domain, low volume. Use it after `python -m osintcc.setup install ...` to see whether an adapter's parser really
understands the tool's output.
"""
from __future__ import annotations

import asyncio
import sys

from osintcc.adapters.base import AdapterContext, Target
from osintcc.adapters.registry import default_adapters
from osintcc.config import Settings
from osintcc.policy.ssrf import SafeHttp


async def main() -> int:
    aid = sys.argv[1] if len(sys.argv) > 1 else "subfinder"
    domain = sys.argv[2] if len(sys.argv) > 2 else "example.com"
    s = Settings()
    ad = default_adapters(s).get(aid)
    if ad is None or not hasattr(ad, "locate"):
        print(f"{aid}: not a CLI adapter")
        return 2
    print("health:", await ad.health())
    ad.manifest.timeout_seconds = max(ad.manifest.timeout_seconds, 300)
    r = await ad.run(Target(type="domain", raw=domain, canonical=domain), AdapterContext(http=SafeHttp()))
    print("status:", r.status, r.error_code, "| findings:", len(r.findings), "| warnings:", [w[:160] for w in r.warnings])
    if r.artifacts:
        print("raw output (first 800 bytes):", r.artifacts[0].content[:800].decode(errors="replace"))
    for f in r.findings[:8]:
        print("  finding:", f.subject.key, f.predicate, str(f.value)[:80])
    return 0 if r.status in ("success", "partial") else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
