import asyncio
import sys
import time

from osintcc.adapters.base import AdapterContext, Target
from osintcc.adapters.registry import default_adapters
from osintcc.config import Settings
from osintcc.policy.ssrf import SafeHttp


async def main(aid, user):
    ad = default_adapters(Settings())[aid]
    print(aid, "health:", await ad.health(), flush=True)
    ad.manifest.timeout_seconds = 600
    t = time.time()
    r = await ad.run(Target(type="username", raw=user, canonical=user), AdapterContext(http=SafeHttp()))
    print(f"{aid}: status={r.status} code={r.error_code} findings={len(r.findings)} secs={time.time()-t:.0f} warnings={[w[:150] for w in r.warnings]}", flush=True)
    for f in r.findings[:12]: print("   ", f.subject.display, "|", f.predicate, flush=True)
    if r.artifacts: print("   raw tail:", r.artifacts[0].content[-300:].decode(errors="replace").replace("\n", " | "), flush=True)
asyncio.run(main(sys.argv[1], sys.argv[2]))
