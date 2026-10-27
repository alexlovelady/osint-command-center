"""Synthetic demo backend for screenshots and manual review: a real app, a fresh temp database, NO real network, and fictional data only.

    uv run python scripts/demo_server.py 8792 5174            # seeded: one finished investigation with leads, decisions and limits
    uv run python scripts/demo_server.py 8792 5174 --empty    # first-run state

GitHub, Gravatar and the key server answer from a mock transport (fictional "Jane Example"; example.org). Nothing is contacted and nothing here is a real person.
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "tests" / "fixtures"), str(ROOT / "backend")]

from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.config import Settings
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from profile_helpers import seed_candidates

TOKEN = "e2e-token-local-only"
COMMITS = {"items": [
    {"html_url": "https://github.com/jane-example/notes/commit/abc", "repository": {"html_url": "https://github.com/jane-example/notes", "full_name": "jane-example/notes"},
     "commit": {"message": "Add notes", "author": {"name": "jane-example", "email": "jane.example@gmail.com"}}},
    {"html_url": "https://github.com/jane-example/tools/commit/def", "repository": {"html_url": "https://github.com/jane-example/tools", "full_name": "jane-example/tools"},
     "commit": {"message": "Fix tools", "author": {"name": "Jane Example", "email": "jane.example@gmail.com"}}}]}
SIGHTINGS = [("sherlock", "https://github.com/jane-example", "GitHub"), ("maigret", "https://github.com/jane-example", "GitHub"), ("sherlock", "https://www.youtube.com/@jane-example", "YouTube"),
             ("maigret", "https://www.youtube.com/@jane-example/about", "YouTube"), ("sherlock", "https://venmo.com/jane-example", "Venmo"), ("maigret", "https://venmo.com/u/jane-example", "Venmo"),
             ("sherlock", "https://www.tiktok.com/@jane-example", "TikTok"), ("sherlock", "https://www.reddit.com/user/jane-example", "Reddit"), ("maigret", "https://medium.com/@jane-example", "Medium"),
             ("maigret", "https://about.me/jane-example", "About.me"), ("sherlock", "https://gitlab.com/jane-example", "GitLab"), ("maigret", "https://keybase.io/jane-example", "Keybase")]


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8792
    web_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5174
    empty = "--empty" in sys.argv
    data = Path(tempfile.mkdtemp(prefix="osintcc-demo-"))
    s = Settings(data_dir=data, session_token=TOKEN, vault_encryption="off", run_scheduler=False, retry_scale=0.001,
                 allowed_origins=(f"http://127.0.0.1:{web_port}", f"http://localhost:{web_port}"))
    s.ensure_dirs()
    calls: list[str] = []
    base = make_handler(calls)

    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if u.startswith("https://api.github.com/search/users"):
            return httpx.Response(200, json={"items": [{"login": "jane-example", "html_url": "https://github.com/jane-example"}]})
        if u.startswith("https://api.github.com/search/commits"):
            return httpx.Response(200, json=COMMITS)
        if u.startswith(("https://api.gravatar.com/", "https://keys.openpgp.org/")):
            return httpx.Response(404, text="none")
        return base(request)

    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(handler))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    orig = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(a):
        async with orig(a):
            if not empty:
                await seed(a)
            yield

    async def seed(a) -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {TOKEN}"}) as c:
            r = await c.post("/api/v1/investigations", json={"kind": "person", "display_name": "Jane Example", "purpose": "synthetic demonstration of a self-audit; fictional person",
                                                              "inputs": [{"kind": "email", "value": "jane.example@gmail.com"}, {"kind": "username", "value": "jane-example"},
                                                                         {"kind": "name", "value": "Jane Example"}, {"kind": "phone", "value": "+1 555 010 4242"}],
                                                              "authorization": {"verification_method": "self_attestation", "verifier": "demo operator"}, "start": True, "approved_sources": "listed"})
            out = r.json()
            seed_candidates(a.state.core, out["case_id"], "jane-example", SIGHTINGS)
            from osintcc.profile import investigate
            for _ in range(10):
                step = investigate.advance(a.state.core, out["run"]["id"])
                for rid in step["run_ids"]:
                    await a.state.core.runner.run_until_idle(rid)
                if step["finished"]:
                    break
                await asyncio.sleep(0.05)

    app.router.lifespan_context = lifespan
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    finally:
        shutil.rmtree(data, ignore_errors=True)


if __name__ == "__main__":
    main()
