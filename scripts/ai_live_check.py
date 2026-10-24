"""Opt-in end-to-end check of the REAL local model through the application's own AI pipeline (retrieval -> prompt -> model ->
citation verification). Needs Ollama running with the model pulled. Uses a throwaway data directory and a mocked network.

    uv run python scripts/ai_live_check.py [model]       (default: the setup catalog's recommendation for this machine)
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "tests" / "fixtures"), str(ROOT / "backend")]

from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.config import Settings
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from osintcc.setup import installer


async def main() -> int:
    model = sys.argv[1] if len(sys.argv) > 1 else installer.recommended_model(installer.ram_gb())["id"]
    s = Settings(data_dir=Path(tempfile.mkdtemp(prefix="osintcc-ai-")), vault_encryption="off", run_scheduler=False)
    s.ensure_dirs()
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler([])))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1/api/v1", timeout=900,
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            cid = (await c.post("/cases", json={"title": "AI live check", "purpose": "verify the local model"})).json()["id"]
            await c.post(f"/cases/{cid}/searches", json={"target": "example.com", "wait": True})
            await c.put("/settings", json={"values": {"ai_enabled": True}})
            pid = (await c.post("/ai/profiles", json={"name": "live", "provider_type": "ollama", "model_id": model})).json()["id"]
            print("preflight:", (await c.post("/ai/preflight", json={"profile_id": pid})).json())
            t0 = time.perf_counter()
            r = (await c.post("/ai/ask", json={"case_id": cid, "profile_id": pid, "question": "Who is the registrar of example.com and when was it registered?"})).json()
            dt = time.perf_counter() - t0
            ev = {e["id"] for e in (await c.get(f"/cases/{cid}/evidence")).json()["items"]}
            print(f"answer in {dt:.1f}s  status={r.get('status')} structured={r.get('structured')} model={r.get('model')}")
            print(json.dumps({k: r.get(k) for k in ("verified_evidence", "inferences", "unknowns", "rejected_citations", "proposed_actions")}, indent=1)[:3000])
            ok = r.get("status") == "answered" and bool(r.get("verified_evidence")) and all(set(v["evidence_ids"]) <= ev for v in r["verified_evidence"])
            print("RESULT:", "PASS" if ok else "FAIL (see output above)")
            return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
