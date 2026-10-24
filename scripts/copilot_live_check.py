"""Opt-in check of the Copilot with the REAL local model (Ollama) through the application's own pipeline.

    uv run python scripts/copilot_live_check.py [model]

Uses a throwaway data directory and a mocked network (no internet). Prints what the model actually said and PASS/FAIL per scenario. Some
scenarios (the model choosing to call a tool) depend on the model and are reported as such, not asserted.
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
from osintcc.db.models import SearchRun
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import func, select

B = "/api/v1"
results: list[tuple[str, bool, str]] = []


async def ask(c: httpx.AsyncClient, text: str, **kw):
    t0 = time.perf_counter()
    first = None
    events = []
    async with c.stream("POST", f"{B}/copilot/chat", json={"text": text, **kw}) as r:
        async for line in r.aiter_lines():
            if not line.strip():
                continue
            e = json.loads(line)
            events.append(e)
            if e["type"] == "delta" and first is None:
                first = time.perf_counter() - t0
    final = next((e for e in events if e["type"] == "final"), None)
    print(f"\n--- {text!r}  (first token {first and round(first, 1)}s, total {time.perf_counter() - t0:.1f}s)")
    print((final or events[-1]).get("text", events[-1]))
    return events, final


def check(name: str, ok: bool, note: str = "") -> None:
    results.append((name, ok, note))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {note}")


async def main() -> int:
    model = sys.argv[1] if len(sys.argv) > 1 else "huihui_ai/qwen3-abliterated:8b"
    s = Settings(data_dir=Path(tempfile.mkdtemp(prefix="osintcc-cop-")), vault_encryption="off", run_scheduler=False)
    s.ensure_dirs()
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler([])))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", timeout=1200,
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            cid = (await c.post(f"{B}/cases", json={"title": "Copilot live check", "purpose": "verify the assistant"})).json()["id"]
            await c.post(f"{B}/cases/{cid}/searches", json={"target": "example.com", "wait": True})
            await c.put(f"{B}/settings", json={"values": {"ai_enabled": True}})
            await c.post(f"{B}/ai/profiles", json={"name": "live", "provider_type": "ollama", "model_id": model})
            st = (await c.get(f"{B}/copilot/status")).json()
            print("status:", json.dumps({k: st[k] for k in ("ai_enabled", "ready", "reason", "active")}, indent=1))
            if not st["ready"]:
                print("model not ready; nothing to check")
                return 2
            ctx = {"route": "case", "tab": "Findings", "case_id": cid}

            ev, fin = await ask(c, "What does confidence mean in this app, and can I treat a high-confidence finding as proven?", mode="general", ctx={"route": "overview"})
            check("general question answered by the model from documentation", bool(fin) and any(s["ref"].startswith("d") for s in fin["sources"]) and "model" in json.dumps(ev[0]).lower(), f"sources={[x['ref'] for x in fin['sources']] if fin else None}")

            ev, fin = await ask(c, "Does this app have a built-in Telegram scraper?", mode="general", ctx={"route": "overview"})
            check("undocumented feature is not invented", bool(fin) and "isn't in the documentation" in fin["text"])

            ev, fin = await ask(c, "Who is the registrar of example.com and when was it registered?", mode="investigation", ctx=ctx)
            ids = {e["id"] for e in (await c.get(f"{B}/cases/{cid}/evidence")).json()["items"]}
            ok = bool(fin) and any(s.get("evidence_ids") for s in fin["sources"]) and all(set(s.get("evidence_ids", [])) <= ids for s in fin["sources"])
            check("case answer cites real evidence of this case", ok, f"mentions registrar={'Example Registrar' in (fin or {}).get('text', '')}")

            ev, fin = await ask(c, "Please start a search of example.net with the rdap and dns sources now.", mode="investigation", ctx=ctx)
            with app.state.core.sm() as db:
                runs = db.scalar(select(func.count()).select_from(SearchRun))
            props = [e for e in ev if e["type"] == "proposal"]
            check("nothing ran without approval", runs == 1, f"runs={runs}")
            print(f"       model {'proposed an action for approval' if props else 'did not emit a tool call'}; flagged claim: {bool(fin and 'Nothing was run' in fin['text'])}")

            ev, fin = await ask(c, "Why is subfinder not working?", mode="tutor", ctx={"route": "tools"})
            check("tool failure explained from real health data", bool(fin) and ("not_installed" in fin["text"] or "no current problem" in fin["text"]))

    bad = [r for r in results if not r[1]]
    print(f"\nRESULT: {len(results) - len(bad)}/{len(results)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
