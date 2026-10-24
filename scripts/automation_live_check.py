"""Opt-in LIVE check of the Automation Builder: a real local model proposes a workflow, and real bundled templates run against the IANA-reserved
example.com using the real passive sources (RDAP, DNS, certificate transparency, Internet Archive). Low volume, public data, no keys.

    uv run python scripts/automation_live_check.py [model]

Uses a throwaway data directory. Prints what actually happened and PASS/FAIL per scenario; it never claims a source worked that did not.
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
sys.path[:0] = [str(ROOT / "backend")]

from osintcc.config import Settings
from osintcc.main import create_app

B = "/api/v1/automations"
results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, note: str = "") -> None:
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {note}")


async def main() -> int:
    model = sys.argv[1] if len(sys.argv) > 1 else "huihui_ai/qwen3-abliterated:8b"
    s = Settings(data_dir=Path(tempfile.mkdtemp(prefix="osintcc-auto-")), vault_encryption="off", run_scheduler=False)
    s.ensure_dirs()
    app = create_app(s)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", timeout=1200, headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            cid = (await c.post("/api/v1/cases", json={"title": "Automation live check", "purpose": "verify automations against IANA example.com"})).json()["id"]
            await c.put("/api/v1/settings", json={"values": {"ai_enabled": True}})
            await c.post("/api/v1/ai/profiles", json={"name": "live", "provider_type": "ollama", "model_id": model})
            st = (await c.get("/api/v1/copilot/status")).json()
            print("model ready:", st["ready"], st["reason"])
            goal = "Monitor my domain example.com for new public-facing assets, compare the findings to the previous run, and alert me only on meaningful changes"
            t0 = time.perf_counter()
            r = (await c.post(f"{B}/ai/propose", json={"goal": goal, "case_id": cid})).json()
            print(f"\n--- propose ({time.perf_counter() - t0:.1f}s): source={r['source']} valid={r['valid']} attempts={r['attempts']}")
            if r["draft"]:
                print("draft steps:", [(n['id'], n['type']) for n in r["draft"]["nodes"]], "trigger:", r["draft"]["trigger"])
                print("assumptions:", r["assumptions"])
                print("validation errors:", [e["message"] for e in r["validation"]["errors"]])
            check("model proposal is a valid disabled draft (or a labelled template fallback)", bool(r["draft"]) and r["valid"] and r["draft"]["trigger"]["enabled"] is False, f"source={r['source']}")
            if r["draft"]:
                wf = (await c.post(f"{B}/workflows", json={"definition": r["draft"], "case_id": cid})).json()
                dry = (await c.post(f"{B}/workflows/{wf['id']}/dry-run", json={"case_id": cid})).json()
                check("the proposed draft dry-runs (simulated)", dry["run"]["state"] in ("completed", "completed_with_warnings", "failed") and dry["run"]["simulated"], dry["run"]["state"])

            wf = (await c.post(f"{B}/from-template", json={"slug": "cy-01-domain-recon", "case_id": cid, "inputs": {"domain": "example.com"}})).json()
            await c.post(f"{B}/workflows/{wf['id']}/publish")
            t0 = time.perf_counter()
            run = (await c.post(f"{B}/workflows/{wf['id']}/run", json={"case_id": cid, "wait": True})).json()
            d = (await c.get(f"{B}/runs/{run['id']}")).json()
            print(f"\n--- CY-01 live on example.com ({time.perf_counter() - t0:.1f}s): {d['state']}, evidence {d['evidence_count']}")
            for n in d["nodes"]:
                print(f"   {n['node']:10} {n['state']:10} {n['error_code'] or '':22} {json.dumps(n['output'])[:90] if n['output'] else ''}")
            print("   source URLs:", d["source_urls"][:6])
            ok_nodes = {n["node"] for n in d["nodes"] if n["state"] == "succeeded"}
            check("CY-01 live: real sources answered and results were saved as evidence", {"rdap", "dns", "crtsh", "save"} <= ok_nodes and d["evidence_count"] > 0, f"succeeded={sorted(ok_nodes)}")

            wf2 = (await c.post(f"{B}/from-template", json={"slug": "cy-02-domain-change-watch", "case_id": cid, "inputs": {"domain": "example.com"}})).json()
            await c.post(f"{B}/workflows/{wf2['id']}/publish")
            r1 = (await c.get(f"{B}/runs/{(await c.post(f'{B}/workflows/{wf2['id']}/run', json={'case_id': cid, 'wait': True})).json()['id']}")).json()
            r2 = (await c.get(f"{B}/runs/{(await c.post(f'{B}/workflows/{wf2['id']}/run', json={'case_id': cid, 'wait': True})).json()['id']}")).json()
            diff = lambda x: next((n for n in x["nodes"] if n["node"] == "diff"), {}).get("output") or {}
            print("\n--- CY-02 twice: first run baseline =", diff(r1).get("baseline"), "| second run changed =", diff(r2).get("changed"), "added", diff(r2).get("added_count"))
            check("CY-02 live: the first run is a baseline and an unchanged second run raises nothing", diff(r1).get("baseline") is True and diff(r2).get("changed") is False)
            n = (await c.get(f"{B}/notifications")).json()
            check("no notification for an unchanged domain", n["total"] == 0, f"notifications={n['total']}")
    bad = [r for r in results if not r[1]]
    print(f"\nRESULT: {len(results) - len(bad)}/{len(results)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
