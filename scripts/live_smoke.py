"""Live passive smoke test (opt-in, low volume): runs RDAP/DNS/crt.sh against a reserved domain via the real stack."""
import asyncio
import sys
import tempfile
from pathlib import Path

import httpx
from osintcc.config import Settings
from osintcc.main import create_app


async def main(domain: str) -> int:
    with tempfile.TemporaryDirectory() as td:
        s = Settings(data_dir=Path(td))
        app = create_app(s)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                         headers={"Authorization": f"Bearer {s.session_token}"}, timeout=180) as c:
                cid = (await c.post("/api/v1/cases", json={"title": "live smoke", "purpose": "smoke test"})).json()["id"]
                run = (await c.post(f"/api/v1/cases/{cid}/searches", json={"target": domain, "wait": True})).json()
                for j in run["jobs"]:
                    print(f"{j['adapter_id']:10s} {j['status']:10s} attempts={j['attempts']} code={j['error_code']} {j['warnings'][:1]}")
                f = (await c.get(f"/api/v1/cases/{cid}/findings?limit=500")).json()
                print("run:", run["status"], "findings:", f["total"])
                by = {}
                for i in f["items"]:
                    by[i["adapter"]] = by.get(i["adapter"], 0) + 1
                print("by adapter:", by)
                for i in f["items"][:6]:
                    print(" ", i["subject"], i["predicate"], str(i["value"])[:60], i["source_url"])
                return 0 if len(by) >= 3 else 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "example.com")))
