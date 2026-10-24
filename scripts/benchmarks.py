"""Measured performance numbers (spec 18: "record measured values instead of inventing benchmarks").

    uv run python scripts/benchmarks.py [--json] [--size N]

Runs in-process against a fresh temp data directory with the vault encryption OFF for the data-volume cases and ON for the
vault case. Synthetic data only; no network. Numbers depend on the machine; the machine is printed with the results.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "tests" / "fixtures"), str(ROOT / "backend")]

import synthetic_intel as si
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.config import Settings
from osintcc.db.models import Entity, Evidence, Finding, Observation, Relationship
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp

RESULTS: list[dict] = []
ENCRYPTED = "--encrypted" in sys.argv  # SQLCipher database + encrypted vault and reports


def record(name: str, seconds: float, **extra) -> None:
    RESULTS.append({"name": name, "seconds": round(seconds, 4), **extra})


def timed_ms(samples: list[float]) -> dict:
    s = sorted(samples)
    return {"n": len(s), "median_ms": round(statistics.median(s) * 1000, 1), "p95_ms": round(s[max(0, int(len(s) * 0.95) - 1)] * 1000, 1)}


async def main(size: int) -> None:
    data = Path(tempfile.mkdtemp(prefix="osintcc-bench-"))
    try:
        settings = Settings(data_dir=data, session_token="bench", vault_encryption="required" if ENCRYPTED else "off", run_scheduler=False, retry_scale=0.001)
        settings.ensure_dirs()
        t0 = time.perf_counter()
        http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler([])))
        app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns), vault_key=os.urandom(32) if ENCRYPTED else None)
        async with app.router.lifespan_context(app):
            record("app startup (create_app + lifespan, migrations applied)", time.perf_counter() - t0)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer bench"}) as c:
                cid = (await c.post("/api/v1/cases", json={"title": "bench", "purpose": "benchmarks"})).json()["id"]

                # --- end-to-end passive run on the mocked network (RDAP + DNS + crt.sh + Wayback) --------------------------
                t = time.perf_counter()
                r = await c.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "wait": True})
                record("passive search, 4 sources, mocked network", time.perf_counter() - t, status=r.json().get("status"))

                # --- bulk data straight into the DB (the app's own models) -----------------------------------------------
                core = app.state.core
                with core.sm() as db:
                    ev = db.scalars(__import__("sqlalchemy").select(Evidence).where(Evidence.case_id == cid)).first()
                    assert ev is not None
                    now = datetime.now(UTC)
                    t = time.perf_counter()
                    ents = [Entity(case_id=cid, type="domain", canonical_key=f"host{i}.bench.test", display_name=f"host{i}.bench.test",
                                   sensitivity="INTERNAL", first_seen_at=now, last_seen_at=now) for i in range(size)]
                    db.add_all(ents)
                    db.flush()
                    db.add_all([Relationship(case_id=cid, from_entity_id=ents[i].id, to_entity_id=ents[(i * 7 + 1) % size].id, relation_type="related_to",
                                             confidence="low", confidence_reason="bench", status="unverified", asserted_by="bench") for i in range(size)])
                    db.add_all([Finding(case_id=cid, subject_entity_id=ents[i % size].id, predicate="bench.value", value_type="str",
                                        value_json=f"synthetic finding number {i} alpha{i % 97}", confidence="low", confidence_reason="bench",
                                        evidence_id=ev.id, adapter_id="bench", adapter_version="1", observed_at=now,
                                        dedup_key=hashlib.sha256(f"{i}".encode()).hexdigest()) for i in range(size)])
                    disciplines = ["GEOINT", "CYBINT", "MASINT", "SIGINT"]
                    db.add_all([Observation(case_id=cid, discipline_id=disciplines[i % 4], kind="bench", access_class="IMPORTED",
                                            observed_at=now - timedelta(seconds=i * 30), ingested_at=now,
                                            data_json={"location": {"lat": 48.0 + (i % 100) / 1000, "lon": 2.0 + (i % 100) / 1000, "accuracy_m": 10}} if i % 4 == 0 else {},
                                            raw_evidence_id=ev.id, sensitivity="INTERNAL", confidence="low") for i in range(size)])
                    db.commit()
                record(f"bulk insert {size} entities, {size} relationships, {size} findings, {size} observations", time.perf_counter() - t)

                async def lat(path: str, n: int = 15) -> dict:
                    xs = []
                    for _ in range(n):
                        t = time.perf_counter()
                        rr = await c.get(path)
                        assert rr.status_code == 200, (path, rr.text[:200])
                        xs.append(time.perf_counter() - t)
                    return timed_ms(xs)

                record(f"GET findings page (limit 100) of {size}", 0, **await lat(f"/api/v1/cases/{cid}/findings?limit=100"))
                record(f"full-text search over ~{size * 2} indexed rows", 0, **await lat(f"/api/v1/cases/{cid}/search?q=alpha42"))
                record(f"graph payload ({size} nodes available, capped by the server)", 0, **await lat(f"/api/v1/cases/{cid}/graph", 5))
                record("observations page (limit 100)", 0, **await lat(f"/api/v1/cases/{cid}/observations?limit=100"))
                record(f"unified timeline over {size} observations (limit 500)", 0, **await lat(f"/api/v1/cases/{cid}/timeline/unified", 5))
                record(f"cross-link suggestions over {size} observations (window 5 min)", 0, **await lat(f"/api/v1/cases/{cid}/cross-links?window_s=300&radius_m=500", 3))

                for prof, fmt in (("technical", "html"), ("multi_int", "json"), ("technical", "pdf")):
                    t = time.perf_counter()
                    rr = await c.post(f"/api/v1/cases/{cid}/reports", json={"profile": prof, "format": fmt})
                    record(f"report {prof}/{fmt} with {size} findings", time.perf_counter() - t, status=rr.status_code)

                # --- ingest throughput: unique synthetic JPEGs (EXIF parse + store + observation) ------------------------------
                n_files = 100
                t = time.perf_counter()
                for i in range(n_files):
                    jpg = si.jpeg_with_gps(40.0 + i / 1000, -3.0 - i / 1000) + uuid.uuid4().bytes  # unique bytes => unique evidence
                    rr = await c.post(f"/api/v1/cases/{cid}/ingest?filename=p{i}.jpg&consent_confirmed=true", content=jpg)
                    assert rr.status_code == 201
                dt = time.perf_counter() - t
                record(f"ingest {n_files} small JPEGs sequentially", dt, per_file_ms=round(dt / n_files * 1000, 1))

        # --- vault with encryption ON ---------------------------------------------------------------------------------------
        from osintcc.evidence.crypto import VaultCipher
        from osintcc.evidence.vault import Vault
        vdir = data / "vault-enc"
        v = Vault(vdir, VaultCipher(b"k" * 32), require_encryption=True)
        blob = uuid.uuid4().bytes * (10 * 1024 * 1024 // 16)
        t = time.perf_counter()
        sha, _, rel, _ = v.store(blob)
        record("vault store 10 MiB (AES-256-GCM + SHA-256/512)", time.perf_counter() - t, mib_per_s=round(10 / max(time.perf_counter() - t, 1e-9), 1))
        t = time.perf_counter()
        back = v.read(rel, sha) if hasattr(v, "read") else b""
        record("vault read + integrity verify 10 MiB", time.perf_counter() - t, ok=(back == blob) if back else None)
    finally:
        shutil.rmtree(data, ignore_errors=True)


if __name__ == "__main__":
    size = int(sys.argv[sys.argv.index("--size") + 1]) if "--size" in sys.argv else 3000
    asyncio.run(main(size))
    env = {"platform": platform.platform(), "python": platform.python_version(), "processor": platform.processor(), "size": size, "encrypted": ENCRYPTED}
    if "--json" in sys.argv:
        print(json.dumps({"environment": env, "results": RESULTS}, indent=2))
    else:
        print(f"environment: {env}")
        for r in RESULTS:
            rest = {k: v for k, v in r.items() if k not in ("name", "seconds")}
            print(f"{r['name']:<80} {r['seconds']:>8.3f}s  {rest if rest else ''}")
