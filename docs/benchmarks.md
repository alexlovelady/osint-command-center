# Measured performance

Spec §18 asks for measured values, not invented ones. These come from `scripts/benchmarks.py` (raw output: `docs/benchmarks.json` and
`docs/benchmarks-encrypted.json`), run in-process against a fresh temporary data directory with synthetic data and **no network**.

Environment: Windows-11-10.0.26200-SP0, Python 3.14.6, Intel64 Family 6 Model 198 Stepping 2, GenuineIntel. Dataset size parameter: 3000
(that many entities, relationships, findings and observations in one case). "Encrypted" = SQLCipher database + encrypted vault and reports
(`--encrypted`), which is the default configuration of the shipped app.

| Measurement | Plain | Encrypted (default) |
|---|---|---|
| app startup (create_app + lifespan, migrations applied) | 0.3718 s | 0.3735 s |
| passive search, 4 sources, mocked network | 0.0938 s, status=succeeded | 0.0889 s, status=succeeded |
| bulk insert 3000 entities, 3000 relationships, 3000 findings, 3000 observations | 0.5529 s | 0.5275 s |
| GET findings page (limit 100) of 3000 | 13.3 ms (p95 16.8) | 11.9 ms (p95 13.3) |
| full-text search over ~6000 indexed rows | 1.9 ms (p95 2.3) | 1.8 ms (p95 2.0) |
| graph payload (3000 nodes available, capped by the server) | 53.2 ms (p95 54.8) | 53.1 ms (p95 53.6) |
| observations page (limit 100) | 4.3 ms (p95 5.0) | 4.5 ms (p95 5.4) |
| unified timeline over 3000 observations (limit 500) | 66.5 ms (p95 87.9) | 55.4 ms (p95 84.0) |
| cross-link suggestions over 3000 observations (window 5 min) | 91.9 ms (p95 91.9) | 95.0 ms (p95 95.0) |
| report technical/html with 3000 findings | 0.5751 s, status=201 | 0.5778 s, status=201 |
| report multi_int/json with 3000 findings | 0.6025 s, status=201 | 0.5036 s, status=201 |
| report technical/pdf with 3000 findings | 2.3153 s, status=201 | 2.1853 s, status=201 |
| ingest 100 small JPEGs sequentially | 1.4512 s, per_file_ms=14.5 | 1.3119 s, per_file_ms=13.1 |
| vault store 10 MiB (AES-256-GCM + SHA-256/512) | 0.0305 s, mib_per_s=328.0 | 0.0273 s, mib_per_s=365.8 |
| vault read + integrity verify 10 MiB | 0.0217 s, ok=True | 0.0209 s, ok=True |

## How to read these numbers

- **Encryption overhead is not measurable at this scale**: differences between the two columns are within run-to-run noise (single runs,
  15 samples for the latency rows). Do not read any single cell as a regression or an improvement.
- Single machine, single user, warm cache, one run. Other hardware will differ; rerun `uv run python scripts/benchmarks.py --size 3000 [--encrypted]`.
- API timings are measured through the ASGI app, so they exclude browser rendering, the WebView and loopback TCP.
- The graph endpoint caps what it returns (the UI shows the best-connected nodes and says so), so its time is not proportional to case size.
- Not measured: cold start of the packaged desktop app (the frozen backend printed its handshake after 1.5–2.0 s on Windows and Linux in
  `sidecar_smoke.py`, one observation each), UI frame rates, memory use, cases above 3000 rows per table, concurrent adapters.
- **Local model speed** (separate, measured with Ollama on this CPU, no GPU used): `huihui_ai/qwen3-abliterated:8b` generates about
  **5.9 tokens/s**; a full grounded, cited answer through the app's retrieval pipeline took **17 s**. A typical laptop CPU will be slower.
- The vault figure is for an in-memory 10 MiB object (SHA-256 + SHA-512 + AES-256-GCM); disk speed is included but not isolated.
