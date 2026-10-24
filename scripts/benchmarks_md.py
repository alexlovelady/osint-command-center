"""Render docs/benchmarks.md from docs/benchmarks.json (plain) and docs/benchmarks-encrypted.json (SQLCipher + encrypted vault/reports)."""
from __future__ import annotations

import json
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "docs"


def cell(r: dict) -> str:
    if "median_ms" in r:
        return f"{r['median_ms']} ms (p95 {r['p95_ms']})"
    extra = "".join(f", {k}={v}" for k, v in r.items() if k not in ("name", "seconds"))
    return f"{r['seconds']} s{extra}"


def main() -> None:
    a = json.loads((DOCS / "benchmarks.json").read_text(encoding="utf8"))
    b = json.loads((DOCS / "benchmarks-encrypted.json").read_text(encoding="utf8"))
    env = a["environment"]
    rows = "\n".join(f"| {x['name']} | {cell(x)} | {cell(y)} |" for x, y in zip(a["results"], b["results"], strict=True))
    text = f"""# Measured performance

Spec §18 asks for measured values, not invented ones. These come from `scripts/benchmarks.py` (raw output: `docs/benchmarks.json` and
`docs/benchmarks-encrypted.json`), run in-process against a fresh temporary data directory with synthetic data and **no network**.

Environment: {env['platform']}, Python {env['python']}, {env['processor']}. Dataset size parameter: {env['size']}
(that many entities, relationships, findings and observations in one case). "Encrypted" = SQLCipher database + encrypted vault and reports
(`--encrypted`), which is the default configuration of the shipped app.

| Measurement | Plain | Encrypted (default) |
|---|---|---|
{rows}

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
"""
    (DOCS / "benchmarks.md").write_text(text, encoding="utf8")
    print("written", len(text))


if __name__ == "__main__":
    main()
