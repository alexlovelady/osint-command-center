"""Backend for browser end-to-end tests: real app, real SQLite in a fresh temp dir, NO real network.

Outbound HTTP is answered by the same mock transport the integration tests use, so E2E runs are offline and repeatable.

    uv run python scripts/e2e_server.py 8792
"""
from __future__ import annotations

import shutil
import sys
import tempfile
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

TOKEN = "e2e-token-local-only"


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8792
    web_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5174
    data = Path(tempfile.mkdtemp(prefix="osintcc-e2e-"))
    s = Settings(data_dir=data, session_token=TOKEN, vault_encryption="off", run_scheduler=False, retry_scale=0.001,
                 allowed_origins=(f"http://127.0.0.1:{web_port}", f"http://localhost:{web_port}"))
    s.ensure_dirs()
    calls: list[str] = []
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(s, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    finally:
        shutil.rmtree(data, ignore_errors=True)


if __name__ == "__main__":
    main()
