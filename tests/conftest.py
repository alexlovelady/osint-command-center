from __future__ import annotations

import json

import httpx
import pytest
from osintcc.adapters.base import AdapterContext
from osintcc.adapters.registry import default_adapters
from osintcc.config import Settings
from osintcc.db import (
    make_engine,
    models,  # noqa: F401
    session_factory,
)
from osintcc.db.migrate import upgrade_to_head
from osintcc.evidence.vault import Vault
from osintcc.jobs.runner import JobRunner
from osintcc.policy.ssrf import SafeHttp

PUBLIC_IP = "93.184.216.34"

BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.example-registry.test/"]]]}
RDAP_DOMAIN = {
    "handle": "EX-1", "status": ["client transfer prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"}],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc"]]]}],
}
CRT_ROWS = [
    {"id": 1, "name_value": "example.com\nwww.example.com", "not_before": "2024-01-01T00:00:00"},
    {"id": 2, "name_value": "*.example.com\nmail.example.com\nunrelated.org", "not_before": "2023-05-05T00:00:00"},
]


def make_handler(calls: list[str], fail_crt: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        u = str(request.url)
        if u.startswith("https://data.iana.org/rdap/dns.json"):
            return httpx.Response(200, json=BOOTSTRAP)
        if "rdap.example-registry.test" in u:
            return httpx.Response(200, content=json.dumps(RDAP_DOMAIN).encode(),
                                  headers={"content-type": "application/rdap+json"})
        if u.startswith("https://crt.sh/"):
            if fail_crt:
                return httpx.Response(503)
            return httpx.Response(200, json=CRT_ROWS)
        if u.startswith("https://web.archive.org/cdx/"):
            return httpx.Response(200, json=[["timestamp", "original", "statuscode", "mimetype", "digest"],
                                             ["20010305120000", "http://example.com/", "200", "text/html", "A"],
                                             ["20240101000000", "http://example.com/", "200", "text/html", "B"]])
        return httpx.Response(404)
    return handler


async def fake_resolver(host: str) -> list[str]:
    return [PUBLIC_IP]


async def fake_dns(name: str, rtype: str) -> list[str]:
    return {"A": ["93.184.216.34"], "AAAA": ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
            "NS": ["a.iana-servers.net."], "MX": ["0 ."], "TXT": ['"v=spf1 -all"'], "CNAME": []}[rtype]


@pytest.fixture
def settings(tmp_path):
    s = Settings(data_dir=tmp_path / "data", vault_encryption="off", run_scheduler=False, retry_scale=0.001)  # tests never touch the OS keyring
    s.ensure_dirs()
    return s


@pytest.fixture
def sm(settings):
    engine = make_engine(settings.db_path)
    upgrade_to_head(engine, settings.db_path)
    yield session_factory(engine)
    engine.dispose()


@pytest.fixture
def calls():
    return []


@pytest.fixture
def make_runner(sm, settings):
    def _make(calls, fail_crt=False, adapters=None):
        transport = httpx.MockTransport(make_handler(calls, fail_crt))
        http = SafeHttp(resolver=fake_resolver, transport=transport)
        return JobRunner(sm, settings, Vault(settings.vault_dir), adapters or default_adapters(),
                         lambda: AdapterContext(http=http, dns_query=fake_dns))
    return _make
