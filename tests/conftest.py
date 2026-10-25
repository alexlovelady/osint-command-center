from __future__ import annotations

import json

import httpx
import pytest
from aiv_lab import WEAK_HEADERS, Lab, Resolver, client_trust, make_ca, make_server_cert, server_ctx
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
from osintcc.main import create_app
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


# ---- shared by integration tests: a keyring that never touches the real credential store, and a ready app + client ----------------------------
class FakeKeyring:
    def __init__(self):
        self.data = {}

    def get_password(self, s, u):
        return self.data.get((s, u))

    def set_password(self, s, u, p):
        self.data[(s, u)] = p

    def delete_password(self, s, u):
        self.data.pop((s, u), None)


@pytest.fixture
def _no_real_keyring(monkeypatch):
    from osintcc.secrets_store import SecretStore
    kr = FakeKeyring()
    monkeypatch.setattr(SecretStore, "_keyring", staticmethod(lambda: kr))


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}, timeout=60)
        c.app = app
        yield c
        await c.aclose()


# ---- Active Intelligence & Verification: a throwaway CA and a real local lab (shared by tests/integration/test_aiv_*.py) ----------------------------------
TABLE = {"lab.test": ["127.0.0.1"], "other.test": ["127.0.0.1"], "evil.test": ["127.0.0.1"], "rebind.test": ["10.0.0.5"], "meta.test": ["169.254.169.254"]}


@pytest.fixture
def pki(tmp_path):
    key, cert, pem = make_ca(tmp_path)
    return {"key": key, "cert": cert, "pem": pem, "tmp": tmp_path}


@pytest.fixture
async def env(settings, calls, pki):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    resolver = Resolver(TABLE)
    labs: list[Lab] = []
    async with app.router.lifespan_context(app):
        st = app.state.core
        st.aiv.resolver, st.aiv.ssl_context, st.aiv.rate_boost = resolver, client_trust(pki["pem"]), 1000.0
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            c.app = app

            async def lab(routes=None, tls: list[str] | None = None, **kw) -> Lab:
                lb = Lab(routes=routes or {"*": (200, WEAK_HEADERS, b"<html>hello</html>")}, **kw)
                ctx = None
                if tls is not None:
                    cp, kp = make_server_cert(pki["tmp"], pki["key"], pki["cert"], tls, tag=f"srv{len(labs)}")
                    ctx = server_ctx(cp, kp)
                await lb.start(ctx)
                labs.append(lb)
                return lb
            yield {"api": c, "st": st, "resolver": resolver, "lab": lab, "pki": pki, "calls": calls}
    for lb in labs:
        await lb.stop()
