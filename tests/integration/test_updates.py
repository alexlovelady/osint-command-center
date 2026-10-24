from __future__ import annotations

import json
from base64 import b64encode

import httpx
import pytest
from conftest import fake_resolver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from osintcc import __version__
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def envelope(version="9.9.9", key=KEY):
    payload = json.dumps({"version": version, "released": "2030-01-01", "notes": "n", "url": "https://example.com/setup.exe", "sha256": "ab" * 32})
    return json.dumps({"payload": payload, "signature": b64encode(key.sign(payload.encode())).decode()}).encode()


def make_api(settings, body, status=200, configured=True):
    if configured:
        settings.update_manifest_url, settings.update_public_key = "https://updates.example.com/manifest.json", PUB
    seen = []

    def h(req):
        seen.append(str(req.url))
        return httpx.Response(status, content=body)
    app = create_app(settings)
    app.state.core.update_http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(h))
    return app, seen


async def call(app, settings):
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            return await c.post("/api/v1/updates/check")


async def test_unconfigured_makes_no_request(settings):
    app, seen = make_api(settings, envelope(), configured=False)
    r = await call(app, settings)
    assert r.json()["configured"] is False and seen == []


async def test_valid_signature_reports_newer_version_and_downloads_nothing(settings):
    app, seen = make_api(settings, envelope("9.9.9"))
    j = (await call(app, settings)).json()
    assert j["update_available"] and j["latest"] == "9.9.9" and j["current"] == __version__ and j["signature"] == "verified"
    assert seen == ["https://updates.example.com/manifest.json"] and "Nothing was downloaded" in j["note"]


async def test_same_version_is_not_an_update_and_hides_download(settings):
    app, _ = make_api(settings, envelope(__version__))
    j = (await call(app, settings)).json()
    assert j["update_available"] is False and j["download_url"] is None


@pytest.mark.parametrize("body", [envelope(key=Ed25519PrivateKey.generate()), b"{}", b"not json",
                                  json.dumps({"payload": '{"version": "x"}', "signature": "AAAA"}).encode()])
async def test_bad_or_forged_manifests_are_rejected(settings, body):
    app, _ = make_api(settings, body)
    r = await call(app, settings)
    assert r.status_code == 422 and r.json()["code"] in ("bad_signature", "bad_manifest")


async def test_offline_mode_blocks_the_check(settings):
    settings.offline = True
    app, seen = make_api(settings, envelope())
    r = await call(app, settings)
    assert r.status_code == 409 and seen == []
