from __future__ import annotations

import hashlib
import importlib.util
import json
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from conftest import fake_resolver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from osintcc import __version__
from osintcc.config import Settings
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from osintcc.setup.installer import platform_key

TOOL = importlib.util.spec_from_file_location("update_tool", Path(__file__).parents[2] / "scripts" / "update_tool.py")
assert TOOL and TOOL.loader
update_tool = importlib.util.module_from_spec(TOOL)
TOOL.loader.exec_module(update_tool)

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
PRIV = KEY.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
PLAT = platform_key() or "win32-x86_64"
BLOB = b"installer-bytes" * 1000


def platform_envelope(version="9.9.9", blob=BLOB, name="app-setup.exe", url="https://updates.example.com/app-setup.exe", plat=PLAT, size=None):
    payload = {"version": version, "released": "2030-01-01", "notes": "notes", "platforms": {plat: {
        "name": name, "url": url, "sha256": hashlib.sha256(blob).hexdigest(), "size": size if size is not None else len(blob)}}}
    return json.dumps(update_tool.sign_envelope(payload, PRIV)).encode()


def make_app(settings, manifest, blob=BLOB, file_status=200, manifest_url="https://updates.example.com/manifest.json"):
    settings.update_manifest_url, settings.update_public_key = manifest_url, PUB
    seen = []

    def h(req):
        seen.append(str(req.url))
        if str(req.url).endswith("manifest.json"):
            return httpx.Response(200, content=manifest)
        return httpx.Response(file_status, content=blob)
    app = create_app(settings)
    t = httpx.MockTransport(h)
    app.state.core.update_http = SafeHttp(resolver=fake_resolver, transport=t)
    app.state.core.update_transport = t
    return app, seen


async def post(app, settings, path, body=None, headers=None):
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            return await c.post(f"/api/v1{path}", json=body, headers=headers)


async def test_platform_manifest_picks_this_machines_build_and_signs_the_hash(settings):
    app, seen = make_app(settings, platform_envelope())
    j = (await post(app, settings, "/updates/check")).json()
    assert j["update_available"] and j["artifact"]["name"] == "app-setup.exe" and j["artifact"]["sha256"] == hashlib.sha256(BLOB).hexdigest()
    assert seen == ["https://updates.example.com/manifest.json"]                  # a check downloads no file
    other = "linux-x86_64" if PLAT.startswith("win") else "win32-x86_64"
    s2 = Settings(data_dir=settings.data_dir / "o", vault_encryption="off", run_scheduler=False)
    app2, _ = make_app(s2, platform_envelope(plat=other))
    j2 = (await post(app2, s2, "/updates/check")).json()
    assert j2["update_available"] and j2["artifact"] is None and j2["no_build_for_this_platform"]


async def test_download_verifies_the_signed_hash_and_saves_without_running_anything(settings):
    app, _ = make_app(settings, platform_envelope())
    assert (await post(app, settings, "/updates/download", {})).json()["code"] == "confirmation_required"
    r = await post(app, settings, "/updates/download", {"confirm": True})
    assert r.status_code == 200, r.text
    j = r.json()
    f = Path(j["file"])
    assert f.parent == settings.data_dir / "updates" and f.read_bytes() == BLOB and j["verified"] and "does not install" in j["next"]
    assert not list(f.parent.glob("*.part"))


@pytest.mark.parametrize("case", ["tampered", "other_host", "unsafe_name", "too_big", "up_to_date", "http_error"])
async def test_download_refuses_bad_inputs_and_leaves_nothing_behind(settings, case):
    blob = BLOB
    kw = {}
    if case == "tampered":
        blob = b"X" * len(BLOB)
    elif case == "other_host":
        kw["url"] = "https://evil.example.net/app-setup.exe"
    elif case == "unsafe_name":
        kw["name"] = "../../evil.exe"
    elif case == "too_big":
        kw["size"] = 10
    elif case == "up_to_date":
        kw["version"] = __version__
    app, _ = make_app(settings, platform_envelope(**kw), blob=blob, file_status=500 if case == "http_error" else 200)
    r = await post(app, settings, "/updates/download", {"confirm": True})
    assert r.status_code >= 400 and r.json()["code"] in ("hash_mismatch", "policy_denied", "bad_manifest", "too_large", "up_to_date", "bad_response")
    updates = settings.data_dir / "updates"
    assert not (updates.exists() and list(updates.glob("*")))


async def test_offline_and_non_admin_cannot_download(settings):
    app, seen = make_app(settings, platform_envelope())
    from osintcc.db.models import User
    with app.state.core.sm() as db:
        db.add(User(id="u2", display_name="x"))
        db.commit()
    app.state.core.tokens["t2"] = "u2"
    assert (await post(app, settings, "/updates/download", {"confirm": True}, headers={"Authorization": "Bearer t2"})).status_code == 403
    settings.offline = True
    assert (await post(app, settings, "/updates/download", {"confirm": True})).status_code == 409 and seen == []


async def test_manifest_url_is_a_setting_and_must_be_http(settings):
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1/api/v1",
                                     headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            assert (await c.put("/settings", json={"values": {"update_manifest_url": "ftp://x/y"}})).status_code == 422
            assert (await c.put("/settings", json={"values": {"update_manifest_url": "javascript:alert(1)"}})).status_code == 422
            ok = await c.put("/settings", json={"values": {"update_manifest_url": "http://192.168.1.10:8800/manifest.json"}})
            assert ok.json()["update_manifest_url"] == "http://192.168.1.10:8800/manifest.json"
            assert (await c.put("/settings", json={"values": {"update_manifest_url": ""}})).json()["update_manifest_url"] == ""


def test_the_built_in_public_key_matches_the_committed_key_file():
    committed = (Path(__file__).parents[2] / "backend" / "osintcc" / "setup" / "update_key.pub").read_text().strip()
    assert Settings().update_public_key == committed and len(bytes.fromhex(committed)) == 32


async def test_real_http_server_end_to_end_with_the_publish_tool(settings, tmp_path):
    out = tmp_path / "srv"
    keyfile = tmp_path / "k.key"
    keyfile.write_text(PRIV)
    installer_file = tmp_path / f"OSINT-Command-Center_9.9.9_{PLAT}.bin"   # the tool infers the platform from the file name
    installer_file.write_bytes(BLOB * 5)
    out.mkdir()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(out)))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert update_tool.main(["publish", "--version", "9.9.9", "--notes", "e2e", "--base-url", f"http://127.0.0.1:{port}/", "--dir", str(out),
                                 "--key", str(keyfile), str(installer_file)]) == 0
        settings.update_manifest_url, settings.update_public_key = f"http://127.0.0.1:{port}/manifest.json", PUB
        chk = await post(create_app(settings), settings, "/updates/check")
        assert chk.json()["update_available"] and chk.json()["signature"] == "verified"
        r = await post(create_app(settings), settings, "/updates/download", {"confirm": True})
        assert r.status_code == 200, r.text
        assert Path(r.json()["file"]).read_bytes() == BLOB * 5
        (out / installer_file.name).write_bytes(b"swapped" * 100)               # changed on the server after signing
        bad = await post(create_app(settings), settings, "/updates/download", {"confirm": True})
        assert bad.json()["code"] in ("hash_mismatch", "too_large")
    finally:
        srv.shutdown()
        srv.server_close()


def test_publish_tool_signature_roundtrip_and_tamper_detection():
    from osintcc.api.v1.updates import verify_manifest
    from osintcc.main import ApiError
    env = update_tool.sign_envelope({"version": "1.2.3", "platforms": {}}, PRIV)
    assert verify_manifest(json.dumps(env).encode(), PUB)["version"] == "1.2.3"
    env["payload"] = env["payload"].replace("1.2.3", "9.9.9")
    with pytest.raises(ApiError):
        verify_manifest(json.dumps(env).encode(), PUB)
