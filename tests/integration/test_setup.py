from __future__ import annotations

import asyncio
import hashlib
import io
import json
import stat
import sys
import tarfile
import zipfile

import httpx
import pytest
from osintcc.config import Settings
from osintcc.main import create_app
from osintcc.setup import installer
from osintcc.setup.installer import SetupError
from osintcc.setup.state import managed_path

PLAT = installer.platform_key() or "win32-x86_64"
EXE = "tool.exe" if sys.platform == "win32" else "tool"


def make_zip(files: dict[str, bytes], symlink: str | None = None) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
        if symlink:
            i = zipfile.ZipInfo(symlink)
            i.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(i, "target")
    return b.getvalue()


def make_tgz(files: dict[str, bytes]) -> bytes:
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for n, d in files.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
    return b.getvalue()


@pytest.fixture
def fake_catalog(monkeypatch):
    blob = make_zip({EXE: b"MZ-not-really-a-program", "LICENSE": b"MIT"})
    cat = {"schema": 1, "tools": {
        "faketool": {"kind": "archive", "name": "Fake tool", "version": "1.0", "license": "MIT", "homepage": "https://github.com/x/y",
                     "platforms": {PLAT: {"url": "https://github.com/x/y/releases/download/v1/fake.zip", "sha256": hashlib.sha256(blob).hexdigest(),
                                          "size": len(blob), "format": "zip", "main": EXE, "members": [EXE]}}},
        "nobuild": {"kind": "archive", "name": "No build", "version": "1", "license": "MIT", "homepage": "https://example.org", "platforms": {}}},
        "models": [{"id": "x/model:8b", "label": "m", "download_gb": 5.0, "min_ram_gb": 12}, {"id": "x/model:1b", "label": "s", "download_gb": 1.0, "min_ram_gb": 2}]}
    monkeypatch.setattr(installer, "catalog", lambda: cat)
    return cat, blob


def transport(routes: dict[str, httpx.Response | list[httpx.Response]]):
    seen: list[str] = []

    def h(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        r = routes.get(str(req.url))
        if r is None:
            return httpx.Response(404)
        return r.pop(0) if isinstance(r, list) else r
    t = httpx.MockTransport(h)
    t.seen = seen  # type: ignore[attr-defined]
    return t


async def test_install_verifies_hash_extracts_and_records(tmp_path, fake_catalog):
    _cat, blob = fake_catalog
    s = Settings(data_dir=tmp_path)
    t = transport({"https://github.com/x/y/releases/download/v1/fake.zip": httpx.Response(302, headers={"location": "https://objects.githubusercontent.com/abc"}),
                   "https://objects.githubusercontent.com/abc": httpx.Response(200, content=blob)})
    events: list[dict] = []
    r = await installer.install(s, "faketool", progress=events.append, transport=t)
    p = managed_path(s.tools_state_path, "faketool")
    assert p and p.endswith(EXE) and r["path"] == p and (tmp_path / "tools" / "faketool" / "1.0" / EXE).read_bytes().startswith(b"MZ")
    assert not (tmp_path / "tools" / "faketool" / "1.0" / "LICENSE").exists()      # only the declared members are extracted
    assert [e["phase"] for e in events if e["phase"] != "download"] == ["extract", "done"] and t.seen[-1].startswith("https://objects.")


async def test_hash_mismatch_deletes_the_download_and_installs_nothing(tmp_path, fake_catalog):
    _, blob = fake_catalog
    s = Settings(data_dir=tmp_path)
    t = transport({"https://github.com/x/y/releases/download/v1/fake.zip": httpx.Response(200, content=blob + b"tampered")})
    with pytest.raises(SetupError, match="larger than the pinned size|SHA-256 mismatch"):
        await installer.install(s, "faketool", transport=t)
    t2 = transport({"https://github.com/x/y/releases/download/v1/fake.zip": httpx.Response(200, content=b"x" * len(blob))})
    with pytest.raises(SetupError, match="SHA-256 mismatch"):
        await installer.install(s, "faketool", transport=t2)
    assert managed_path(s.tools_state_path, "faketool") is None and not (tmp_path / "tools" / "faketool").exists()


@pytest.mark.parametrize("url", ["http://github.com/a.zip", "https://evil.example.net/a.zip", "https://127.0.0.1/a.zip", "https://github.com.evil.io/a"])
async def test_only_https_publisher_hosts_are_allowed(tmp_path, url):
    with pytest.raises(SetupError, match="not an allowed https publisher host"):
        await installer.download(url, tmp_path / "x", "0" * 64, 1000, transport=transport({}))


async def test_redirect_to_an_unlisted_host_is_refused(tmp_path):
    t = transport({"https://github.com/a": httpx.Response(302, headers={"location": "https://attacker.example/payload"})})
    with pytest.raises(SetupError, match="not an allowed"):
        await installer.download("https://github.com/a", tmp_path / "x", "0" * 64, 1000, transport=t)
    assert t.seen == ["https://github.com/a"]                                      # the second hop was never requested


def test_extraction_blocks_traversal_symlinks_and_bombs(tmp_path):
    z = tmp_path / "a.zip"
    z.write_bytes(make_zip({"../escape.txt": b"x"}))
    with pytest.raises(SetupError, match="unsafe path"):
        installer.extract(z, "zip", tmp_path / "out", whole=True)
    z.write_bytes(make_zip({"ok.txt": b"x"}, symlink="evil"))
    with pytest.raises(SetupError, match="symlink"):
        installer.extract(z, "zip", tmp_path / "out2", whole=True)
    g = tmp_path / "a.tgz"
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        ti = tarfile.TarInfo("link")
        ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
        t.addfile(ti)
    g.write_bytes(b.getvalue())
    with pytest.raises(SetupError, match="non-regular"):
        installer.extract(g, "tar.gz", tmp_path / "out3", whole=True)
    assert not (tmp_path / "escape.txt").exists()
    big = tmp_path / "big.zip"
    big.write_bytes(make_zip({"a": b"0" * 1000}))
    old = installer.MAX_EXTRACT_BYTES
    installer.MAX_EXTRACT_BYTES = 10
    try:
        with pytest.raises(SetupError, match="size limit"):
            installer.extract(big, "zip", tmp_path / "out4", whole=True)
    finally:
        installer.MAX_EXTRACT_BYTES = old


def test_strip_rename_and_member_filter(tmp_path):
    a = tmp_path / "a.tgz"
    a.write_bytes(make_tgz({"top/bin/tool": b"1", "top/README": b"2"}))
    out = installer.extract(a, "tar.gz", tmp_path / "o", members=["top/bin/tool"], strip=1)
    assert [p.relative_to(tmp_path / "o").as_posix() for p in out] == ["bin/tool"]
    z = tmp_path / "b.zip"
    z.write_bytes(make_zip({"d/exiftool(-k).exe": b"1"}))
    installer.extract(z, "zip", tmp_path / "o2", whole=True, strip=1, rename={"exiftool(-k).exe": "exiftool.exe"})
    assert (tmp_path / "o2" / "exiftool.exe").exists()


async def test_status_plan_and_recommendation(tmp_path, fake_catalog, monkeypatch):
    s = Settings(data_dir=tmp_path)
    st = await installer.status(s)
    by = {t["id"]: t for t in st["tools"]}
    assert by["faketool"]["installable"] and not by["faketool"]["installed"] and by["faketool"]["download_mb"] is not None
    assert not by["nobuild"]["installable"] and by["nobuild"]["reason"]
    assert installer.plan(s, ["faketool"])[0]["urls"] == ["https://github.com/x/y/releases/download/v1/fake.zip"]
    with pytest.raises(SetupError, match="not installable"):
        installer.plan(s, ["nobuild"])
    assert installer.recommended_model(32)["id"] == "x/model:8b"
    assert installer.recommended_model(4)["id"] == "x/model:1b"
    assert installer.recommended_model(None)["id"] == "x/model:1b"       # unknown RAM => the smallest, never the biggest


async def test_pull_model_streams_progress_and_checks_listing(tmp_path, fake_catalog):
    lines = "\n".join(json.dumps(x) for x in [{"status": "pulling manifest"}, {"status": "pulling abc", "total": 100, "completed": 40},
                                              {"status": "success"}])
    t = transport({"http://127.0.0.1:11434/api/tags": httpx.Response(200, json={"models": [{"name": "x/model:1b"}]}),
                   "http://127.0.0.1:11434/api/pull": httpx.Response(200, content=lines.encode())})
    got: list[dict] = []
    r = await installer.pull_model("x/model:1b", got.append, transport=t)
    assert r["status"] == "success" and any(g.get("total") == 100 and g["completed"] == 40 for g in got)
    with pytest.raises(SetupError, match="not in the setup catalog"):
        await installer.pull_model("evil/model:latest", transport=t)
    t2 = transport({"http://127.0.0.1:11434/api/tags": httpx.Response(200, json={"models": []}),
                    "http://127.0.0.1:11434/api/pull": httpx.Response(200, content=b'{"status":"success"}\n')})
    with pytest.raises(SetupError, match="not listed"):
        await installer.pull_model("x/model:1b", transport=t2)
    t3 = transport({"http://127.0.0.1:11434/api/tags": httpx.Response(200, json={"models": []}),
                    "http://127.0.0.1:11434/api/pull": httpx.Response(200, content=b'{"error":"pull model manifest: file does not exist"}\n')})
    with pytest.raises(SetupError, match="file does not exist"):
        await installer.pull_model("x/model:1b", transport=t3)


# ---- API ------------------------------------------------------------------------------------------------------------
@pytest.fixture
async def api(tmp_path, fake_catalog):
    s = Settings(data_dir=tmp_path / "d", vault_encryption="off", run_scheduler=False)
    app = create_app(s)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {s.session_token}"
            c.app, c.settings = app, s
            yield c


async def test_api_requires_confirmation_and_respects_offline(api):
    body = {"ids": ["faketool"]}
    assert (await api.post("/api/v1/setup/install", json=body)).json()["code"] == "confirmation_required"
    assert (await api.post("/api/v1/setup/plan", json=body)).json()["items"][0]["id"] == "faketool"
    await api.put("/api/v1/settings", json={"values": {"offline": True}})
    r = await api.post("/api/v1/setup/install", json={**body, "confirm": True})
    assert r.status_code == 409 and r.json()["code"] == "offline"
    assert (await api.post("/api/v1/setup/model", json={"confirm": True})).json()["code"] == "offline"
    await api.put("/api/v1/settings", json={"values": {"offline": False}})
    assert (await api.post("/api/v1/setup/install", json={"ids": ["nobuild"], "confirm": True})).json()["code"] == "not_installable"


async def test_api_install_runs_in_background_and_adapters_see_the_result(api, fake_catalog, monkeypatch):
    _, blob = fake_catalog
    orig = installer.download

    async def fake_download(url, dest, sha256, max_bytes, progress=None, transport=None):
        return await orig(url, dest, sha256, max_bytes, progress, transport=httpx.MockTransport(lambda r: httpx.Response(200, content=blob)))
    monkeypatch.setattr(installer, "download", fake_download)
    r = await api.post("/api/v1/setup/install", json={"ids": ["faketool"], "confirm": True})
    assert r.status_code == 202
    tid = r.json()["task_id"]
    for _ in range(100):
        t = (await api.get(f"/api/v1/setup/tasks/{tid}")).json()
        if t["status"] != "running":
            break
        await asyncio.sleep(0.05)
    assert t["status"] == "done" and t["results"][0]["id"] == "faketool"
    st = (await api.get("/api/v1/setup/status")).json()
    assert next(x for x in st["tools"] if x["id"] == "faketool")["managed"] is True and st["completed"] is False
    assert (await api.post("/api/v1/setup/complete")).json() == {"completed": True}
    assert (await api.get("/api/v1/setup/status")).json()["completed"] is True
    assert (await api.get("/api/v1/setup/tasks/nope")).status_code == 404


async def test_non_admin_cannot_install(api):
    from osintcc.db.models import User
    with api.app.state.core.sm() as db:
        db.add(User(id="u2", display_name="Other"))
        db.commit()
    api.app.state.core.tokens["tok2"] = "u2"
    r = await api.post("/api/v1/setup/install", json={"ids": ["faketool"], "confirm": True}, headers={"Authorization": "Bearer tok2"})
    assert r.status_code == 403


async def test_model_setup_creates_a_local_profile_and_enables_ai(api, monkeypatch):
    async def fake_pull(model, progress=None, base=installer.OLLAMA, transport=None):
        return {"model": model, "status": "success"}
    monkeypatch.setattr(installer, "pull_model", fake_pull)
    monkeypatch.setattr(installer, "ollama_path", lambda: "/usr/bin/ollama")
    r = await api.post("/api/v1/setup/model", json={"confirm": True, "model_id": "x/model:1b"})
    assert r.status_code == 202
    tid = r.json()["task_id"]
    for _ in range(100):
        t = (await api.get(f"/api/v1/setup/tasks/{tid}")).json()
        if t["status"] != "running":
            break
        await asyncio.sleep(0.05)
    assert t["status"] == "done"
    prof = (await api.get("/api/v1/ai/profiles")).json()
    assert prof["ai_enabled"] is True and prof["items"][0]["model_id"] == "x/model:1b" and prof["items"][0]["kind"] == "local"
    assert prof["items"][0]["base_url"] == "http://127.0.0.1:11434"
    bad = await api.post("/api/v1/setup/model", json={"confirm": True, "model_id": "evil/other:latest"})
    assert bad.status_code == 422 and bad.json()["code"] == "unknown_model"


def test_publisher_host_allow_list_is_exact():
    ok = ["github.com", "codeload.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "sourceforge.net",
          "netix.dl.sourceforge.net", "downloads.sourceforge.net"]
    bad = ["evil.com", "github.com.evil.com", "notgithub.com", "dl.sourceforge.net.evil.io", "raw.githubusercontent.com", "pypi.org", ""]
    assert all(installer.host_allowed(h) for h in ok) and not any(installer.host_allowed(h) for h in bad)


def test_catalog_pins_every_download_with_a_sha256_and_locks_python_tools():
    cat = installer.catalog.__wrapped__() if hasattr(installer.catalog, "__wrapped__") else json.loads((installer.HERE / "catalog.json").read_text(encoding="utf8"))
    for tid, t in cat["tools"].items():
        for plat, e in t["platforms"].items():
            if "url" in e:
                assert len(e["sha256"]) == 64 and e["url"].startswith("https://") and installer.host_allowed(e["url"].split("/")[2]), (tid, plat)
            if "requirements" in e:
                body = (installer.HERE / "requirements" / e["requirements"]).read_text(encoding="utf8")
                pins = [ln for ln in body.splitlines() if ln and not ln.startswith(("#", " "))]
                assert pins and body.count("--hash=sha256:") >= len(pins), (tid, plat)   # every pinned package carries hashes
