from __future__ import annotations

import json
import shutil

import httpx
import pytest
import synthetic_intel as si
from osintcc.adapters.cli import ProcResult
from osintcc.config import Settings
from osintcc.ingest import exiftool
from osintcc.main import create_app
from osintcc.setup.state import managed_path

REAL = managed_path(Settings().tools_state_path, "exiftool") or shutil.which("exiftool")


async def test_tag_filtering_caps_and_position_flag(monkeypatch):
    out = {"SourceFile": "x", "System:FileName": "x", "IFD0:Make": "ACME", "IFD0:ThumbnailData": "zzz", "GPS:GPSLatitude": 48.8, "XMP:Big": "a" * 5000}

    async def fake(argv, timeout, max_output=0, **kw):
        assert argv[-2] == "--" and "-n" in argv and kw["cwd"]          # fixed argv, scratch cwd
        return ProcResult(0, json.dumps([out]).encode(), b"")
    monkeypatch.setattr(exiftool, "run_argv", fake)
    o = await exiftool.read_tags("exiftool", b"data", "weird name.JPG")
    assert o and o.kind == "exiftool.metadata" and o.discipline == "GEOINT" and o.sensitivity == "RESTRICTED"
    assert set(o.data["tags"]) == {"IFD0:Make", "GPS:GPSLatitude", "XMP:Big"} and len(o.data["tags"]["XMP:Big"]) == exiftool.MAX_VALUE
    assert "claims made by the file" in o.data["note"]

    async def bad(argv, timeout, max_output=0, **kw):
        return ProcResult(1, b"", b"error")
    monkeypatch.setattr(exiftool, "run_argv", bad)
    assert await exiftool.read_tags("exiftool", b"d", "a.jpg") is None


@pytest.mark.skipif(not REAL, reason="ExifTool is not installed (run: python -m osintcc.setup install exiftool --yes)")
async def test_real_exiftool_enriches_an_import(tmp_path, monkeypatch):
    monkeypatch.setattr("osintcc.setup.state.managed_path", lambda p, t: REAL if t == "exiftool" else None)
    s = Settings(data_dir=tmp_path, vault_encryption="off", run_scheduler=False)
    app = create_app(s)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1/api/v1",
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            cid = (await c.post("/cases", json={"title": "E", "purpose": "x"})).json()["id"]
            r = await c.post(f"/cases/{cid}/ingest?filename=photo.jpg&consent_confirmed=true", content=si.jpeg_with_gps(48.8584, 2.2945))
            assert r.status_code == 201
            obs = (await c.get(f"/cases/{cid}/observations")).json()["items"]
            ex = next(o for o in obs if o["kind"] == "exiftool.metadata")
            assert ex["sensitivity"] == "RESTRICTED" and any("GPSLatitude" in k for k in ex["data"]["tags"])
            assert any(o["kind"] != "exiftool.metadata" for o in obs)              # the built-in parser still ran
