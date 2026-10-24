from __future__ import annotations

import secrets
import sqlite3

import httpx
import pytest
import sqlcipher3.dbapi2 as sqlcipher
from osintcc.config import Settings
from osintcc.db import encrypt as dbenc
from osintcc.db.encrypt import DbKeyError
from osintcc.main import create_app

KEY = secrets.token_bytes(32)
OTHER = secrets.token_bytes(32)
MARK = "needle-case-title-98765"


async def run_app(settings, key, fn):
    app = create_app(settings, vault_key=key)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            return await fn(c)


def raw_bytes(settings) -> bytes:
    return b"".join(p.read_bytes() for p in settings.data_dir.glob("osintcc.sqlite*") if p.is_file() and not p.name.endswith(".bak"))


async def test_database_file_is_ciphertext_and_wrong_key_is_refused(tmp_path):
    s = Settings(data_dir=tmp_path / "d", vault_encryption="required")

    async def work(c):
        r = await c.post("/api/v1/cases", json={"title": MARK, "purpose": "x"})
        await c.post(f"/api/v1/cases/{r.json()['id']}/notes", json={"body_markdown": "secret note body zzz"})
        return (await c.get("/api/v1/system/vault")).json()
    st = await run_app(s, KEY, work)
    assert st["database_encrypted"] is True
    assert dbenc.file_state(s.db_path) == "encrypted"
    blob = raw_bytes(s)
    assert MARK.encode() not in blob and b"secret note body" not in blob and b"SQLite format 3" not in blob
    before = s.db_path.read_bytes()
    with pytest.raises(DbKeyError, match="different key"):
        create_app(s, vault_key=OTHER)
    assert s.db_path.read_bytes() == before           # a wrong key never modifies the file
    with pytest.raises(DbKeyError, match="switched off"):
        create_app(Settings(data_dir=s.data_dir, vault_encryption="off"))
    con = sqlite3.connect(s.db_path)
    try:
        with pytest.raises(sqlite3.DatabaseError):      # the standard library cannot read it either
            con.execute("select * from cases").fetchall()
    finally:
        con.close()


async def test_plaintext_database_is_migrated_with_data_fts_and_leftover_removal(tmp_path):
    d = tmp_path / "d"
    plain = Settings(data_dir=d, vault_encryption="off")

    async def seed(c):
        cid = (await c.post("/api/v1/cases", json={"title": MARK, "purpose": "x"})).json()["id"]
        await c.post(f"/api/v1/cases/{cid}/notes", json={"body_markdown": "searchable zebra note"})
        return cid
    cid = await run_app(plain, None, seed)
    assert dbenc.file_state(plain.db_path) == "plaintext" and MARK.encode() in raw_bytes(plain)

    enc = Settings(data_dir=d, vault_encryption="required")

    async def check(c):
        got = (await c.get(f"/api/v1/cases/{cid}")).json()
        hits = (await c.get(f"/api/v1/cases/{cid}/search?q=zebra")).json()["items"]
        st = (await c.get("/api/v1/system/vault")).json()
        return got, hits, st
    got, hits, st = await run_app(enc, KEY, check)
    assert got["title"] == MARK and hits and st["database_encrypted"] and st["plaintext_leftovers"] == ["osintcc.sqlite.plaintext.bak"]
    assert dbenc.file_state(enc.db_path) == "encrypted" and MARK.encode() not in raw_bytes(enc)

    async def clean(c):
        denied = await c.post("/api/v1/system/database/remove-plaintext-leftovers")
        return denied.json()
    assert (await run_app(enc, KEY, clean))["removed"] == ["osintcc.sqlite.plaintext.bak"]
    assert not list(d.glob("*.plaintext.bak"))
    assert (await run_app(enc, KEY, check))[1]          # still works after the plaintext copy is gone


def test_migration_failure_leaves_the_original_untouched(tmp_path, monkeypatch):
    p = tmp_path / "osintcc.sqlite"
    con = sqlcipher.connect(str(p))
    con.execute("create table t(a)")
    con.execute("insert into t values (1)")
    con.commit()
    con.close()
    orig = dbenc._tables
    calls = {"n": 0}

    def fake(con):
        calls["n"] += 1
        return orig(con) if calls["n"] == 1 else []      # the encrypted copy "loses" its tables
    monkeypatch.setattr(dbenc, "_tables", fake)
    with pytest.raises(DbKeyError, match="did not match"):
        dbenc.migrate_plaintext(p, KEY)
    assert dbenc.file_state(p) == "plaintext" and not list(tmp_path.glob("*.enc-tmp"))


def test_key_required_but_missing_fails_closed(tmp_path):
    with pytest.raises(DbKeyError, match="no key is available"):
        dbenc.prepare(tmp_path / "x.sqlite", None, "required")
    assert dbenc.prepare(tmp_path / "x.sqlite", None, "off") is None


async def test_backup_restores_on_a_machine_with_a_different_key_and_reencrypts(tmp_path):
    s = Settings(data_dir=tmp_path / "a", vault_encryption="required")

    async def work(c):
        cid = (await c.post("/api/v1/cases", json={"title": MARK, "purpose": "x"})).json()["id"]
        b = (await c.post("/api/v1/backups", json={"passphrase": "a-long-passphrase"})).json()
        r = await c.post("/api/v1/backups/restore", json={"file": b["file"], "passphrase": "a-long-passphrase", "target_name": "moved", "confirm": True})
        assert r.status_code in (200, 201), r.text
        return cid
    cid = await run_app(s, KEY, work)
    restored = s.data_dir / "restores" / "moved"
    assert dbenc.file_state(restored / "osintcc.sqlite") == "plaintext"      # portable snapshot
    s2 = Settings(data_dir=restored, vault_encryption="required")

    async def look(c):
        return (await c.get(f"/api/v1/cases/{cid}")).json()["title"]
    assert await run_app(s2, OTHER, look) == MARK                              # a different master key
    assert dbenc.file_state(restored / "osintcc.sqlite") == "encrypted"


async def test_reports_are_encrypted_at_rest_and_download_as_plaintext(tmp_path):
    s = Settings(data_dir=tmp_path / "d", vault_encryption="required")

    async def work(c):
        cid = (await c.post("/api/v1/cases", json={"title": MARK, "purpose": "x"})).json()["id"]
        rep = (await c.post(f"/api/v1/cases/{cid}/reports", json={"profile": "technical", "format": "html"})).json()
        dl = await c.get(f"/api/v1/reports/{rep['id']}/download")
        return rep, dl
    rep, dl = await run_app(s, KEY, work)
    assert rep["file"].endswith(".html.enc")
    on_disk = (s.export_dir / rep["file"]).read_bytes()
    assert MARK.encode() not in on_disk and not list(s.export_dir.glob("*.html"))
    assert dl.status_code == 200 and MARK.encode() in dl.content and 'filename="' in dl.headers["content-disposition"]
    assert ".enc" not in dl.headers["content-disposition"]
    import hashlib
    assert hashlib.sha256(dl.content).hexdigest() == rep["sha256"]
