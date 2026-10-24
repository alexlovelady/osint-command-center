from __future__ import annotations

import base64
import secrets

import httpx
import pytest
from osintcc.config import Settings
from osintcc.evidence.crypto import (
    CryptoError,
    VaultCipher,
    decrypt_file,
    encrypt_file,
    is_encrypted_backup,
    load_or_create_key,
)
from osintcc.evidence.vault import IntegrityError, Vault, VaultLocked
from osintcc.main import create_app

KEY = secrets.token_bytes(32)


# ---- primitives --------------------------------------------------------------------------------------------------
def test_cipher_roundtrip_and_aad_binding():
    c = VaultCipher(KEY)
    blob = c.encrypt(b"secret", "name1")
    assert b"secret" not in blob and c.decrypt(blob, "name1") == b"secret"
    with pytest.raises(CryptoError):
        c.decrypt(blob, "name2")  # swapped under another object's name
    with pytest.raises(CryptoError):
        VaultCipher(secrets.token_bytes(32)).decrypt(blob, "name1")  # wrong key
    bad = bytearray(blob)
    bad[-1] ^= 1
    with pytest.raises(CryptoError):
        c.decrypt(bytes(bad), "name1")
    with pytest.raises(CryptoError):
        VaultCipher(b"short")


def test_key_from_env_validation():
    good = base64.b64encode(KEY).decode()
    assert load_or_create_key({"OSINTCC_VAULT_KEY": good}) == KEY
    assert load_or_create_key({"OSINTCC_VAULT_KEY": "not base64!!"}) is None
    assert load_or_create_key({"OSINTCC_VAULT_KEY": base64.b64encode(b"short").decode()}) is None


def test_keyring_failure_yields_no_key_not_a_random_one(monkeypatch):
    import keyring
    monkeypatch.setattr(keyring, "get_password", lambda *a: (_ for _ in ()).throw(RuntimeError("locked")))
    assert load_or_create_key({}) is None


# ---- vault -------------------------------------------------------------------------------------------------------
def test_encrypted_vault_stores_ciphertext_and_verifies(tmp_path):
    v = Vault(tmp_path / "v", VaultCipher(KEY), True)
    sha, _, rel, _ = v.store(b"top secret evidence")
    on_disk = (tmp_path / "v" / rel).read_bytes()
    assert b"top secret" not in on_disk and v.is_object_encrypted(rel)
    assert v.read(rel, sha) == b"top secret evidence" and v.verify(rel, sha)
    (tmp_path / "v" / rel).write_bytes(on_disk[:-3] + b"xyz")
    with pytest.raises(IntegrityError):
        v.read(rel, sha)


def test_swapping_two_ciphertexts_is_detected(tmp_path):
    v = Vault(tmp_path / "v", VaultCipher(KEY), True)
    a, _, ra, _ = v.store(b"alpha")
    b, _, rb, _ = v.store(b"bravo")
    pa, pb = tmp_path / "v" / ra, tmp_path / "v" / rb
    ca, cb = pa.read_bytes(), pb.read_bytes()
    pa.write_bytes(cb)
    pb.write_bytes(ca)
    assert not v.verify(ra, a) and not v.verify(rb, b)


def test_required_encryption_fails_closed_without_key(tmp_path):
    v = Vault(tmp_path / "v", None, require_encryption=True)
    with pytest.raises(VaultLocked):
        v.store(b"data")
    import io
    with pytest.raises(VaultLocked):
        v.store_stream(io.BytesIO(b"data"), 1000)
    assert not any(p.is_file() for p in (tmp_path / "v").rglob("*"))  # nothing written, not even temp files


def test_encrypted_object_unreadable_without_key_and_legacy_plaintext_readable(tmp_path):
    plain = Vault(tmp_path / "v")
    legacy_sha, _, legacy_rel, _ = plain.store(b"legacy plaintext")
    enc = Vault(tmp_path / "v", VaultCipher(KEY), True)
    sha, _, rel, _ = enc.store(b"new secret")
    assert enc.read(legacy_rel, legacy_sha) == b"legacy plaintext"  # mixed vaults keep working
    with pytest.raises(VaultLocked):
        Vault(tmp_path / "v").read(rel, sha)
    out = enc.encrypt_existing()
    assert out == {"encrypted": 1, "already_encrypted": 1}
    assert enc.is_object_encrypted(legacy_rel) and enc.read(legacy_rel, legacy_sha) == b"legacy plaintext"
    assert enc.encrypt_existing() == {"encrypted": 0, "already_encrypted": 2}  # idempotent


def test_stream_import_is_encrypted_too(tmp_path):
    import io
    v = Vault(tmp_path / "v", VaultCipher(KEY), True)
    sha, _, rel, _ = v.store_stream(io.BytesIO(b"streamed content"), 1000)
    assert v.is_object_encrypted(rel) and v.read(rel, sha) == b"streamed content"


# ---- backup container --------------------------------------------------------------------------------------------
def test_backup_container_roundtrip_wrong_passphrase_and_truncation(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(secrets.token_bytes(3 * (1 << 20) + 17))
    enc, dec = tmp_path / "a.enc", tmp_path / "a.dec"
    encrypt_file(src, enc, "correct horse battery")
    assert is_encrypted_backup(enc) and enc.read_bytes()[:6] == b"OSCCB1"
    decrypt_file(enc, dec, "correct horse battery")
    assert dec.read_bytes() == src.read_bytes()
    with pytest.raises(CryptoError):
        decrypt_file(enc, tmp_path / "x", "wrong passphrase!!")
    raw = enc.read_bytes()
    (tmp_path / "trunc.enc").write_bytes(raw[:len(raw) - (1 << 20) - 16])  # drop the final chunk
    with pytest.raises(CryptoError):
        decrypt_file(tmp_path / "trunc.enc", tmp_path / "x", "correct horse battery")
    flipped = bytearray(raw)
    flipped[100] ^= 1
    (tmp_path / "flip.enc").write_bytes(bytes(flipped))
    with pytest.raises(CryptoError):
        decrypt_file(tmp_path / "flip.enc", tmp_path / "x", "correct horse battery")
    with pytest.raises(CryptoError):
        encrypt_file(src, tmp_path / "w", "short")


def test_backup_container_empty_and_exact_chunk_sizes(tmp_path):
    for n in (0, 1, 1 << 20, 2 * (1 << 20)):
        s = tmp_path / f"s{n}"
        s.write_bytes(b"z" * n)
        encrypt_file(s, tmp_path / f"e{n}", "passphrase-123")
        decrypt_file(tmp_path / f"e{n}", tmp_path / f"d{n}", "passphrase-123")
        assert (tmp_path / f"d{n}").read_bytes() == s.read_bytes(), n


# ---- API end to end with an encrypting vault -----------------------------------------------------------------------
@pytest.fixture
async def secure(tmp_path):
    s = Settings(data_dir=tmp_path / "data", vault_encryption="required")
    app = create_app(s, vault_key=KEY)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {s.session_token}"
            c.app, c.settings = app, s
            yield c


async def test_api_vault_is_encrypted_and_backup_requires_passphrase(secure):
    cid = (await secure.post("/api/v1/cases", json={"title": "Enc", "purpose": "t"})).json()["id"]
    imp = await secure.post(f"/api/v1/cases/{cid}/evidence/import?filename=n.txt&consent_confirmed=true",
                            content=b"plaintext marker 12345")
    assert imp.status_code == 201
    obj = next(secure.settings.vault_dir.rglob(imp.json()["sha256"]))
    assert b"plaintext marker" not in obj.read_bytes()
    assert (await secure.get(f"/api/v1/evidence/{imp.json()['id']}/download")).content == b"plaintext marker 12345"
    st = (await secure.get("/api/v1/system/vault")).json()
    assert st["key_available"] and st["encrypted_objects"] == 1 and st["plaintext_objects"] == 0
    assert st["database_encrypted"] is True

    refused = await secure.post("/api/v1/backups", json={})
    assert refused.status_code == 409 and refused.json()["code"] == "backup_refused"
    assert (await secure.post("/api/v1/backups", json={"passphrase": "short"})).status_code == 422

    b = (await secure.post("/api/v1/backups", json={"passphrase": "a-long-passphrase"})).json()
    assert b["file"].endswith(".zip.enc") and b["verification"]["ok"] and b["encrypted"]
    path = secure.settings.backup_dir / b["file"]
    assert b"plaintext marker" not in path.read_bytes() and b"SQLite format" not in path.read_bytes()
    nopass = (await secure.post("/api/v1/backups/verify", json={"file": b["file"]})).json()
    assert not nopass["ok"] and nopass["needs_passphrase"]
    wrong = (await secure.post("/api/v1/backups/verify", json={"file": b["file"], "passphrase": "not-the-passphrase"})).json()
    assert not wrong["ok"]

    body = {"file": b["file"], "target_name": "restored1", "passphrase": "a-long-passphrase", "confirm": True}
    assert (await secure.post("/api/v1/backups/restore", json=body)).status_code == 200
    restored = secure.settings.data_dir / "restores" / "restored1" / "vault"
    robj = next(restored.rglob(imp.json()["sha256"]))
    assert b"plaintext marker" not in robj.read_bytes()  # re-sealed with the destination key, not left plaintext
    assert Vault(restored, VaultCipher(KEY), True).read(
        robj.relative_to(restored).as_posix(), imp.json()["sha256"]) == b"plaintext marker 12345"


async def test_api_fails_closed_when_key_missing(tmp_path, monkeypatch):
    import osintcc.main as m
    monkeypatch.setattr(m, "load_or_create_key", lambda: None)
    from osintcc.db.encrypt import DbKeyError
    with pytest.raises(DbKeyError, match="no key is available"):   # the encrypted database cannot even be opened: fail closed
        create_app(Settings(data_dir=tmp_path / "strict", vault_encryption="required"))
    # with the database explicitly left plaintext the vault-only fail-closed behaviour still holds
    s = Settings(data_dir=tmp_path / "data", vault_encryption="required", db_encryption="off")
    app = create_app(s)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            cid = (await c.post("/api/v1/cases", json={"title": "x", "purpose": "t"})).json()["id"]
            r = await c.post(f"/api/v1/cases/{cid}/evidence/import?filename=n.txt&consent_confirmed=true", content=b"abc")
            assert r.status_code == 503 and r.json()["code"] == "vault_locked"
            assert not any(p.is_file() for p in s.vault_dir.rglob("*"))
            assert (await c.get("/api/v1/system/vault")).json()["key_available"] is False
