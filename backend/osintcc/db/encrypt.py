"""SQLite encryption at rest (SQLCipher 4, AES-256 with per-page HMAC) and the one-way migration from a plaintext database.

The database key is an HKDF subkey of the same 32-byte master key that protects the evidence vault (OS credential store or
`OSINTCC_VAULT_KEY`), so one secret protects everything and nothing new has to be remembered. Backups carry a *plaintext*
snapshot inside their passphrase-encrypted container so they can be restored on a machine that has a different master key; the
restored database is re-encrypted automatically on first start.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import sqlcipher3.dbapi2 as sqlcipher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SQLITE_MAGIC = b"SQLite format 3\x00"


class DbKeyError(RuntimeError):
    """The database is encrypted but no usable key exists, or the key is wrong. Nothing is ever recreated or overwritten."""


def derive_db_key(master: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"osintcc/sqlite-db/v1").derive(master)


def key_pragma(key: bytes) -> str:
    return f"PRAGMA key=\"x'{key.hex()}'\""


def file_state(path: Path) -> str:
    """'missing' | 'empty' | 'plaintext' | 'encrypted' (anything that is not the SQLite magic and not empty)."""
    if not path.exists():
        return "missing"
    if path.stat().st_size == 0:
        return "empty"
    with path.open("rb") as f:
        return "plaintext" if f.read(16) == SQLITE_MAGIC else "encrypted"


def connect_raw(path: Path | str, key: bytes | None = None, **kw: Any) -> sqlcipher.Connection:
    con = sqlcipher.connect(str(path), **kw)
    if key:
        con.execute(key_pragma(key))
    return con


def check_key(path: Path, key: bytes) -> bool:
    con = connect_raw(path, key)
    try:
        con.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    except sqlcipher.DatabaseError:
        return False
    finally:
        con.close()


def _tables(con: sqlcipher.Connection) -> list[str]:
    return [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]


def migrate_plaintext(path: Path, key: bytes) -> dict[str, Any]:
    """Encrypt `path` in place. The plaintext original is kept as `<name>.plaintext.bak` until the owner removes it
    (`remove_plaintext_leftovers`), and the new file is verified table-by-table before it replaces anything."""
    tmp = path.with_name(path.name + ".enc-tmp")
    for stale in (tmp, Path(str(tmp) + "-wal"), Path(str(tmp) + "-shm")):
        stale.unlink(missing_ok=True)
    src = connect_raw(path)
    try:
        src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        version = src.execute("PRAGMA user_version").fetchone()[0]
        src.execute("ATTACH DATABASE ? AS enc KEY ?", (str(tmp), f"x'{key.hex()}'"))
        src.execute("SELECT sqlcipher_export('enc')")
        src.execute(f"PRAGMA enc.user_version={int(version)}")
        src.execute("DETACH DATABASE enc")
        plain_counts = {t: src.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0] for t in _tables(src)}
    finally:
        src.close()
    enc = connect_raw(tmp, key)
    try:
        enc_counts = {t: enc.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0] for t in _tables(enc)}
        ok = enc.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        enc.close()
    if enc_counts != plain_counts or not ok:
        tmp.unlink(missing_ok=True)
        raise DbKeyError("encrypted copy did not match the original; the plaintext database was left untouched")
    bak = path.with_name(path.name + ".plaintext.bak")
    bak.unlink(missing_ok=True)
    os.replace(path, bak)
    for ext in ("-wal", "-shm"):
        Path(str(path) + ext).unlink(missing_ok=True)
    os.replace(tmp, path)
    return {"tables": len(plain_counts), "rows": sum(plain_counts.values()), "plaintext_backup": bak.name}


def snapshot_plaintext(db_path: Path, dest: Path, key: bytes | None) -> Any:
    """Consistent PLAINTEXT snapshot of the live database into `dest`; returns the Alembic revision row (or None)."""
    src = connect_raw(db_path, key)
    try:
        if key is None:
            dst = connect_raw(dest)
            try:
                src.backup(dst)  # online backup API: consistent even with WAL writers
                try:
                    return dst.execute("SELECT version_num FROM alembic_version").fetchone()
                except sqlcipher.OperationalError:
                    return None
            finally:
                dst.close()
        src.execute("ATTACH DATABASE ? AS plain KEY ''", (str(dest),))
        src.execute("SELECT sqlcipher_export('plain')")
        try:
            return src.execute("SELECT version_num FROM plain.alembic_version").fetchone()
        except sqlcipher.OperationalError:
            return None
        finally:
            src.execute("DETACH DATABASE plain")
    finally:
        src.close()


def plaintext_leftovers(db_path: Path) -> list[Path]:
    return [p for p in (db_path.with_name(db_path.name + ".plaintext.bak"), *db_path.parent.glob(db_path.stem + ".pre-*.bak"))
            if p.exists() and file_state(p) == "plaintext"]


def remove_plaintext_leftovers(db_path: Path) -> list[str]:
    """Overwrite with zeros, then delete. Only the files `plaintext_leftovers` returned; explicit admin action."""
    gone = []
    for p in plaintext_leftovers(db_path):
        size = p.stat().st_size
        with p.open("r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
        p.unlink()
        gone.append(p.name)
    return gone


def prepare(db_path: Path, master: bytes | None, mode: str) -> bytes | None:
    """Decide the database key at startup. mode is 'off' or 'required'. Returns the key to use (None = plaintext database)."""
    state = file_state(db_path)
    if mode == "off":
        if state == "encrypted":
            raise DbKeyError("the database is encrypted but database encryption is switched off; refusing to touch it")
        return None
    if master is None:
        raise DbKeyError("database encryption is required but no key is available (OS credential store locked or OSINTCC_VAULT_KEY unset)")
    key = derive_db_key(master)
    if state == "plaintext":
        migrate_plaintext(db_path, key)
    elif state == "encrypted" and not check_key(db_path, key):
        raise DbKeyError("the database is encrypted with a different key; restore the key or a backup (nothing was changed)")
    return key
