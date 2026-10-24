"""Consistent backup / verify / restore-to-new-directory (spec 17.2, 21.9).

Vault objects are stored as PLAINTEXT inside the backup container (decrypted with the live vault key), so the
container itself must be protected: pass a passphrase to produce an AES-256-GCM `.zip.enc`. Without a passphrase a
backup of an encrypting vault is refused unless the caller explicitly allows a plaintext backup. On restore, objects
are re-sealed with the destination vault's key. Secrets and keys are never included.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .config import Settings
from .db import encrypt as dbenc
from .evidence.crypto import CryptoError, decrypt_file, encrypt_file, is_encrypted_backup
from .evidence.vault import Vault, VaultError

SCHEMA_TAG = "osintcc-backup-v2"
SUPPORTED_TAGS = {"osintcc-backup-v1", SCHEMA_TAG}


class BackupError(Exception):
    pass


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def create_backup(settings: Settings, vault: Vault | None = None, *, passphrase: str | None = None,
                  allow_plaintext: bool = False, dest_dir: Path | None = None, db_key: bytes | None = None) -> Path:
    vault = vault or Vault(settings.vault_dir)
    if not passphrase and not allow_plaintext and (vault.encrypting or vault.require_encryption):
        raise BackupError("this vault is encrypted: provide a backup passphrase (or explicitly allow a plaintext backup)")
    dest_dir = dest_dir or settings.backup_dir
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    final = dest_dir / (f"OSINTCC-backup-{stamp}.zip" + (".enc" if passphrase else ""))
    with tempfile.TemporaryDirectory(dir=dest_dir) as td:
        tmpdb = Path(td) / "database.sqlite"
        # the snapshot is PLAINTEXT on purpose: it must be restorable on a machine with a different master key (it is re-encrypted on first start)
        rev = dbenc.snapshot_plaintext(settings.db_path, tmpdb, db_key)
        sums: dict[str, str] = {"database.sqlite": _sha(tmpdb)}
        tmpzip = Path(td) / "out.zip"
        with zipfile.ZipFile(tmpzip, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(tmpdb, "database.sqlite")
            if settings.vault_dir.exists():
                for f in sorted(settings.vault_dir.glob("sha256/*/*")):
                    if not f.is_file() or f.name.startswith("."):
                        continue
                    rel = f"sha256/{f.name[:2]}/{f.name}"
                    try:
                        plain = vault.read(rel, f.name)  # decrypts + verifies hash
                    except VaultError as exc:
                        raise BackupError(
                            f"vault object {f.name} cannot be read/verified ({exc}); refusing to back up") from exc
                    z.writestr("evidence/" + rel, plain)
                    sums["evidence/" + rel] = f.name  # an evidence object's name IS its sha256
            manifest = {"format": SCHEMA_TAG, "created_at": datetime.now(UTC).isoformat(),
                        "alembic_revision": rev[0] if rev else None, "files": len(sums),
                        "encrypted": bool(passphrase), "vault_objects_plaintext_inside": True,
                        "secrets_included": False}
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
            z.writestr("checksums.sha256", "".join(f"{v}  {k}\n" for k, v in sorted(sums.items())))
        if passphrase:
            try:
                encrypt_file(tmpzip, Path(td) / "out.enc", passphrase)
            except CryptoError as exc:
                raise BackupError(str(exc)) from exc
            (Path(td) / "out.enc").replace(final)
        else:
            tmpzip.replace(final)  # atomic move into place only after the full write
    return final


def _open_zip(path: Path, passphrase: str | None, workdir: Path) -> zipfile.ZipFile:
    if is_encrypted_backup(path):
        if not passphrase:
            raise BackupError("this backup is encrypted: a passphrase is required")
        plain = workdir / "dec.zip"
        try:
            decrypt_file(path, plain, passphrase)
        except CryptoError as exc:
            raise BackupError(str(exc)) from exc
        return zipfile.ZipFile(plain)
    return zipfile.ZipFile(path)


def verify_backup(path: Path, passphrase: str | None = None) -> dict:
    """Read-only verification. Never writes anywhere except a private temp dir."""
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        try:
            z = _open_zip(path, passphrase, Path(td))
        except BackupError as exc:
            return {"ok": False, "problems": [str(exc)], "needs_passphrase": "passphrase is required" in str(exc)}
        except (zipfile.BadZipFile, OSError) as exc:
            return {"ok": False, "problems": [f"not a readable backup: {exc}"]}
        with z:
            names = set(z.namelist())
            for need in ("manifest.json", "checksums.sha256", "database.sqlite"):
                if need not in names:
                    problems.append(f"missing {need}")
            if problems:
                return {"ok": False, "problems": problems}
            try:
                manifest = json.loads(z.read("manifest.json"))
            except ValueError:
                return {"ok": False, "problems": ["manifest.json unreadable"]}
            if manifest.get("format") not in SUPPORTED_TAGS:
                problems.append("unknown backup format")
            listed = {}
            for line in z.read("checksums.sha256").decode().splitlines():
                digest, _, name = line.partition("  ")
                listed[name] = digest
            for name, digest in listed.items():
                if name not in names:
                    problems.append(f"listed file missing: {name}")
                    continue
                if ".." in Path(name).parts or Path(name).is_absolute():
                    problems.append(f"unsafe path: {name}")
                    continue
                h = hashlib.sha256()
                with z.open(name) as fh:
                    while chunk := fh.read(1 << 20):
                        h.update(chunk)
                if h.hexdigest() != digest:
                    problems.append(f"checksum mismatch: {name}")
            extra = names - set(listed) - {"manifest.json", "checksums.sha256"}
            if extra:
                problems.append(f"unlisted files: {sorted(extra)[:5]}")
            db = Path(td) / "d.sqlite"
            db.write_bytes(z.read("database.sqlite"))
            con = sqlite3.connect(db)
            try:
                if con.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    problems.append("database integrity_check failed")
                con.execute("PRAGMA foreign_keys=ON")
                if con.execute("PRAGMA foreign_key_check").fetchall():
                    problems.append("database foreign_key_check failed")
            except sqlite3.DatabaseError as exc:
                problems.append(f"database unreadable: {exc}")
            finally:
                con.close()
    return {"ok": not problems, "problems": problems, "manifest": manifest, "files": len(listed),
            "encrypted": is_encrypted_backup(path)}


def restore_preview(path: Path, target_dir: Path, passphrase: str | None = None) -> dict:
    v = verify_backup(path, passphrase)
    collisions = []
    if target_dir.exists() and any(target_dir.iterdir()):
        collisions = sorted(p.name for p in target_dir.iterdir())[:20]
    return {"verification": v, "target_dir": str(target_dir), "collisions": collisions,
            "would_restore": v.get("files", 0) if v["ok"] else 0, "restore_allowed": v["ok"] and not collisions}


def restore(path: Path, target_dir: Path, *, confirm: bool, passphrase: str | None = None,
            vault_factory: Callable[[Path], Vault] | None = None) -> Path:
    """Restores into a NEW (empty or nonexistent) directory; never overwrites live data. Evidence is re-sealed by
    `vault_factory(<dir>/vault)` so it is encrypted with the destination key when one is configured."""
    if not confirm:
        raise BackupError("explicit confirmation required")
    prev = restore_preview(path, target_dir, passphrase)
    if not prev["verification"]["ok"]:
        raise BackupError(f"backup failed verification: {prev['verification']['problems']}")
    if prev["collisions"]:
        raise BackupError("target directory is not empty; choose a new directory")
    target_dir.mkdir(parents=True, exist_ok=True)
    root = target_dir.resolve()
    vault = (vault_factory or Vault)(root / "vault")
    with tempfile.TemporaryDirectory() as td:
        z = _open_zip(path, passphrase, Path(td))
        with z:
            for name in z.namelist():
                if name in ("manifest.json", "checksums.sha256"):
                    continue
                if name.startswith("evidence/"):
                    sha = vault.store(z.read(name))[0]
                    if sha != Path(name).name:
                        raise BackupError("restored object does not match its name")
                    continue
                dest = (root / name).resolve()
                if root not in dest.parents:
                    raise BackupError("unsafe path in archive")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(z.read(name))
    (root / "osintcc.sqlite").unlink(missing_ok=True)
    (root / "database.sqlite").replace(root / "osintcc.sqlite")
    return root
