"""Content-addressed evidence vault (spec 6.2). Paths are derived from hashes only; never from user input."""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

from .crypto import CryptoError, VaultCipher, is_encrypted

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class VaultError(Exception):
    pass


class IntegrityError(VaultError):
    pass


class VaultLocked(VaultError):
    """Encryption is required but no key is available (or an encrypted object cannot be opened)."""


class Vault:
    def __init__(self, root: Path, cipher: VaultCipher | None = None, require_encryption: bool = False):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.cipher, self.require_encryption = cipher, require_encryption

    @property
    def encrypting(self) -> bool:
        return self.cipher is not None

    def _seal(self, plain: bytes, sha256: str) -> bytes:
        if self.cipher is not None:
            return self.cipher.encrypt(plain, sha256)
        if self.require_encryption:
            raise VaultLocked("vault encryption is required but no key is available; nothing was written")
        return plain

    def relpath(self, sha256: str) -> str:
        if not _HEX64.match(sha256):
            raise VaultError("invalid digest")
        return f"sha256/{sha256[:2]}/{sha256}"

    def _abs(self, relpath: str) -> Path:
        p = (self.root / relpath).resolve()
        if self.root != p and self.root not in p.parents:
            raise VaultError("path escapes vault")
        if p.is_symlink():
            raise VaultError("symlinks are not allowed in the vault")
        return p

    def store(self, data: bytes) -> tuple[str, str, str, int]:
        """Returns (sha256, sha512, relpath, size). Idempotent: identical content is stored once."""
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()
        rel = self.relpath(sha256)
        dest = self._abs(rel)
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(self._seal(data, sha256))
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, dest)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        return sha256, sha512, rel, len(data)

    def store_stream(self, fh, max_bytes: int) -> tuple[str, str, str, int]:
        """Stream a file into the vault with a hard size cap (used by evidence import)."""
        h256, h512, size = hashlib.sha256(), hashlib.sha512(), 0
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".import-")
        try:
            with os.fdopen(fd, "wb") as out:
                while chunk := fh.read(1024 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        raise VaultError(f"file exceeds the {max_bytes} byte limit")
                    h256.update(chunk)
                    h512.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            sha256 = h256.hexdigest()
            rel = self.relpath(sha256)
            dest = self._abs(rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                Path(tmp).unlink(missing_ok=True)
            else:
                if self.cipher is not None or self.require_encryption:
                    sealed = self._seal(Path(tmp).read_bytes(), sha256)
                    Path(tmp).write_bytes(sealed)
                os.replace(tmp, dest)
            return sha256, h512.hexdigest(), rel, size
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def read(self, relpath: str, expected_sha256: str | None = None) -> bytes:
        p = self._abs(relpath)
        if not p.is_file():
            raise VaultError("evidence object missing from vault")
        data = p.read_bytes()
        plain_named = hashlib.sha256(data).hexdigest() == Path(relpath).name  # legacy plaintext object
        if is_encrypted(data) and not plain_named:
            if self.cipher is None:
                raise VaultLocked("object is encrypted and no key is available")
            try:
                data = self.cipher.decrypt(data, Path(relpath).name)
            except CryptoError as exc:
                raise IntegrityError(str(exc)) from exc
        if expected_sha256 and hashlib.sha256(data).hexdigest() != expected_sha256:
            raise IntegrityError("hash mismatch: vault object was modified")
        return data

    def verify(self, relpath: str, expected_sha256: str) -> bool:
        try:
            self.read(relpath, expected_sha256)
            return True
        except VaultError:
            return False

    def is_object_encrypted(self, relpath: str) -> bool:
        return is_encrypted(self._abs(relpath).read_bytes()[:8])

    def encrypt_existing(self) -> dict[str, int]:
        """Re-seal legacy plaintext objects in place (verified before and after). Idempotent."""
        if self.cipher is None:
            raise VaultLocked("no key available")
        done = skipped = 0
        for f in sorted(self.root.glob("sha256/*/*")):
            if not f.is_file() or f.name.startswith("."):
                continue
            raw = f.read_bytes()
            if is_encrypted(raw):
                skipped += 1
                continue
            if hashlib.sha256(raw).hexdigest() != f.name:
                raise IntegrityError(f"{f.name} fails its own hash; not encrypting a damaged object")
            fd, tmp = tempfile.mkstemp(dir=f.parent, prefix=".enc-")
            with os.fdopen(fd, "wb") as fh:
                fh.write(self.cipher.encrypt(raw, f.name))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, f)
            if self.cipher.decrypt(f.read_bytes(), f.name) != raw:
                raise IntegrityError("round-trip verification failed")
            done += 1
        return {"encrypted": done, "already_encrypted": skipped}
