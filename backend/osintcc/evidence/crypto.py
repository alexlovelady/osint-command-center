"""Encryption at rest for evidence objects and backup containers (spec 12.1, 21.9).

* Vault objects: AES-256-GCM, 12-byte random nonce, AAD = the object's SHA-256 name (a ciphertext cannot be swapped
  under another object's name). Key lives in the OS credential store (never in the database or repo).
* Backups: scrypt(passphrase) -> AES-256-GCM over 1 MiB chunks with per-chunk nonce/AAD (index + final flag), so
  truncation, reordering and tampering are detected.
There is no silent plaintext fallback: if a key is required and unavailable, writes fail (`VaultLocked`).
"""
from __future__ import annotations

import base64
import os
import secrets
import struct
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

OBJ_MAGIC = b"OSCC1"
BAK_MAGIC = b"OSCCB1"
CHUNK = 1 << 20
KEYRING_SERVICE, KEYRING_USER = "osintcc", "vault-key"


class CryptoError(Exception):
    pass


class VaultCipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise CryptoError("vault key must be 32 bytes")
        self._aes = AESGCM(key)

    def encrypt(self, plain: bytes, aad: str) -> bytes:
        nonce = secrets.token_bytes(12)
        return OBJ_MAGIC + nonce + self._aes.encrypt(nonce, plain, aad.encode())

    def decrypt(self, blob: bytes, aad: str) -> bytes:
        if not blob.startswith(OBJ_MAGIC) or len(blob) < len(OBJ_MAGIC) + 12 + 16:
            raise CryptoError("not an encrypted vault object")
        nonce = blob[len(OBJ_MAGIC):len(OBJ_MAGIC) + 12]
        try:
            return self._aes.decrypt(nonce, blob[len(OBJ_MAGIC) + 12:], aad.encode())
        except InvalidTag as exc:
            raise CryptoError("authentication failed (wrong key or modified object)") from exc


def is_encrypted(blob: bytes) -> bool:
    return blob.startswith(OBJ_MAGIC)


def load_or_create_key(env: dict[str, str] | None = None) -> bytes | None:
    """Key sources, in order: OSINTCC_VAULT_KEY (base64; for headless servers/tests), then the OS credential store.
    A new key is created only if the store is reachable and empty. Returns None when no key can be obtained."""
    src: Mapping[str, str] = os.environ if env is None else env
    raw = src.get("OSINTCC_VAULT_KEY")
    if raw:
        try:
            key = base64.b64decode(raw, validate=True)
            return key if len(key) == 32 else None
        except ValueError:
            return None
    try:
        import keyring
        stored = keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
        if stored:
            return base64.b64decode(stored)
        key = secrets.token_bytes(32)
        keyring.set_password(KEYRING_SERVICE, KEYRING_USER, base64.b64encode(key).decode())
        return key
    except Exception:
        return None


# ---------------------------------------------------------------- passphrase-protected backup container ----------
def _kdf(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def _nonce(prefix: bytes, index: int, final: bool) -> bytes:
    return prefix + struct.pack(">I", index) + (b"\x01" if final else b"\x00")  # 7 + 4 + 1 = 12 bytes


def encrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    if len(passphrase) < 8:
        raise CryptoError("passphrase must be at least 8 characters")
    salt, prefix = secrets.token_bytes(16), secrets.token_bytes(7)
    aes = AESGCM(_kdf(passphrase, salt))
    size = src.stat().st_size
    with src.open("rb") as fi, dst.open("wb") as fo:
        fo.write(BAK_MAGIC + salt + prefix)
        index, done = 0, 0
        while True:
            chunk = fi.read(CHUNK)
            done += len(chunk)
            final = done >= size
            fo.write(aes.encrypt(_nonce(prefix, index, final), chunk, BAK_MAGIC))
            index += 1
            if final:
                break


def decrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    with src.open("rb") as fi:
        head = fi.read(len(BAK_MAGIC) + 16 + 7)
        if not head.startswith(BAK_MAGIC) or len(head) != len(BAK_MAGIC) + 23:
            raise CryptoError("not an encrypted backup")
        salt, prefix = head[len(BAK_MAGIC):len(BAK_MAGIC) + 16], head[-7:]
        aes = AESGCM(_kdf(passphrase, salt))
        rest_size = src.stat().st_size - len(head)
        index, consumed = 0, 0
        with dst.open("wb") as fo:
            while consumed < rest_size:
                ct = fi.read(CHUNK + 16)
                consumed += len(ct)
                final = consumed >= rest_size
                try:
                    fo.write(aes.decrypt(_nonce(prefix, index, final), ct, BAK_MAGIC))
                except InvalidTag as exc:
                    raise CryptoError("wrong passphrase, or the backup is corrupt/truncated") from exc
                index += 1
            if index == 0:
                raise CryptoError("empty backup container")


def is_encrypted_backup(path: Path) -> bool:
    with path.open("rb") as fh:
        return fh.read(len(BAK_MAGIC)) == BAK_MAGIC
