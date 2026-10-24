"""Reports at rest. When the vault has a key, a generated report is stored as `<name>.enc` (AES-256-GCM, AAD bound to the report
id) and the plaintext file is removed; downloads and the MCP `get_report` tool decrypt for the authenticated caller. Without a
key (encryption explicitly off) reports stay ordinary files."""
from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path

from ..evidence.crypto import CryptoError
from ..evidence.vault import Vault, VaultLocked

SUFFIX = ".enc"


def aad(report_id: str) -> str:
    return f"report:{report_id}"


def seal(vault: Vault, report_id: str, path: Path) -> tuple[Path, str]:
    """Returns (final path, sha256 of the plaintext). Encrypts and removes the plaintext when the vault is encrypting."""
    plain = path.read_bytes()
    digest = hashlib.sha256(plain).hexdigest()
    if vault.cipher is None:
        if vault.require_encryption:
            path.unlink(missing_ok=True)
            raise VaultLocked("report encryption is required but no key is available; nothing was written")
        return path, digest
    final = path.with_name(path.name + SUFFIX)
    tmp = final.with_name(final.name + ".tmp")
    tmp.write_bytes(vault.cipher.encrypt(plain, aad(report_id)))
    tmp.replace(final)
    path.unlink()
    return final, digest


def read(vault: Vault, report_id: str, path: Path) -> tuple[bytes, str]:
    """Returns (plaintext bytes, download file name without the .enc suffix)."""
    data = path.read_bytes()
    if path.suffix != SUFFIX:
        return data, path.name
    if vault.cipher is None:
        raise VaultLocked("the report is encrypted and no key is available")
    try:
        return vault.cipher.decrypt(data, aad(report_id)), path.name[: -len(SUFFIX)]
    except CryptoError as exc:
        raise VaultLocked(f"report could not be decrypted: {exc}") from exc


def media_type(name: str) -> str:
    return mimetypes.guess_type(name)[0] or "application/octet-stream"
