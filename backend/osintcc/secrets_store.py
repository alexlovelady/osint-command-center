"""API-key storage. Keys are entered by the user (Setup page or Settings), never shipped or hard-coded, and never returned by the API.

Primary store: the OS credential store (Windows Credential Manager / Secret Service / Keychain), service name `osintcc`.
Fallback, used only when no OS credential store is available (headless Linux): an AES-256-GCM-sealed row in the encrypted database
(`settings` key `secret:<name>`), sealed with the same master key as the vault and bound to the name, so a row cannot be swapped to another provider.
"""
from __future__ import annotations

import base64
import contextlib
import re
from typing import Any

from sqlalchemy.orm import sessionmaker

from .db.models import Setting
from .evidence.vault import Vault

SERVICE = "osintcc"
NAME = re.compile(r"[a-z0-9_\-]{2,40}")


class SecretStoreError(Exception):
    pass


class SecretStore:
    def __init__(self, sm: sessionmaker, vault: Vault):
        self.sm, self.vault = sm, vault

    @staticmethod
    def _keyring() -> Any:
        try:
            import keyring
            return keyring
        except Exception:  # pragma: no cover - keyring is a hard dependency, but a broken backend must not crash the app
            return None

    def _aad(self, name: str) -> str:
        return f"secret:{name}"

    def get(self, name: str) -> str | None:
        if not NAME.fullmatch(name):
            return None
        kr = self._keyring()
        if kr is not None:
            with contextlib.suppress(Exception):
                v = kr.get_password(SERVICE, name)
                if v:
                    return v
        with self.sm() as db:
            row = db.get(Setting, self._aad(name))
            if row and self.vault.cipher is not None:
                try:
                    return self.vault.cipher.decrypt(base64.b64decode(row.value_json), self._aad(name)).decode()
                except Exception:
                    return None
        return None

    def exists(self, name: str) -> bool:
        return self.get(name) is not None

    def set(self, name: str, value: str) -> str:
        """Returns where it was stored: 'os-keyring' or 'encrypted-database'."""
        if not NAME.fullmatch(name):
            raise SecretStoreError("invalid provider name")
        kr = self._keyring()
        if kr is not None:
            try:
                kr.set_password(SERVICE, name, value)
                with self.sm() as db:  # a stale fallback copy must not shadow or outlive the keyring entry
                    row = db.get(Setting, self._aad(name))
                    if row:
                        db.delete(row)
                        db.commit()
                return "os-keyring"
            except Exception:  # noqa: S110 - no usable OS credential store: fall through to the sealed database copy
                pass
        if self.vault.cipher is None:
            raise SecretStoreError("no OS credential store and no encryption key are available; nothing was saved")
        blob = base64.b64encode(self.vault.cipher.encrypt(value.encode(), self._aad(name))).decode()
        with self.sm() as db:
            db.merge(Setting(key=self._aad(name), value_json=blob))
            db.commit()
        return "encrypted-database"

    def delete(self, name: str) -> bool:
        removed = False
        kr = self._keyring()
        if kr is not None:
            with contextlib.suppress(Exception):
                kr.delete_password(SERVICE, name)
                removed = True
        with self.sm() as db:
            row = db.get(Setting, self._aad(name))
            if row:
                db.delete(row)
                db.commit()
                removed = True
        return removed
