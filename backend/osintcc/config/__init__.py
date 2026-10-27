"""Runtime configuration. Paths live under the OS app-data dir, never the repo (except tests)."""
from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path


def default_data_dir() -> Path:
    override = os.environ.get("OSINTCC_DATA_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "osintcc"


def _builtin_update_key() -> str:
    try:
        return (Path(__file__).resolve().parent.parent / "setup" / "update_key.pub").read_text(encoding="utf8").strip()
    except OSError:
        return ""


@dataclass
class Settings:
    data_dir: Path = field(default_factory=default_data_dir)
    # OSINTCC_SESSION_TOKEN is a development convenience; packaged builds always generate a random per-launch token.
    session_token: str = field(
        default_factory=lambda: os.environ.get("OSINTCC_SESSION_TOKEN") or secrets.token_urlsafe(32))
    allowed_origins: tuple[str, ...] = (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "tauri://localhost",
        "http://tauri.localhost",
    )
    max_concurrency: int = 3
    max_import_bytes: int = 256 * 1024 * 1024
    offline: bool = False
    retry_scale: float = field(default_factory=lambda: float(os.environ.get("OSINTCC_RETRY_SCALE", "1.0")))  # multiplies retry delays (tests shrink it)
    run_scheduler: bool = True  # tests drive Scheduler.tick() directly
    # Provider budgets (addendum PQ-1.0). "off" is for unit tests that exercise adapters with their own fixtures; the packaged app always enforces.
    quota_enforce: bool = field(default_factory=lambda: os.environ.get("OSINTCC_QUOTA", "on") != "off")
    # Test/dev seam: lets adapters reach loopback fixture servers. Never enabled by default.
    allow_private_destinations: bool = False
    # Active-assessment module: absent from the registry unless the owner turns it on (it still needs a
    # scope authorization per target and per-run confirmation).
    enable_active_module: bool = field(default_factory=lambda: os.environ.get("OSINTCC_ENABLE_ACTIVE") == "1")
    # required (default): vault writes need an encryption key and fail closed; off: explicit opt-out.
    vault_encryption: str = field(default_factory=lambda: os.environ.get("OSINTCC_VAULT_ENCRYPTION", "required"))

    # SQLCipher for the database: "auto" follows vault_encryption; "required" / "off" force it.
    db_encryption: str = field(default_factory=lambda: os.environ.get("OSINTCC_DB_ENCRYPTION", "auto"))

    @property
    def db_encryption_mode(self) -> str:
        if self.db_encryption == "auto":
            return "off" if self.vault_encryption == "off" else "required"
        return "off" if self.db_encryption == "off" else "required"

    # Update check: a signed manifest is fetched ONLY when the user presses "check"; nothing is downloaded or installed.
    update_manifest_url: str = field(default_factory=lambda: os.environ.get("OSINTCC_UPDATE_URL", ""))
    update_public_key: str = field(default_factory=lambda: os.environ.get("OSINTCC_UPDATE_KEY") or _builtin_update_key())  # Ed25519 public key, hex

    @property
    def tools_state_path(self) -> Path:
        return self.data_dir / "tools" / "installed.json"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "osintcc.sqlite"

    @property
    def vault_dir(self) -> Path:
        return self.data_dir / "vault"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def export_dir(self) -> Path:
        return self.data_dir / "exports"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.vault_dir, self.backup_dir, self.export_dir):
            d.mkdir(parents=True, exist_ok=True)
