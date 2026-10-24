"""Programmatic Alembic helpers. Existing databases are only ever upgraded, never recreated (spec 4.1)."""
from __future__ import annotations

import shutil
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Engine

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def _cfg(engine: Engine, connection) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["connection"] = connection
    return cfg


def head_revision() -> str:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    head = ScriptDirectory.from_config(cfg).get_current_head()
    assert head is not None
    return head


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as c:
        return MigrationContext.configure(c).get_current_revision()


def upgrade_to_head(engine: Engine, db_path: Path | None = None) -> str:
    """Upgrade in a transaction. A consistent pre-migration copy is kept when upgrading a non-empty database."""
    cur = current_revision(engine)
    if cur is None and "cases" in inspect(engine).get_table_names():
        # Legacy/dev database created before migrations existed: adopt it at the baseline, never recreate it.
        with engine.begin() as conn:
            command.stamp(_cfg(engine, conn), "0001")
        cur = "0001"
    if db_path and cur is not None and cur != head_revision() and db_path.exists():
        shutil.copy2(db_path, db_path.with_suffix(f".pre-{cur}.bak"))
    with engine.begin() as conn:
        command.upgrade(_cfg(engine, conn), "head")
    return head_revision()


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """FTS5 virtual/shadow tables are created by raw-SQL migrations, not ORM metadata; ignore them in autogenerate."""
    return not (type_ == "table" and reflected and name.startswith("search_index"))
