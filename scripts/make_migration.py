"""Autogenerate the next Alembic revision from the ORM models.  uv run python scripts/make_migration.py <rev_id> "<message>"

Review the generated file (FTS/trigger/seed SQL is hand-written), then run the migration tests.
"""
import sys
import tempfile
from pathlib import Path

from alembic import command
from alembic.config import Config
from osintcc.db import make_engine
from osintcc.db.migrate import MIGRATIONS_DIR, include_object  # noqa: F401  (env.py imports it as well)

rev_id, message = sys.argv[1], sys.argv[2]
with tempfile.TemporaryDirectory() as td:
    eng = make_engine(Path(td) / "g.db")
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    with eng.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
        command.revision(cfg, message=message, autogenerate=True, rev_id=rev_id)
    eng.dispose()
