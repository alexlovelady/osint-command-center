from __future__ import annotations

import sqlite3
import sys

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from osintcc.db import Base, make_engine, models  # noqa: F401
from osintcc.db.migrate import _cfg, current_revision, head_revision, include_object, upgrade_to_head
from sqlalchemy import inspect, text


@pytest.fixture(autouse=True)
def _dispose_engines(monkeypatch):
    made = []
    orig = make_engine

    def tracking(path):
        e = orig(path)
        made.append(e)
        return e
    monkeypatch.setattr(sys.modules[__name__], "make_engine", tracking)
    yield
    for e in made:
        e.dispose()


def test_upgrade_empty_db_to_head_and_no_model_drift(tmp_path):
    eng = make_engine(tmp_path / "m.db")
    assert upgrade_to_head(eng, tmp_path / "m.db") == head_revision()
    assert current_revision(eng) == head_revision()
    names = set(inspect(eng).get_table_names())
    assert {"cases", "evidence", "findings", "relationships", "audit_events", "jobs"} <= names
    with eng.connect() as c:
        diff = compare_metadata(MigrationContext.configure(c, opts={"include_object": include_object}), Base.metadata)
    assert diff == [], f"models drifted from migrations: {diff}"
    with eng.connect() as c:
        assert c.execute(text("PRAGMA foreign_keys")).scalar() == 1
        assert c.execute(text("PRAGMA journal_mode")).scalar().lower() == "wal"


def test_upgrade_is_idempotent_and_preserves_data(tmp_path):
    p = tmp_path / "m.db"
    eng = make_engine(p)
    upgrade_to_head(eng, p)
    with eng.begin() as c:
        c.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,"
                       "created_at,updated_at) VALUES ('c1','keep me','','cyber','open','','','{}',"
                       "'2026-01-01','2026-01-01')"))
    upgrade_to_head(eng, p)  # second run is a no-op
    with eng.connect() as c:
        assert c.execute(text("SELECT title FROM cases WHERE id='c1'")).scalar() == "keep me"


def test_legacy_database_without_version_table_is_adopted_not_recreated(tmp_path):
    p = tmp_path / "legacy.db"
    eng = make_engine(p)
    with eng.begin() as conn:  # build exactly what a pre-migration (revision 0001) install looked like
        command.upgrade(_cfg(eng, conn), "0001")
        conn.execute(text("DROP TABLE alembic_version"))
        conn.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,"
                          "created_at,updated_at) VALUES ('c1','legacy','','cyber','open','','','{}',"
                          "'2026-01-01','2026-01-01')"))
    assert current_revision(eng) is None
    upgrade_to_head(eng, p)
    assert current_revision(eng) == head_revision()
    with eng.connect() as c:
        assert c.execute(text("SELECT title FROM cases")).scalar() == "legacy"
        assert c.execute(text("SELECT count(*) FROM roles")).scalar() == 4


def test_downgrade_to_base_then_back(tmp_path):
    p = tmp_path / "d.db"
    eng = make_engine(p)
    upgrade_to_head(eng, p)
    with eng.begin() as conn:
        command.downgrade(_cfg(eng, conn), "base")
    assert "cases" not in inspect(eng).get_table_names()
    upgrade_to_head(eng, p)
    assert "cases" in inspect(eng).get_table_names()


def test_foreign_keys_enforced_and_cascade(tmp_path):
    p = tmp_path / "f.db"
    eng = make_engine(p)
    upgrade_to_head(eng, p)
    con = sqlite3.connect(p)
    con.execute("PRAGMA foreign_keys=ON")
    try:
        con.execute("INSERT INTO targets (id,case_id,type,raw_input,canonical_value,scope_status,created_at) "
                    "VALUES ('t','missing','domain','x','x','in_scope','2026-01-01')")
        raise AssertionError("FK violation was accepted")
    except sqlite3.IntegrityError:
        pass
    finally:
        con.close()
