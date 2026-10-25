"""Migration 0015 (associated emails, expansion runs) keeps existing profile data and rolls back cleanly."""
from __future__ import annotations

import sqlite3

from alembic import command
from osintcc.db import make_engine
from osintcc.db.migrate import _cfg, current_revision, head_revision, upgrade_to_head
from sqlalchemy import inspect, text

NEW = ("associated_emails", "expansion_runs")


def test_upgrade_from_0014_keeps_profile_data_and_adds_empty_tables(tmp_path):
    p = tmp_path / "old.db"
    eng = make_engine(p)
    with eng.begin() as conn:
        command.upgrade(_cfg(eng, conn), "0014")
        conn.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,created_at,updated_at) VALUES ('c1','Old','','people','open','x','','{}','2026-01-01','2026-01-01')"))
        conn.execute(text("INSERT INTO subjects (id,case_id,type,display_name,mode,purpose,status,sensitivity,created_at,updated_at) VALUES ('s1','c1','person','Jane','self','self audit','active','RESTRICTED','2026-01-01','2026-01-01')"))
        conn.execute(text("INSERT INTO subject_identifiers (id,subject_id,case_id,kind,value,value_hash,status,recorded_at) VALUES ('i1','s1','c1','email','jane@example.com','h','active','2026-01-01')"))
    assert current_revision(eng) == "0014"
    upgrade_to_head(eng, p)
    assert current_revision(eng) == head_revision()
    assert set(NEW) <= set(inspect(eng).get_table_names())
    with eng.connect() as c:
        assert c.execute(text("SELECT value FROM subject_identifiers WHERE id='i1'")).scalar() == "jane@example.com"
        assert all(c.execute(text(f"SELECT count(*) FROM {t}")).scalar() == 0 for t in NEW)
    eng.dispose()


def test_the_migration_rolls_back_and_forward(tmp_path):
    p = tmp_path / "rt.db"
    eng = make_engine(p)
    upgrade_to_head(eng, p)
    with eng.begin() as c:
        c.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,created_at,updated_at) VALUES ('keep','keep me','','cyber','open','','','{}','2026-01-01','2026-01-01')"))
    with eng.begin() as conn:
        command.downgrade(_cfg(eng, conn), "0014")
    assert current_revision(eng) == "0014" and not (set(NEW) & set(inspect(eng).get_table_names()))
    with eng.connect() as c:
        assert c.execute(text("SELECT title FROM cases WHERE id='keep'")).scalar() == "keep me"
    upgrade_to_head(eng, p)
    eng.dispose()
    con = sqlite3.connect(p)
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    con.close()
