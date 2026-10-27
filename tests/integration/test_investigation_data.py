"""Migration 0017 (investigation runs and events) is additive: it keeps every existing profile record and rolls back cleanly."""
from __future__ import annotations

import sqlite3

from alembic import command
from osintcc.db import make_engine
from osintcc.db.migrate import _cfg, current_revision, head_revision, upgrade_to_head
from sqlalchemy import inspect, text

NEW = ("investigation_runs", "investigation_events")


def _seed(conn) -> None:
    conn.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,created_at,updated_at) VALUES ('c1','Old','','people','open','x','','{}','2026-01-01','2026-01-01')"))
    conn.execute(text("INSERT INTO subjects (id,case_id,type,display_name,mode,purpose,status,sensitivity,created_at,updated_at) VALUES ('s1','c1','person','Jane','self','self audit','active','RESTRICTED','2026-01-01','2026-01-01')"))
    conn.execute(text("INSERT INTO subject_identifiers (id,subject_id,case_id,kind,value,value_hash,status,recorded_at) VALUES ('i1','s1','c1','email','jane@example.com','h','active','2026-01-01')"))
    conn.execute(text("INSERT INTO profile_items (id,subject_id,case_id,category,type,custom_type,value,normalized_value,attributes,source_id,evidence_ids,collection_method,origin,recorded_by,confidence,"
                      "verification_state,self_attested,sensitivity,retention_policy,is_input,version,status,note,created_at,updated_at) VALUES ('p1','s1','c1','online_footprint','username','','jane_e','jane_e','{}',"
                      "'x','[]','manual','analyst_supplied','me','low','candidate',0,'INTERNAL','{}',0,1,'active','','2026-01-01','2026-01-01')"))


def test_upgrade_from_0016_keeps_everything_and_adds_empty_tables(tmp_path):
    p = tmp_path / "old.db"
    eng = make_engine(p)
    with eng.begin() as conn:
        command.upgrade(_cfg(eng, conn), "0016")
        _seed(conn)
    assert current_revision(eng) == "0016"
    upgrade_to_head(eng, p)
    assert current_revision(eng) == head_revision() and set(NEW) <= set(inspect(eng).get_table_names())
    with eng.connect() as c:
        assert c.execute(text("SELECT value FROM profile_items WHERE id='p1'")).scalar() == "jane_e"
        assert c.execute(text("SELECT value FROM subject_identifiers WHERE id='i1'")).scalar() == "jane@example.com"
        assert all(c.execute(text(f"SELECT count(*) FROM {t}")).scalar() == 0 for t in NEW)
    assert list(p.parent.glob("old.pre-0016*.bak")) or list(p.parent.glob("*.bak"))          # the pre-upgrade copy is kept
    eng.dispose()


def test_the_migration_rolls_back_and_forward(tmp_path):
    p = tmp_path / "rt.db"
    eng = make_engine(p)
    upgrade_to_head(eng, p)
    with eng.begin() as c:
        _seed(c)
        c.execute(text("INSERT INTO investigation_runs (id,case_id,subject_id,kind,status,phase,pass_no,policy_json,approved_sources,excluded_sources,manifest_json,counts_json,stop_reason,last_error,"
                       "requested_by,created_at,updated_at) VALUES ('r1','c1','s1','person','completed','',1,'{}','[]','[]','{}','{}','','','me','2026-01-01','2026-01-01')"))
    with eng.begin() as conn:
        command.downgrade(_cfg(eng, conn), "0016")
    assert current_revision(eng) == "0016" and not (set(NEW) & set(inspect(eng).get_table_names()))
    with eng.connect() as c:
        assert c.execute(text("SELECT value FROM profile_items WHERE id='p1'")).scalar() == "jane_e"            # nothing else was touched
    upgrade_to_head(eng, p)
    eng.dispose()
    con = sqlite3.connect(p)
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    con.close()
