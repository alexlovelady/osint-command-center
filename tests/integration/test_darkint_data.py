"""DARKINT data safety: upgrade from existing profile data, rollback, backup and restore (addendum 14.7 criterion 12)."""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import httpx
from alembic import command
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.config import Settings
from osintcc.db import make_engine
from osintcc.db.migrate import _cfg, current_revision, head_revision, upgrade_to_head
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import inspect, text

NEW = ("exposure_sources", "exposure_events", "exposure_reviews", "exposure_monitor_configs", "exposure_checks")
B = "/api/v1"


def test_upgrade_from_0013_keeps_profile_exposure_and_remediation_data(tmp_path):
    p = tmp_path / "old.db"
    eng = make_engine(p)
    with eng.begin() as conn:
        command.upgrade(_cfg(eng, conn), "0013")
        conn.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,created_at,updated_at) VALUES ('c1','Old','','people','open','x','','{}','2026-01-01','2026-01-01')"))
        conn.execute(text("INSERT INTO subjects (id,case_id,type,display_name,mode,purpose,status,sensitivity,created_at,updated_at) VALUES ('s1','c1','person','Jane','self','self audit','active','RESTRICTED','2026-01-01','2026-01-01')"))
        conn.execute(text("INSERT INTO exposure_indicators (id,subject_id,case_id,cls,provider,last_checked,status,risk,masked_descriptor,verification_basis,remediation_state,created_at) "
                          "VALUES ('x1','s1','c1','breach_account','manual','2026-01-01','confirmed_exposure','high','Breach: Old (2023-05)','provider_notice','open','2026-01-01')"))
        conn.execute(text("INSERT INTO remediation_tasks (id,subject_id,case_id,indicator_id,issue,priority,guidance,state,created_at,updated_at) VALUES ('r1','s1','c1','x1','Change password','high','','open','2026-01-01','2026-01-01')"))
    assert current_revision(eng) == "0013"
    upgrade_to_head(eng, p)
    assert current_revision(eng) == head_revision()
    assert set(NEW) <= set(inspect(eng).get_table_names())
    with eng.connect() as c:
        assert c.execute(text("SELECT masked_descriptor FROM exposure_indicators WHERE id='x1'")).scalar() == "Breach: Old (2023-05)"
        row = c.execute(text("SELECT issue, exposure_event_id, action_type FROM remediation_tasks WHERE id='r1'")).one()
        assert tuple(row) == ("Change password", None, None)
        for t in NEW:
            assert c.execute(text(f"SELECT count(*) FROM {t}")).scalar() == 0
    eng.dispose()


def test_the_darkint_migration_rolls_back_and_forward_without_touching_older_data(tmp_path):
    p = tmp_path / "rt.db"
    eng = make_engine(p)
    upgrade_to_head(eng, p)
    with eng.begin() as c:
        c.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,created_at,updated_at) VALUES ('keep','keep me','','cyber','open','','','{}','2026-01-01','2026-01-01')"))
    with eng.begin() as conn:
        command.downgrade(_cfg(eng, conn), "0013")
    assert current_revision(eng) == "0013" and not (set(NEW) & set(inspect(eng).get_table_names()))
    assert "exposure_event_id" not in {c["name"] for c in inspect(eng).get_columns("remediation_tasks")}
    with eng.connect() as c:
        assert c.execute(text("SELECT title FROM cases WHERE id='keep'")).scalar() == "keep me"
    upgrade_to_head(eng, p)
    eng.dispose()
    con = sqlite3.connect(p)
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    con.close()


async def test_backup_and_restore_keep_events_checks_and_monitors_and_hold_no_secret(tmp_path, calls):
    key = "hibp-secret-key-0001"
    s = Settings(data_dir=tmp_path / "live", vault_encryption="off", db_encryption="off", run_scheduler=False)
    s.ensure_dirs()

    def handler(request: httpx.Request) -> httpx.Response:
        if "breachedaccount" in str(request.url):
            return httpx.Response(200, json=[{"Name": "ExampleForum", "BreachDate": "2021-03-14", "DataClasses": ["Email addresses", "Passwords"]}])
        return make_handler(calls)(request)

    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(handler))

    def factory() -> AdapterContext:
        return AdapterContext(http=http, dns_query=fake_dns, secret=lambda n: key if n == "hibp" else None)

    app = create_app(s, ctx_factory=factory)
    async with app.router.lifespan_context(app):
        api = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {s.session_token}"}, timeout=60)
        await api.put(f"{B}/darkint/sources/hibp", json={"enabled": True, "acknowledge_terms": True})
        cid = (await api.post(f"{B}/cases", json={"title": "J", "category": "people", "purpose": "self audit"})).json()["id"]
        sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Jane", "mode": "self"})).json()["id"]
        soon = (datetime.now(UTC) + timedelta(days=30)).isoformat()
        await api.post(f"{B}/subjects/{sid}/consent", json={"verification_method": "email_confirmation", "verifier": "J", "source_classes": ["exposure_check"], "permitted_purposes": ["a"], "expires_at": soon})
        iid = (await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "email", "value": "jane.doe@example.com"})).json()["id"]
        out = (await api.post(f"{B}/cases/{cid}/darkint/check", json={"subject_id": sid, "identifier_ids": [iid], "provider_ids": ["hibp"], "confirm": True})).json()
        assert out["results"][0]["outcome"] == "match"
        mon = (await api.post(f"{B}/cases/{cid}/darkint/monitors", json={"subject_id": sid, "name": "w", "identifier_ids": [iid], "provider_ids": ["hibp"], "cadence_hours": 168,
                                                                          "expires_at": (datetime.now(UTC) + timedelta(days=20)).isoformat()})).json()
        before = (await api.get(f"{B}/cases/{cid}/darkint/exposures", params={"subject_id": sid})).json()["groups"][0]["events"][0]["id"]
        b = (await api.post(f"{B}/backups", json={"passphrase": "a-long-passphrase"})).json()
        assert (await api.post(f"{B}/backups/restore", json={"file": b["file"], "target_name": "darkrestore", "passphrase": "a-long-passphrase", "confirm": True})).status_code == 200
        await api.aclose()
    restored = s.data_dir / "restores" / "darkrestore"
    assert all(key.encode() not in f.read_bytes() for f in restored.rglob("*") if f.is_file() and f.stat().st_size < 5_000_000)
    s2 = Settings(data_dir=restored, vault_encryption="off", db_encryption="off", run_scheduler=False)
    app2 = create_app(s2, ctx_factory=factory, init_db=True)
    async with app2.router.lifespan_context(app2):
        api2 = httpx.AsyncClient(transport=httpx.ASGITransport(app=app2), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {s2.session_token}"}, timeout=60)
        j = (await api2.get(f"{B}/cases/{cid}/darkint/exposures", params={"subject_id": sid})).json()
        assert j["groups"][0]["events"][0]["id"] == before and j["coverage"]["items"][0]["state"] == "match_reported"
        assert [m["id"] for m in (await api2.get(f"{B}/cases/{cid}/darkint/monitors")).json()["items"]] == [mon["id"]]
        await api2.aclose()
