"""AIV-1: migrations keep what exists (items 1, 21) and the display name changes nothing that identifies an installation (item 24)."""
from __future__ import annotations

import json
import sqlite3

import httpx
import pytest
from alembic import command
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db import make_engine
from osintcc.db.migrate import _cfg, current_revision, head_revision, upgrade_to_head
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import inspect, text

B = "/api/v1"
NEW_TABLES = ("asset_authorizations", "aiv_plans", "aiv_approvals", "aiv_runs", "aiv_run_events", "aiv_observations", "aiv_template_approvals")


def test_upgrade_from_0012_keeps_cases_profiles_and_thirty_workflows(tmp_path):
    p = tmp_path / "old.db"
    eng = make_engine(p)
    with eng.begin() as conn:
        command.upgrade(_cfg(eng, conn), "0012")
        conn.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,created_at,updated_at) "
                          "VALUES ('c1','Old case','','people','open','self audit','','{}','2026-01-01','2026-01-01')"))
        conn.execute(text("INSERT INTO subjects (id,case_id,type,display_name,mode,purpose,status,sensitivity,created_at,updated_at) "
                          "VALUES ('s1','c1','person','Jane','self','self audit','active','RESTRICTED','2026-01-01','2026-01-01')"))
        for i in range(30):
            conn.execute(text("INSERT INTO automation_workflows (id,case_id,owner_id,name,template_slug,draft_json,draft_rev,state,created_at,updated_at) "
                              "VALUES (:i,'c1','local-user',:n,:t,:d,1,'draft','2026-01-01','2026-01-01')"), {"i": f"w{i}", "n": f"Workflow {i}", "t": f"t-{i}", "d": json.dumps({"n": i})})
    assert current_revision(eng) == "0012"
    upgrade_to_head(eng, p)
    assert current_revision(eng) == head_revision()
    names = set(inspect(eng).get_table_names())
    assert set(NEW_TABLES) <= names
    with eng.connect() as c:
        assert c.execute(text("SELECT count(*) FROM automation_workflows")).scalar() == 30
        assert json.loads(c.execute(text("SELECT draft_json FROM automation_workflows WHERE id='w7'")).scalar()) == {"n": 7}
        assert c.execute(text("SELECT display_name FROM subjects WHERE id='s1'")).scalar() == "Jane"
        for t in NEW_TABLES:
            assert c.execute(text(f"SELECT count(*) FROM {t}")).scalar() == 0
    assert list(p.parent.glob("old.pre-0012.bak")) or list(p.parent.glob("*.bak"))                       # the upgrade kept a copy first
    eng.dispose()


def test_the_aiv_migration_round_trips_without_touching_older_tables(tmp_path):
    p = tmp_path / "rt.db"
    eng = make_engine(p)
    upgrade_to_head(eng, p)
    with eng.begin() as c:
        c.execute(text("INSERT INTO cases (id,title,description,category,status,purpose,legal_basis_notes,scope_json,created_at,updated_at) "
                       "VALUES ('keep','keep me','','cyber','open','','','{}','2026-01-01','2026-01-01')"))
    with eng.begin() as conn:
        command.downgrade(_cfg(eng, conn), "0012")
    assert current_revision(eng) == "0012" and not (set(NEW_TABLES) & set(inspect(eng).get_table_names()))
    with eng.connect() as c:
        assert c.execute(text("SELECT title FROM cases WHERE id='keep'")).scalar() == "keep me"
    upgrade_to_head(eng, p)
    assert set(NEW_TABLES) <= set(inspect(eng).get_table_names())
    eng.dispose()
    con = sqlite3.connect(p)
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    con.close()


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            c.app = app
            yield c


async def test_default_name_is_unchanged_and_presets_are_labelled_honestly(api):
    j = (await api.get(f"{B}/branding")).json()
    assert j["preset"] == "current" and j["active"]["productName"] == "OSINT Command Center"
    fusion = j["presets"]["fusion"]
    assert fusion["branding"]["shortName"] == "Fusion Command Center" and "not a cleared trademark" in fusion["status"] and "owner has not approved" in fusion["status"]
    assert any("repository" in u for u in j["unchanged"]) and "trademark" in j["notice"]


async def test_changing_the_display_name_needs_approval_and_is_previewable(api):
    r = await api.put(f"{B}/branding", json={"preset": "fusion"})
    assert r.status_code == 422 and r.json()["code"] == "approval_required"
    pv = (await api.put(f"{B}/branding", json={"preset": "fusion", "preview_only": True})).json()
    assert pv["applied"] is False and pv["preview"]["productName"] == "Fusion Intelligence Command Center"
    assert (await api.get(f"{B}/branding")).json()["preset"] == "current"                      # preview changed nothing


@pytest.mark.parametrize("name", ["Intel", "Intel Command Center", "intel", "<script>x</script>", 'Fusion "Cmd"', "ab", "x" * 61])
async def test_intel_as_a_brand_and_markup_are_refused(api, name):
    r = await api.put(f"{B}/branding", json={"preset": "custom", "custom": {"productName": name, "shortName": "Fusion Cmd", "tagline": "tagline here"}, "approve_display_change": True})
    assert r.status_code == 422 and r.json()["code"] == "invalid_branding"


async def test_intelligence_is_fine_and_extra_fields_are_not(api):
    ok = await api.put(f"{B}/branding", json={"preset": "custom", "custom": {"productName": "Acme Intelligence Workbench", "shortName": "Acme Workbench", "tagline": "Analysis for Acme"},
                                              "approve_display_change": True})
    assert ok.status_code == 200 and ok.json()["active"]["edition"] == "Community"
    bad = await api.put(f"{B}/branding", json={"preset": "custom", "custom": {"productName": "Acme Workbench", "shortName": "Acme", "tagline": "t t t", "dataDir": "/elsewhere"}, "approve_display_change": True})
    assert bad.status_code == 422


async def test_the_display_name_never_touches_identity_data_or_keys(api, settings):
    before = {"vault": (await api.get(f"{B}/system/vault")).json(), "health": (await api.get(f"{B}/health/ready")).json()["status"], "openapi": (await api.get("/api/openapi.json")).json()["info"]["title"],
              "db": settings.db_path.name, "data_dir": str(settings.data_dir), "token_len": len(settings.session_token)}
    cid = (await api.post(f"{B}/cases", json={"title": "Existing", "purpose": "x"})).json()["id"]
    r = await api.put(f"{B}/branding", json={"preset": "fusion", "approve_display_change": True})
    assert r.status_code == 200 and r.json()["active"]["productName"] == "Fusion Intelligence Command Center" and "OSINT Command Center" in r.json()["active"]["legacyNames"]
    after = {"vault": (await api.get(f"{B}/system/vault")).json(), "health": (await api.get(f"{B}/health/ready")).json()["status"], "openapi": (await api.get("/api/openapi.json")).json()["info"]["title"],
             "db": settings.db_path.name, "data_dir": str(settings.data_dir), "token_len": len(settings.session_token)}
    assert after == before                                                                  # same API title, database file, data directory, vault state
    assert (await api.get(f"{B}/cases/{cid}")).json()["title"] == "Existing"
    assert (await api.put(f"{B}/branding", json={"preset": "current", "approve_display_change": True})).json()["active"]["productName"] == "OSINT Command Center"
    from osintcc.telemetry import audit
    with api.app.state.core.sm() as db:
        assert audit.verify_chain(db)[0] is True
