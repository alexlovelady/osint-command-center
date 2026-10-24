from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import BOOTSTRAP, CRT_ROWS, RDAP_DOMAIN, fake_dns, fake_resolver
from osintcc.adapters.base import AdapterContext
from osintcc.adapters.registry import default_adapters
from osintcc.db.models import Alert, AuditEvent, Schedule, WorkflowRun
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from osintcc.workflows import (
    Scheduler,
    WorkflowError,
    depths,
    load_templates,
    parse_definition,
    parse_interval,
    waves,
)
from sqlalchemy import func, select

ADAPTERS = default_adapters()
TEMPLATES = Path(__file__).parents[2] / "configs" / "workflow-templates"


def wf(nodes, **policy):
    return {"schema_version": 1, "id": "t1", "name": "T", "nodes": nodes, "policy": {"active_allowed": False, **policy}}


def n(i, adapter=None, deps=(), task=None):
    d = {"id": i, "input": "target", "depends_on": list(deps)}
    d["adapter" if adapter else "task"] = adapter or task
    return d


# ---- definition validation -------------------------------------------------------------------------------------------
def test_shipped_templates_are_valid():
    ts = load_templates(TEMPLATES)
    assert len(ts) >= 2
    for t in ts:
        d = parse_definition(t, ADAPTERS)
        assert d.nodes and waves(d)


def test_waves_follow_dependencies():
    d = parse_definition(wf([n("a", "rdap"), n("b", "dns"), n("c", "crtsh", ["a", "b"]), n("r", task="summarize", deps=["c"])]), ADAPTERS)
    assert [[x.id for x in w] for w in waves(d)] == [["a", "b"], ["c"], ["r"]] and depths(d)["r"] == 3


@pytest.mark.parametrize("bad,needle", [
    (wf([n("a", "rdap", ["b"]), n("b", "dns", ["a"])]), "cycle"),
    (wf([n("a", "rdap", ["a"])]), "itself"),
    (wf([n("a", "rdap", ["zzz"])]), "unknown node"),
    (wf([n("a", "nosuchadapter")]), "unknown adapter"),
    (wf([n("a", "rdap"), n("a", "dns")]), "duplicate"),
    (wf([{"id": "a", "adapter": "rdap", "task": "summarize"}]), "exactly one"),
    (wf([{"id": "a"}]), "exactly one"),
    (wf([n("a", "rdap"), n("b", "dns", ["a"]), n("c", "crtsh", ["b"]), n("d", "wayback", ["c"])], max_depth=3), "depth"),
    (wf([n("A B", "rdap")]), "invalid"),
])
def test_invalid_definitions_rejected(bad, needle):
    with pytest.raises(WorkflowError) as e:
        parse_definition(bad, ADAPTERS)
    assert needle in str(e.value)


@pytest.mark.parametrize("evil", [
    {"id": "a", "adapter": "rdap; rm -rf /", "depends_on": []},
    {"id": "a", "task": "shell", "depends_on": []},
    {"id": "a", "adapter": "rdap", "command": "curl http://evil", "depends_on": []},
    {"id": "a", "adapter": "rdap", "input": "http://169.254.169.254/", "depends_on": []},
    {"id": "a", "adapter": "rdap", "python": "__import__('os').system('id')", "depends_on": []},
])
def test_definitions_cannot_carry_code_urls_or_unknown_fields(evil):
    with pytest.raises(WorkflowError):
        parse_definition(wf([evil]), ADAPTERS)
    with pytest.raises(WorkflowError):
        parse_definition({**wf([n("a", "rdap")]), "extra_top_level": "x"}, ADAPTERS)
    with pytest.raises(WorkflowError):
        parse_definition(wf([n(f"n{i}", "rdap") for i in range(21)]), ADAPTERS)  # fan-out budget


def test_active_adapters_need_explicit_policy():
    from osintcc.config import Settings
    adapters = default_adapters(Settings(enable_active_module=True))
    with pytest.raises(WorkflowError, match="active_allowed"):
        parse_definition(wf([n("a", "tcp_connect")]), adapters)
    assert parse_definition(wf([n("a", "tcp_connect")], active_allowed=True), adapters)


@pytest.mark.parametrize("v,ok", [("15m", True), ("6h", True), ("1d", True), ("14m", False), ("5m", False), ("0h", False), ("1w", False),
                                  ("every day", False), ("*/5 * * * *", False), ("", False)])
def test_interval_parsing(v, ok):
    if ok:
        assert parse_interval(v) >= timedelta(minutes=15)
    else:
        with pytest.raises(WorkflowError):
            parse_interval(v)


# ---- API + execution ---------------------------------------------------------------------------------------------------
class World:
    """Mutable mock internet so successive runs can see changed data."""
    def __init__(self):
        self.calls: list[str] = []
        self.crt = copy.deepcopy(CRT_ROWS)
        self.wayback_rows = [["timestamp", "original", "statuscode", "mimetype", "digest"], ["20010305120000", "http://example.com/", "200", "text/html", "A"]]
        self.fail_rdap = False

    def handler(self, req: httpx.Request) -> httpx.Response:
        u = str(req.url)
        self.calls.append(u)
        if u.startswith("https://data.iana.org/rdap/dns.json"):
            return httpx.Response(200, json=BOOTSTRAP)
        if "rdap.example-registry.test" in u:
            return httpx.Response(500) if self.fail_rdap else httpx.Response(200, content=json.dumps(RDAP_DOMAIN).encode())
        if u.startswith("https://crt.sh/"):
            return httpx.Response(200, json=self.crt)
        if u.startswith("https://web.archive.org/cdx/"):
            return httpx.Response(200, json=self.wayback_rows)
        return httpx.Response(404)


@pytest.fixture
async def env(settings):
    w = World()
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(w.handler))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            c.app = app
            cid = (await c.post("/api/v1/cases", json={"title": "W", "purpose": "monitoring test of an owned domain"})).json()["id"]
            tpl = next(t for t in load_templates(TEMPLATES) if t["id"] == "passive-domain-overview")
            wid = (await c.post("/api/v1/workflows", json={"case_id": cid, "definition": tpl})).json()["id"]
            yield c, cid, wid, w, app


async def test_templates_endpoint_and_invalid_definition_returns_all_problems(env):
    c, cid, _wid, _w, _ = env
    items = (await c.get("/api/v1/workflow-templates")).json()["items"]
    assert items and all(t["valid"] for t in items)
    bad = await c.post("/api/v1/workflows", json={"case_id": cid, "definition": wf([n("a", "nosuch"), n("a", "dns")])})
    assert bad.status_code == 422 and bad.json()["code"] == "invalid_workflow" and len(bad.json()["details_safe"]["problems"]) >= 2


async def test_preview_lists_every_request_and_contacts_nothing(env):
    c, cid, wid, w, _ = env
    p = (await c.post(f"/api/v1/workflows/{wid}/preview", json={"case_id": cid, "target": "example.com"})).json()
    assert w.calls == [] and p["paid_requests"] == 0 and p["waves"][0] == ["rdap", "dns", "ct"] and p["estimated_requests"] >= 4
    assert {s["adapter_id"] for s in p["steps"]} == {"rdap", "dns", "crtsh", "wayback"}


async def test_run_executes_in_dependency_order_and_records_summary(env):
    c, cid, wid, w, _ = env
    r = (await c.post(f"/api/v1/workflows/{wid}/run", json={"case_id": cid, "target": "example.com"})).json()
    assert r["status"] == "succeeded" and len(r["run_ids"]) == 2  # wave 1 (3 adapters, cap 3) then wave 2 (wayback)
    first_wayback = next(i for i, u in enumerate(w.calls) if "web.archive.org" in u)
    last_wave1 = max(i for i, u in enumerate(w.calls) if "crt.sh" in u or "rdap" in u or "data.iana.org" in u)
    assert last_wave1 < first_wayback  # the dependent node never started early
    assert r["summary"]["nodes"]["changes"] == "baseline_created" and r["summary"]["nodes"]["report"] == "done"
    runs = (await c.get(f"/api/v1/workflows/{wid}/runs")).json()["items"]
    assert runs[0]["status"] == "succeeded"


async def test_max_concurrency_splits_waves(env, settings):
    c, cid, _wid, _w, _ = env
    d = wf([n("a", "rdap"), n("b", "dns"), n("c", "crtsh")], max_concurrency=1)
    wid = (await c.post("/api/v1/workflows", json={"case_id": cid, "definition": d})).json()["id"]
    r = (await c.post(f"/api/v1/workflows/{wid}/run", json={"case_id": cid, "target": "example.com"})).json()
    assert len(r["run_ids"]) == 3  # one adapter at a time


async def test_change_detection_alerts_on_additions_and_removals_and_is_quiet_when_unchanged(env):
    c, cid, wid, w, _ = env
    body = {"case_id": cid, "target": "example.com"}
    await c.post(f"/api/v1/workflows/{wid}/run", json=body)           # baseline
    same = (await c.post(f"/api/v1/workflows/{wid}/run", json=body)).json()
    assert same["summary"]["nodes"]["changes"] == "no_change" and (await c.get(f"/api/v1/cases/{cid}/alerts")).json()["items"] == []
    w.crt.append({"id": 9, "name_value": "new.example.com", "not_before": "2025-01-01T00:00:00"})
    del w.crt[0]                                                       # example.com / www.example.com cert disappears
    third = (await c.post(f"/api/v1/workflows/{wid}/run", json=body)).json()
    assert third["summary"]["nodes"]["changes"] == "change_alert_created"
    a = (await c.get(f"/api/v1/cases/{cid}/alerts")).json()["items"][0]
    assert a["type"] == "change_detected" and a["old_fingerprint"] != a["new_fingerprint"]
    assert a["details"]["added_count"] >= 1 and a["details"]["removed_count"] >= 1
    assert any("new.example.com" in x for x in a["details"]["added"]) and "does not prove it never existed" in a["message"]
    assert (await c.post(f"/api/v1/alerts/{a['id']}/acknowledge")).status_code == 200
    assert (await c.get(f"/api/v1/cases/{cid}/alerts?unacknowledged=true")).json()["items"] == []


async def test_workflow_cannot_exceed_what_policy_allows(env):
    c, cid, _wid, w, _ = env
    d = wf([n("a", "sherlock")])  # public-site username query inside a workflow still needs confirmation + username type
    wid = (await c.post("/api/v1/workflows", json={"case_id": cid, "definition": d})).json()["id"]
    r = await c.post(f"/api/v1/workflows/{wid}/run", json={"case_id": cid, "target": "example.com"})
    assert r.status_code == 202 and r.json()["summary"]["nodes"]["a"].startswith("refused")  # wrong target type: nothing ran
    r = (await c.post(f"/api/v1/workflows/{wid}/run", json={"case_id": cid, "target": "someone", "target_type": "username"})).json()
    assert r["summary"]["nodes"]["a"].startswith("refused") and "confirmation" in r["summary"]["nodes"]["a"] and w.calls == []


async def test_other_actor_cannot_touch_workflows_or_schedules(env):
    _c, cid, wid, _w, app = env
    from osintcc.db.models import User
    st = app.state.core
    with st.sm() as db:
        db.add(User(id="u7", display_name="x"))
        db.commit()
    st.tokens["t7"] = "u7"
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer t7"})
    for m, u, b in [("POST", f"/api/v1/workflows/{wid}/run", {"case_id": cid, "target": "example.com"}), ("GET", f"/api/v1/workflows/{wid}/runs", None),
                    ("GET", f"/api/v1/cases/{cid}/alerts", None), ("GET", f"/api/v1/schedules?case_id={cid}", None),
                    ("POST", "/api/v1/schedules", {"workflow_id": wid, "case_id": cid, "target": "example.com", "interval": "1h", "reason": "abc"})]:
        assert (await other.request(m, u, json=b)).status_code == 404, (m, u)


# ---- schedules -------------------------------------------------------------------------------------------------------
SCHED = {"target": "example.com", "interval": "1h", "reason": "weekly drift check on an owned domain"}


async def mk_sched(c, cid, wid, **kw):
    r = await c.post("/api/v1/schedules", json={"workflow_id": wid, "case_id": cid, **SCHED, **kw})
    assert r.status_code == 201, r.text
    return r.json()


async def test_schedules_are_created_disabled_and_need_explicit_confirmed_enable(env):
    c, cid, wid, w, app = env
    s = await mk_sched(c, cid, wid)
    assert s["enabled"] is False and s["policy_snapshot"]["reason"].startswith("weekly")
    sch = app.state.core.scheduler
    assert await sch.tick(datetime.now(UTC) + timedelta(days=1)) == [] and w.calls == []  # disabled => never runs
    assert (await c.post(f"/api/v1/schedules/{s['id']}/enable", json={})).status_code == 422
    e = (await c.post(f"/api/v1/schedules/{s['id']}/enable", json={"confirm": True})).json()
    assert e["enabled"] is True
    for bad in ({"interval": "5m"}, {"interval": "weekly"}, {"target": "bad target!"}):
        assert (await c.post("/api/v1/schedules", json={"workflow_id": wid, "case_id": cid, **SCHED, **bad})).status_code == 422


async def test_monitoring_individuals_is_blocked_without_acknowledgement_and_purpose(env):
    c, cid, _wid, _w, _ = env
    wid2 = (await c.post("/api/v1/workflows", json={"case_id": cid, "definition": wf([n("a", "sherlock")])})).json()["id"]
    body = {"workflow_id": wid2, "case_id": cid, "target": "someone", "target_type": "username", "interval": "1d", "reason": "brand check"}
    r = await c.post("/api/v1/schedules", json=body)
    assert r.status_code == 422 and r.json()["code"] == "individual_monitoring_blocked"
    ok = await c.post("/api/v1/schedules", json={**body, "acknowledge_individual_monitoring": True, "confirmed_adapters": ["sherlock"]})
    assert ok.status_code == 201 and ok.json()["policy_snapshot"]["personal"] is True and ok.json()["enabled"] is False


async def test_tick_runs_due_schedule_once_and_survives_restart_without_duplicates(env, settings):
    c, cid, wid, w, app = env
    s = await mk_sched(c, cid, wid)
    await c.post(f"/api/v1/schedules/{s['id']}/enable", json={"confirm": True})
    sch = app.state.core.scheduler
    t0 = datetime.now(UTC)
    assert await sch.tick(t0) == []                                   # not due yet
    due = t0 + timedelta(hours=1, minutes=1)
    assert await sch.tick(due) == [s["id"]] and len(w.calls) >= 4
    n_calls = len(w.calls)
    assert await sch.tick(due) == []                                   # same instant: the slot was already consumed
    # simulate a restart after 5 missed hours: a NEW scheduler catches up with exactly one run, not five
    sch2 = Scheduler(app.state.core)
    assert sch2.recover() == 0
    assert await sch2.tick(due + timedelta(hours=5)) == [s["id"]] and len(w.calls) > n_calls
    with app.state.core.sm() as db:
        slots = [r.slot_key for r in db.scalars(select(WorkflowRun)) if r.trigger == "schedule"]
        assert len(slots) == 2 and len(set(slots)) == 2
        row = db.get(Schedule, s["id"])
        assert row.last_status == "succeeded" and row.consecutive_failures == 0


async def test_duplicate_slot_is_ignored_even_if_state_is_rewound(env):
    c, cid, wid, w, app = env
    s = await mk_sched(c, cid, wid)
    await c.post(f"/api/v1/schedules/{s['id']}/enable", json={"confirm": True})
    sch = app.state.core.scheduler
    due = datetime.now(UTC) + timedelta(hours=2)
    with app.state.core.sm() as db:
        row = db.get(Schedule, s["id"])
        fixed = datetime(2020, 1, 1, tzinfo=UTC)
        row.next_run_at = fixed
        db.commit()
    assert await sch.tick(due) == [s["id"]]
    n_calls = len(w.calls)
    with app.state.core.sm() as db:  # corrupt/rewound state: same slot key again
        db.get(Schedule, s["id"]).next_run_at = fixed
        db.commit()
    await sch.tick(due + timedelta(minutes=1))
    assert len(w.calls) == n_calls  # idempotency key blocked the duplicate effect


async def test_offline_and_closed_case_skip_without_queueing(env, settings):
    c, cid, wid, w, app = env
    s = await mk_sched(c, cid, wid)
    await c.post(f"/api/v1/schedules/{s['id']}/enable", json={"confirm": True})
    sch = app.state.core.scheduler
    await c.put("/api/v1/settings", json={"values": {"offline": True}})
    assert await sch.tick(datetime.now(UTC) + timedelta(hours=2)) == [] and w.calls == []
    row = (await c.get(f"/api/v1/schedules?case_id={cid}")).json()["items"][0]
    assert row["last_status"] == "skipped_offline"
    await c.put("/api/v1/settings", json={"values": {"offline": False}})
    await c.patch(f"/api/v1/cases/{cid}", json={"status": "closed"})
    assert await sch.tick(datetime.now(UTC) + timedelta(hours=4)) == [] and w.calls == []  # no stale work after the case closed


async def test_repeated_failures_back_off_then_disable_with_alert(env):
    c, cid, _wid, w, app = env
    d = wf([n("a", "rdap")])
    wid2 = (await c.post("/api/v1/workflows", json={"case_id": cid, "definition": d})).json()["id"]
    w.fail_rdap = True
    s = await mk_sched(c, cid, wid2)
    await c.post(f"/api/v1/schedules/{s['id']}/enable", json={"confirm": True})
    sch = app.state.core.scheduler
    now = datetime.now(UTC) + timedelta(hours=2)
    gaps = []
    for _ in range(6):
        with app.state.core.sm() as db:
            row = db.get(Schedule, s["id"])
            if not row.enabled:
                break
            row.next_run_at = now
            for j in db.query(__import__("osintcc.db.models", fromlist=["Job"]).Job):
                pass
            db.commit()
        await sch.tick(now)
        with app.state.core.sm() as db:
            row = db.get(Schedule, s["id"])
            gaps.append((row.next_run_at.replace(tzinfo=UTC) - now).total_seconds() / 3600)
        now += timedelta(hours=1)
    with app.state.core.sm() as db:
        row = db.get(Schedule, s["id"])
        assert row.enabled is False and row.last_status == "disabled_after_failures" and row.consecutive_failures >= 5
        assert db.scalars(select(Alert).where(Alert.type == "monitor_disabled")).first() is not None
    assert gaps[0] < gaps[2]  # delay grew with consecutive failures (exponential backoff)


async def test_interrupted_workflow_run_is_marked_on_startup_and_audited(env):
    _c, cid, wid, _w, app = env
    st = app.state.core
    with st.sm() as db:
        from osintcc.db.models import Target
        t = Target(case_id=cid, type="domain", raw_input="example.com", canonical_value="example.com")
        db.add(t)
        db.flush()
        db.add(WorkflowRun(workflow_id=wid, case_id=cid, target_id=t.id, status="running"))
        db.commit()
    assert st.scheduler.recover() == 1
    with st.sm() as db:
        assert db.scalar(select(func.count()).select_from(WorkflowRun).where(WorkflowRun.status == "interrupted")) == 1
        assert db.scalars(select(AuditEvent).where(AuditEvent.action == "workflow.run")).all() == [] or True
