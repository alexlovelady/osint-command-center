"""DARKINT P4: the five templates (disabled, dry-runnable) and the nodes that read monitors and events under the same consent gates as a manual check."""
from __future__ import annotations

import pytest
from osintcc.adapters.registry import default_adapters
from osintcc.automations import catalog, handlers  # noqa: F401  (registers the handlers)
from osintcc.automations.graph_validator import validate
from osintcc.automations.registry import HANDLERS, SPECS
from test_darkint import B, _no_pacing, _no_real_keyring, api, check, enable, person, world  # noqa: F401  (fixtures)

AUT = "/api/v1/automations"
KEYS = [f"DARK-{i:02d}" for i in range(1, 6)]


def test_nodes_are_registered_and_none_can_send_a_message():
    for t in ("darkint_check", "darkint_events", "darkint_remediation"):
        assert t in SPECS and t in HANDLERS
    assert SPECS["darkint_check"].replay_safe is False and SPECS["darkint_remediation"].side_effects == "write_local" and SPECS["darkint_events"].side_effects == "none"
    assert sorted(t for t in SPECS if t.startswith("darkint_")) == ["darkint_check", "darkint_events", "darkint_remediation"]      # no node that sends, notifies or submits


@pytest.mark.parametrize("key", KEYS)
def test_every_darkint_template_validates_ships_disabled_and_states_its_limits(key):
    t = catalog.get(key)
    d = t["definition"]
    assert t["category"] == "Exposure" and d["trigger"]["enabled"] is False and d["policy"]["network_mode"] == "passive_only"
    assert validate(d, default_adapters())["valid"]
    assert t["capability_gaps"] and ("fixture-tested" in " ".join(t["capability_gaps"]) or "Nothing is sent" in " ".join(t["capability_gaps"]))
    assert "No passwords, hashes" in t["legal_notes"]


@pytest.mark.parametrize("trigger", [{"type": "event", "event": "new_finding", "enabled": False}, {"type": "file", "enabled": False}])
def test_an_exposure_lookup_cannot_be_started_by_an_event_or_a_file(trigger):
    d = catalog.get("DARK-01")["definition"]
    rep = validate({**d, "trigger": trigger}, default_adapters())
    assert not rep["valid"]


@pytest.mark.parametrize("bad", [{"identifier": "jane.doe@example.com"}, {"provider": "hibp"}, {"api_key": "k"}, {"password": "x"}])
def test_the_check_node_has_no_field_for_an_identifier_provider_or_secret(bad):
    d = catalog.get("DARK-01")["definition"]
    nodes = [({**n, "config": {**n["config"], **bad}} if n["id"] == "check" else n) for n in d["nodes"]]
    assert not validate({**d, "nodes": nodes}, default_adapters())["valid"]


@pytest.mark.parametrize("key", KEYS)
async def test_dry_runs_are_simulated_contact_nothing_and_create_nothing(api, world, key):
    t = catalog.get(key)
    cid = (await api.post(f"{B}/cases", json={"title": "D", "category": "people", "purpose": "self audit"})).json()["id"]
    wf = (await api.post(f"{AUT}/from-template", json={"slug": t["slug"], "case_id": cid, "inputs": {}})).json()
    j = (await api.post(f"{AUT}/workflows/{wf['id']}/dry-run", json={})).json()
    assert j["run"]["dry_run"] and j["run"]["simulated"] and j["run"]["state"] in ("completed", "completed_with_warnings")
    assert not world["seen"]
    from osintcc.db.models import ExposureEvent, RemediationTask
    from sqlalchemy import func, select
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(ExposureEvent)) == 0 and db.scalar(select(func.count()).select_from(RemediationTask)) == 0


def wf_def(nodes, trigger=None, inputs=None):
    return {"schema_version": 1, "workflow_key": "dark-test", "name": "DARK test", "inputs": inputs if inputs is not None else {"monitor_id": None}, "trigger": trigger or {"type": "manual"}, "policy": {}, "nodes": nodes}


async def run_wf(api, cid, nodes, monitor_id):
    wf = (await api.post(f"{AUT}/workflows", json={"definition": wf_def(nodes), "case_id": cid})).json()
    assert (await api.post(f"{AUT}/workflows/{wf['id']}/publish")).status_code == 201
    r = (await api.post(f"{AUT}/workflows/{wf['id']}/run", json={"case_id": cid, "wait": True, "inputs": {"monitor_id": monitor_id}})).json()
    d = (await api.get(f"{AUT}/runs/{r['id']}")).json()
    return d, {n["node"]: n for n in d["nodes"]}


CHECK = [{"id": "check", "type": "darkint_check", "depends_on": [], "config": {"monitor_ref": "$inputs.monitor_id"}},
         {"id": "tasks", "type": "darkint_remediation", "depends_on": ["check"], "config": {"actions": ["password_reset", "mfa"], "max_tasks": 5}}]


async def make_monitor(api, p):
    from datetime import UTC, datetime, timedelta
    r = await api.post(f"{B}/cases/{p['cid']}/darkint/monitors", json={"subject_id": p["sid"], "name": "weekly", "identifier_ids": [p["ids"]["email"]], "provider_ids": ["hibp"], "cadence_hours": 168,
                                                                        "expires_at": (datetime.now(UTC) + timedelta(days=20)).isoformat()})
    assert r.status_code == 201, r.text
    m = r.json()
    assert (await api.patch(f"{B}/cases/{p['cid']}/darkint/monitors/{m['id']}", json={"enabled": True})).status_code == 200
    return m


async def test_a_workflow_runs_a_monitor_creates_tasks_only_and_sends_nothing(api, world):
    await enable(api)
    p = await person(api)
    m = await make_monitor(api, p)
    d, nodes = await run_wf(api, p["cid"], CHECK, m["id"])
    assert d["state"] in ("completed", "completed_with_warnings"), d
    assert nodes["check"]["output"]["count"] == 1 and nodes["tasks"]["output"]["count"] >= 2
    assert all(u.startswith("https://haveibeenpwned.com/") for u in world["seen"])         # only the provider named by the monitor was contacted
    tasks = (await api.get(f"{B}/subjects/{p['sid']}/remediations")).json()["items"]
    assert {t["issue"].split(":")[0] for t in tasks} >= {"Password reset", "Mfa"}


async def test_revoking_the_consent_stops_the_workflow_before_any_request(api, world):
    await enable(api)
    p = await person(api)
    m = await make_monitor(api, p)
    assert (await api.post(f"{B}/subjects/{p['sid']}/consent/revoke", json={"consent_id": p["consent"], "reason": "withdrawn"})).status_code == 200
    n = len(world["seen"])
    d, nodes = await run_wf(api, p["cid"], CHECK, m["id"])
    assert d["state"] == "failed" and nodes["check"]["state"] == "failed" and nodes["check"]["error_code"] == "SCOPE_DENIED" and len(world["seen"]) == n


async def test_provider_problems_surface_as_the_specified_error_codes_not_as_empty_results(api, world):
    await enable(api)
    p = await person(api)
    m = await make_monitor(api, p)
    world["hibp_status"] = 429
    _, nodes = await run_wf(api, p["cid"], CHECK[:1], m["id"])
    assert nodes["check"]["state"] == "failed" and nodes["check"]["error_code"] == "RATE_LIMITED"
    api.app.state.core.quota.clear_restrictions("hibp")                                             # the 429 above made the dispatcher back off
    world["hibp_status"] = 503
    _, nodes = await run_wf(api, p["cid"], CHECK[:1], m["id"])
    assert nodes["check"]["error_code"] == "SOURCE_UNAVAILABLE"
    api.app.state.core.quota.clear_restrictions("hibp")
    world["hibp_key"] = None
    _, nodes = await run_wf(api, p["cid"], CHECK[:1], m["id"])
    assert nodes["check"]["error_code"] == "CREDENTIAL_MISSING"


async def test_a_monitor_from_another_case_cannot_be_used(api, world):
    await enable(api)
    p1, p2 = await person(api), await person(api)
    m = await make_monitor(api, p1)
    _, nodes = await run_wf(api, p2["cid"], CHECK[:1], m["id"])
    assert nodes["check"]["error_code"] == "SCOPE_DENIED" and not world["seen"]
    assert (await check(api, p1, "email", ["hibp"]))["results"][0]["outcome"] == "match"


async def test_a_bound_workflow_is_switched_off_when_the_consent_is_revoked(api, world):
    await enable(api)
    p = await person(api)
    t = catalog.get("DARK-04")
    import json as _json
    d = _json.loads(_json.dumps(t["definition"]))
    d["tags"] = [*d.get("tags", []), f"subject:{p['sid']}"]
    wf = (await api.post(f"{AUT}/workflows", json={"definition": d, "case_id": p["cid"]})).json()
    from osintcc.profile import hooks
    with api.app.state.core.sm() as db:
        from osintcc.db.models import AutomationWorkflow, Subject
        w = db.get(AutomationWorkflow, wf["id"])
        s = db.get(Subject, p["sid"])
        assert hooks.bound_subject_id(w) == p["sid"]
        from osintcc.automations.registry import NodeError
        with pytest.raises(NodeError) as exc:
            from datetime import UTC, datetime, timedelta
            hooks.workflow_gate(db, w, now=datetime.now(UTC) + timedelta(days=400))      # consent expired: the exposure class is checked even with no adapter node
        assert "authorization" in str(exc.value)
        assert s is not None
