"""AIV-5: automation nodes that read verification state, and the five AIV templates (shipped disabled, manual only, unable to send a request)."""
from __future__ import annotations

import pytest
from osintcc.adapters.registry import default_adapters
from osintcc.automations import (
    catalog,
    handlers,  # noqa: F401  (registers the handlers)
)
from osintcc.automations.graph_validator import validate
from osintcc.automations.registry import HANDLERS, SPECS
from test_aiv_core import approve, enable, mk_auth, mk_case, mk_plan, run

B = "/api/v1"
AIV_KEYS = [f"AIV-{i:02d}" for i in range(1, 6)]


def test_aiv_nodes_are_registered_with_handlers_and_cannot_touch_the_network():
    for t in ("aiv_authorizations", "aiv_observations"):
        assert t in SPECS and t in HANDLERS
        assert SPECS[t].side_effects == "none" and SPECS[t].network is False and SPECS[t].risk == "low"
    assert not [t for t in SPECS if t.startswith("aiv_") and t not in ("aiv_authorizations", "aiv_observations")]   # no node can plan, approve or run


@pytest.mark.parametrize("key", AIV_KEYS)
def test_every_aiv_template_is_valid_manual_only_and_passive(key):
    t = catalog.get(key)
    d = t["definition"]
    assert t["category"] == "Verification" and d["trigger"] == {"type": "manual", "enabled": False} and d["policy"]["network_mode"] == "passive_only"
    rep = validate(d, default_adapters())
    assert rep["valid"] and rep["permissions"]["network"] is False and rep["permissions"]["active"] is False
    assert t["capability_gaps"] and "cannot send requests" in " ".join(t["capability_gaps"])


@pytest.mark.parametrize("trigger", [{"type": "schedule", "schedule": "0 8 * * *", "timezone": "UTC", "enabled": False}, {"type": "event", "event": "new_finding", "enabled": False}])
def test_aiv_steps_are_rejected_in_a_scheduled_or_event_driven_workflow(trigger):
    d = dict(catalog.get("AIV-01")["definition"])
    rep = validate({**d, "trigger": trigger}, default_adapters())
    assert not rep["valid"] and any("manually started" in e["message"] for e in rep["errors"])


@pytest.mark.parametrize("bad", [{"command": "nmap -sV x"}, {"url": "http://x.test"}, {"template_path": "/t/x.yaml"}, {"credentials": "x"}, {"limit": 100000}])
def test_aiv_node_config_has_no_field_for_a_command_url_template_path_or_credential(bad):
    d = catalog.get("AIV-01")["definition"]
    nodes = [({**n, "config": {**n["config"], **bad}} if n["id"] == "observed" else n) for n in d["nodes"]]
    assert not validate({**d, "nodes": nodes}, default_adapters())["valid"]


AUT = "/api/v1/automations"


def wf_def(nodes):
    return {"schema_version": 1, "workflow_key": "aiv-read-test", "name": "AIV read test", "inputs": {}, "trigger": {"type": "manual"}, "policy": {}, "nodes": nodes}


async def test_the_nodes_read_only_this_cases_records_and_never_send_a_request(env):
    api = env["api"]
    await enable(env)
    lb = await env["lab"]()
    cid, other = await mk_case(env), await mk_case(env)
    live = await mk_auth(env, cid, ["lab.test"], [lb.port])
    expired = await mk_auth(env, cid, ["other.test"], [lb.port])
    assert (await api.post(f"/api/v1/cases/{cid}/asset-authorizations/{expired['id']}/revoke", json={"reason": "no longer needed"})).status_code in (200, 201)
    p = await mk_plan(env, cid, live["id"], [{"kind": "http_metadata", "url": f"http://lab.test:{lb.port}/", "method": "GET", "follow_redirects": False}])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    assert r["status"] == "completed"
    seen_before = len(lb.seen)
    nodes = [{"id": "auth", "type": "aiv_authorizations", "depends_on": [], "config": {"only_live": True}},
             {"id": "all_auth", "type": "aiv_authorizations", "depends_on": [], "config": {"only_live": False}},
             {"id": "obs", "type": "aiv_observations", "depends_on": [], "config": {"min_severity": "low"}},
             {"id": "none", "type": "aiv_observations", "depends_on": [], "config": {"min_severity": "high"}}]
    wf = (await api.post(f"{AUT}/workflows", json={"definition": wf_def(nodes), "case_id": cid})).json()
    assert (await api.post(f"{AUT}/workflows/{wf['id']}/publish")).status_code == 201
    run_row = (await api.post(f"{AUT}/workflows/{wf['id']}/run", json={"case_id": cid, "wait": True})).json()
    detail = (await api.get(f"{AUT}/runs/{run_row['id']}")).json()
    outs = {n["node"]: n["output"] for n in detail["nodes"]}
    assert outs["auth"]["count"] == 1 and outs["all_auth"]["count"] == 2           # the revoked authorization is excluded unless asked for
    assert outs["obs"]["count"] >= 1 and outs["none"]["count"] == 0
    from osintcc.db.models import AutomationNodeRun
    from sqlalchemy import select
    with env["st"].sm() as db:
        full = {nr.node_id: nr.output_json for nr in db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == run_row["id"]))}
    assert [i["id"] for i in full["auth"]["items"]] == [live["id"]] and full["auth"]["adapters"] == ["aiv"]
    assert all(i["adapter"] == "aiv" and i["severity"] in ("low", "medium", "high") for i in full["obs"]["items"])
    assert full["obs"]["items"] and all(i["predicate"].startswith("aiv.") for i in full["obs"]["items"])
    assert len(lb.seen) == seen_before                                                  # reading verification records sent nothing
    # another case sees none of it
    wf2 = (await api.post(f"{AUT}/workflows", json={"definition": wf_def(nodes), "case_id": other})).json()
    assert (await api.post(f"{AUT}/workflows/{wf2['id']}/publish")).status_code == 201
    r2 = (await api.post(f"{AUT}/workflows/{wf2['id']}/run", json={"case_id": other, "wait": True})).json()
    o2 = {n["node"]: n["output"] for n in (await api.get(f"{AUT}/runs/{r2['id']}")).json()["nodes"]}
    assert o2["obs"]["count"] == 0 and o2["all_auth"]["count"] == 0


def _signed(definition, name="imported"):
    import hashlib
    import json
    body = {"format": "osintcc-automation/1", "name": name, "definition": definition}
    body["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return body


@pytest.mark.parametrize("mutate", [
    lambda d: d["nodes"][1]["config"].update({"command": "nmap -A target"}),
    lambda d: d["nodes"][1]["config"].update({"credentials": {"user": "a", "password": "b"}}),
    lambda d: d["nodes"].append({"id": "sneak", "type": "shell", "depends_on": [], "config": {"cmd": "id"}}),
    lambda d: d.update({"trigger": {"type": "schedule", "schedule": "0 8 * * *", "timezone": "UTC", "enabled": False}}),
], ids=["command", "credentials", "hidden-active-step", "scheduled-aiv"])
async def test_importing_a_definition_with_a_command_credentials_or_hidden_active_step_is_rejected(env, mutate):
    import copy
    api = env["api"]
    cid = await mk_case(env)
    d = copy.deepcopy(catalog.get("AIV-01")["definition"])
    mutate(d)
    r = await api.post(f"{AUT}/import", json={"document": _signed(d), "case_id": cid})
    if r.status_code < 300:                       # stored only as an invalid, never-runnable draft
        assert r.json()["validation"]["valid"] is False
        run = await api.post(f"{AUT}/workflows/{r.json()['id']}/publish")
        assert run.status_code >= 400
    else:
        assert r.status_code == 422
