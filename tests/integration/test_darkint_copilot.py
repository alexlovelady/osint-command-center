"""DARKINT P5: the Copilot explains stored, redacted events and may propose a disabled workflow draft. It cannot look anything up, widen a consent or reveal content."""
from __future__ import annotations

import json
import re

from osintcc.ai.providers import FixtureProvider
from osintcc.copilot import darkint_tools
from osintcc.copilot.tools import ACTIONS, TOOLS
from osintcc.db.models import AutomationWorkflow, CopilotProposal
from sqlalchemy import func, select
from test_darkint import B, _no_pacing, _no_real_keyring, api, check, enable, person, world  # noqa: F401  (fixtures)


async def chat(api, text, cid):
    r = await api.post(f"{B}/copilot/chat", json={"text": text, "mode": "investigation", "ctx": {"route": "case", "tab": "Profile", "case_id": cid}})
    assert r.status_code == 200, r.text
    ev = [json.loads(line) for line in r.text.splitlines() if line.strip()]
    return ev, next((e for e in ev if e["type"] == "final"), None)


async def enable_ai(api, provider):
    api.app.state.core.ai_factory = lambda p: provider
    await api.post(f"{B}/ai/profiles", json={"name": "fx", "provider_type": "fixture", "model_id": "fixture-1"})
    await api.put(f"{B}/settings", json={"values": {"ai_enabled": True}})


def test_no_exposure_tool_can_look_anything_up_or_widen_access():
    names = [n for n in TOOLS if "darkint" in n or "exposure_event" in n]
    assert sorted(names) == ["darkint_summary", "explain_exposure_event", "propose_darkint_workflow"]
    assert not [n for n in TOOLS if re.search(r"run_check|start_check|monitor|enable|consent|fetch|download|breach_lookup", n)]
    assert {n for n in ACTIONS if "darkint" in n} == {"propose_darkint_workflow"}


async def test_summary_and_event_explanations_need_no_model_cite_evidence_and_never_invent_contents(api, world):
    await enable(api)
    p = await person(api)
    _, empty = await chat(api, "Show the breach coverage summary", p["cid"])
    assert "Not checked" in empty["text"] and "not the same as no exposure" in empty["text"]
    await check(api, p, "email", ["hibp"])
    _, final = await chat(api, "Show the breach coverage summary", p["cid"])
    t = final["text"]
    assert "Match reported" in t and "Example Forum" in t and "reported, not independently verified" in t and "not proof that data leaked" in t and "evidence `" in t
    assert "jane.doe@" not in t and "must not be stored" not in t and "password:" not in t.lower()
    _, ex = await chat(api, "Explain this breach report", p["cid"])
    assert "Practical next steps" in ex["text"] and "Change the password" in ex["text"] and "none is stored here" in ex["text"]
    assert final["profile_citations"] and final["profile_citations"][0]["sha256"]


async def test_a_proposal_installs_only_a_disabled_draft_and_needs_a_live_authorization(api, world):
    await enable(api)
    p = await person(api)
    from test_darkint_automation import make_monitor
    m = await make_monitor(api, p)
    call = '```osintcc-tools\n' + json.dumps({"calls": [{"tool": "propose_darkint_workflow", "args": {"slug": "DARK-04", "inputs": {"monitor_id": m["id"]}}}]}) + '\n```'
    await api.post(f"{B}/cases/{p['cid']}/notes", json={"body_markdown": "Install the DARK-04 template as a draft for the exposure monitor."})
    await enable_ai(api, FixtureProvider(script=lambda msg: "I prepared a draft workflow. " + call))
    ev, _ = await chat(api, "Install the DARK-04 template as a draft", p["cid"])
    prop = next(e["proposal"] for e in ev if e["type"] == "proposal")
    assert prop["tool"] == "propose_darkint_workflow" and "DISABLED draft" in prop["preview"]["installs"] and prop["preview"]["will_contact"] == ["hibp"]
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(AutomationWorkflow)) == 0
    n = len(world["seen"])
    r = await api.post(f"{B}/copilot/proposals/{prop['id']}/approve", json={"confirm": True})
    assert r.status_code == 200, r.text
    with api.app.state.core.sm() as db:
        wf = db.scalars(select(AutomationWorkflow)).one()
        assert wf.state == "draft" and wf.draft_json["trigger"]["enabled"] is False and f"subject:{p['sid']}" in wf.draft_json["tags"]
    assert len(world["seen"]) == n                                                                  # installing a draft contacted no provider
    # a subject without a live authorization gets no proposal
    q = await person(api, classes=())
    await api.post(f"{B}/cases/{q['cid']}/notes", json={"body_markdown": "Install the DARK-04 template as a draft."})
    ev, _ = await chat(api, "Install the DARK-04 template as a draft", q["cid"])
    assert not [e for e in ev if e["type"] == "proposal"]
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(CopilotProposal)) == 1


def test_a_cloud_model_sees_counts_and_generic_text_only():
    r = {"subject": "Jane Example", "coverage": [{"identifier": "j***@example.com", "kind": "email", "state": "Match reported", "meaning": "m", "providers": []}],
         "incidents": [{"sources": ["hibp"], "categories": ["email addresses"], "events": [{"title": "Breach: Secret Forum"}]}], "unreviewed_incidents": 1, "caveat": "c", "notice": "n"}
    out = json.dumps(darkint_tools.cloud_view("darkint_summary", r))
    assert "Jane" not in out and "Secret Forum" not in out and "example.com" not in out and '"incident_count": 1' in out
