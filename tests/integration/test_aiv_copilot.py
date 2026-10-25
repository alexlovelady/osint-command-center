"""AIV-5: the Copilot may explain verification state and propose a DRAFT plan. It cannot authorize, approve or run anything."""
from __future__ import annotations

import json
import re

import pytest
from osintcc.ai.providers import FixtureProvider
from osintcc.copilot import aiv_tools
from osintcc.copilot.tools import ACTIONS, TOOLS
from osintcc.db.models import AivApproval, AivPlan, AivRun, AssetAuthorization, CopilotProposal
from osintcc.secrets_store import SecretStore
from sqlalchemy import func, select
from test_aiv_core import B, enable, mk_auth, mk_case, mk_plan


class FakeKeyring:
    def __init__(self):
        self.data = {}

    def get_password(self, s, u):
        return self.data.get((s, u))

    def set_password(self, s, u, p):
        self.data[(s, u)] = p

    def delete_password(self, s, u):
        self.data.pop((s, u), None)


@pytest.fixture(autouse=True)
def _no_real_keyring(monkeypatch):
    kr = FakeKeyring()
    monkeypatch.setattr(SecretStore, "_keyring", staticmethod(lambda: kr))


def tool_call(authorization_id, steps):
    body = json.dumps({"calls": [{"tool": "propose_aiv_plan", "args": {"authorization_id": authorization_id, "steps": steps}}]})
    return "```osintcc-tools\n" + body + "\n```"


async def chat(api, text, cid):
    r = await api.post(f"{B}/copilot/chat", json={"text": text, "mode": "investigation", "ctx": {"route": "case", "tab": "Verification", "case_id": cid}})
    assert r.status_code == 200, r.text
    ev = [json.loads(line) for line in r.text.splitlines() if line.strip()]
    return ev, next((e for e in ev if e["type"] == "final"), None)


async def noted_case(env):
    """A case with one stored note, so the model path runs (without stored records the Copilot answers 'not documented' and never consults a model)."""
    cid = await mk_case(env)
    r = await env["api"].post(f"{B}/cases/{cid}/notes", json={"body_markdown": "Prepare a plan: a TLS check plan for the lab host before the audit."})
    assert r.status_code in (200, 201), r.text
    return cid


async def enable_ai(api, provider):
    api.app.state.core.ai_factory = lambda p: provider
    await api.post(f"{B}/ai/profiles", json={"name": "fx", "provider_type": "fixture", "model_id": "fixture-1"})
    await api.put(f"{B}/settings", json={"values": {"ai_enabled": True}})


def test_there_is_no_tool_that_authorizes_approves_or_runs():
    assert sorted(n for n in TOOLS if "aiv" in n) == sorted(["aiv_status", "explain_aiv_plan", "explain_aiv_observation", "propose_aiv_plan"])
    assert not [n for n in TOOLS if re.search(r"approve|authori[sz]e|run_aiv|start_aiv|revoke|widen|attest", n)]
    assert {n for n in ACTIONS if "aiv" in n} == {"propose_aiv_plan"}


async def test_status_and_plan_explanations_need_no_model_and_are_honest(env):
    api = env["api"]
    cid = await mk_case(env)
    _, final = await chat(api, "What is the verification status of this case?", cid)
    assert "switched off" in final["text"] and "Nothing active can run" in final["text"]
    await enable(env)
    lb = await env["lab"]()
    a = await mk_auth(env, cid, ["lab.test"], [lb.port], classes=("tls_handshake", "tcp_connect"))
    p = await mk_plan(env, cid, a["id"], [{"kind": "tls_handshake", "host": "lab.test", "port": lb.port}, {"kind": "tcp_connect", "host": "lab.test", "ports": [lb.port]}])
    _, final = await chat(api, "What is the active verification status?", cid)
    assert "1 live of 1" in final["text"] and "1 draft" in final["text"]
    _, final = await chat(api, "Explain this verification plan", cid)
    t = final["text"]
    assert "TLS connection" in t and "plain TCP connection" in t and "never" in t.lower() and "approve this exact plan" in t and "I cannot approve or run it" in t
    assert lb.connections == 0 and p["status"] == "draft"                                  # explaining sent nothing


async def test_a_proposal_stores_only_a_draft_after_approval_and_sends_nothing(env):
    api = env["api"]
    await enable(env)
    lb = await env["lab"]()
    cid = await noted_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port], classes=("tls_handshake",))
    call = tool_call(a["id"], [{"kind": "tls_handshake", "host": "lab.test", "port": lb.port}])
    await enable_ai(api, FixtureProvider(script=lambda m: "I prepared a draft plan for your review. " + call))
    ev, _ = await chat(api, "Prepare a TLS check plan for the lab host", cid)
    prop = next(e["proposal"] for e in ev if e["type"] == "proposal")
    assert prop["tool"] == "propose_aiv_plan" and "DRAFT plan only" in prop["preview"]["stores"]
    with env["st"].sm() as db:
        assert db.scalar(select(func.count()).select_from(AivPlan)) == 0                     # a proposal is not a plan
    r = await api.post(f"{B}/copilot/proposals/{prop['id']}/approve", json={"confirm": True})
    assert r.status_code == 200, r.text
    with env["st"].sm() as db:
        plan = db.scalars(select(AivPlan)).one()
        assert plan.status == "draft" and plan.created_by.startswith("copilot:") and plan.steps_json[0]["kind"] == "tls_handshake"
        assert db.scalar(select(func.count()).select_from(AivApproval)) == 0 and db.scalar(select(func.count()).select_from(AivRun)) == 0
        assert db.scalar(select(func.count()).select_from(AssetAuthorization)) == 1           # no authorization was created or changed
    assert lb.connections == 0


@pytest.mark.parametrize("steps", [
    [{"kind": "tcp_connect", "host": "lab.test", "ports": [1]}],
    [{"kind": "tls_handshake", "host": "other.test", "port": 443}],
    [{"kind": "http_metadata", "url": "http://lab.test/", "method": "GET"}],
    [{"kind": "shell", "command": "nmap -A x"}],
])
async def test_out_of_scope_or_malformed_proposals_are_refused_with_no_card(env, steps):
    api = env["api"]
    await enable(env)
    lb = await env["lab"]()
    cid = await noted_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port], classes=("tls_handshake",))
    await enable_ai(api, FixtureProvider(script=lambda m: "Here you go. " + tool_call(a["id"], steps)))
    ev, _ = await chat(api, "Prepare a plan", cid)
    assert not [e for e in ev if e["type"] == "proposal"] and "not proposed" in json.dumps(ev).lower()
    with env["st"].sm() as db:
        assert db.scalar(select(func.count()).select_from(CopilotProposal)) == 0
    assert lb.connections == 0


async def test_proposals_are_refused_for_another_cases_authorization_and_while_verification_is_off(env):
    api = env["api"]
    cid, other = await noted_case(env), await noted_case(env)
    await enable(env)
    lb = await env["lab"]()
    a = await mk_auth(env, other, ["lab.test"], [lb.port], classes=("tls_handshake",))
    await enable_ai(api, FixtureProvider(script=lambda m: "Plan. " + tool_call(a["id"], [{"kind": "tls_handshake", "host": "lab.test", "port": lb.port}])))
    ev, _ = await chat(api, "Prepare a plan", cid)
    assert not [e for e in ev if e["type"] == "proposal"] and "authorization of this case" in json.dumps(ev)
    assert (await api.put(f"{B}/aiv/settings", json={"enabled": False})).status_code == 200
    ev, _ = await chat(api, "Prepare a plan", other)
    assert not [e for e in ev if e["type"] == "proposal"] and "switched off" in json.dumps(ev)


def test_a_cloud_model_sees_counts_and_generic_text_only():
    explained = {"plan_id": "p" * 32, "status": "draft", "version": 1, "hash": "h" * 16, "steps": [{"index": 0, "kind": "tls_handshake", "what_happens": "Open one TLS connection to secret-host.example:443"}],
                 "authorization": {"scope": ["secret-host.example"]}, "approval_needed": "A person must approve."}
    out = json.dumps(aiv_tools.cloud_view("explain_aiv_plan", explained))
    assert "secret-host" not in out and '"step_count": 1' in out
    obs = {"observations": [{"asset": "secret-host.example", "title": "Header missing", "evidence_id": "e" * 32}], "not_proof": "x"}
    assert "secret-host" not in json.dumps(aiv_tools.cloud_view("explain_aiv_observation", obs))
