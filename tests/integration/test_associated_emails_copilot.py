"""Associated Email addendum, section 6: the Copilot explains, plans and proposes with real citations; it cannot confirm, reject, widen or start sensitive checks."""
from __future__ import annotations

import json
import re

from osintcc.ai.providers import FixtureProvider
from osintcc.copilot import email_tools
from osintcc.copilot.tools import ACTIONS, TOOLS
from osintcc.db.models import CopilotProposal, ResearchTask
from sqlalchemy import func, select
from test_associated_emails import (
    B,
    _no_real_keyring,  # noqa: F401  (fixture)
    api,  # noqa: F401  (fixture)
    by_addr,
    discover_via_github_and_page,
    listing,
    make,
    world,  # noqa: F401  (fixture)
)


async def chat(api, text, cid):
    r = await api.post(f"{B}/copilot/chat", json={"text": text, "mode": "investigation", "ctx": {"route": "case", "tab": "Profile", "case_id": cid}})
    assert r.status_code == 200, r.text
    ev = [json.loads(line) for line in r.text.splitlines() if line.strip()]
    return ev, next((e for e in ev if e["type"] == "final"), None)


async def enable_ai(api, provider):
    api.app.state.core.ai_factory = lambda p: provider
    await api.post(f"{B}/ai/profiles", json={"name": "fx", "provider_type": "fixture", "model_id": "fixture-1"})
    await api.put(f"{B}/settings", json={"values": {"ai_enabled": True}})


def test_no_tool_can_confirm_reject_merge_or_promote_an_address():
    names = [n for n in TOOLS if n in ("associated_emails_summary", "plan_cross_int", "propose_expansion_run")]
    assert len(names) == 3
    assert not [n for n in TOOLS if re.search(r"confirm|reject|merge|promote|attest|verify_email", n)]
    assert {n for n in ACTIONS if "expansion" in n} == {"propose_expansion_run"}


async def test_summary_separates_facts_hypotheses_and_rejected_and_cites_real_evidence(api, world):
    p = await make(api, kinds=("email", "username", "url"))
    _, empty = await chat(api, "Which associated emails do we have?", p["cid"])
    assert "None yet" in empty["text"] and "not a fact" in empty["text"]
    await discover_via_github_and_page(api, p)
    j = await listing(api, p)
    work, press = by_addr(j, "jane.work@acme-example.com"), by_addr(j, "press@jane-example.org")
    await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [work["id"]], "to_state": "confirmed", "basis": "owner told me", "attestation": "subject"})
    await api.post(f"{B}/subjects/{p['sid']}/associated-emails/review", json={"ids": [press["id"]], "to_state": "rejected", "basis": "a shared press inbox"})
    _, final = await chat(api, "Which associated emails do we have?", p["cid"])
    t = final["text"]
    assert "Confirmed by a person** (1)" in t and "Hypotheses (not facts)" in t and "Rejected matches** (1)" in t
    assert "jane.work@acme-example.com" in t and "Confirmed" in t and "Evidence `" in t
    cited = {c["id"] for c in final["profile_citations"]}
    assert cited and cited <= {e["id"] for e in work["evidence"]} | {e["id"] for i in j["items"] for e in i["evidence"]}      # every citation is a real record of this case
    assert "fabricat" not in t.lower()


async def test_the_example_request_gets_a_scoped_plan_with_approvals_marked(api, world):
    p = await make(api, kinds=("email", "username", "url"), classes=("public_passive", "public_site_query", "exposure_check"))
    q = ("Starting with this authorized email address, investigate associated public accounts, identify other evidence-backed contact addresses, correlate findings across available "
         "intelligence disciplines, assess permitted exposure indicators, and recommend the next investigative steps.")
    _, final = await chat(api, q, p["cid"])
    t = final["text"]
    assert "Cross-INT plan" in t and "Ready to run" in t and "Needs a person first" in t
    assert "DARKINT" in t and "explicit approval" in t and "AIV" not in t.replace("Active verification", "") or "Active verification" in t
    assert not [u for u in world["seen"] if "haveibeenpwned" in u]                                       # planning contacts nothing


async def test_a_proposal_runs_one_bounded_passive_pass_after_approval_and_nothing_more(api, world):
    p = await make(api, kinds=("email", "username", "url"))
    key = f"{p['ids']['url']}:page_contacts"
    call = "```osintcc-tools\n" + json.dumps({"calls": [{"tool": "propose_expansion_run", "args": {"keys": [key]}}]}) + "\n```"
    await api.post(f"{B}/cases/{p['cid']}/notes", json={"body_markdown": "Run the contact page check for the public site."})
    await enable_ai(api, FixtureProvider(script=lambda m: "I prepared a bounded research pass. " + call))
    ev, _ = await chat(api, "Run the contact page check for the public site", p["cid"])
    prop = next(e["proposal"] for e in ev if e["type"] == "proposal")
    assert prop["tool"] == "propose_expansion_run" and prop["preview"]["steps"][0]["source"] == "Public page contact addresses" and "once" in prop["preview"]["note"]
    n = len(world["seen"])
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(ResearchTask)) == 0                              # a proposal runs nothing
    r = await api.post(f"{B}/copilot/proposals/{prop['id']}/approve", json={"confirm": True})
    assert r.status_code == 200, r.text
    await api.app.state.core.runner.run_until_idle(next(iter([t.run_id for t in _tasks(api)])))
    assert len(world["seen"]) > n and all(u.startswith("https://jane-example.org/") for u in world["seen"][n:])
    j = await listing(api, p)
    assert j["counts"]["confirmed"] == 0 and j["items"] and all(i["state"] == "candidate" for i in j["items"])    # the pass found candidates, it confirmed nothing


def _tasks(api):
    with api.app.state.core.sm() as db:
        return list(db.scalars(select(ResearchTask)))


async def test_a_proposal_is_refused_when_authorization_is_gone_or_a_step_needs_its_own_approval(api, world):
    p = await make(api, kinds=("email", "username", "url"))
    await api.post(f"{B}/cases/{p['cid']}/notes", json={"body_markdown": "Run the contact page check for the public site."})
    bad = "```osintcc-tools\n" + json.dumps({"calls": [{"tool": "propose_expansion_run", "args": {"keys": [f"{p['ids']['email']}:darkint"]}}]}) + "\n```"
    await enable_ai(api, FixtureProvider(script=lambda m: "Here. " + bad))
    ev, _ = await chat(api, "Run the contact page check for the public site", p["cid"])
    assert not [e for e in ev if e["type"] == "proposal"] and "not proposed" in json.dumps(ev).lower()       # an exposure check is never started from an expansion proposal
    assert (await api.post(f"{B}/subjects/{p['sid']}/consent/revoke", json={"consent_id": p["consent"], "reason": "withdrawn"})).status_code == 200
    good = "```osintcc-tools\n" + json.dumps({"calls": [{"tool": "propose_expansion_run", "args": {}}]}) + "\n```"
    api.app.state.core.ai_factory = lambda pr: FixtureProvider(script=lambda m: "Here. " + good)
    ev, _ = await chat(api, "Run the contact page check for the public site", p["cid"])
    assert not [e for e in ev if e["type"] == "proposal"] and "stopped" in json.dumps(ev).lower()
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(CopilotProposal)) == 0


def test_a_cloud_model_sees_counts_and_generic_text_only():
    r = {"verified": [{"address": "j***@acme-example.com"}], "hypotheses": [], "rejected": [], "gaps": ["x"], "caveat": "c"}
    out = json.dumps(email_tools.cloud_view("associated_emails_summary", r))
    assert "acme" not in out and '"confirmed": 1' in out
    plan = {"next": [{"on": "janedoe"}], "needs_a_person": [], "blocked": [], "stop_reason": "", "caveat": "c"}
    assert "janedoe" not in json.dumps(email_tools.cloud_view("plan_cross_int", plan))
