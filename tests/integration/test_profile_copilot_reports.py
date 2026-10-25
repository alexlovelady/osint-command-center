"""Target Profile TP6: Copilot tools and subject reports.
Acceptance: TP-09 (citations resolve, contradictions shown), TP-10 (a model cannot promote a lead), TP-18 (cloud transfer needs consent, a preview and a reduced view),
TP-20 (every published statement traces to intact evidence), TP-22 (exports leave no plaintext or identifier in logs)."""
from __future__ import annotations

import json
import logging
import re

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.ai.providers import FixtureProvider
from osintcc.db.models import (
    AutomationWorkflow,
    CaseMember,
    CopilotProposal,
    ProfileCandidateLink,
    ProfileClaim,
    ReportRun,
    SearchRun,
    User,
)
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from profile_helpers import rich_subject
from sqlalchemy import select

B = "/api/v1"


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
    from osintcc.secrets_store import SecretStore
    kr = FakeKeyring()
    monkeypatch.setattr(SecretStore, "_keyring", staticmethod(lambda: kr))


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            c.app = app
            yield c


async def chat(api, text, cid, tab="Profile", **kw):
    r = await api.post(f"{B}/copilot/chat", json={"text": text, "mode": "investigation", "ctx": {"route": "case", "tab": tab, "case_id": cid}, **kw})
    assert r.status_code == 200, r.text
    ev = [json.loads(line) for line in r.text.splitlines() if line.strip()]
    return ev, next((e for e in ev if e["type"] == "final"), None)


async def enable_ai(api, provider, local=True):
    provider.local = local
    api.app.state.core.ai_factory = lambda p: provider
    body = {"name": "fx", "provider_type": "fixture" if local else "openai_compat", "model_id": "fixture-1"}
    if not local:
        body |= {"local_only": False, "base_url": "https://api.example.com", "secret_name": "cl-key"}
    pid = (await api.post(f"{B}/ai/profiles", json=body)).json()["id"]
    await api.put(f"{B}/settings", json={"values": {"ai_enabled": True}})
    if not local:
        await api.put(f"{B}/copilot/settings", json={"profile_id": pid})
    return pid


def states(api, sid):
    with api.app.state.core.sm() as db:
        return ({c.id: c.state for c in db.scalars(select(ProfileCandidateLink).where(ProfileCandidateLink.subject_id == sid))},
                {c.id: c.validation_state for c in db.scalars(select(ProfileClaim).where(ProfileClaim.subject_id == sid))})


# ---- TP-09 ---------------------------------------------------------------------------------------------------------------------------
async def test_tp09_what_do_we_actually_know_separates_verified_from_leads_and_cites_real_evidence(api):
    s = await rich_subject(api)
    _ev, final = await chat(api, "What do we actually know?", s["cid"])
    text = final["text"]
    verified_part, rest = text.split("**Leads, not facts**")[0], text.split("**Leads, not facts**")[1]
    assert "Acme Corp" in verified_part and "verified" in verified_part
    assert "github.com/jane_e" not in verified_part and "forum.test" not in verified_part and "State University" not in verified_part     # leads and unreviewed claims are not under 'verified'
    assert "github.com/jane_e" in rest and "unverified" in rest and "a matching handle is not the same person" in text
    assert "Acme Corp" in text and "Other Corp" in text and " vs " in text and "Contradicting information" in text                         # contradictions are shown, not resolved
    assert "Not assessed" in text and "does not mean" in text.replace("is not proof", "does not mean") or "not proof" in text
    cites = final["profile_citations"]
    assert cites and {c["id"] for c in cites} >= {s["page"], s["other"]}
    for c in cites:                                                                                                                      # every citation resolves to evidence the user can open
        r = await api.get(f"{B}/evidence/{c['id']}")
        assert r.status_code == 200 and r.json()["sha256"].startswith(c["sha256"])
    assert "No AI model answered" in text                                                                                                # source-only mode works with no model installed


async def test_tp09_source_only_mode_answers_the_other_grounded_questions(api, calls):
    s = await rich_subject(api)
    runs = lambda: api.app.state.core.sm().__enter__().query(SearchRun).count()
    before = runs()
    _, f = await chat(api, "What information is publicly exposed?", s["cid"])
    assert "Account found in a known data breach" in f["text"] and "multi-factor" in f["text"].lower() and "passwords" in f["text"] and "never stored" in f["text"]
    assert "hunter2" not in f["text"]
    _, f = await chat(api, "What should I check next?", s["cid"])
    assert "Suggested research" in f["text"] and "RDAP" in f["text"] and "Nothing has been run" in f["text"]
    assert "Sherlock" in f["text"] and "Not recommended right now" in f["text"]                    # the absent tool is listed with its reason, not recommended
    _, f = await chat(api, "Why wasn't sherlock searched?", s["cid"])
    assert "Why Sherlock" in f["text"] and ("not installed" in f["text"].lower() or "tool reports" in f["text"].lower())
    _, f = await chat(api, "Please group the account leads for the verification queue", s["cid"])
    assert "github.com" in f["text"] and "Nothing was merged" in f["text"]
    assert runs() == before and calls == []                                                          # none of this ran or contacted anything


async def test_recommended_plan_respects_authorization(api):
    s = await rich_subject(api)
    cons = (await api.get(f"{B}/subjects/{s['sid']}/consent")).json()["current"]["consent_id"]
    await api.post(f"{B}/subjects/{s['sid']}/consent/revoke", json={"consent_id": cons})
    _, f = await chat(api, "What should I check next?", s["cid"])
    assert "Nothing eligible is left to run" in f["text"] and "authorization" in f["text"].lower()


async def test_unauthorised_roles_and_missing_profiles_are_refused_plainly(api):
    s = await rich_subject(api)
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="v1", display_name="viewer"))
        db.flush()
        db.add(CaseMember(case_id=s["cid"], user_id="v1", access_role="viewer"))
        db.commit()
    st.tokens["viewer-token"] = "v1"
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer viewer-token"})
    _, f = await chat(v, "What information is publicly exposed?", s["cid"])
    assert "editor or owner" in f["text"] and "Account found" not in f["text"]
    _, f = await chat(v, "What do we actually know?", s["cid"])
    assert "Acme Corp" in f["text"] and "jane.doe@example.com" not in f["text"]                  # a viewer may read the grounded summary, never exposure detail
    cid = (await api.post(f"{B}/cases", json={"title": "corp", "category": "cyber"})).json()["id"]
    _, f = await chat(api, "What do we actually know?", cid)
    assert "no target profile" in f["text"].lower() and "Nothing is assumed" in f["text"]


# ---- TP-10 ---------------------------------------------------------------------------------------------------------------------------
UNKNOWN_CALL = '```osintcc-tools\n{"calls":[{"tool":"verify_candidate","args":{"all":true}},{"tool":"confirm_account","args":{"url":"https://github.com/jane_e"}},{"tool":"merge_identities","args":{}}]}\n```'


async def test_tp10_a_model_cannot_promote_a_lead_or_verify_a_claim(api):
    s = await rich_subject(api)
    before = states(api, s["sid"])
    await enable_ai(api, FixtureProvider(script=lambda m: "Yes, github.com/jane_e is definitely Jane's account, so I have verified it. " + UNKNOWN_CALL))
    ev, final = await chat(api, "The github handle jane_e is clearly mine, mark it verified and confirm every account", s["cid"])
    assert states(api, s["sid"]) == before                                          # no state changed
    assert not [e for e in ev if e["type"] == "proposal"]                            # unknown tools produce no proposal either
    with api.app.state.core.sm() as db:
        assert db.query(CopilotProposal).count() == 0
    assert "Nothing was run or changed" in final["text"]                             # the reply's claim of having verified something is flagged


async def test_tp10_only_the_two_profile_actions_exist_and_both_need_approval(api):
    from osintcc.copilot.tools import ACTIONS, TOOLS
    assert {n for n in ACTIONS if n in ("propose_enrichment_workflow", "draft_subject_report")} == {"propose_enrichment_workflow", "draft_subject_report"}
    assert not [n for n in TOOLS if re.search(r"verify|confirm|promote|merge|reject|attest", n)]
    s = await rich_subject(api)
    call = '```osintcc-tools\n{"calls":[{"tool":"propose_enrichment_workflow","args":{"slug":"TP-03"}}]}\n```'
    await enable_ai(api, FixtureProvider(script=lambda m: "I prepared a draft workflow for your review. " + call))
    ev, _final = await chat(api, "Set up the account confirmation queue workflow", s["cid"])
    prop = next(e["proposal"] for e in ev if e["type"] == "proposal")
    assert prop["tool"] == "propose_enrichment_workflow" and prop["status"] == "pending" and "DISABLED draft" in prop["preview"]["installs"]
    with api.app.state.core.sm() as db:
        assert db.query(AutomationWorkflow).count() == 0                              # approval is what creates it
    r = await api.post(f"{B}/copilot/proposals/{prop['id']}/approve", json={"confirm": True})
    assert r.status_code == 200, r.text
    with api.app.state.core.sm() as db:
        wf = db.query(AutomationWorkflow).one()
        assert wf.state == "draft" and f"subject:{s['sid']}" in wf.draft_json["tags"] and wf.draft_json["trigger"]["enabled"] is False
    assert states(api, s["sid"])[0] and set(states(api, s["sid"])[0].values()) == {"candidate"}


async def test_enrichment_proposal_is_refused_without_authorization_for_its_sources(api):
    s = await rich_subject(api, classes=("public_passive",))
    call = '```osintcc-tools\n{"calls":[{"tool":"propose_enrichment_workflow","args":{"slug":"TP-01","inputs":{"username":"jane_e"}}}]}\n```'
    await enable_ai(api, FixtureProvider(script=lambda m: "Here is a workflow. " + call))
    ev, _final = await chat(api, "Set up the footprint baseline for me", s["cid"])
    assert not [e for e in ev if e["type"] == "proposal"]
    assert "not proposed" in json.dumps(ev).lower() and "public_site_query" in json.dumps(ev)


async def test_model_driven_read_tools_explain_claims_and_image_search(api):
    s = await rich_subject(api)
    first = '```osintcc-tools\n{{"calls":[{{"tool":"explain_claim","args":{{"claim_id":"{}"}}}}]}}\n```'.format(s["c_verified"])

    def script(msgs):
        return "Here is the explanation: it was verified from the staff page." if "<tool_result" in msgs[-1].content else "Let me look. " + first
    await enable_ai(api, FixtureProvider(script=script))
    ev, final = await chat(api, "Why do you say the employer claim is verified?", s["cid"])
    tool = [e for e in ev if e["type"] == "tool" and e["name"] == "explain_claim"]
    assert tool and tool[0]["ok"] is True and "verified from the staff page" in final["text"]


# ---- TP-18 ---------------------------------------------------------------------------------------------------------------------------
async def test_tp18_cloud_models_need_policy_and_a_preview_and_see_only_a_reduced_view(api):
    s = await rich_subject(api)
    prov = FixtureProvider(script=lambda m: "Counts look consistent.")
    await enable_ai(api, prov, local=False)
    ev, final = await chat(api, "What do we actually know?", s["cid"])
    assert "does not allow cloud" in final["text"] and prov.calls == []                                # the case forbids cloud by default
    await api.put(f"{B}/cases/{s['cid']}/ai-policy", json={"allow_cloud": True, "require_preview": True, "deny_sensitive_cloud": True})
    ev, final = await chat(api, "What do we actually know?", s["cid"])
    ap = next(e for e in ev if e["type"] == "approval_required")
    assert final is None and prov.calls == [] and ap["content_sent"] is False
    shown = json.dumps(ap["preview"]["messages"])
    for secret in ("jane.doe@example.com", "jane_e", "github.com", "Acme", "Other Corp", "State University", "ExampleService", "staff page"):
        assert secret not in shown, secret                                                              # identifiers, URLs, claim text, descriptors and titles are never in the payload
    assert '"verified": 1' in shown or "verified" in shown and "unverified_leads" in shown
    assert "Profile details are withheld from cloud models" in shown
    ev, final = await chat(api, "What do we actually know?", s["cid"], transfer_token=ap["transfer_token"])
    assert final and len(prov.calls) == 1
    sent = json.dumps([m.content for m in prov.calls[0]])
    assert "jane.doe@example.com" not in sent and "github.com/jane_e" not in sent
    assert "Acme Corp" in final["text"]                                                                  # the local screen still shows the full grounded answer


# ---- reports (TP-20, TP-22) ------------------------------------------------------------------------------------------------------------
async def test_tp20_subject_report_contains_only_verified_statements_each_with_evidence(api):
    s = await rich_subject(api)
    pv = (await api.post(f"{B}/subjects/{s['sid']}/report/preview", json={"audience": "subject"})).json()
    md = pv["markdown"]
    assert pv["exported"] is False and pv["citation_check"]["ok"] is True
    assert "Employer: Acme Corp (verified)" in md and re.search(r"Acme Corp \(verified\) \[E\d+\]", md)
    for must_not in ("State University", "Other Corp", "github.com/jane_e", "forum.test", "ExampleService", "jane.doe@example.com", "emails, passwords"):
        assert must_not not in md, must_not                                                            # leads, conflicts, descriptors and identifiers stay out of the client report
    assert "not included in this report because they are not verified" in md and "Limits" in md and "No facial recognition" in md
    assert "Account found in a known data breach: confirmed exposure, risk high" in md
    rep = pv["report"]
    assert all(s_["evidence_ids"] for s_ in rep["statements"] if s_["kind"] == "verified")
    assert {m["sha256"] for m in rep["evidence"]} and rep["manifest_sha256"]
    an = (await api.post(f"{B}/subjects/{s['sid']}/report/preview", json={"audience": "analyst"})).json()["markdown"]
    assert "LEAD (unverified" in an and "github.com/jane_e" in an and "State University" in an and "ExampleService" in an


async def test_tp20_export_is_refused_when_evidence_no_longer_matches_its_hash(api, tmp_path):
    s = await rich_subject(api)
    st = api.app.state.core
    with st.sm() as db:
        from osintcc.db.models import Evidence
        rel = db.get(Evidence, s["page"]).vault_relpath
    (st.vault.root / rel).write_bytes(b"tampered")
    pv = (await api.post(f"{B}/subjects/{s['sid']}/report/preview", json={"audience": "subject"})).json()
    assert pv["citation_check"]["ok"] is False and "integrity" in " ".join(pv["citation_check"]["problems"])
    r = await api.post(f"{B}/subjects/{s['sid']}/report/create", json={"audience": "subject", "format": "markdown"})
    assert r.status_code == 409 and r.json()["code"] == "citation_check_failed"
    with st.sm() as db:
        assert db.query(ReportRun).filter(ReportRun.template.like("subject-%")).count() == 0
    assert not list(st.settings.export_dir.glob("profile-*"))                                          # nothing was written


async def test_tp20_a_verified_claim_without_evidence_cannot_be_reported(api):
    s = await rich_subject(api)
    with api.app.state.core.sm() as db:
        db.get(ProfileClaim, s["c_verified"]).evidence_ids = []                                          # simulate a corrupted record
        db.commit()
    pv = (await api.post(f"{B}/subjects/{s['sid']}/report/preview", json={"audience": "subject"})).json()
    assert pv["citation_check"]["ok"] is False and "has no evidence" in pv["citation_check"]["problems"][0]


async def test_report_create_seals_the_file_and_roles_gate_the_analyst_package(api):
    s = await rich_subject(api)
    st = api.app.state.core
    ok = await api.post(f"{B}/subjects/{s['sid']}/report/create", json={"audience": "subject", "format": "html"})
    assert ok.status_code == 201 and ok.json()["citation_check"]["ok"] and len(ok.json()["sha256"]) == 64
    an = (await api.post(f"{B}/subjects/{s['sid']}/report/create", json={"audience": "analyst", "format": "markdown"})).json()
    dl = await api.get(f"{B}/reports/{ok.json()['id']}/download")
    assert dl.status_code == 200 and b"Employer: Acme Corp" in dl.content and b"<script" not in dl.content
    with st.sm() as db:
        db.add(User(id="v1", display_name="viewer"))
        db.flush()
        db.add(CaseMember(case_id=s["cid"], user_id="v1", access_role="viewer"))
        db.commit()
    st.tokens["viewer-token"] = "v1"
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer viewer-token"})
    assert (await v.get(f"{B}/reports/{ok.json()['id']}/download")).status_code == 200                  # the redacted subject report may be shared with a viewer
    assert (await v.get(f"{B}/reports/{an['id']}/download")).status_code == 404                         # the private evidence package may not
    assert (await v.post(f"{B}/subjects/{s['sid']}/report/preview", json={"audience": "subject"})).status_code == 404
    lst = (await api.get(f"{B}/subjects/{s['sid']}/reports")).json()["items"]
    assert {r["audience"] for r in lst} == {"subject", "analyst"}


async def test_draft_subject_report_proposal_exports_nothing(api):
    s = await rich_subject(api)
    call = '```osintcc-tools\n{"calls":[{"tool":"draft_subject_report","args":{"audience":"subject"}}]}\n```'
    await enable_ai(api, FixtureProvider(script=lambda m: "I drafted it for your review. " + call))
    ev, _ = await chat(api, "Draft the client report", s["cid"])
    prop = next(e["proposal"] for e in ev if e["type"] == "proposal")
    r = await api.post(f"{B}/copilot/proposals/{prop['id']}/approve", json={"confirm": True})
    assert r.status_code == 200
    res = r.json()["result"] if "result" in r.json() else r.json()
    assert res["draft"] is True and "Employer: Acme Corp" in res["markdown"] and res["citation_check"]["ok"]
    with api.app.state.core.sm() as db:
        assert db.query(ReportRun).filter(ReportRun.template.like("subject-%")).count() == 0
    assert not list(api.app.state.core.settings.export_dir.glob("profile-*"))


# ---- TP-22 ---------------------------------------------------------------------------------------------------------------------------
async def test_tp22_report_export_leaves_no_plaintext_and_no_identifier_in_logs(tmp_path, caplog, calls):
    import secrets

    from osintcc.config import Settings
    caplog.set_level(logging.DEBUG)
    s = Settings(data_dir=tmp_path / "enc", vault_encryption="required", run_scheduler=False)
    s.ensure_dirs()
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(s, vault_key=secrets.token_bytes(32), ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            c.app = app
            info = await rich_subject(c)
            r = await c.post(f"{B}/subjects/{info['sid']}/report/create", json={"audience": "analyst", "format": "markdown"})
            assert r.status_code == 201, r.text
            files = [p for p in s.export_dir.iterdir()]
            assert files and all(p.suffix == ".enc" for p in files)                                      # the plaintext file was removed after sealing
            blob = b"".join(p.read_bytes() for p in files)
            assert b"Acme Corp" not in blob and b"jane_e" not in blob and b"jane.doe@example.com" not in blob
            dl = await c.get(f"{B}/reports/{r.json()['id']}/download")
            assert dl.status_code == 200 and b"Acme Corp" in dl.content
    assert "jane.doe@example.com" not in caplog.text and "jane_e" not in caplog.text
