"""AI Automation Builder & Workflow Library acceptance tests (addendum A1.0, AUT-01 .. AUT-24). See docs/automation-builder.md for the mapping."""
from __future__ import annotations

import json

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.automations import catalog, handlers
from osintcc.automations.graph_validator import validate
from osintcc.automations.models import Definition
from osintcc.automations.registry import HANDLERS, SPECS
from osintcc.db.models import (
    AutomationNotification,
    AutomationSnapshot,
    AutomationTrigger,
    Evidence,
    Finding,
)
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import func, select

pytestmark = pytest.mark.usefixtures("_no_real_keyring")                       # these tests never touch the real credential store
B = "/api/v1/automations"
API = "/api/v1"


def make_api(settings, calls, adapters=None, fail_crt=False):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls, fail_crt)))
    return create_app(settings, adapters=adapters, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))


async def client_for(app, settings):
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {settings.session_token}"}, timeout=60)
    c.app = app
    return c


async def mk_case(api, title="Auto", purpose="automation tests", category="cyber"):
    return (await api.post(f"{API}/cases", json={"title": title, "purpose": purpose, "category": category})).json()["id"]


async def from_template(api, slug, case_id=None, **inputs):
    r = await api.post(f"{B}/from-template", json={"slug": slug, "case_id": case_id, "inputs": inputs})
    assert r.status_code == 201, r.text
    return r.json()


def wf_def(nodes, inputs=None, trigger=None, policy=None, key="test-wf"):
    return {"schema_version": 1, "workflow_key": key, "name": "Test workflow", "inputs": inputs if inputs is not None else {"domain": "example.com"}, "trigger": trigger or {"type": "manual"},
            "policy": policy or {}, "nodes": nodes}


def node(id, type, deps=(), **cfg):
    extra = {k: cfg.pop(k) for k in ("optional", "when", "run_on") if k in cfg}
    return {"id": id, "type": type, "depends_on": list(deps), "config": cfg, **extra}


SCOPE = node("scope", "authorization_check", target_ref="$inputs.domain")


def q(id, adapter, **kw):
    return node(id, "adapter_query", ["scope"], adapter=adapter, target_ref="$inputs.domain", **kw)


async def new_wf(api, definition, case_id=None):
    r = await api.post(f"{B}/workflows", json={"definition": definition, "case_id": case_id})
    assert r.status_code == 201, r.text
    return r.json()


async def publish(api, wid):
    r = await api.post(f"{B}/workflows/{wid}/publish")
    assert r.status_code == 201, r.text
    return r.json()


async def run_now(api, wid, case_id, **kw):
    r = await api.post(f"{B}/workflows/{wid}/run", json={"case_id": case_id, "wait": True, **kw})
    assert r.status_code == 202, r.text
    return r.json()


async def run_detail(api, rid):
    return (await api.get(f"{B}/runs/{rid}")).json()


# =============================================================================================== AUT-01 catalog
def test_exactly_the_30_catalog_templates_exist_with_the_specified_ids():
    keys = [t["key"] for t in catalog.load_all()]
    expect = (["CY-01", "CY-02", "CY-03", "CY-04", "CY-05", "CY-06", "CY-07", "ID-01", "ID-02", "ID-03", "ID-04", "ID-05", "ID-06", "CO-01", "CO-02", "CO-03", "CO-04", "CO-05",
               "GEO-01", "GEO-02", "GEO-03", "GEO-04", "GEO-05", "GEO-06", "CASE-01", "CASE-02", "CASE-03", "CASE-04", "CASE-05", "CASE-06"])
    assert sorted(keys) == sorted(expect) and len(keys) == 30


@pytest.mark.parametrize("t", catalog.load_all(), ids=lambda t: t["key"])
def test_every_template_is_schema_valid_disabled_and_documented(t, tmp_path):
    from osintcc.adapters.registry import default_adapters
    d = Definition.model_validate(t["definition"])
    assert d.trigger.enabled is False and d.status == "draft"
    rep = validate(t["definition"], default_adapters())
    assert rep["valid"], rep["errors"]
    for field in ("description", "legal_notes", "example_output", "quota_note", "instructions", "inputs", "catalog_trigger"):
        assert t[field] != "" and t[field] is not None, field
    assert t["maturity"] in catalog.MATURITY and t["fixture"]["inputs"] is not None
    assert set(t["dependencies"]) <= set(default_adapters())


def test_registry_and_handlers_describe_exactly_the_same_node_types():
    assert handlers.Ctx is not None and HANDLERS                              # importing handlers registers them
    assert set(SPECS) == set(HANDLERS)                                         # no node can claim a capability that has no runtime handler
    used = {n["type"] for t in catalog.load_all() for n in t["definition"]["nodes"]}
    assert used <= set(SPECS)


@pytest.mark.parametrize("t", catalog.load_all(), ids=lambda t: t["key"])
async def test_every_template_passes_its_fixture_dry_run_with_no_network_and_no_writes(api, calls, t):
    n_calls = len(calls)
    wf = await from_template(api, t["slug"])
    assert wf["state"] == "draft" and wf["definition"]["trigger"]["enabled"] is False
    r = await api.post(f"{B}/workflows/{wf['id']}/dry-run", json={})
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["run"]["state"] in ("completed", "completed_with_warnings"), json.dumps(j["run"]["summary"])[:800]
    assert j["run"]["dry_run"] and j["run"]["simulated"] and "SIMULATED" in j["label"]
    for nd in j["nodes"]:
        out = nd["output"] or {}
        assert nd["state"] in ("succeeded", "skipped"), nd
        if nd["state"] == "succeeded" and out:
            assert out.get("simulated", True) is not False
    assert len(calls) == n_calls                                               # a dry run contacts nothing
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == 0
        assert db.scalar(select(func.count()).select_from(Evidence)) == 0
        assert db.scalar(select(func.count()).select_from(AutomationSnapshot)) == 0
        assert db.scalar(select(func.count()).select_from(AutomationNotification)) == 0
        assert db.scalar(select(func.count()).select_from(AutomationTrigger)) == 0


@pytest.mark.parametrize("slug", ["cy-02-domain-change-watch", "co-03-sec-filing-monitor", "geo-05-sensor-health-monitor", "case-05-investigation-brief"])
async def test_watch_templates_show_new_and_changed_in_their_dry_run(api, slug):
    wf = await from_template(api, slug)
    j = (await api.post(f"{B}/workflows/{wf['id']}/dry-run", json={})).json()
    diff = next(n for n in j["nodes"] if n["node"] == "diff")
    assert diff["output"]["changed"] is True and (diff["output"].get("added_count", 0) + diff["output"].get("changed_count", 0)) > 0
    note = next((n for n in j["nodes"] if n["node"] in ("notify",)), None)
    assert note is None or note["output"]["sent"] is True


async def test_template_library_lists_availability_honestly_and_installs_disabled(api):
    j = (await api.get(f"{B}/templates")).json()
    assert j["total"] == 30 and all(t["installed_disabled"] for t in j["items"])
    by = {t["key"]: t for t in j["items"]}
    assert by["CY-01"]["availability"]["state"] == "ready"                                           # rdap, dns, crtsh are built in
    assert by["ID-01"]["availability"]["state"] == "setup_required"                                  # sherlock is not installed in tests
    assert any(m["adapter"] == "sherlock" and m["status"] == "not_installed" and m["setup"] for m in by["ID-01"]["availability"]["missing"])
    assert "opencorporates" in by["CO-01"]["availability"]["optional_missing"]                      # optional and keyed: reported, not hidden
    assert by["CY-04"]["availability"]["state"] in ("partial", "setup_required") and by["CY-04"]["capability_gaps"]
    assert by["CY-01"]["maturity"] == "runtime_tested"
    assert [t["key"] for t in (await api.get(f"{B}/templates", params={"category": "Corporate"})).json()["items"]] == ["CO-01", "CO-02", "CO-03", "CO-04", "CO-05"]
    assert (await api.get(f"{B}/templates", params={"q": "phishing"})).json()["total"] == 1
    d = (await api.get(f"{B}/templates/cy-01-domain-recon")).json()
    assert d["definition"]["nodes"] and d["inputs"] and d["legal_notes"]
    assert (await api.get(f"{B}/templates/nope")).status_code == 404


# =============================================================================================== runtime: real adapters (mocked network), 3 workflows end to end
async def test_cy01_domain_recon_runs_end_to_end_and_saves_cited_evidence(api, calls):
    cid = await mk_case(api)
    wf = await from_template(api, "cy-01-domain-recon", cid, domain="example.com")
    v = await publish(api, wf["id"])
    r = await run_now(api, wf["id"], cid)
    d = await run_detail(api, r["id"])
    assert d["state"] in ("completed", "completed_with_warnings"), d["summary_full"]
    nodes = {n["node"]: n for n in d["nodes"] if n["attempt"] == 1}
    assert nodes["scope"]["output"]["allowed"] and nodes["rdap"]["state"] == "succeeded" and nodes["dns"]["state"] == "succeeded" and nodes["crtsh"]["state"] == "succeeded"
    assert nodes["unique"]["output"]["count"] >= 5 and nodes["save"]["output"]["evidence_id"]
    assert any("rdap.example-registry.test" in c for c in calls) and any("crt.sh" in c for c in calls)
    assert d["version"]["revision"] == v["revision"] and d["version"]["hash"] == v["hash"]
    assert d["evidence_count"] > 0 and d["environment"]["platform"]
    with api.app.state.core.sm() as db:
        saved = db.get(Evidence, nodes["save"]["output"]["evidence_id"])
        assert saved.kind == "automation.dataset" and saved.case_id == cid and len(saved.sha256) == 64
        assert db.scalar(select(func.count()).select_from(Finding).where(Finding.case_id == cid)) >= 5
    # optional sources that are not installed are warnings, not fake results
    assert nodes["subfinder"]["state"] == "failed" and nodes["subfinder"]["error_code"] == "SOURCE_UNAVAILABLE"
    assert d["state"] == "completed_with_warnings" and any("subfinder" in w for w in d["summary"]["warnings"])


async def test_case01_and_id05_process_a_real_file_offline_and_withhold_restricted_values(api):
    cid = await mk_case(api)
    eml = (b"From: a@example.com\nTo: b@example.org\nSubject: hello\nDate: Tue, 02 Jan 2024 10:30:00 +0000\n\nbody")
    for slug in ("case-01-evidence-processing", "id-05-document-metadata"):
        wf = await from_template(api, slug, cid)
        await publish(api, wf["id"])
        r = await api.post(f"{B}/workflows/{wf['id']}/run-file", params={"filename": "m.eml", "case_id": cid, "consent_confirmed": True, "wait": True}, content=eml)
        assert r.status_code == 202, r.text
        d = await run_detail(api, r.json()["id"])
        assert d["state"] == "completed", d["summary_full"]
        ing = next(n for n in d["nodes"] if n["node"] == "ingest")
        assert ing["output"]["kind"] == "eml" and ing["output"]["count"] >= 1 and ing["output"]["evidence_id"]
    assert (await api.post(f"{B}/workflows/{wf['id']}/run-file", params={"filename": "m.eml", "case_id": cid}, content=eml)).status_code == 422       # consent first
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(Evidence).where(Evidence.case_id == cid, Evidence.kind == "import.eml")) == 1             # same bytes: one evidence item


async def test_case03_flags_a_duplicate_file(api):
    cid = await mk_case(api)
    wf = await from_template(api, "case-03-duplicate-finder", cid)
    await publish(api, wf["id"])
    eml = b"From: a@example.com\nTo: b@example.org\nSubject: dup\nDate: Tue, 02 Jan 2024 10:30:00 +0000\n\nbody"
    first = (await api.post(f"{B}/workflows/{wf['id']}/run-file", params={"filename": "d.eml", "case_id": cid, "consent_confirmed": True, "wait": True}, content=eml)).json()
    assert first["duplicate"] is False
    second = (await api.post(f"{B}/workflows/{wf['id']}/run-file", params={"filename": "d.eml", "case_id": cid, "consent_confirmed": True, "wait": True}, content=eml)).json()
    assert second["duplicate"] is True
    d = await run_detail(api, second["id"])
    assert next(n for n in d["nodes"] if n["node"] == "notify")["output"]["sent"] is True
    d1 = await run_detail(api, first["id"])
    assert next(n for n in d1["nodes"] if n["node"] == "notify")["output"]["sent"] is False


# =============================================================================================== AUT-02 missing tools and keys
async def test_missing_key_and_missing_tool_are_reported_and_never_produce_fake_results(api):
    cid = await mk_case(api)
    d = wf_def([SCOPE, q("vt", "virustotal"), node("save", "evidence_save", ["vt"], ref="$nodes.vt.output", title="x")])
    wf = await new_wf(api, d, cid)
    val = (await api.post(f"{B}/workflows/{wf['id']}/validate")).json()
    assert val["valid"] and any(w["code"] == "CREDENTIAL_MISSING" and "API key" in w["message"] for w in val["warnings"])
    await publish(api, wf["id"])
    r = await run_now(api, wf["id"], cid)
    det = await run_detail(api, r["id"])
    assert det["state"] == "failed" and det["error_code"] == "CREDENTIAL_MISSING"
    vt = next(n for n in det["nodes"] if n["node"] == "vt")
    assert vt["state"] == "failed" and vt["output"] is None and "virustotal" in (vt["diagnostics"].get("message") or "").lower()
    assert next(n for n in det["nodes"] if n["node"] == "save")["state"] == "skipped"
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == 0 and db.scalar(select(func.count()).select_from(Evidence).where(Evidence.kind == "automation.dataset")) == 0
    d2 = wf_def([SCOPE, q("x", "nmap")])
    r2 = await api.post(f"{B}/workflows", json={"definition": d2})
    assert r2.status_code == 201
    assert any(e["code"] == "UNSUPPORTED_ADAPTER" for e in (await api.post(f"{B}/workflows/{r2.json()['id']}/validate")).json()["errors"])
    assert (await api.post(f"{B}/workflows/{r2.json()['id']}/publish")).status_code == 422
