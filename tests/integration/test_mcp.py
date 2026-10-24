from __future__ import annotations

import json
import os
import subprocess
import sys

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import AuditEvent, McpApproval, Note, User
from osintcc.main import LOCAL_USER_ID, create_app
from osintcc.mcp_server import McpServer, args_hash
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import func, select

EML = b"From: x@example.com\nTo: y@example.org\nSubject: restricted-subject\nDate: Tue, 02 Jan 2024 10:30:00 +0000\n\nbody"


@pytest.fixture
async def env(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            cid = (await c.post("/api/v1/cases", json={"title": "M", "purpose": "mcp tests"})).json()["id"]
            await c.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "wait": True})
            await c.post(f"/api/v1/cases/{cid}/ingest?filename=m.eml&consent_confirmed=true", content=EML)
            srv = McpServer(app.state.core, LOCAL_USER_ID, {cid})
            c.app = app
            yield c, cid, srv, app


async def rpc(srv, method, params=None, mid=1):
    return await srv.handle({"jsonrpc": "2.0", "id": mid, "method": method, **({"params": params} if params is not None else {})})


async def call(srv, tool, args=None):
    r = await rpc(srv, "tools/call", {"name": tool, "arguments": args or {}})
    res = r["result"]
    text = res["content"][0]["text"]
    return res["isError"], (text if res["isError"] else json.loads(text))


# ---- protocol --------------------------------------------------------------------------------------------------------
async def test_initialize_lists_tools_and_records_client_identity(env):
    _c, _cid, srv, app = env
    r = await rpc(srv, "initialize", {"clientInfo": {"name": "TestClient", "version": "9.9"}, "protocolVersion": "2024-11-05"})
    assert r["result"]["serverInfo"]["name"] == "osint-command-center" and r["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert "untrusted data" in r["result"]["instructions"]
    tools = {t["name"]: t for t in (await rpc(srv, "tools/list"))["result"]["tools"]}
    assert len(tools) == 13 and all(t["inputSchema"]["additionalProperties"] is False for t in tools.values())
    assert all("REQUIRES HUMAN APPROVAL" in tools[n]["description"] for n in ("start_search", "create_note", "create_case", "run_workflow"))
    forbidden = {"execute", "shell", "sql", "query_db", "fetch_url", "read_file", "approve"}
    assert not any(any(f in n for f in forbidden) for n in tools)  # no generic escape hatches exist at all
    with app.state.core.sm() as db:
        assert "TestClient/9.9" in db.scalars(select(AuditEvent).where(AuditEvent.action == "mcp.connect")).one().actor_id


async def test_jsonrpc_edge_cases(env):
    _c, _cid, srv, _ = env
    assert (await srv.handle("junk"))["error"]["code"] == -32600
    assert (await srv.handle({"jsonrpc": "1.0", "id": 1, "method": "ping"}))["error"]["code"] == -32600
    assert (await rpc(srv, "ping"))["result"] == {}
    assert (await rpc(srv, "no/such/method"))["error"]["code"] == -32601
    assert await srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert await srv.handle({"jsonrpc": "2.0", "method": "no/such/notification"}) is None
    assert (await rpc(srv, "tools/call", {"name": "nope", "arguments": {}}))["result"]["isError"]
    assert (await rpc(srv, "tools/call", {"name": "list_cases", "arguments": "x"}))["result"]["isError"]


# ---- read tools -------------------------------------------------------------------------------------------------------
async def test_read_tools_are_scoped_to_the_sessions_cases(env, settings):
    c, cid, srv, app = env
    other = (await c.post("/api/v1/cases", json={"title": "Not in scope", "purpose": "x"})).json()["id"]
    err, out = await call(srv, "list_cases")
    assert not err and [x["id"] for x in out["cases"]] == [cid]  # a member of 2 cases still only sees the allowed one
    err, msg = await call(srv, "get_case_summary", {"case_id": other})
    err2, msg2 = await call(srv, "get_case_summary", {"case_id": "00000000-0000-0000-0000-000000000000"})
    assert err and err2 and msg == msg2  # no oracle for existence
    err, s = await call(srv, "get_case_summary", {"case_id": cid})
    assert not err and s["counts"]["findings"] > 10 and s["counts"]["evidence"] >= 4
    empty = McpServer(app.state.core, LOCAL_USER_ID, set())
    assert (await call(empty, "list_cases"))[1] == {"cases": []}  # default session sees nothing
    stranger = McpServer(app.state.core, "someone-else", {cid})
    assert (await call(stranger, "get_case_summary", {"case_id": cid}))[0] is True  # membership still enforced per user


async def test_search_omits_restricted_unless_server_started_with_the_flag(env):
    _c, cid, srv, app = env
    _, out = await call(srv, "search_case_evidence", {"case_id": cid, "query": "restricted-subject"})
    assert out["items"] == [] and out["restricted_omitted"] is True
    _, out = await call(srv, "search_case_evidence", {"case_id": cid, "query": "registrar"})
    assert out["items"] and all(i["kind"] in ("finding", "note", "evidence", "observation") for i in out["items"])
    srv2 = McpServer(app.state.core, LOCAL_USER_ID, {cid}, allow_restricted=True)
    _, out = await call(srv2, "search_case_evidence", {"case_id": cid, "query": "email message"})
    assert out["items"] and out["restricted_omitted"] is False
    err, _ = await call(srv, "search_case_evidence", {"case_id": cid, "query": "x" * 500})
    assert err


async def test_entity_and_graph_tools_carry_evidence_ids(env):
    c, cid, srv, _ = env
    ents = (await c.get(f"/api/v1/cases/{cid}/entities?limit=1000")).json()["items"]
    dom = next(e for e in ents if e["key"] == "example.com")
    _, e = await call(srv, "get_entity", {"case_id": cid, "entity_id": dom["id"]})
    assert e["findings"] and all(f["evidence_id"] for f in e["findings"])
    _, g = await call(srv, "get_graph_neighbors", {"case_id": cid, "entity_id": dom["id"], "depth": 99})
    assert g["edges"] and all(x["evidence_ids"] for x in g["edges"]) and len(g["edges"]) <= 100
    assert (await call(srv, "get_entity", {"case_id": cid, "entity_id": "nope"}))[0]
    assert (await call(srv, "get_entity", {"case_id": cid, "entity_id": dom["id"], "extra": 1}))[0]  # unknown argument rejected


async def test_preview_and_status_and_report_tools(env, calls):
    c, cid, srv, _ = env
    n = len(calls)
    _, plan = await call(srv, "preview_investigation", {"case_id": cid, "target": "example.org"})
    assert plan["executed"] is False and len(calls) == n and {s["adapter_id"] for s in plan["steps"]} >= {"rdap", "dns"}
    assert (await call(srv, "preview_investigation", {"case_id": cid, "target": "127.0.0.1"}))[0]
    run = (await c.get(f"/api/v1/cases/{cid}/runs")).json()["items"][0]
    _, st = await call(srv, "get_job_status", {"run_id": run["id"]})
    assert st["status"] in ("succeeded", "partial") and st["jobs"]
    rep = (await c.post(f"/api/v1/cases/{cid}/reports", json={"format": "markdown"})).json()
    _, r = await call(srv, "get_report", {"report_id": rep["id"]})
    assert r["sha256"] == rep["sha256"] and "Limitations" in r["content"]
    pdf = (await c.post(f"/api/v1/cases/{cid}/reports", json={"format": "pdf"})).json()
    assert (await call(srv, "get_report", {"report_id": pdf["id"]}))[1]["content"] is None
    _, tools = await call(srv, "list_tools")
    assert any(t["id"] == "rdap" for t in tools["tools"]) and "secret" not in json.dumps(tools).lower()


# ---- write tools: human approval -------------------------------------------------------------------------------------------
async def test_write_requests_are_held_until_a_person_approves_and_are_single_use(env):
    c, cid, srv, app = env
    args = {"case_id": cid, "body_markdown": "note from an agent"}
    err, msg = await call(srv, "create_note", args)
    assert err and "Approval required" in msg and "cannot approve it yourself" in msg
    with app.state.core.sm() as db:
        ap = db.scalars(select(McpApproval)).one()
        assert ap.status == "pending" and db.scalar(select(func.count()).select_from(Note).where(Note.body_markdown == "note from an agent")) == 0
    aid = ap.id
    assert (await call(srv, "create_note", {**args, "approval_id": aid}))[0]               # still pending
    assert (await call(srv, "create_note", {**args, "approval_id": "bogus"}))[0]            # unknown approval
    pend = (await c.get("/api/v1/mcp/approvals")).json()["items"]
    assert pend[0]["id"] == aid and pend[0]["arguments"] == args and pend[0]["client"]
    assert (await c.post(f"/api/v1/mcp/approvals/{aid}/approve")).json()["status"] == "approved"
    tampered = await call(srv, "create_note", {"case_id": cid, "body_markdown": "DIFFERENT TEXT", "approval_id": aid})
    assert tampered[0] and "exact arguments" in tampered[1]                                  # approval is bound to the exact arguments
    err, out = await call(srv, "create_note", {**args, "approval_id": aid})
    assert not err and out["note_id"]
    again = await call(srv, "create_note", {**args, "approval_id": aid})
    assert again[0] and "used" in again[1]                                                   # single use
    assert (await c.post(f"/api/v1/mcp/approvals/{aid}/approve")).status_code == 409
    with app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(Note).where(Note.body_markdown == "note from an agent")) == 1
        log = json.dumps([e.metadata_json for e in db.scalars(select(AuditEvent).where(AuditEvent.action == "mcp.call"))])
        assert "note from an agent" not in log  # arguments never enter the audit trail


async def test_denied_approval_never_executes(env):
    c, _cid, srv, app = env
    args = {"title": "Agent case", "purpose": "should not exist"}
    await call(srv, "create_case", args)
    with app.state.core.sm() as db:
        aid = db.scalars(select(McpApproval)).one().id
    assert (await c.post(f"/api/v1/mcp/approvals/{aid}/deny")).json()["status"] == "denied"
    err, msg = await call(srv, "create_case", {**args, "approval_id": aid})
    assert err and "denied" in msg
    assert all(x["title"] != "Agent case" for x in (await c.get("/api/v1/cases")).json()["items"])


async def test_approved_search_still_passes_the_policy_gate(env, calls):
    c, cid, srv, app = env
    bad = {"case_id": cid, "target": "127.0.0.1", "target_type": "ip"}
    await call(srv, "start_search", bad)
    with app.state.core.sm() as db:
        aid = db.scalars(select(McpApproval).where(McpApproval.tool == "start_search")).one().id
    await c.post(f"/api/v1/mcp/approvals/{aid}/approve")
    n = len(calls)
    err, msg = await call(srv, "start_search", {**bad, "approval_id": aid})
    assert err and "policy refused" in msg and len(calls) == n  # a person's approval does not override scope policy
    good = {"case_id": cid, "target": "example.com"}
    await call(srv, "start_search", good)
    with app.state.core.sm() as db:
        aid2 = db.scalars(select(McpApproval).where(McpApproval.status == "pending")).one().id
    await c.post(f"/api/v1/mcp/approvals/{aid2}/approve")
    err, out = await call(srv, "start_search", {**good, "approval_id": aid2})
    assert not err and out["status"] in ("succeeded", "partial") and len(calls) > n


async def test_create_case_adds_it_to_the_sessions_scope_and_other_users_cannot_approve(env):
    c, _cid, srv, app = env
    args = {"title": "From agent", "purpose": "approved by owner"}
    await call(srv, "create_case", args)
    with app.state.core.sm() as db:
        row = db.scalars(select(McpApproval)).one()
        aid = row.id
        db.add(User(id="u3", display_name="x"))
        db.commit()
    app.state.core.tokens["t3"] = "u3"
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer t3"})
    cid2 = (await other.post("/api/v1/cases", json={"title": "theirs", "purpose": "x"})).json()["id"]
    assert (await other.post(f"/api/v1/mcp/approvals/{aid}/approve")).status_code == 404  # not their session
    assert (await other.get("/api/v1/mcp/approvals")).json()["items"] == []
    assert (await c.post("/api/v1/mcp/approvals/" + aid + "/deny")).status_code == 200
    # a fresh request approved by the owner works and the new case becomes visible to this session only
    await call(srv, "create_case", {**args, "title": "From agent 2"})
    with app.state.core.sm() as db:
        aid3 = db.scalars(select(McpApproval).where(McpApproval.status == "pending")).first().id
    await c.post(f"/api/v1/mcp/approvals/{aid3}/approve")
    err, out = await call(srv, "create_case", {**args, "title": "From agent 2", "approval_id": aid3})
    assert not err and out["case_id"] in srv.allowed
    assert cid2 not in srv.allowed
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1")
    assert (await anon.post(f"/api/v1/mcp/approvals/{aid3}/approve")).status_code == 401


async def test_workflow_write_tool_is_gated_too(env):
    c, cid, srv, _ = env
    from pathlib import Path

    from osintcc.workflows import load_templates
    tpl = next(t for t in load_templates(Path(__file__).parents[2] / "configs" / "workflow-templates") if t["id"] == "passive-domain-overview")
    wid = (await c.post("/api/v1/workflows", json={"case_id": cid, "definition": tpl})).json()["id"]
    args = {"case_id": cid, "workflow_id": wid, "target": "example.com"}
    err, msg = await call(srv, "run_workflow", args)
    assert err and "Approval required" in msg


def test_args_hash_ignores_only_the_approval_id():
    a = args_hash("t", {"x": 1, "approval_id": "A"})
    assert a == args_hash("t", {"x": 1, "approval_id": "B"}) == args_hash("t", {"x": 1})
    assert a != args_hash("t", {"x": 2}) and a != args_hash("u", {"x": 1})


# ---- real stdio transport ------------------------------------------------------------------------------------------------------
def test_stdio_process_speaks_jsonrpc_and_defaults_to_no_cases(tmp_path):
    lines = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "pytest", "version": "1"}}},
             {"jsonrpc": "2.0", "method": "notifications/initialized"},
             {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
             {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_cases", "arguments": {}}}]
    inp = "\n".join(json.dumps(x) for x in lines) + "\nnot json\n"
    p = subprocess.run([sys.executable, "-I", "-m", "osintcc.mcp_server", "--data-dir", str(tmp_path / "d")], check=False, input=inp,
                       capture_output=True, text=True, timeout=60, env={"OSINTCC_VAULT_ENCRYPTION": "off", "SYSTEMROOT": "C:\\Windows", "PATH": "",
                                                                        "PYTHONPATH": ""} if sys.platform == "win32" else {**os.environ, "OSINTCC_VAULT_ENCRYPTION": "off"})
    out = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
    assert [o.get("id") for o in out] == [1, 2, 3, None]  # no reply to the notification; parse error answered with id null
    assert out[0]["result"]["protocolVersion"] == "2024-11-05" and len(out[1]["result"]["tools"]) == 13
    assert json.loads(out[2]["result"]["content"][0]["text"]) == {"cases": []}
    assert out[3]["error"]["code"] == -32700
