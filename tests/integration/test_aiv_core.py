"""AIV core (addendum v1.1 section 12, items 1-9, 14-16, 21): authorization model, plans, approvals, runs, against a REAL local lab.

The lab servers are real sockets on 127.0.0.1 that record every connection and request, so 'zero outbound packets' and 'only the designated requests' are measured, not assumed."""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
from aiv_lab import (
    GOOD_HEADERS,
    WEAK_HEADERS,
    Lab,
    make_server_cert,
    server_ctx,
)
from osintcc.adapters.active.http_metadata import ScopedHttp
from osintcc.db.models import AivApproval, AivPlan, AivRun, AssetAuthorization, Evidence
from sqlalchemy import select

B = "/api/v1"


def soon(days=7):
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


async def enable(e):
    assert (await e["api"].put(f"{B}/aiv/settings", json={"enabled": True})).status_code == 200


async def mk_case(e, category="cyber"):
    return (await e["api"].post(f"{B}/cases", json={"title": "AIV", "category": category, "purpose": "authorized verification of my own lab"})).json()["id"]


def auth_body(scope, ports, classes=("http_metadata",), **kw):
    return {"asset_type": "fqdn", "scope": scope, "ports": ports, "allowed_classes": [*classes, "lab_network"], "authorized_by": "Owner Operator", "authority_role": "asset owner",
            "source_of_authority": "I own and operate this lab server on my own machine.", "attestation_kind": "owner_statement", "expires_at": soon(), **kw}


async def mk_auth(e, cid, scope, ports, classes=("http_metadata",), **kw):
    r = await e["api"].post(f"{B}/cases/{cid}/asset-authorizations", json=auth_body(scope, ports, classes, **kw))
    assert r.status_code == 201, r.text
    return r.json()


async def mk_plan(e, cid, aid, steps, expect=201):
    r = await e["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": aid, "steps": steps})
    assert r.status_code == expect, r.text
    return r.json()


async def approve(e, pid, expect=200, **kw):
    r = await e["api"].post(f"{B}/aiv/plans/{pid}/approve", json={"confirm": True, **kw})
    assert r.status_code == expect, r.text
    return r.json()


async def run(e, pid, apid, expect=202):
    r = await e["api"].post(f"{B}/aiv/plans/{pid}/run", json={"approval_id": apid, "wait": True})
    assert r.status_code == expect, r.text
    return r.json()


def http_step(url, method="HEAD", follow=False):
    return {"kind": "http_metadata", "url": url, "method": method, "follow_redirects": follow}


async def obs(e, cid, run_id=None):
    q = f"?run_id={run_id}" if run_id else ""
    return (await e["api"].get(f"{B}/cases/{cid}/aiv/observations{q}")).json()["items"]


# ---- item 3: off by default, and an unapproved run sends nothing ------------------------------------------------------------------------
async def test_aiv_is_off_by_default_and_nothing_connects(env):
    lb = await env["lab"]()
    cap = (await env["api"].get(f"{B}/aiv/capabilities")).json()
    assert cap["enabled"] is False and "exploitation or payload delivery" in cap["forbidden"] and any(t["id"] == "nmap" for t in cap["tools"])
    cid = await mk_case(env)
    r = await env["api"].post(f"{B}/cases/{cid}/asset-authorizations", json=auth_body(["lab.test"], [lb.port]))
    assert r.status_code == 403 and r.json()["code"] == "aiv_disabled"
    r = await env["api"].post(f"{B}/cases/{cid}/aiv/plans/preview", json={"authorization_id": "x", "steps": [http_step(f"http://lab.test:{lb.port}/")]})
    assert r.status_code == 403
    assert lb.connections == 0 and env["resolver"].calls == []


async def test_preview_and_plan_creation_make_no_dns_queries_and_no_connections(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    pv = await env["api"].post(f"{B}/cases/{cid}/aiv/plans/preview", json={"authorization_id": a["id"], "steps": [http_step(f"http://lab.test:{lb.port}/")]})
    assert pv.status_code == 200 and pv.json()["ok"] and pv.json()["disclosure"]["external_services"] == []
    plan = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/")])
    await approve(env, plan["id"])                                                      # approving is still not running
    assert lb.connections == 0 and env["resolver"].calls == []


# ---- item 4: consent for a person is not authorization for an asset -----------------------------------------------------------------------
async def test_person_consent_does_not_authorize_an_associated_domain(env):
    await enable(env)
    lb = await env["lab"]()
    api = env["api"]
    cid = (await api.post(f"{B}/cases", json={"title": "Jane", "category": "people", "purpose": "self audit"})).json()["id"]
    sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Jane Example"})).json()["id"]
    await api.post(f"{B}/subjects/{sid}/identifiers", json={"kind": "domain", "value": "lab.test"})
    r = await api.post(f"{B}/subjects/{sid}/consent", json={"verification_method": "email_confirmation", "verifier": "Jane", "source_classes": ["public_passive", "exposure_check"],
                                                            "permitted_purposes": ["self audit"], "expires_at": soon(30)})
    assert r.status_code == 201
    r = await api.post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": "none", "steps": [http_step(f"http://lab.test:{lb.port}/")]})
    assert r.status_code == 404                                                           # there is no authorization, and consent does not create one
    r = await api.post(f"{B}/cases/{cid}/aiv/plans/preview", json={"authorization_id": "none", "steps": [http_step(f"http://lab.test:{lb.port}/")], "target_profile_id": sid})
    assert r.status_code == 404
    assert (await api.get(f"{B}/cases/{cid}/asset-authorizations")).json()["total"] == 0
    assert lb.connections == 0 and env["resolver"].calls == []


# ---- authorization records --------------------------------------------------------------------------------------------------------------
async def test_authorization_needs_proof_scope_ports_and_a_bounded_future_expiry(env):
    await enable(env)
    cid = await mk_case(env)
    post = lambda body: env["api"].post(f"{B}/cases/{cid}/asset-authorizations", json=body)
    good = auth_body(["lab.test"], [8080])
    cases = [
        ({**good, "scope": ["localhost"]}, "invalid_scope"), ({**good, "scope": ["*.*.lab.test"]}, "invalid_scope"), ({**good, "scope": ["10.0.0.0/8"], "asset_type": "cidr"}, "invalid_scope"),
        ({**good, "allowed_classes": ["lab_network"]}, "invalid_classes"), ({**good, "allowed_classes": ["exploit"]}, "invalid_classes"),
        ({**good, "ports": [0]}, "invalid_ports"), ({**good, "authorized_by": " "}, "approver_required"),
        ({**good, "source_of_authority": "mine"}, "source_required"), ({**good, "attestation_kind": "signed_document"}, "proof_required"),
        ({**good, "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat()}, "expiry_invalid"), ({**good, "expires_at": soon(400)}, "duration_too_long"),
        ({**good, "limits": {"max_requests": 5000}}, "invalid_scope"), ({**good, "limits": {"requests_per_second": 50}}, "invalid_scope"), ({**good, "limits": {"shell": "x"}}, "invalid_scope"),
        ({**good, "extra_field": 1}, "validation_error"), ({**good, "attestation_ref": "nope", "attestation_kind": "email_confirmation"}, "evidence_not_in_case"),
    ]
    for body, code in cases:
        r = await post(body)
        assert r.status_code == 422 and r.json()["code"] == code, (body, r.text)
    assert (await post(good)).status_code == 201


async def test_only_a_case_owner_can_authorize_and_an_editor_can_revoke(env):
    from osintcc.db.models import CaseMember, User
    await enable(env)
    cid = await mk_case(env)
    st = env["st"]
    with st.sm() as db:
        db.add(User(id="ed", display_name="editor"))
        db.flush()
        db.add(CaseMember(case_id=cid, user_id="ed", access_role="editor"))
        db.commit()
    st.tokens["ed-token"] = "ed"
    ed = httpx.AsyncClient(transport=httpx.ASGITransport(app=env["api"].app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer ed-token"})
    assert (await ed.post(f"{B}/cases/{cid}/asset-authorizations", json=auth_body(["lab.test"], [8080]))).status_code == 404
    a = await mk_auth(env, cid, ["lab.test"], [8080])
    assert (await ed.post(f"{B}/cases/{cid}/asset-authorizations/{a['id']}/revoke", json={"reason": "stop"})).status_code == 200


# ---- item 5: an exact, live authorization permits only the designated action -------------------------------------------------------------------
async def test_exact_authorization_runs_only_the_designated_request_and_stores_evidence(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    plan = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/", "HEAD")])
    ap = await approve(env, plan["id"])
    run_row = await run(env, plan["id"], ap["approval_id"])
    assert run_row["status"] == "completed" and run_row["counts"]["requests"] == 1 and run_row["counts"]["by_class"] == {"http_metadata": 1}
    assert len(lb.seen) == 1 and lb.seen[0].method == "HEAD" and lb.seen[0].target == "/"
    h = lb.seen[0].headers
    assert h["user-agent"].startswith("osintcc-aiv/") and "cookie" not in h and "authorization" not in h and h["host"] == f"lab.test:{lb.port}"
    items = await obs(env, cid, run_row["id"])
    rules = {o["observed"]["rule"] for o in items}
    assert {"server_version", "powered_by", "csp_missing", "response"} <= rules and "cookie_flags:sid" in rules
    assert all(o["basis"] in ("observed", "inferred") and o["evidence_id"] and o["observed"]["title"] for o in items)
    assert next(o for o in items if o["observed"]["rule"] == "cookie_flags:sid")["basis"] == "inferred"       # only a header was read, so what the cookie is for is inferred
    with env["st"].sm() as db:
        ev = db.get(Evidence, items[0]["evidence_id"])
        stored = env["st"].vault.read(ev.vault_relpath, ev.sha256).decode()
    assert "SECRET-SESSION-VALUE" not in stored and "sid=<redacted>" in stored                  # cookie values are never kept
    ev_list = (await env["api"].get(f"{B}/aiv/runs/{run_row['id']}/events")).json()
    assert next(e["kind"] for e in ev_list["items"]) == "started" and ev_list["items"][-1]["kind"] == "finished" and ev_list["status"] == "completed"


async def test_a_class_that_was_not_granted_is_refused_even_for_an_in_scope_host(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port], classes=("http_metadata",))
    r = await env["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": a["id"], "steps": [{"kind": "tls_handshake", "host": "lab.test", "port": lb.port}]})
    assert r.status_code == 422 and r.json()["code"] == "class_not_allowed"
    r = await env["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": a["id"], "steps": [{"kind": "tcp_connect", "host": "lab.test", "ports": [lb.port]}]})
    assert r.status_code == 422 and r.json()["code"] == "class_not_allowed"
    assert lb.connections == 0


# ---- item 6: wrong port, path, host, expiry, revocation fail closed ---------------------------------------------------------------------------
async def test_wrong_host_port_and_path_never_reach_the_network(env):
    await enable(env)
    lb, other = await env["lab"](), await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port], paths=["/app"], exclusions=["path:/app/admin"])
    bad = [(f"http://other.test:{lb.port}/app", "host_out_of_scope"), (f"http://lab.test:{other.port}/app", "port_out_of_scope"), (f"http://lab.test:{lb.port}/private", "path_out_of_scope"),
           (f"http://lab.test:{lb.port}/app/admin/x", "excluded"), (f"http://127.0.0.1:{lb.port}/app", "host_out_of_scope"), (f"http://lab.test.evil.test:{lb.port}/app", "host_out_of_scope"),
           (f"http://user:pw@lab.test:{lb.port}/app", "credentials_in_url"), (f"ftp://lab.test:{lb.port}/app", "scheme_denied")]
    for url, code in bad:
        r = await env["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": a["id"], "steps": [http_step(url)]})
        assert r.status_code == 422 and r.json()["code"] == code, (url, r.text)
    assert lb.connections == 0 and other.connections == 0 and env["resolver"].calls == []


async def test_expiry_revocation_and_scope_edits_between_approval_and_run_fail_closed(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)

    async def ready():
        a = await mk_auth(env, cid, ["lab.test"], [lb.port])
        p = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/")])
        return a, p, await approve(env, p["id"])
    a, p, ap = await ready()
    with env["st"].sm() as db:                                                           # it lapses after approval
        db.get(AssetAuthorization, a["id"]).expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    r = await run(env, p["id"], ap["approval_id"], 403)
    assert r["code"] == "auth_expired"
    a, p, ap = await ready()
    rv = (await env["api"].post(f"{B}/cases/{cid}/asset-authorizations/{a['id']}/revoke", json={"reason": "owner changed their mind"})).json()
    assert rv["approvals_revoked"] == 1 and rv["authorization"]["state"] == "revoked"
    r = await run(env, p["id"], ap["approval_id"], 409)
    assert r["code"] == "approval_revoked"
    a, p, ap = await ready()
    with env["st"].sm() as db:                                                           # its scope is widened after the plan was made
        row = db.get(AssetAuthorization, a["id"])
        row.ports_json = [*row.ports_json, 9999]
        db.commit()
    r = await run(env, p["id"], ap["approval_id"], 403)
    assert r["code"] == "scope_changed"
    assert lb.connections == 0
    with env["st"].sm() as db:
        assert db.query(AivRun).count() == 0                                             # a refused run leaves no run behind


# ---- item 7 and 8: redirects and DNS ---------------------------------------------------------------------------------------------------
async def test_redirects_out_of_scope_are_reported_and_not_followed(env):
    await enable(env)
    lb = await env["lab"]()
    lb.routes.update({"/ext": (302, {"Location": f"http://evil.test:{lb.port}/stolen"}, b""), "/meta": (302, {"Location": "http://169.254.169.254/latest/meta-data/"}, b""),
                      "/loop": (302, {"Location": f"http://127.0.0.1:{lb.port}/secret"}, b""), "/port": (302, {"Location": f"http://lab.test:{lb.port + 1}/x"}, b""),
                      "/ok": (302, {"Location": "/final"}, b""), "/final": (200, GOOD_HEADERS, b"done")})
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    for path in ("/ext", "/meta", "/loop", "/port"):
        lb.seen.clear()
        p = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}{path}", "GET", True)])
        r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
        assert r["status"] == "partial" and "redirect_out_of_scope" in r["abort_reason"], (path, r)
        assert [s.target for s in lb.seen] == [path]                                      # exactly one request: the redirect target was never contacted
        o = await obs(env, cid, r["id"])
        assert any(x["observed"]["rule"] == "redirect_blocked" for x in o)
    lb.seen.clear()
    p = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/ok", "GET", True)])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    assert r["status"] == "completed" and [s.target for s in lb.seen] == ["/ok", "/final"]
    lb.seen.clear()
    p = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/ok", "GET", False)])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    assert [s.target for s in lb.seen] == ["/ok"] and any(x["observed"].get("location") and x["observed"]["rule"] == "redirect_seen" for x in await obs(env, cid, r["id"]))      # not following is the default


async def test_dns_answers_in_private_or_metadata_space_fail_closed_at_connection_time(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    lab_auth = await mk_auth(env, cid, ["rebind.test", "meta.test"], [lb.port])                                    # includes the explicit lab class
    pub = (await env["api"].post(f"{B}/cases/{cid}/asset-authorizations", json={**auth_body(["rebind.test", "meta.test"], [lb.port]), "allowed_classes": ["http_metadata"]})).json()
    for host, a in (("meta.test", lab_auth), ("rebind.test", pub), ("meta.test", pub)):                              # metadata is refused even in a lab; private space needs the lab class
        p = await mk_plan(env, cid, a["id"], [http_step(f"http://{host}:{lb.port}/")])
        r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
        assert r["status"] == "partial" and "resolved_ip_forbidden" in r["abort_reason"], (host, r)
    env["resolver"].table["rebind.test"] = ["127.0.0.1"]                                                           # the name now points at loopback...
    p = await mk_plan(env, cid, pub["id"], [http_step(f"http://rebind.test:{lb.port}/")])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    assert r["status"] == "partial" and "resolved_ip_forbidden" in r["abort_reason"]                                # ...and without an explicit lab authorization loopback is refused
    assert lb.connections == 0


async def test_the_checked_address_is_the_address_that_is_used(env, monkeypatch):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    flips = {"n": 0}

    async def flipping(host):
        flips["n"] += 1
        return ["127.0.0.1"] if flips["n"] == 1 else ["8.8.8.8"]                         # a second lookup would point somewhere else
    env["st"].aiv.resolver = flipping
    used = []
    real_one = ScopedHttp._one

    async def spy(self, url, method, ip, host, port, scheme):
        used.append(ip)
        return await real_one(self, url, method, ip, host, port, scheme)
    monkeypatch.setattr(ScopedHttp, "_one", spy)
    p = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/")])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    assert r["status"] == "completed" and used == ["127.0.0.1"] and flips["n"] == 1 and len(lb.seen) == 1


# ---- item 9: real TLS ---------------------------------------------------------------------------------------------------------------------
async def test_tls_posture_from_real_handshakes(env, pki):
    await enable(env)
    good = await env["lab"](routes={"*": (200, GOOD_HEADERS, b"ok")}, tls=["lab.test"])
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [good.port], classes=("http_metadata", "tls_handshake"))
    p = await mk_plan(env, cid, a["id"], [{"kind": "tls_handshake", "host": "lab.test", "port": good.port}])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    assert r["status"] == "completed"
    items = await obs(env, cid, r["id"])
    summary = next(o for o in items if o["observed"]["rule"] == "summary")["observed"]
    assert summary["protocols"]["TLSv1.3"] == "supported" and summary["protocols"]["TLSv1.2"] == "supported" and summary["trust"] == "ok"
    assert summary["protocols"]["TLSv1.1"] in ("not_supported", "not_testable") and summary["protocols"]["TLSv1.0"] in ("not_supported", "not_testable")
    assert not [(o["observed"]["rule"], o["observed"]) for o in items if o["severity"] in ("medium", "high")]                    # a healthy server produces no hygiene findings
    with env["st"].sm() as db:
        stored = json.loads(env["st"].vault.read(db.get(Evidence, items[0]["evidence_id"]).vault_relpath).decode())
    cert = stored["result"]["certificate"]
    assert cert["host_matches"] is True and cert["key_type"] in ("EC", "RSA") and cert["signature_hash"] == "sha256" and len(cert["sha256_fingerprint"]) == 64
    assert "TLSv1.3" in stored["result"]["negotiated"] or stored["result"]["negotiated"] == "TLSv1.3"


async def test_tls_findings_for_expired_self_signed_and_mismatched_certificates(env, pki):
    await enable(env)
    cid = await mk_case(env)
    expect = {"expired": ("cert_expired", "high"), "selfsigned": ("cert_self_signed", "medium"), "mismatch": ("hostname_mismatch", "medium")}
    for tag, kw in {"expired": {"expired": True}, "selfsigned": {"self_signed": True}, "mismatch": {}}.items():
        cp, kp = make_server_cert(pki["tmp"], pki["key"], pki["cert"], ["wrong.test"] if tag == "mismatch" else ["lab.test"], tag=tag, **kw)
        lb = Lab(routes={"*": (200, GOOD_HEADERS, b"ok")})
        await lb.start(server_ctx(cp, kp))
        try:
            a = await mk_auth(env, cid, ["lab.test"], [lb.port], classes=("tls_handshake",))
            p = await mk_plan(env, cid, a["id"], [{"kind": "tls_handshake", "host": "lab.test", "port": lb.port}])
            r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
            found = {o["observed"]["rule"]: o for o in await obs(env, cid, r["id"])}
            rule, sev = expect[tag]
            assert rule in found and found[rule]["severity"] == sev and found[rule]["basis"] == "observed" and found[rule]["remediation"], (tag, sorted(found))
        finally:
            await lb.stop()


# ---- ports -------------------------------------------------------------------------------------------------------------------------------
async def test_port_checks_touch_only_authorized_ports(env):
    await enable(env)
    open_a, open_b = await env["lab"](), await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [open_a.port], classes=("tcp_connect",))
    r = await env["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": a["id"], "steps": [{"kind": "tcp_connect", "host": "lab.test", "ports": [open_a.port, open_b.port]}]})
    assert r.status_code == 422 and r.json()["code"] == "port_out_of_scope" and open_b.connections == 0
    p = await mk_plan(env, cid, a["id"], [{"kind": "tcp_connect", "host": "lab.test", "ports": [open_a.port]}])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    items = await obs(env, cid, r["id"])
    assert r["status"] == "completed" and (items[0]["observed"]["host"], items[0]["observed"]["port"], items[0]["observed"]["state"]) == ("lab.test", open_a.port, "open") and open_b.connections == 0
    assert open_a.connections == 1 and open_a.seen == []                               # connect only: nothing was sent
    for bad in ([], list(range(2000, 2012)), [open_a.port, open_a.port]):
        r = await env["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": a["id"], "steps": [{"kind": "tcp_connect", "host": "lab.test", "ports": bad}]})
        assert r.status_code == 422


# ---- item 14: approvals ------------------------------------------------------------------------------------------------------------------
async def test_approvals_are_explicit_single_use_expiring_and_bound_to_the_exact_plan(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    p1 = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/")])
    assert (await env["api"].post(f"{B}/aiv/plans/{p1['id']}/approve", json={})).status_code == 422             # no implied approval
    r = await run(env, p1["id"], "nonexistent", 409)
    assert r["code"] == "approval_missing" and lb.connections == 0
    ap = await approve(env, p1["id"], expires_in_minutes=5)
    assert ap["maximum_uses"] == 1
    assert (await run(env, p1["id"], ap["approval_id"]))["status"] == "completed"
    r = await run(env, p1["id"], ap["approval_id"], 409)
    assert r["code"] == "approval_used" and len(lb.seen) == 1                                                       # a second run needs a second approval
    # editing the plan (a new version) revokes the old approval and the new version needs its own
    ap2 = await approve(env, p1["id"])
    p2 = (await env["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": a["id"], "steps": [http_step(f"http://lab.test:{lb.port}/x", "GET")], "supersedes": p1["id"]})).json()
    assert p2["version"] == 2 and p2["plan_hash"] != p1["plan_hash"]
    r = await run(env, p1["id"], ap2["approval_id"], 409)
    assert r["code"] == "approval_revoked"
    r = await run(env, p2["id"], ap2["approval_id"], 409)
    assert r["code"] == "approval_missing"                                                                          # an approval for another plan is not an approval for this one
    with env["st"].sm() as db:
        row = db.get(AivApproval, (await approve(env, p2["id"]))["approval_id"])
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        aid = row.id
    assert (await run(env, p2["id"], aid, 409))["code"] == "approval_expired"
    with env["st"].sm() as db:                                                                                      # tampering with a stored plan breaks its approval
        ap3 = await approve(env, p2["id"])
        pl = db.get(AivPlan, p2["id"])
        pl.plan_hash = "0" * 64
        db.commit()
    assert (await run(env, p2["id"], ap3["approval_id"], 409))["code"] == "approval_mismatch"


# ---- item 15 and 16: cancellation and crash recovery -----------------------------------------------------------------------------------
async def test_cancel_stops_a_run_in_flight(env):
    await enable(env)
    lb = await env["lab"](delay=3.0)
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    p = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/", "GET")])
    ap = await approve(env, p["id"])
    r = (await env["api"].post(f"{B}/aiv/plans/{p['id']}/run", json={"approval_id": ap["approval_id"]})).json()
    await asyncio.sleep(0.4)
    t0 = asyncio.get_running_loop().time()
    assert (await env["api"].post(f"{B}/aiv/runs/{r['id']}/cancel")).json()["cancelling"] is True
    await env["st"].aiv.wait(r["id"])
    assert asyncio.get_running_loop().time() - t0 < 2.0
    row = (await env["api"].get(f"{B}/aiv/runs/{r['id']}")).json()
    assert row["status"] == "cancelled" and "cancelled" in row["abort_reason"]


async def test_a_run_interrupted_by_a_restart_is_never_replayed(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    p = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/")])
    ap = await approve(env, p["id"])
    with env["st"].sm() as db:                                                                                      # the process died mid-run
        ap_row = db.get(AivApproval, ap["approval_id"])
        ap_row.uses = 1
        db.add(AivRun(plan_id=p["id"], case_id=cid, approval_id=ap_row.id, actor_id="local-user", status="running"))
        db.commit()
    assert env["st"].aiv.recover() == 1
    runs = [r for r in env["st"].sm().__enter__().scalars(select(AivRun))]
    assert runs[0].status == "interrupted" and "not resumed" in runs[0].abort_reason
    r = await run(env, p["id"], ap["approval_id"], 409)
    assert r["code"] == "approval_used" and lb.connections == 0                                                     # recovery sent nothing, and the consumed approval cannot be reused


# ---- reverification and review -----------------------------------------------------------------------------------------------------------
async def test_reverification_only_calls_a_finding_resolved_when_the_same_check_was_repeated(env):
    await enable(env)
    lb = await env["lab"](routes={"*": (200, WEAK_HEADERS, b"x")})
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    p = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/")])
    r1 = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    lb.routes["*"] = (200, GOOD_HEADERS | {"Content-Security-Policy": "default-src 'self'"}, b"x")      # the owner fixed things
    r2 = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    cmp_ = (await env["api"].get(f"{B}/aiv/runs/{r1['id']}/compare/{r2['id']}")).json()
    assert cmp_["resolved"] and cmp_["new"] == [] and any(o["observed"].get("server") for o in cmp_["resolved"])
    assert "never as fixed" in cmp_["note"]
    # a later run of a DIFFERENT check on the asset says nothing about the earlier findings
    p3 = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/other", "HEAD")])
    r3 = await run(env, p3["id"], (await approve(env, p3["id"]))["approval_id"])
    cmp2 = (await env["api"].get(f"{B}/aiv/runs/{r1['id']}/compare/{r3['id']}")).json()
    assert cmp2["resolved"] == [] and cmp2["not_rechecked"]


async def test_observations_can_be_reviewed_with_a_reason(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    p = await mk_plan(env, cid, a["id"], [http_step(f"http://lab.test:{lb.port}/")])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    o = next(x for x in await obs(env, cid, r["id"]) if x["severity"] == "low")
    bad = await env["api"].post(f"{B}/cases/{cid}/aiv/observations/{o['id']}/review", json={"status": "false_positive", "note": ""})
    assert bad.status_code == 422
    good = (await env["api"].post(f"{B}/cases/{cid}/aiv/observations/{o['id']}/review", json={"status": "accepted_risk", "note": "internal tool, documented exception"})).json()
    assert good["review_status"] == "accepted_risk" and good["reviewer"]
    assert (await obs(env, cid, r["id"]))[0]["id"] is not None


async def test_unknown_plan_fields_and_shell_like_steps_are_rejected_by_the_api(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port])
    for step in ({"kind": "shell", "command": "curl http://lab.test"}, {**http_step(f"http://lab.test:{lb.port}/"), "headers": {"X": "y"}}, {**http_step(f"http://lab.test:{lb.port}/"), "method": "POST"},
                 {"kind": "tcp_connect", "host": "lab.test", "ports": [lb.port], "scripts": "vuln"}):
        r = await env["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": a["id"], "steps": [step]})
        assert r.status_code == 422 and r.json()["code"] == "invalid_plan", (step, r.text)
    assert lb.connections == 0
