from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path

import httpx
import pytest
from conftest import fake_dns, fake_resolver
from osintcc.adapters.base import AdapterContext, Target
from osintcc.db.models import AuditEvent, Evidence, Finding, User
from osintcc.db.models import PluginManifest as Row
from osintcc.main import create_app
from osintcc.plugins import PluginError, safe_rel, tree_hash, validate_manifest
from osintcc.policy.ssrf import SafeHttp
from sqlalchemy import select

REPO = Path(__file__).parents[2]
EXAMPLE = REPO / "plugins" / "examples" / "example-robots"
SDK = REPO / "sdk" / "osintcc_plugin_sdk.py"
BASE = json.loads((EXAMPLE / "plugin.json").read_text())
ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /tmp/\nDisallow:\nSitemap: https://example.com/sitemap.xml\n"


def make_plugin(tmp: Path, code: str | None = None, name: str = "evil-plugin", **over) -> Path:
    d = tmp / f"src-{name}-{over.get('version', '1.0.0')}"
    (d / "fixtures").mkdir(parents=True)
    shutil.copyfile(SDK, d / "osintcc_plugin_sdk.py")
    m = {**copy.deepcopy(BASE), "id": name, **over}
    (d / "plugin.json").write_text(json.dumps(m))
    (d / "main.py").write_text(code if code is not None else (EXAMPLE / "main.py").read_text())
    shutil.copyfile(EXAMPLE / "fixtures" / "robots.json", d / "fixtures" / "robots.json")
    return d


@pytest.fixture
async def env(settings, tmp_path):
    seen: list[str] = []

    def handler(req: httpx.Request):
        seen.append(str(req.url))
        return httpx.Response(200, text=ROBOTS) if req.url.path == "/robots.txt" else httpx.Response(404)
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(handler))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            cid = (await c.post("/api/v1/cases", json={"title": "P", "purpose": "plugin tests"})).json()["id"]
            c.app = app
            yield c, cid, app, seen, tmp_path


async def install(c, path: Path):
    r = await c.post("/api/v1/plugins/install", json={"path": str(path)})
    return r


async def enable(c, pid, version, h):
    return await c.post(f"/api/v1/plugins/{pid}/{version}/enable", json={"accept_hash": h})


async def run_plugin(c, cid, aid, target="example.com"):
    r = await c.post(f"/api/v1/cases/{cid}/searches", json={"target": target, "adapters": [aid], "wait": True})
    return r


# ---- manifest validation -------------------------------------------------------------------------------------------------
def test_example_manifest_is_valid_and_has_every_required_field():
    m = validate_manifest(BASE)
    required = {"id", "version", "maintainer", "license", "entrypoint", "platforms", "capabilities", "input_types", "output_schema_version",
                "active_network_access", "minimum_permissions", "required_secrets", "rate_limits", "dependencies", "healthcheck",
                "fixture_path", "uninstall_cleanup"}
    assert required <= set(BASE) and m.id == "example-robots"


@pytest.mark.parametrize("patch,needle", [
    ({"entrypoint": "../evil.py"}, "entrypoint"), ({"entrypoint": "C:/x.py"}, "entrypoint"), ({"entrypoint": "run.sh"}, "entrypoint"),
    ({"extra_key": 1}, "extra"), ({"id": "Bad_ID"}, "id"), ({"version": "1.0"}, "version"), ({"input_types": ["nonsense"]}, "unknown input type"),
    ({"minimum_permissions": {"network_domains": ["not a host"], "max_requests": 1}}, "network domain"),
    ({"minimum_permissions": {"network_domains": [], "max_requests": 2}}, "network_domains"),
    ({"minimum_permissions": {"network_domains": ["a.com"], "max_requests": 9}}, "max_requests"),
    ({"minimum_permissions": {"filesystem": "read"}}, "filesystem"), ({"platforms": []}, "platforms"), ({"output_schema_version": 2}, "output_schema"),
    ({"fixture_path": "../../etc/passwd"}, "unsafe"), ({"uninstall_cleanup": ["/abs"]}, "unsafe"), ({"timeout_seconds": 9999}, "timeout"),
])
def test_manifest_rejections(patch, needle):
    with pytest.raises(PluginError) as e:
        validate_manifest({**BASE, **patch})
    assert needle.lower() in str(e.value).lower()


def test_safe_rel():
    assert safe_rel("a/b.py") == "a/b.py"
    for bad in ("", "/a", "../a", "a/../../b", "C:\\x", "a:b"):
        with pytest.raises(PluginError):
            safe_rel(bad)


# ---- install / review / enable ------------------------------------------------------------------------------------------
async def test_install_is_disabled_until_the_exact_hash_is_accepted(env):
    c, cid, app, seen, _tmp = env
    r = await install(c, EXAMPLE)
    assert r.status_code == 201, r.text
    p = r.json()
    assert p["enabled"] is False and p["health"] == "installed_disabled" and len(p["tree_sha256"]) == 64
    assert p["compatibility"] == {"host_api_ok": True, "platform_ok": True, "output_schema_ok": True, "hash_ok": True}
    assert "NOT enforced" in p["network_isolation"] and "rlimits on POSIX only" in p["resource_limits"]
    assert "plugin_example_robots" not in app.state.core.adapters  # not registered, therefore not runnable
    r = await run_plugin(c, cid, "plugin_example_robots")
    assert r.status_code == 422 and seen == []
    assert (await enable(c, "example-robots", "1.0.0", "0" * 64)).status_code == 409           # wrong hash
    assert (await enable(c, "example-robots", "1.0.0", p["tree_sha256"])).json()["enabled"] is True
    assert "plugin_example_robots" in app.state.core.adapters
    assert (await install(c, EXAMPLE)).status_code == 422                                      # same version again
    with app.state.core.sm() as db:
        a = db.scalars(select(AuditEvent).where(AuditEvent.action == "plugin.enable")).one()
        assert a.metadata_json["sha256"] == p["tree_sha256"]


async def test_enabled_plugin_runs_host_mediated_and_findings_are_cited(env):
    c, cid, _app, seen, _ = env
    h = (await install(c, EXAMPLE)).json()["tree_sha256"]
    await enable(c, "example-robots", "1.0.0", h)
    ct = (await c.post("/api/v1/plugins/example-robots/1.0.0/contract-test")).json()
    assert ct["passed"] is True and all(x["ok"] for x in ct["checks"]) and any("deterministic" in x["name"] for x in ct["checks"])
    plan = (await c.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "example.com"})).json()
    flags = {s["adapter_id"]: s["default_selected"] for s in plan["steps"]}
    assert flags["plugin_example_robots"] is False                                            # never part of the default run
    run = (await run_plugin(c, cid, "plugin_example_robots")).json()
    assert run["status"] == "succeeded" and seen == ["https://example.com/robots.txt"]         # exactly the one declared request
    f = (await c.get(f"/api/v1/cases/{cid}/findings")).json()["items"]
    cnt = next(x for x in f if x["predicate"] == "example-robots.robots.disallow_rule_count")
    assert cnt["value"] == 2 and cnt["source_url"] == "https://example.com/robots.txt" and cnt["adapter_version"] == "1.0.0"
    ev = (await c.get(f"/api/v1/evidence/{cnt['evidence_id']}")).json()
    assert ev["integrity_verified"] and ev["source"]["adapter_id"] == "plugin_example_robots"


async def test_install_refuses_dangerous_trees(env):
    c, _cid, app, _seen, tmp = env
    d = make_plugin(tmp, name="has-exe")
    (d / "payload.exe").write_bytes(b"MZ")
    assert "not allowed" in (await install(c, d)).json()["message"]
    d = make_plugin(tmp, name="has-sh")
    (d / "run.sh").write_text("rm -rf /")
    assert (await install(c, d)).status_code == 422
    d = make_plugin(tmp, name="no-entry")
    (d / "main.py").unlink()
    assert "entrypoint" in (await install(c, d)).json()["message"]
    d = make_plugin(tmp, name="big")
    (d / "blob.txt").write_bytes(b"x" * (5 * 1024 * 1024 + 1))
    assert "5 MB" in (await install(c, d)).json()["message"]
    d = make_plugin(tmp, name="many")
    for i in range(201):
        (d / f"f{i}.txt").write_text("x")
    assert "too many" in (await install(c, d)).json()["message"]
    assert (await install(c, tmp / "does-not-exist")).status_code == 422
    assert not (app.state.core.settings.data_dir / "plugins" / "big").exists()               # failed installs leave nothing behind
    link = make_plugin(tmp, name="has-link")
    try:
        (link / "l.txt").symlink_to(link / "main.py")
    except OSError:
        return  # symlink creation needs privileges on Windows; the code path is covered on POSIX CI
    assert "symbolic" in (await install(c, link)).json()["message"]


async def test_tampering_after_review_is_detected_on_run_health_and_restart(env, settings):
    c, cid, app, seen, _tmp = env
    h = (await install(c, EXAMPLE)).json()["tree_sha256"]
    await enable(c, "example-robots", "1.0.0", h)
    main = settings.data_dir / "plugins" / "example-robots" / "1.0.0" / "main.py"
    main.write_text(main.read_text() + "\n# sneaky change\n")
    r = (await run_plugin(c, cid, "plugin_example_robots")).json()
    job = r["jobs"][0]
    assert job["status"] == "failed" and job["error_code"] == "plugin_tampered" and seen == []
    assert (await app.state.core.adapters["plugin_example_robots"].health())["status"] == "unavailable"
    assert (await c.post("/api/v1/plugins/example-robots/1.0.0/contract-test")).status_code == 409
    assert (await enable(c, "example-robots", "1.0.0", h)).status_code == 409                 # cannot be re-enabled in place
    app.state.core.plugin_manager.sync()
    assert "plugin_example_robots" not in app.state.core.adapters                              # restart/sync refuses to re-register it
    assert next(p for p in (await c.get("/api/v1/plugins")).json()["items"])["health"] == "tampered"


# ---- hostile plugins -------------------------------------------------------------------------------------------------------
HEADER = "from osintcc_plugin_sdk import *\n"


async def enabled(c, tmp, name, code, **over):
    d = make_plugin(tmp, code, name, **over)
    h = (await install(c, d)).json()["tree_sha256"]
    r = await enable(c, name, over.get("version", "1.0.0"), h)
    assert r.status_code == 200, r.text
    return "plugin_" + name.replace("-", "_")


async def job_of(c, cid, aid, **kw):
    r = (await run_plugin(c, cid, aid, **kw)).json()
    return r["jobs"][0]


async def test_undeclared_network_destinations_are_refused_without_any_request(env):
    c, cid, _app, seen, tmp = env
    for i, url in enumerate(["https://evil.example/steal", "http://example.com/robots.txt", "https://127.0.0.1/admin",
                             "https://user:pw@example.com/x", "https://example.com.evil.example/robots.txt", "file:///etc/passwd"]):
        aid = await enabled(c, tmp, f"net-{i}", HEADER + f"run(lambda t: [{url!r}], lambda t, r: result())")
        j = await job_of(c, cid, aid)
        assert j["error_code"] == "undeclared_network_destination", url
    assert seen == []


async def test_plugin_cannot_request_more_urls_than_its_manifest_allows(env):
    c, cid, _app, seen, tmp = env
    aid = await enabled(c, tmp, "greedy", HEADER + "run(lambda t: ['https://example.com/a', 'https://example.com/b'], lambda t, r: result())")
    j = await job_of(c, cid, aid)
    assert j["error_code"] == "plugin_invalid_output" and seen == []


@pytest.mark.parametrize("name,code", [
    ("garbage", "print('not json at all')"),
    ("crash", "import sys; sys.exit(3)"),
    ("empty", "pass"),
    ("extra-keys", HEADER + "run(lambda t: [], lambda t, r: {**result(), 'run_this': 'os.system(\"id\")'})"),
    ("bad-status", HEADER + "run(lambda t: [], lambda t, r: result(status='verified_truth'))"),
    ("bad-conf", HEADER + "run(lambda t, ): [], None" if False else HEADER + "run(lambda t: [], lambda t, r: result(findings=[finding('domain', t['canonical'], 'x.y', 1, 'certain')]))"),
    ("bad-pred", HEADER + "run(lambda t: [], lambda t, r: result(findings=[finding('domain', t['canonical'], 'Drop Table;', 1)]))"),
    ("bad-index", HEADER + "run(lambda t: [], lambda t, r: result(findings=[finding('domain', t['canonical'], 'x.y', 1, artifact_index=7)]))"),
    ("bad-b64", HEADER + "run(lambda t: [], lambda t, r: result(artifacts=[{'name':'a','content_b64':'***','mime_type':'x'}]))"),
    ("plan-wrong-shape", "import json,sys; print(json.dumps({'requests': ['https://example.com/robots.txt']}))"),
])
async def test_malformed_plugin_output_is_rejected_and_counted(env, name, code):
    c, cid, app, _seen, tmp = env
    aid = await enabled(c, tmp, name, code)
    j = await job_of(c, cid, aid)
    assert j["status"] == "failed" and j["error_code"] == "plugin_invalid_output", (name, j)
    with app.state.core.sm() as db:
        assert db.scalars(select(Row).where(Row.plugin_id == name)).one().invalid_outputs >= 1
        assert db.scalar(select(Finding).where(Finding.adapter_id == aid)) is None            # nothing from it was stored


async def test_three_invalid_outputs_quarantine_the_plugin_and_remove_it_from_the_registry(env):
    c, cid, app, _seen, tmp = env
    aid = await enabled(c, tmp, "flaky", "print('garbage')")
    for _ in range(3):
        await job_of(c, cid, aid)
    p = next(x for x in (await c.get("/api/v1/plugins")).json()["items"] if x["plugin_id"] == "flaky")
    assert p["health"] == "quarantined" and p["enabled"] is False and aid not in app.state.core.adapters
    assert (await run_plugin(c, cid, aid)).status_code == 422                                    # cannot be selected any more


async def test_timeout_kills_a_runaway_plugin_and_other_adapters_still_work(env):
    c, cid, _app, _seen, tmp = env
    aid = await enabled(c, tmp, "sleepy", "import time; time.sleep(60)", timeout_seconds=1)
    j = await job_of(c, cid, aid)
    assert j["error_code"] == "timeout"
    ok = (await c.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "adapters": ["lookalike"], "wait": True})).json()
    assert ok["status"] == "succeeded"                                                          # one plugin's failure is isolated


async def test_huge_output_is_capped_not_buffered_forever(env):
    c, cid, _app, _seen, tmp = env
    aid = await enabled(c, tmp, "chatty", "import sys\nfor _ in range(200):\n    sys.stdout.write('x' * 100000)\n")
    j = await job_of(c, cid, aid)
    assert j["error_code"] == "plugin_invalid_output"


async def test_fabricated_provenance_urls_are_stripped(env):
    c, cid, _app, _seen, tmp = env
    code = HEADER + ("run(lambda t: ['https://example.com/robots.txt'], lambda t, r: result(artifacts=[artifact('x', b'{}', "
                     "'https://bank.example/proof', 'application/json', 200)], findings=[finding('domain', t['canonical'], 'claims.owner', 'someone', 'high')]))")
    aid = await enabled(c, tmp, "liar", code)
    r = (await run_plugin(c, cid, aid)).json()
    assert r["status"] == "succeeded" and any("did not fetch" in w for w in r["jobs"][0]["warnings"])
    f = (await c.get(f"/api/v1/cases/{cid}/findings")).json()["items"][0]
    assert f["source_url"] is None and f["predicate"] == "liar.claims.owner"                    # namespaced + no forged source


async def test_plugin_findings_cannot_claim_verification_only_labels(env):
    c, cid, _app, _seen, tmp = env
    aid = await enabled(c, tmp, "loud", HEADER + "run(lambda t: [], lambda t, r: result(artifacts=[artifact('a', b'{}')], findings=[finding('domain', t['canonical'], 'p.q', 1, 'high')]))")
    await run_plugin(c, cid, aid)
    with c.app.state.core.sm() as db:
        f = db.scalars(select(Finding).where(Finding.adapter_id == aid)).one()
        assert f.status == "unverified"                                                         # status is set by the host, not the plugin


async def test_active_network_plugins_need_a_scope_authorization(env):
    c, cid, _app, seen, tmp = env
    aid = await enabled(c, tmp, "prober", HEADER + "run(lambda t: ['https://example.com/robots.txt'], lambda t, r: result())", active_network_access=True)
    plan = (await c.post(f"/api/v1/cases/{cid}/searches/preview", json={"target": "example.com", "adapters": [aid], "mode": "active"})).json()
    step = plan["steps"][0]
    assert step["operation_class"] == "active" and step["runnable"] is False and "authorization" in step["reason"]
    r = await c.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.com", "adapters": [aid], "mode": "active", "wait": True})
    assert r.status_code == 409 and seen == []


async def test_platform_and_host_api_constraints_block_enabling(env):
    c, _cid, _app, _seen, tmp = env
    other = "linux" if sys.platform == "win32" else "windows"
    d = make_plugin(tmp, name="wrong-os", platforms=[other])
    p = (await install(c, d)).json()
    assert p["compatibility"]["platform_ok"] is False
    assert "does not support" in (await enable(c, "wrong-os", "1.0.0", p["tree_sha256"])).json()["message"]
    d = make_plugin(tmp, name="future-api", min_host_api=99)
    p = (await install(c, d)).json()
    assert p["compatibility"]["host_api_ok"] is False
    assert "host API" in (await enable(c, "future-api", "1.0.0", p["tree_sha256"])).json()["message"]


# ---- versions: upgrade and rollback keep evidence ------------------------------------------------------------------------------
async def test_upgrade_and_rollback_preserve_provenance_and_require_review_per_version(env):
    c, cid, app, _seen, tmp = env
    v1 = make_plugin(tmp, name="vers", version="1.0.0")
    v2 = make_plugin(tmp, name="vers", version="1.1.0")
    (v2 / "main.py").write_text((v2 / "main.py").read_text().replace("Disallow:", "Disallow:"))  # same logic, different bytes below
    (v2 / "README.md").write_text("v1.1.0 notes")
    h1 = (await install(c, v1)).json()["tree_sha256"]
    h2 = (await install(c, v2)).json()["tree_sha256"]
    assert h1 != h2
    assert (await c.post("/api/v1/plugins/vers/1.1.0/activate")).status_code == 409           # never reviewed
    await enable(c, "vers", "1.0.0", h1)
    await run_plugin(c, cid, "plugin_vers")
    await enable(c, "vers", "1.1.0", h2)                                                       # upgrade: 1.0.0 is deactivated
    items = {p["version"]: p for p in (await c.get("/api/v1/plugins")).json()["items"] if p["plugin_id"] == "vers"}
    assert items["1.1.0"]["active"] and not items["1.0.0"]["active"]
    assert app.state.core.adapters["plugin_vers"].manifest.version == "1.1.0"
    await c.post(f"/api/v1/cases/{cid}/searches", json={"target": "example.org", "adapters": ["plugin_vers"], "wait": True})
    act = (await c.post("/api/v1/plugins/vers/1.0.0/activate")).json()                          # rollback
    assert act["active"] and app.state.core.adapters["plugin_vers"].manifest.version == "1.0.0"
    with app.state.core.sm() as db:
        versions = {f.adapter_version for f in db.scalars(select(Finding).where(Finding.adapter_id == "plugin_vers"))}
        assert versions == {"1.0.0", "1.1.0"}                                                   # old parsing provenance retained
        for e in db.scalars(select(Evidence).where(Evidence.kind == "plugin_vers.raw")):
            assert app.state.core.vault.verify(e.vault_relpath, e.sha256)


async def test_uninstall_removes_files_but_never_evidence(env, settings):
    c, cid, app, _seen, _tmp = env
    h = (await install(c, EXAMPLE)).json()["tree_sha256"]
    await enable(c, "example-robots", "1.0.0", h)
    await run_plugin(c, cid, "plugin_example_robots")
    assert (await c.post("/api/v1/plugins/example-robots/1.0.0/uninstall", json={})).status_code == 422
    r = (await c.post("/api/v1/plugins/example-robots/1.0.0/uninstall", json={"confirm": True})).json()
    assert r["evidence"] == "untouched" and not (settings.data_dir / "plugins" / "example-robots" / "1.0.0").exists()
    assert "plugin_example_robots" not in app.state.core.adapters
    assert (await c.get(f"/api/v1/cases/{cid}/findings")).json()["total"] >= 2


async def test_enabled_plugin_survives_restart_when_files_are_intact(settings):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    mk = lambda: create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    app = mk()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"Authorization": f"Bearer {settings.session_token}"}) as c:
            h = (await install(c, EXAMPLE)).json()["tree_sha256"]
            await enable(c, "example-robots", "1.0.0", h)
    app2 = mk()
    async with app2.router.lifespan_context(app2):
        assert "plugin_example_robots" in app2.state.core.adapters


# ---- authorization at the API boundary ---------------------------------------------------------------------------------------------
async def test_non_admin_cannot_manage_plugins_settings_secrets_backups(env):
    _c, _cid, app, _seen, _tmp = env
    st = app.state.core
    with st.sm() as db:
        db.add(User(id="u20", display_name="analyst"))
        db.commit()
    st.tokens["t20"] = "u20"
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer t20"})
    for m, u, b in [("POST", "/api/v1/plugins/install", {"path": str(EXAMPLE)}), ("POST", "/api/v1/plugins/x/1.0.0/enable", {"accept_hash": "0" * 64}),
                    ("POST", "/api/v1/plugins/x/disable", None), ("PUT", "/api/v1/settings", {"values": {"offline": True}}),
                    ("POST", "/api/v1/secrets/shodan", {"value": "k"}), ("POST", "/api/v1/backups", {"allow_plaintext": True}),
                    ("POST", "/api/v1/system/vault/encrypt-existing", None), ("POST", "/api/v1/ai/profiles", {"name": "xx", "provider_type": "fixture", "model_id": "m"}),
                    ("POST", "/api/v1/system/shutdown", None)]:
        r = await other.request(m, u, json=b)
        assert r.status_code == 403 and r.json()["code"] == "admin_required", (m, u, r.status_code)
    assert (await other.get("/api/v1/plugins")).status_code == 200                              # reading is allowed
    assert (await other.get("/api/v1/settings")).status_code == 200
    with st.sm() as db:
        assert db.scalars(select(AuditEvent).where(AuditEvent.action == "access.denied", AuditEvent.decision == "deny")).first()
    _ = (Target, tree_hash)
