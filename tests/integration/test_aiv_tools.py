"""AIV-4: external tools (Nmap, Naabu, Nuclei, dnstwist). Parsers run on output captured from the real tools; the runner is exercised with stand-in programs that
replay those captures; tests against the real binaries run only where they are installed."""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from osintcc.adapters.base import Target
from osintcc.adapters.cli import DnstwistAdapter, run_argv
from osintcc.aiv import tools
from test_aiv_core import (
    B,
    approve,
    enable,
    mk_auth,
    mk_case,
    mk_plan,
    obs,
      run,
)

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "aiv"
OK_TEMPLATE = (FIX / "nuclei_template_ok.yaml").read_text(encoding="utf-8")


# ---- health: a missing, wrong or unreviewed program is reported as such --------------------------------------------------------------------
class _Res:
    def __init__(self, out: str, rc: int = 0):
        self.stdout, self.stderr, self.returncode, self.timed_out = out.encode(), b"", rc, False


async def _health(monkeypatch, tool_id: str, which: str | None, output: str = ""):
    monkeypatch.setattr(tools.shutil, "which", lambda n: which)

    async def fake_run(argv, timeout, **kw):
        return _Res(output)
    monkeypatch.setattr(tools, "run_argv", fake_run)
    return await tools._probe_uncached(tools.TOOLS[tool_id])


async def test_tool_health_states_are_truthful(monkeypatch):
    assert (await _health(monkeypatch, "nmap", None))["status"] == "not_installed"
    ok = await _health(monkeypatch, "nmap", "/usr/bin/nmap", "Nmap version 7.98 ( https://nmap.org )")
    assert ok["status"] == "healthy" and ok["version"] == "7.98"
    new = await _health(monkeypatch, "nmap", "/usr/bin/nmap", "Nmap version 9.01 ( https://nmap.org )")
    assert new["status"] == "unverified_version" and "will not be run" in new["detail"]
    # the Python HTTP client installs a program called `httpx`; it must never be mistaken for ProjectDiscovery httpx
    wrong = await _health(monkeypatch, "httpx_pd", "/usr/bin/httpx", "Usage: httpx [OPTIONS] URL\n  A next generation HTTP client.")
    assert wrong["status"] == "wrong_program" and "Python HTTP client" in wrong["detail"]
    pd = await _health(monkeypatch, "httpx_pd", "/usr/bin/httpx-toolkit", "[INF] Current Version: v1.12.0\nprojectdiscovery.io")
    assert pd["status"] == "healthy" and pd["version"] == "1.12"
    nu = await _health(monkeypatch, "nuclei", "/usr/bin/nuclei", "[INF] Nuclei Engine Version: v3.11.1\n[INF] projectdiscovery.io")
    assert nu["status"] == "healthy"
    dt = await _health(monkeypatch, "dnstwist", "/usr/bin/dnstwist", "dnstwist 20240812\n\nUsage: dnstwist [OPTION]")
    assert dt["status"] == "healthy" and dt["version"] == "2024.08.12"


# ---- parsers on real captures --------------------------------------------------------------------------------------------------------------
def test_nmap_xml_from_the_real_tool_is_parsed_and_entities_are_refused():
    rows = tools.parse_nmap_xml((FIX / "nmap_ports.xml").read_bytes())
    assert [(r["port"], r["state"]) for r in rows] == [(8080, "open")]
    evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "boom">]><nmaprun><host><ports/></host></nmaprun>'
    with pytest.raises(ValueError):
        tools.parse_nmap_xml(evil)


def test_naabu_duplicates_collapse_to_one_port_and_junk_lines_are_ignored():
    rows = tools.parse_jsonl((FIX / "naabu_ports.jsonl").read_bytes() + b"\nnot json\n[1,2]\n")
    assert len(rows) >= 2 and {r["port"] for r in rows} == {8080}
    assert {int(r["port"]): "open" for r in rows} == {8080: "open"}


def test_nuclei_output_becomes_a_signature_observation_with_a_remedy():
    o = tools.nuclei_observations(tools.parse_jsonl((FIX / "nuclei_match.jsonl").read_bytes()))
    assert len(o) == 1 and o[0].severity == "low" and o[0].observed["template_id"] == "lab-apache-banner" and "ServerTokens" in o[0].remediation


# ---- fixed argv: target text is one element, and no risky flag exists in any builder -------------------------------------------------------------
def test_argv_builders_use_fixed_flags_and_keep_the_target_as_a_single_element():
    nmap = tools.nmap_argv("nmap", "127.0.0.1", [80, 443], version_probe=True)
    assert "-sT" in nmap and "-Pn" in nmap and nmap[-1] == "127.0.0.1" and not {"-sS", "-sU", "-A", "-O", "--script", "-T5", "-iL", "-oN", "--script-args"} & set(nmap)
    assert nmap[nmap.index("-p") + 1] == "80,443" and "--max-rate" in nmap
    naabu = tools.naabu_argv("naabu", "127.0.0.1", [80])
    assert "-rate" in naabu and "-c" in naabu and not {"-nmap-cli", "-top-ports", "-p-", "-list", "-iL"} & set(naabu)
    nuc = tools.nuclei_argv("nuclei", "/t/x.yaml", "http://lab.test:80/")
    assert "-ni" in nuc and "-rl" in nuc and not {"-headless", "-code", "-dast", "-fuzz", "-w", "-workflows", "-l", "-tags", "-severity", "-update-templates", "-ut"} & set(nuc)
    assert nuc[nuc.index("-u") + 1] == "http://lab.test:80/" and nuc[nuc.index("-t") + 1] == "/t/x.yaml"
    twist = tools.dnstwist_argv("dnstwist", "example.com")
    assert twist == ["dnstwist", "-f", "list", "example.com"]
    nasty = "example.com; rm -rf /"
    assert tools.dnstwist_argv("dnstwist", nasty)[-1] == nasty and len(tools.dnstwist_argv("dnstwist", nasty)) == 4


T = Target(type="domain", raw="example.com", canonical="example.com")


async def test_dnstwist_adapter_generates_candidates_without_any_network():
    a = DnstwistAdapter()
    assert a.manifest.operation_class == "local_only" and a.manifest.needs_network is False and a.manifest.default_selected is False
    argv = a.build_argv("dnstwist", T)
    assert argv == ["dnstwist", "-f", "list", "example.com"]
    assert not {"-r", "--registered", "-w", "--whois", "-b", "--banners", "-g", "--geoip", "-m", "--mxcheck", "-p", "--phash", "--lsh", "--screenshots", "-d", "--dictionary", "--tld"} & set(argv)
    findings, rels = a.parse(T, (FIX / "dnstwist_list.txt").read_bytes() + b"example.com\n; rm -rf\n")
    cands = [f for f in findings if f.predicate == "lookalike.candidate"]
    count = next(f for f in findings if f.predicate == "lookalike.candidate_count")
    assert count.value == 40 and len(cands) == 40
    assert all(f.confidence == "low" for f in cands) and "example.com" not in {f.value["domain"] for f in cands} and rels == []


# ---- the allowlist: a template runs only if approved by id AND content hash --------------------------------------------------------------------
BAD = {
    "raw request": "id: bad-raw\ninfo:\n  name: x\n  severity: low\nhttp:\n  - raw:\n      - |\n        GET / HTTP/1.1\n    matchers:\n      - type: word\n        words: [a]\n",
    "payloads": "id: bad-pay\ninfo:\n  name: x\n  severity: low\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/{{p}}']\n    payloads:\n      p: [a, b]\n    matchers:\n      - type: word\n        words: [a]\n",
    "post body": "id: bad-post\ninfo:\n  name: x\n  severity: low\nhttp:\n  - method: POST\n    path: ['{{BaseURL}}/']\n    body: a=1\n    matchers:\n      - type: word\n        words: [a]\n",
    "custom headers": "id: bad-hdr\ninfo:\n  name: x\n  severity: low\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/']\n    headers:\n      X-A: b\n    matchers:\n      - type: word\n        words: [a]\n",
    "other protocol": "id: bad-dns\ninfo:\n  name: x\n  severity: low\ndns:\n  - name: '{{FQDN}}'\n    type: A\n",
    "oast": "id: bad-oast\ninfo:\n  name: x\n  severity: low\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/?u={{interactsh-url}}']\n    matchers:\n      - type: word\n        words: [a]\n",
    "off host path": "id: bad-host\ninfo:\n  name: x\n  severity: low\nhttp:\n  - method: GET\n    path: ['http://elsewhere.test/']\n    matchers:\n      - type: word\n        words: [a]\n",
    "flow": "id: bad-flow\nflow: http(1)\ninfo:\n  name: x\n  severity: low\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/']\n    matchers:\n      - type: word\n        words: [a]\n",
}


@pytest.mark.parametrize("name", sorted(BAD))
def test_templates_with_risky_semantics_are_rejected_statically(name):
    r = tools.review_template(BAD[name])
    assert r["ok"] is False and r["errors"], name


def test_a_plain_fingerprint_template_is_accepted_and_its_requests_are_summarised():
    r = tools.review_template(OK_TEMPLATE)
    assert r["ok"] and r["semantics"]["methods"] == ["GET"] and r["semantics"]["request_count"] == 1 and r["id"] == "lab-apache-banner"


async def test_template_approval_is_by_id_and_hash_and_needs_the_reviewer_to_confirm(env):
    await enable(env)
    api = env["api"]
    rv = (await api.post(f"{B}/aiv/templates/review", json={"content": OK_TEMPLATE})).json()
    assert rv["ok"] and len(rv["sha256"]) == 64
    assert (await api.get(f"{B}/aiv/templates")).json()["items"] == []                  # reviewing stored nothing
    r = await api.post(f"{B}/aiv/templates", json={"content": OK_TEMPLATE})
    assert r.status_code == 422 and r.json()["code"] == "confirmation_required"
    r = await api.post(f"{B}/aiv/templates", json={"content": BAD["raw request"], "confirm_reviewed": True})
    assert r.status_code == 422 and r.json()["code"] == "template_rejected"
    ok = await api.post(f"{B}/aiv/templates", json={"content": OK_TEMPLATE, "confirm_reviewed": True})
    assert ok.status_code == 201 and ok.json()["sha256"] == rv["sha256"]
    again = await api.post(f"{B}/aiv/templates", json={"content": OK_TEMPLATE, "confirm_reviewed": True})
    assert again.json()["already_approved"] is True
    # an edited template is a different template: same id, new hash, needs its own review and replaces the old approval
    edited = OK_TEMPLATE.replace("Apache/2.4.41", "Apache/2.4.42")
    ok2 = await api.post(f"{B}/aiv/templates", json={"content": edited, "confirm_reviewed": True})
    assert ok2.json()["sha256"] != rv["sha256"]
    items = (await api.get(f"{B}/aiv/templates")).json()["items"]
    assert [i["sha256"] for i in items if not i.get("revoked_at")] == [ok2.json()["sha256"]]
    # a tampered stored row is refused at load time
    from osintcc.db.models import AivTemplateApproval
    from sqlalchemy import select
    with env["st"].sm() as db:
        row = db.scalars(select(AivTemplateApproval).where(AivTemplateApproval.revoked_at.is_(None))).one()
        row.content = row.content.replace("low", "high")
        db.commit()
        with pytest.raises(ValueError, match="no longer matches"):
            tools.load_approved_template(db, "lab-apache-banner")


async def test_a_plan_naming_an_unapproved_template_is_refused_before_any_request(env):
    await enable(env)
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port], classes=("signature_check",))
    r = await env["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": a["id"], "steps": [{"kind": "signature_check", "url": f"http://lab.test:{lb.port}/", "template_ids": ["lab-apache-banner"]}]})
    assert r.status_code == 422 and r.json()["code"] == "template_not_approved" and lb.connections == 0
    r = await env["api"].post(f"{B}/cases/{cid}/aiv/plans", json={"authorization_id": a["id"], "steps": [{"kind": "signature_check", "url": f"http://lab.test:{lb.port}/", "template_ids": ["../../etc/passwd"]}]})
    assert r.status_code == 422                                                         # an id is a name, never a path


# ---- end to end with stand-in programs that replay the real captures -----------------------------------------------------------------------------
def _replay(path: Path):
    code = "import sys;sys.stdout.buffer.write(open(sys.argv[1],'rb').read())"
    return lambda *a, **k: [sys.executable, "-c", code, str(path)]


@pytest.fixture
def stand_in(monkeypatch):
    async def fake_path(tool_id):
        return sys.executable
    monkeypatch.setattr(tools, "tool_path", fake_path)
    argv_seen: list[list[str]] = []

    def wrap(name: str, fixture: str):
        real = _replay(FIX / fixture)

        def build(*a, **k):
            argv_seen.append(getattr(tools, f"_orig_{name}")(*a, **k))
            return real()
        return build
    for name, fx in (("nmap_argv", "nmap_ports.xml"), ("naabu_argv", "naabu_ports.jsonl"), ("nuclei_argv", "nuclei_match.jsonl")):
        setattr(tools, f"_orig_{name}", getattr(tools, name))
        monkeypatch.setattr(tools, name, wrap(name, fx))
    yield argv_seen
    for name in ("nmap_argv", "naabu_argv", "nuclei_argv"):
        if hasattr(tools, f"_orig_{name}"):
            delattr(tools, f"_orig_{name}")


async def test_service_detection_runs_one_tool_on_the_resolved_address_and_records_open_and_closed_ports(env, stand_in):
    await enable(env)
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [8080, 8081], classes=("service_detect",))
    p = await mk_plan(env, cid, a["id"], [{"kind": "service_detect", "host": "lab.test", "ports": [8080, 8081], "tool": "nmap"}])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    assert r["status"] == "completed"
    items = {i["observed"]["port"]: i["observed"]["state"] for i in await obs(env, cid, r["id"]) if i["observed"].get("port")}
    assert items == {8080: "open", 8081: "closed_or_filtered"}
    argv = stand_in[0]
    assert argv[-1] == "127.0.0.1" and "-sT" in argv and "lab.test" not in argv         # the tool got the address that was checked, never the name
    p2 = await mk_plan(env, cid, a["id"], [{"kind": "service_detect", "host": "lab.test", "ports": [8080], "tool": "naabu"}])
    r2 = await run(env, p2["id"], (await approve(env, p2["id"]))["approval_id"])
    assert {i["observed"]["port"]: i["observed"]["state"] for i in await obs(env, cid, r2["id"]) if i["observed"].get("port") == 8080} == {8080: "open"}


async def test_service_detection_is_blocked_when_the_name_resolves_into_forbidden_space(env, stand_in):
    await enable(env)
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["meta.test"], [8080], classes=("service_detect",))
    p = await mk_plan(env, cid, a["id"], [{"kind": "service_detect", "host": "meta.test", "ports": [8080], "tool": "nmap"}])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    assert stand_in == [] and r["status"] != "completed"


async def test_signature_check_runs_only_an_approved_template_and_stores_the_match(env, stand_in):
    await enable(env)
    assert (await env["api"].post(f"{B}/aiv/templates", json={"content": OK_TEMPLATE, "confirm_reviewed": True})).status_code == 201
    lb = await env["lab"]()
    cid = await mk_case(env)
    a = await mk_auth(env, cid, ["lab.test"], [lb.port], classes=("signature_check",))
    p = await mk_plan(env, cid, a["id"], [{"kind": "signature_check", "url": f"http://lab.test:{lb.port}/", "template_ids": ["lab-apache-banner"]}])
    r = await run(env, p["id"], (await approve(env, p["id"]))["approval_id"])
    assert r["status"] == "completed"
    assert any("lab-apache-banner" in str(i) for i in await obs(env, cid, r["id"]))
    argv = stand_in[0]
    assert "-ni" in argv and "-duc" in argv and "-u" in argv and argv[argv.index("-u") + 1].startswith("http://lab.test:")
    assert lb.connections == 0                                                          # the stand-in sent nothing; the real tool's flags are covered above


# ---- a cancelled tool run leaves no orphan -------------------------------------------------------------------------------------------------
def _alive(pid: int) -> bool:
    if sys.platform == "win32":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], check=False, capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:                                                                                # a zombie is dead for our purposes
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except OSError:
        return True


async def test_cancelling_a_tool_run_kills_the_whole_process_tree(tmp_path):
    pidfile = tmp_path / "child.pid"
    script = textwrap.dedent(f"""
        import subprocess, sys, time
        c = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        open({str(pidfile)!r}, "w").write(str(c.pid))
        time.sleep(120)
    """)
    task = asyncio.create_task(run_argv([sys.executable, "-c", script], 120))
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text():
            break
        await asyncio.sleep(0.1)
    child = int(pidfile.read_text())
    assert _alive(child)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    for _ in range(50):
        if not _alive(child):
            break
        await asyncio.sleep(0.1)
    assert not _alive(child), "the tool's child process survived cancellation"


# ---- real binaries, where present ----------------------------------------------------------------------------------------------------------
@pytest.mark.skipif(not shutil.which("nmap"), reason="nmap is not installed here (covered on the Linux image)")
async def test_real_nmap_connect_scan_of_a_lab_port(env):
    lb = await env["lab"]()
    exe = shutil.which("nmap")
    t0 = time.monotonic()
    res = await run_argv(tools.nmap_argv(exe, "127.0.0.1", [lb.port]), 60)
    assert res.returncode == 0 and any(r["port"] == lb.port and r["state"] == "open" for r in tools.parse_nmap_xml(res.stdout)) and time.monotonic() - t0 < 60


@pytest.mark.skipif(not shutil.which("dnstwist"), reason="dnstwist is not installed here (covered on the Linux image)")
async def test_real_dnstwist_lists_candidates_offline():
    res = await run_argv(tools.dnstwist_argv(shutil.which("dnstwist"), "example.com"), 60)
    assert res.returncode == 0 and len(res.stdout.splitlines()) > 20
