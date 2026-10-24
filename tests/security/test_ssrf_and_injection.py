from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from osintcc.adapters.base import AdapterContext, Target
from osintcc.adapters.cli import SubfinderAdapter, run_argv
from osintcc.evidence.vault import IntegrityError, Vault, VaultError
from osintcc.policy.ssrf import DestinationDenied, SafeHttp, ip_is_public, validate_host


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254", "::1",
                                "fe80::1", "fd00::1", "0.0.0.0", "100.100.100.200", "::ffff:127.0.0.1",
                                "224.0.0.1", "240.0.0.1"])
def test_private_ips_denied(ip):
    assert not ip_is_public(ip)


def test_public_ip_allowed():
    assert ip_is_public("93.184.216.34") and ip_is_public("2606:2800:21f:cb07:6820:80da:af6b:8b2c")


async def _resolver_to(ip):
    async def r(host):
        return [ip]
    return r


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
                                 "http://[::1]/", "http://10.1.1.1:8080/", "http://localhost/"])
async def test_literal_and_localhost_denied(url):
    async def local_resolver(h):
        return ["127.0.0.1"]
    http = SafeHttp(resolver=local_resolver, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(DestinationDenied):
        await http.get(url)


async def test_dns_rebinding_hostname_resolving_private_denied():
    async def r(h):
        return ["93.184.216.34", "10.0.0.7"]  # any private answer poisons the set
    with pytest.raises(DestinationDenied):
        await validate_host("evil.example.com", r)


async def test_redirect_to_private_denied():
    seen = []

    def handler(req: httpx.Request):
        seen.append(str(req.url))
        if req.url.host == "public.example.com":
            return httpx.Response(302, headers={"location": "http://internal.example.com/admin"})
        return httpx.Response(200, text="secret")

    async def r(host):
        return ["93.184.216.34"] if host == "public.example.com" else ["192.168.1.10"]

    http = SafeHttp(resolver=r, transport=httpx.MockTransport(handler))
    with pytest.raises(DestinationDenied):
        await http.get("https://public.example.com/")
    assert seen == ["https://public.example.com/"]  # the internal host was never requested


async def test_redirect_loop_and_scheme_denied():
    def handler(req):
        return httpx.Response(302, headers={"location": "https://public.example.com/again"})

    async def r(h):
        return ["93.184.216.34"]
    with pytest.raises(DestinationDenied):
        await SafeHttp(resolver=r, transport=httpx.MockTransport(handler)).get("https://public.example.com/")
    with pytest.raises(DestinationDenied):
        await SafeHttp(resolver=r, transport=httpx.MockTransport(handler)).get("file:///etc/passwd")


async def test_response_size_cap():
    big = b"x" * (9 * 1024 * 1024)

    async def r(h):
        return ["93.184.216.34"]
    http = SafeHttp(resolver=r, transport=httpx.MockTransport(lambda q: httpx.Response(200, content=big)))
    with pytest.raises(DestinationDenied):
        await http.get("https://public.example.com/")


# ---- command injection ----------------------------------------------------------------------------------------
EVIL = ["; touch PWNED", "$(touch PWNED)", "`touch PWNED`", "a && touch PWNED", "a | touch PWNED",
        "x\ntouch PWNED", "x' ; touch PWNED #", '"; touch PWNED; "', "%COMSPEC% /c echo PWNED > PWNED",
        "-oX /etc/passwd", "--help"]


@pytest.mark.parametrize("payload", EVIL)
async def test_target_text_is_one_argv_element_never_executed(tmp_path, payload):
    script = tmp_path / "fake.py"
    script.write_text("import sys, json\n"
                      "json.dump(sys.argv[1:], open(sys.argv[0] + '.argv', 'w'))\n")
    marker = tmp_path / "PWNED"
    res = await run_argv([sys.executable, str(script), payload], 20)
    assert res.returncode == 0
    import json
    assert json.loads(Path(str(script) + ".argv").read_text()) == [payload]
    assert not marker.exists() and not (Path.cwd() / "PWNED").exists()


async def test_subfinder_adapter_builds_argv_without_shell():
    ad = SubfinderAdapter()
    argv = ad.build_argv("/bin/subfinder", Target(type="domain", raw="x", canonical="example.com"))
    assert argv == ["/bin/subfinder", "-d", "example.com", "-silent", "-json"]


async def test_cli_adapter_runs_fake_binary_and_parses(tmp_path):
    fake = tmp_path / "subfinder.py"
    fake.write_text('import sys,json\n'
                    'for h in ["a.example.com","b.example.com","a.example.com","evil.org"]:\n'
                    '    print(json.dumps({"host": h}))\n')
    wrapper = tmp_path / ("subfinder.cmd" if sys.platform == "win32" else "subfinder")
    wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{fake}" %*\r\n' if sys.platform == "win32"
                       else f'#!/bin/sh\nexec "{sys.executable}" "{fake}" "$@"\n')
    wrapper.chmod(0o755)
    from osintcc.adapters.cli import SubfinderAdapter as S
    ad = S(binary_path=str(wrapper))
    h = await ad.health()
    assert h["status"] in ("healthy", "degraded")
    from osintcc.policy.ssrf import SafeHttp as H
    res = await ad.run(Target(type="domain", raw="example.com", canonical="example.com"), AdapterContext(http=H()))
    assert res.status == "success"
    assert sorted(f.subject.key for f in res.findings) == ["a.example.com", "b.example.com"]  # dedup + scope filter


async def test_cli_timeout_kills_process(tmp_path):
    script = tmp_path / "sleep.py"
    script.write_text("import time; time.sleep(60)\n")
    res = await run_argv([sys.executable, str(script)], 1)
    assert res.timed_out


async def test_missing_binary_reports_not_installed():
    ad = SubfinderAdapter(binary_path="Z:/definitely/not/here")
    ad.binary_names = ("definitely-not-a-real-binary-xyz",)
    assert (await ad.health())["status"] == "not_installed"
    res = await ad.run(Target(type="domain", raw="x.com", canonical="x.com"), AdapterContext(http=SafeHttp()))
    assert res.status == "skipped" and res.error_code == "not_installed"


# ---- vault ------------------------------------------------------------------------------------------------------
def test_vault_roundtrip_and_tamper_detection(tmp_path):
    v = Vault(tmp_path / "v")
    sha, sha512, rel, size = v.store(b"hello")
    assert v.read(rel, sha) == b"hello" and size == 5 and len(sha512) == 128
    assert v.store(b"hello")[2] == rel  # content addressed, idempotent
    (tmp_path / "v" / rel).write_bytes(b"tampered")
    with pytest.raises(IntegrityError):
        v.read(rel, sha)
    assert not v.verify(rel, sha)


@pytest.mark.parametrize("rel", ["../../etc/passwd", "sha256/../../x", "/etc/passwd", "C:/Windows/win.ini",
                                 "..\\..\\x"])
def test_vault_path_traversal_blocked(tmp_path, rel):
    v = Vault(tmp_path / "v")
    with pytest.raises(VaultError):
        v.read(rel)


def test_vault_rejects_bad_digest(tmp_path):
    with pytest.raises(VaultError):
        Vault(tmp_path).relpath("../../evil")


def test_vault_stream_size_cap(tmp_path):
    import io
    v = Vault(tmp_path / "v")
    with pytest.raises(VaultError):
        v.store_stream(io.BytesIO(b"x" * 5000), max_bytes=1000)
    assert not any(p.name.startswith(".import-") for p in (tmp_path / "v").iterdir())  # temp cleaned


def _alive(pid: int) -> bool:
    if sys.platform == "win32":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, check=False).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


async def test_timeout_kills_helper_processes_too(tmp_path):
    """Tools like amass start helper processes; a timeout must not leave them running."""
    pidfile = tmp_path / "child.pid"
    child = tmp_path / "child.py"
    child.write_text(f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(120)\n")
    parent = tmp_path / "parent.py"
    parent.write_text(f"import subprocess, sys, time; subprocess.Popen([sys.executable, {str(child)!r}]); time.sleep(120)\n")
    res = await run_argv([sys.executable, str(parent)], 3)
    assert res.timed_out and pidfile.exists()
    pid = int(pidfile.read_text())
    for _ in range(20):
        if not _alive(pid):
            break
        await asyncio.sleep(0.25)
    assert not _alive(pid)
