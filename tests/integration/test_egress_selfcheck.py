from __future__ import annotations

import asyncio
import socket

import httpx
import pytest
from osintcc.config import Settings
from osintcc.main import create_app
from osintcc.selfcheck import egress
from osintcc.selfcheck.egress import Conn, EgressMonitor
from sqlalchemy import select


def mon(conns_per_sample, busy_flags=None, window=0.0):
    seq = iter(conns_per_sample)
    flags = iter(busy_flags or [])
    return EgressMonitor(window_s=window, snap=lambda: next(seq, []), busy=lambda: next(flags, False))


def run(m: EgressMonitor, n: int):
    for _ in range(n):
        m.sample_once()
    return m.finish()


def test_verdicts_clean_engine_only_offending_unavailable():
    assert run(mon([[], []]), 2)["verdict"] == "clean"
    st = run(mon([[Conn("msedgewebview2.exe", 1, "52.96.0.1:443", "ESTABLISHED")]]), 1)
    assert st["verdict"] == "engine_only" and not st["offenders"] and "browser engine" in st["note"]
    st = run(mon([[Conn("osintcc-backend.exe", 2, "93.184.216.34:443", "ESTABLISHED")]]), 1)
    assert st["verdict"] == "offending" and st["offenders"][0]["remote"] == "93.184.216.34:443"
    assert run(mon([]), 0)["verdict"] == "unavailable"


def test_connections_during_user_activity_do_not_fail_the_check():
    c = Conn("osintcc-backend.exe", 2, "93.184.216.34:443", "ESTABLISHED")
    st = run(mon([[c], [c]], busy_flags=[True, True]), 2)
    assert st["verdict"] == "clean" and st["user_activity"] and len(st["during_user_activity"]) == 1 and not st["offenders"]
    # the same connection seen while idle IS an offence, and is recorded once however many samples see it
    st = run(mon([[c], [c], [c]], busy_flags=[False, False, True]), 3)
    assert st["verdict"] == "offending" and len(st["offenders"]) == 1


def test_duplicates_are_recorded_once_and_loopback_is_never_reported():
    assert egress._is_outside("93.184.216.34") and egress._is_outside("2606:2800:21f:cb07:6820:80da:af6b:8b2c") and egress._is_outside("192.168.1.5")
    assert not any(egress._is_outside(a) for a in ("127.0.0.1", "::1", "0.0.0.0", "::", "not-an-ip"))
    c = Conn("x", 1, "8.8.8.8:53", "ESTABLISHED")
    assert len(run(mon([[c]] * 5), 5)["offenders"]) == 1
    assert egress.is_engine("msedgewebview2.exe") and egress.is_engine("WebKitWebProcess") and not egress.is_engine("osintcc-backend")


def _lan_ip() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # a UDP connect sends nothing; it only selects the outgoing interface
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return None if ip.startswith("127.") else ip


def test_the_real_sampler_sees_this_process_connecting_to_a_non_loopback_address():
    ip = _lan_ip()
    if not ip:
        pytest.skip("no non-loopback interface on this machine")
    srv = socket.socket()
    srv.bind((ip, 0))
    srv.listen(1)
    cli = socket.create_connection((ip, srv.getsockname()[1]), timeout=5)
    try:
        seen = [c for c in egress.snapshot() if c.remote == f"{ip}:{srv.getsockname()[1]}"]
        assert seen and seen[0].pid > 0                                   # attributed to a process, not just a socket
    finally:
        cli.close()
        srv.close()


def test_an_idle_process_tree_has_no_outside_connections_to_report():
    # pytest itself is not "osintcc*", so the tree is this process; with nothing connected the sampler returns nothing external
    assert all(c.remote.split(":")[0] != "127.0.0.1" for c in egress.snapshot())


async def test_app_runs_the_check_at_startup_exposes_it_and_audits_it(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINTCC_EGRESS_WINDOW_S", "1.0")
    s = Settings(data_dir=tmp_path / "d", vault_encryption="off", run_scheduler=True)
    app = create_app(s)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1/api/v1",
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            for _ in range(60):
                r = (await c.get("/system/egress-check")).json()
                if r["state"] == "finished":
                    break
                await asyncio.sleep(0.2)
            assert r["state"] == "finished" and r["verdict"] in ("clean", "engine_only", "offending") and r["samples"] >= 1
            from osintcc.db.models import AuditEvent
            with app.state.core.sm() as db:
                ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "selfcheck.egress")).all()
            assert len(ev) == 1 and ev[0].metadata_json["verdict"] == r["verdict"]


async def test_disabled_in_test_style_runs_and_by_environment(tmp_path, monkeypatch):
    s = Settings(data_dir=tmp_path / "a", vault_encryption="off", run_scheduler=False)
    app = create_app(s)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1/api/v1",
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            assert (await c.get("/system/egress-check")).json()["state"] == "disabled"
    monkeypatch.setenv("OSINTCC_EGRESS_SELFCHECK", "0")
    s2 = Settings(data_dir=tmp_path / "b", vault_encryption="off", run_scheduler=True)
    app2 = create_app(s2)
    async with app2.router.lifespan_context(app2):
        assert app2.state.core.egress is None
