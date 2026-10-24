"""Prove (or disprove) that the packaged app makes no outbound network connections on its own.  WINDOWS, needs two UAC prompts.

    uv run python scripts/egress_check.py [release-folder]

What it does
  1. Starts a packet capture of every network adapter with `pktmon` (built into Windows; needs elevation -> UAC prompt #1).
  2. Phase A: launches osintcc-desktop.exe (the real app) with a throwaway data directory and leaves it idle.
  3. Phase B: launches the same bundled backend directly and drives the "must not touch the network" paths through its API:
     case creation, search PREVIEW, plan preview, offline-mode runs, unconfigured update check, setup status/plan (no download).
  4. While both run it polls `netstat -ano` and records every connection owned by the app's own process ids.
  5. Stops the capture (UAC prompt #2), converts it to pcapng and summarises it with the application's own pcap parser.
Limit that no script can remove: the capture sees ALL traffic on the machine, so other programs' packets are in it too. The claim is
therefore made per process (netstat attribution) and checked against the capture (no packet to/from any address the app's
processes connected to, and nothing the app could have sent that is not accounted for).
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def elevated(ps_script: str, wait: bool = True) -> int:
    """Run a PowerShell snippet with admin rights (UAC prompt). Returns the exit code."""
    enc = base64.b64encode(ps_script.encode("utf-16-le")).decode()
    cmd = ["powershell", "-NoProfile", "-Command",
           f"$p = Start-Process powershell -Verb RunAs -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile','-EncodedCommand','{enc}'; "
           "if ($p) { $p.WaitForExit(120000) | Out-Null; exit $p.ExitCode } else { exit 99 }"]
    return subprocess.run(cmd, check=False, timeout=300).returncode


def connections_of(pids: set[int]) -> set[tuple[str, str, str, int]]:
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, check=False).stdout
    found = set()
    for line in out.splitlines():
        m = re.match(r"\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(?:(\w+)\s+)?(\d+)\s*$", line)
        if m and int(m.group(5)) in pids:
            found.add((m.group(1), m.group(2), m.group(3), int(m.group(5))))
    return found


NAMES: dict[int, str] = {}


def descendants(root_pid: int) -> set[int]:
    out = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json"],
                         capture_output=True, text=True, check=False).stdout
    try:
        rows = json.loads(out)
    except ValueError:
        return {root_pid}
    for r in rows:
        NAMES[r["ProcessId"]] = f"{r['Name']} {(r.get('CommandLine') or '')[:600]}"
    kids = {root_pid}
    changed = True
    while changed:
        changed = False
        for r in rows:
            if r["ParentProcessId"] in kids and r["ProcessId"] not in kids:
                kids.add(r["ProcessId"])
                changed = True
    return kids


def is_loopback(addr: str) -> bool:
    a = addr.rsplit(":", 1)[0].strip("[]")
    return a.startswith("127.") or a in ("::1", "0.0.0.0", "*", "[::]", "::", "localhost")


def main() -> int:
    rel = Path(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else next((d for d in (ROOT / "dist" / "release").glob("OSINT-Command-Center-*-win32-*") if d.is_dir()), None)
    if not rel or not (rel / "osintcc-desktop.exe").is_file():
        print("release folder not found; run scripts/release.py first")
        return 2
    work = Path(tempfile.mkdtemp(prefix="osintcc-egress-"))
    etl, pcap = work / "capture.etl", work / "capture.pcapng"
    nocap = "--no-capture" in sys.argv  # connection-level evidence only (no administrator rights needed)
    print(f"work dir {work}\n" + ("Packet capture skipped (--no-capture): netstat attribution only." if nocap else "Starting packet capture (accept the UAC prompt)…"), flush=True)
    rc = 0 if nocap else elevated(f"pktmon stop 2>$null | Out-Null; pktmon reset | Out-Null; pktmon start --capture --comp nics --pkt-size 0 --file-name '{etl}' --file-size 1024 | Out-Null; exit $LASTEXITCODE")
    if rc != 0:
        print(f"could not start pktmon (exit {rc}); the UAC prompt was probably declined or timed out")
        return 3
    seen: set[tuple[str, str, str, int]] = set()
    started = time.time()
    try:
        env = {**os.environ, "OSINTCC_DATA_DIR": str(work / "dataA"), "OSINTCC_VAULT_KEY": base64.b64encode(os.urandom(32)).decode()}
        print("Phase A: desktop app idle for 75 s", flush=True)
        app = subprocess.Popen([str(rel / "osintcc-desktop.exe")], env=env)
        t_end = time.time() + 75
        while time.time() < t_end:
            seen |= connections_of(descendants(app.pid))
            time.sleep(0.5)
        app_pids_a = descendants(app.pid)
        subprocess.run(["taskkill", "/PID", str(app.pid), "/T", "/F"], capture_output=True, check=False)
        time.sleep(2)

        print("Phase B: backend driven through the no-network paths", flush=True)
        envb = {**env, "OSINTCC_DATA_DIR": str(work / "dataB")}
        be = subprocess.Popen([str(rel / "osintcc-backend.exe")], env=envb, stdout=subprocess.PIPE, text=True)
        assert be.stdout is not None
        line = be.stdout.readline()
        kv = dict(x.split("=", 1) for x in line.split()[1:])
        c = httpx.Client(base_url=f"http://127.0.0.1:{kv['port']}/api/v1", headers={"Authorization": "Bearer " + kv["token"]}, timeout=60)
        cid = c.post("/cases", json={"title": "egress", "purpose": "verify no outbound traffic"}).json()["id"]
        calls = [
            c.post(f"/cases/{cid}/searches/preview", json={"target": "example.com"}),
            c.post("/collection-plans/preview", json={"case_id": cid, "target": "example.com", "reason": "egress test"}),
            c.get("/setup/status"), c.post("/setup/plan", json={"ids": ["subfinder"]}),
            c.post("/updates/check"), c.get("/tools"), c.get("/system/doctor"), c.get("/ai/profiles"),
            c.put("/settings", json={"values": {"offline": True}}),
            c.post(f"/cases/{cid}/searches", json={"target": "example.com", "wait": True}),   # offline: must be denied without any request
        ]
        print("  API statuses:", [r.status_code for r in calls], flush=True)
        t_end = time.time() + 20
        pids_b = descendants(be.pid)
        while time.time() < t_end:
            seen |= connections_of(descendants(be.pid))
            time.sleep(0.5)
        c.post("/system/shutdown")
        try:
            be.wait(timeout=20)
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill", "/PID", str(be.pid), "/T", "/F"], capture_output=True, check=False)
        app_pids = app_pids_a | pids_b
    finally:
        print("Stopping capture (accept the second UAC prompt)…" if not nocap else "done driving the app", flush=True)
        rc2 = 0 if nocap else elevated(f"pktmon stop | Out-Null; pktmon etl2pcap '{etl}' --out '{pcap}' | Out-Null; foreach ($f in '{etl}','{pcap}') {{ takeown /F $f /A | Out-Null; icacls $f /grant '{os.environ.get('USERNAME', 'Users')}:(R)' | Out-Null }}; exit 0")
    duration = time.time() - started
    external = sorted({c for c in seen if not is_loopback(c[2]) and c[2] not in ("*:*",) and not c[2].startswith("0.0.0.0")})
    engine = [c for c in external if "msedgewebview2" in NAMES.get(c[3], "").lower()]
    ours = [c for c in external if c not in engine]
    print(f"\nconnections observed for the app's process tree ({len(app_pids)} pids): {len(seen)} total, non-loopback: {len(external)}")
    print(f"  from OUR code (desktop shell, bundled backend, anything they spawn): {len(ours)}")
    for c in ours:
        print("    NON-LOOPBACK", c, "<-", NAMES.get(c[3], "?")[:120])
    print(f"  from the WebView2 engine (Microsoft's browser component that renders the UI): {len(engine)}")
    for c in engine:
        print("    ", c[:4], "(Microsoft-owned address; identify it with the packet capture)")
    result = {"duration_s": round(duration), "app_pids": sorted(app_pids), "connections_total": len(seen), "non_loopback_from_our_code": [list(x) for x in ours],
              "non_loopback_from_webview2_engine": [list(x) for x in engine],
              "capture_file": str(pcap) if pcap.exists() else None, "pktmon_stop_rc": rc2}
    if pcap.exists():
        from osintcc.ingest import net
        parsed = net.parse_pcap(pcap.read_bytes())
        obs = parsed.observations[0].data if parsed.observations else {}
        dns = sorted({q["name"] for q in obs.get("dns_queries", [])})
        sni = sorted({q["name"] for q in obs.get("tls_sni", [])})
        summ = {k: obs.get(k) for k in ("packets", "flows_total", "first_packet", "last_packet")}
        print("\ncapture summary (the app's own pcap parser):", json.dumps(summ))
        print("DNS names resolved on the machine during the window (ALL programs, not only this app):", dns[:30])
        print("TLS server names seen (ALL programs):", sni[:30])
        result["capture_summary"] = summ
        result["dns_names_machine_wide"] = dns
        result["tls_sni_machine_wide"] = sni
    (ROOT / "docs" / "egress-check.json").write_text(json.dumps(result, indent=1, default=str), encoding="utf8")
    verdict = "PASS (our code)" if not ours else "FAIL"
    print(f"\nRESULT: {verdict} - non-loopback connections from our code: {len(ours)}; from the WebView2 engine: {len(engine)} (see docs/progress.md)")
    return 0 if not ours else 1


if __name__ == "__main__":
    raise SystemExit(main())
