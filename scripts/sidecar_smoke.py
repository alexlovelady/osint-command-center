"""Smoke-test the FROZEN backend (dist/sidecar/osintcc-backend[.exe]) end to end, offline.

    uv run python scripts/sidecar_smoke.py [path-to-exe]

Checks: stdout handshake and its time, API health, migrations from the bundled data files, case create, ingest of a PDF/DOCX/
JPEG, a PDF report (reportlab inside the bundle), the MCP subcommand, the plugin script runner, keyring import, graceful shutdown.
Uses a throwaway data dir and vault encryption OFF, so it never touches the OS credential store.
"""
from __future__ import annotations

import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tests" / "fixtures")]
import synthetic_intel as si

EXE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist" / "sidecar" / ("osintcc-backend.exe" if sys.platform == "win32" else "osintcc-backend")
checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    name = ("[encrypted] " if "encrypted" in os.environ.get("_SMOKE_PHASE", "") else "") + name
    checks.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def docx() -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("word/document.xml", "<w:t>see https://example.com/a and bob@example.org</w:t>")
    return b.getvalue()


def run_checks(encrypted: bool) -> None:
    """One full pass. encrypted=True uses a key from the environment (never the OS credential store) and checks the files on disk."""
    data = Path(tempfile.mkdtemp(prefix="osintcc-frozen-"))
    env = {**os.environ, "OSINTCC_DATA_DIR": str(data)}
    if encrypted:
        env.update(OSINTCC_VAULT_ENCRYPTION="required", OSINTCC_VAULT_KEY=base64.b64encode(os.urandom(32)).decode())
    else:
        env["OSINTCC_VAULT_ENCRYPTION"] = "off"
    t0 = time.perf_counter()
    p = subprocess.Popen([str(EXE)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, env=env, text=True)
    try:
        assert p.stdout is not None
        line = ""
        while time.perf_counter() - t0 < 90:
            line = p.stdout.readline()
            if line.startswith("OSINTCC_READY") or not line:
                break
        handshake = time.perf_counter() - t0
        check("handshake line printed", line.startswith("OSINTCC_READY port="), f"{handshake:.1f}s from launch")
        if not line.startswith("OSINTCC_READY"):
            print(p.stderr.read()[-2000:] if p.stderr else "")
            return
        kv = dict(x.split("=", 1) for x in line.split()[1:])
        c = httpx.Client(base_url=f"http://127.0.0.1:{kv['port']}/api/v1", headers={"Authorization": "Bearer " + kv["token"]}, timeout=60)
        r = c.get("/health/ready")
        check("health ready (migrations ran from bundled files)", r.status_code == 200 and r.json()["status"] == "ready", json.dumps(r.json())[:120])
        cid = c.post("/cases", json={"title": "frozen", "purpose": "packaging smoke test"}).json()["id"]
        for name, body in (("a.jpg", si.jpeg_with_gps(48.8, 2.3)), ("m.docx", docx()), ("w.pdf", b"%PDF-1.4\n1 0 obj<</S/JavaScript>>endobj\n%%EOF"),
                           ("x.pcap", si.pcap())):
            r = c.post(f"/cases/{cid}/ingest?filename={name}&consent_confirmed=true", content=body)
            check(f"ingest {name}", r.status_code == 201, r.json().get("kind", r.text[:80]))
        rep = c.post(f"/cases/{cid}/reports", json={"profile": "multi_int", "format": "pdf", "include_sensitive": True})
        fname = rep.json().get("file", "none") if rep.status_code == 201 else "none"
        pdf = data / "exports" / fname
        body = c.get(f"/reports/{rep.json()['id']}/download").content if rep.status_code == 201 else b""
        check("multi_int PDF report generated and downloadable (reportlab bundled)", body[:5] == b"%PDF-", str(rep.status_code))
        r = c.get(f"/cases/{cid}/cross-links?include_restricted=true")
        check("cross-links endpoint", r.status_code == 200)

        if encrypted:
            check("database file is ciphertext (not 'SQLite format 3')", (data / "osintcc.sqlite").read_bytes()[:16] != b"SQLite format 3\0")
            check("report stored encrypted at rest (.enc, no %PDF- header on disk)", fname.endswith(".enc") and pdf.read_bytes()[:5] != b"%PDF-")
            check("system/vault reports the database as encrypted", c.get("/system/vault").json()["database_encrypted"] is True)
        # MCP subcommand: initialize over stdio
        m = subprocess.run([str(EXE), "mcp", "--cases", cid, "--data-dir", str(data)], check=False, input='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}\n',
                           capture_output=True, text=True, timeout=90, env=env)
        check("mcp subcommand answers initialize", '"result"' in m.stdout and '"serverInfo"' in m.stdout, m.stdout[:100].strip() or m.stderr[-200:])

        # plugin runner: runs a script in the frozen interpreter and honours stdin/stdout
        script = data / "plug.py"
        script.write_text("import sys, json\nd = json.load(sys.stdin)\nprint(json.dumps({'echo': d['x'], 'argv': sys.argv[1:]}))\n")
        s = subprocess.run([str(EXE), "--run-script", str(script), "--phase", "plan"], check=False, input='{"x": 7}', capture_output=True, text=True, timeout=60, env=env)
        check("plugin script runner", s.returncode == 0 and json.loads(s.stdout) == {"echo": 7, "argv": ["--phase", "plan"]}, s.stdout.strip() or s.stderr[-200:])

        kr = data / "kr.py"
        kr.write_text("import keyring, keyring.backends\nprint(type(keyring.get_keyring()).__name__)\n")
        k = subprocess.run([str(EXE), "--run-script", str(kr)], check=False, capture_output=True, text=True, timeout=60, env=env)
        check("keyring backend importable in the bundle", k.returncode == 0 and k.stdout.strip() != "", k.stdout.strip() or k.stderr[-200:])

        r = c.post("/system/shutdown")
        try:
            code = p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            code = None
        check("graceful shutdown exits the process", r.status_code in (200, 202) and code == 0, f"exit={code}")
    finally:
        if p.poll() is None:
            p.kill()
        shutil.rmtree(data, ignore_errors=True)

def main() -> int:
    if not EXE.is_file():
        print(f"missing {EXE}; run scripts/build_sidecar.py first")
        return 2
    for enc in (False, True):
        os.environ["_SMOKE_PHASE"] = "encrypted" if enc else "plain"
        run_checks(enc)
    os.environ["_SMOKE_PHASE"] = "setup"
    st = subprocess.run([str(EXE), "setup", "status"], capture_output=True, text=True, timeout=60, check=False)
    check("`setup status` subcommand lists tools", st.returncode == 0 and "subfinder" in st.stdout and "recommended model" in st.stdout, st.stdout.splitlines()[0] if st.stdout else st.stderr[-200:])
    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} frozen-build checks passed" + (f"; FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
