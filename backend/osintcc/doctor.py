"""System doctor: truthful present/missing/version report (spec Phase 0). `python -m osintcc.doctor [--json]`."""
from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import sys

TOOLS = [
    ("python", ["--version"], "required", "Python 3.12+ (https://www.python.org/downloads/)"),
    ("uv", ["--version"], "required", "https://docs.astral.sh/uv/getting-started/installation/"),
    ("node", ["--version"], "required", "Node.js LTS"),
    ("pnpm", ["--version"], "required", "npm i -g pnpm"),
    ("git", ["--version"], "recommended", "https://git-scm.com/"),
    ("rustc", ["--version"], "desktop-shell", "Install Rust via https://rustup.rs (needed only for the Tauri shell)"),
    ("cargo", ["--version"], "desktop-shell", "Installed with rustup"),
    ("docker", ["--version"], "optional", "Optional container isolation for third-party tools"),
    ("wsl", ["--status"], "optional", "Windows only; optional Linux workers for Linux-only CLIs"),
    ("exiftool", ["-ver"], "optional", "https://exiftool.org/ (media metadata adapter)"),
    ("subfinder", ["-version"], "optional", "https://github.com/projectdiscovery/subfinder"),
    ("sherlock", ["--version"], "optional", "uv tool install sherlock-project"),
    ("maigret", ["--version"], "optional", "uv tool install maigret"),
    ("ollama", ["--version"], "optional", "https://ollama.com (local AI; AI-off mode works without it)"),
]


_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)?")


def _probe(name: str, args: list[str]) -> dict:
    """Found means it runs and exits 0. A tool that is on PATH but fails (missing runtime, broken shim) is reported as broken."""
    if name == "python":
        return {"found": True, "works": True, "path": sys.executable, "version": platform.python_version()}
    path = shutil.which(name)
    if not path:
        return {"found": False}
    try:
        out = subprocess.run([path, *args], capture_output=True, text=True, timeout=15, check=False)
    except Exception as exc:  # report, never crash
        return {"found": True, "works": False, "path": path, "version": f"probe failed: {type(exc).__name__}"}
    text = (out.stdout + "\n" + out.stderr).replace("\x00", "").strip()
    lines = [ln for ln in text.splitlines() if ln.strip()]
    m = _VERSION.search(text)
    if out.returncode != 0:
        return {"found": True, "works": False, "path": path, "version": "broken: " + (lines[0][:100] if lines else f"exit {out.returncode}")}
    return {"found": True, "works": True, "path": path, "version": (m.group(0) if m else (lines[0][:100] if lines else "ok"))}


def webview2() -> dict:
    if sys.platform != "win32":
        return {"applicable": False}
    try:
        import winreg
        key = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            return {"applicable": True, "found": True, "version": winreg.QueryValueEx(k, "pv")[0]}
    except OSError:
        return {"applicable": True, "found": False}


def run_doctor() -> dict:
    tools = {}
    for name, args, level, hint in TOOLS:
        r = _probe(name, args)
        r.update(level=level, install_hint=hint)
        tools[name] = r
    py_ok = sys.version_info >= (3, 12)
    disk = shutil.disk_usage(".")
    missing_required = [n for n, t in tools.items() if t["level"] == "required" and not (t["found"] and t.get("works", True))]
    return {
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                     "python": platform.python_version()},
        "python_ok": py_ok, "webview2": webview2(), "tools": tools,
        "disk_free_gb": round(disk.free / 1e9, 1),
        "summary": {"missing_required": missing_required,
                    "desktop_shell_ready": all(tools[t]["found"] and tools[t].get("works") for t in ("rustc", "cargo")),
                    "broken": [n for n, t in tools.items() if t["found"] and not t.get("works", True)],
                    "optional_missing": [n for n, t in tools.items() if t["level"] == "optional" and not t["found"]]},
    }


def main() -> int:
    rep = run_doctor()
    if "--json" in sys.argv:
        print(json.dumps(rep, indent=2))
    else:
        p = rep["platform"]
        print(f"Platform: {p['system']} {p['release']} ({p['machine']}), Python {p['python']}"
              f"{'' if rep['python_ok'] else '  [needs >= 3.12]'}")
        print(f"WebView2: {rep['webview2']}")
        for n, t in rep["tools"].items():
            state = (f"OK   {t.get('version', '')}" if t.get("works", True) else f"BROKEN {t.get('version', '')}") if t["found"]                 else f"MISSING ({t['level']}) -> {t['install_hint']}"
            print(f"  {n:10s} {state}")
        print(f"Disk free: {rep['disk_free_gb']} GB")
        s = rep["summary"]
        print(f"Desktop shell (Tauri) ready: {s['desktop_shell_ready']}; missing required: {s['missing_required'] or 'none'}")
    return 1 if rep["summary"]["missing_required"] or not rep["python_ok"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
