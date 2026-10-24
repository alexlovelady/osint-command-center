"""Regenerate backend/osintcc/setup/catalog.json and the hash-locked requirement files.

    uv run python scripts/build_catalog.py

Every external download the first-run setup can perform is pinned here with a SHA-256 that this script obtained from the
publisher's own checksum file / release digest AND re-computed by downloading the artifact. Review the diff before shipping a
new catalog. Python tools are locked with `uv pip compile --generate-hashes` so every transitive wheel is hash-checked at install.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "backend" / "osintcc" / "setup"
REQ = OUT / "requirements"

SUBFINDER, AMASS, EXIFTOOL, UV = "2.17.0", "5.1.1", "13.59", "0.13.5"
SHERLOCK, MAIGRET, THEHARVESTER = "0.16.2", "0.6.6", "4.11.1"
PY = "3.12"
PLATS = {"win32-x86_64": "windows", "linux-x86_64": "x86_64-manylinux_2_28"}


def get(url: str) -> bytes:
    r = httpx.get(url, follow_redirects=True, timeout=300)
    r.raise_for_status()
    return r.content


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def checksum_from(text: str, name: str) -> str:
    for ln in text.splitlines():
        parts = ln.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name:
            return parts[0]
    raise SystemExit(f"no checksum for {name}")


def verified(url: str, expected: str) -> int:
    data = get(url)
    if sha(data) != expected:
        raise SystemExit(f"HASH MISMATCH for {url}: published {expected}, downloaded {sha(data)}")
    return len(data)


def lock(name: str, spec: str, plat: str, cwd: Path | None = None, target: str | None = None) -> str:
    out = REQ / f"{name}-{plat}.txt"
    cmd = ["uv", "pip", "compile", target or "-", "--generate-hashes", "--python-version", PY, "--python-platform", PLATS[plat], "-o", str(out), "-q"]
    subprocess.run(cmd, input=None if target else spec, text=True, check=True, cwd=cwd)
    return out.name


def main() -> int:
    REQ.mkdir(parents=True, exist_ok=True)
    tools: dict = {}

    gh = "https://github.com"
    sf_txt = get(f"{gh}/projectdiscovery/subfinder/releases/download/v{SUBFINDER}/subfinder_{SUBFINDER}_checksums.txt").decode()
    plats = {}
    for p, (osn, fmt, member) in {"win32-x86_64": ("windows", "zip", "subfinder.exe"), "linux-x86_64": ("linux", "zip", "subfinder")}.items():
        name = f"subfinder_{SUBFINDER}_{osn}_amd64.zip"
        url = f"{gh}/projectdiscovery/subfinder/releases/download/v{SUBFINDER}/{name}"
        h = checksum_from(sf_txt, name)
        plats[p] = {"url": url, "sha256": h, "size": verified(url, h), "format": fmt, "main": member, "members": [member]}
    tools["subfinder"] = {"kind": "archive", "name": "Subfinder", "version": SUBFINDER, "license": "MIT", "homepage": f"{gh}/projectdiscovery/subfinder", "platforms": plats}

    am_txt = get(f"{gh}/owasp-amass/amass/releases/download/v{AMASS}/amass_checksums.txt").decode()
    plats = {}
    for p, (osn, member) in {"win32-x86_64": ("windows", "amass.exe"), "linux-x86_64": ("linux", "amass")}.items():
        name = f"amass_{osn}_amd64.tar.gz"
        url = f"{gh}/owasp-amass/amass/releases/download/v{AMASS}/{name}"
        h = checksum_from(am_txt, name)
        plats[p] = {"url": url, "sha256": h, "size": verified(url, h), "format": "tar.gz", "main": member, "members": [f"amass_{osn}_amd64/{member}"], "strip": 1}
    tools["amass"] = {"kind": "archive", "name": "OWASP Amass", "version": AMASS, "license": "Apache-2.0", "homepage": f"{gh}/owasp-amass/amass", "platforms": plats}

    ck = get("https://exiftool.org/checksums.txt").decode()

    def exif_hash(fname: str) -> str:
        m = re.search(rf"SHA2-256\({re.escape(fname)}\)=\s*([0-9a-f]{{64}})", ck)
        if not m:
            raise SystemExit(f"no exiftool checksum for {fname}")
        return m.group(1)
    sfurl = "https://sourceforge.net/projects/exiftool/files/{}/download"
    wz, lz = f"exiftool-{EXIFTOOL}_64.zip", f"Image-ExifTool-{EXIFTOOL}.tar.gz"
    tools["exiftool"] = {"kind": "archive", "name": "ExifTool", "version": EXIFTOOL, "license": "Artistic-1.0-Perl OR GPL-1.0-or-later", "homepage": "https://exiftool.org/",
                         "platforms": {"win32-x86_64": {"url": sfurl.format(wz), "sha256": exif_hash(wz), "size": verified(sfurl.format(wz), exif_hash(wz)), "format": "zip",
                                                         "main": "exiftool.exe", "whole": True, "strip": 1, "rename": {"exiftool(-k).exe": "exiftool.exe"}},
                                       "linux-x86_64": {"url": sfurl.format(lz), "sha256": exif_hash(lz), "size": verified(sfurl.format(lz), exif_hash(lz)), "format": "tar.gz",
                                                         "main": "exiftool", "whole": True, "strip": 1, "needs": ["perl"]}}}

    uv_rel = json.loads(get(f"https://api.github.com/repos/astral-sh/uv/releases/tags/{UV}"))
    dig = {a["name"]: a["digest"].removeprefix("sha256:") for a in uv_rel["assets"] if a.get("digest")}
    plats = {}
    for p, (name, fmt, member, strip) in {"win32-x86_64": ("uv-x86_64-pc-windows-msvc.zip", "zip", "uv.exe", 0),
                                          "linux-x86_64": ("uv-x86_64-unknown-linux-gnu.tar.gz", "tar.gz", "uv", 1)}.items():
        url = f"{gh}/astral-sh/uv/releases/download/{UV}/{name}"
        plats[p] = {"url": url, "sha256": dig[name], "size": verified(url, dig[name]), "format": fmt, "main": member,
                    "members": [member if not strip else f"{name.removesuffix('.tar.gz')}/{member}"], "strip": strip}
    tools["uv"] = {"kind": "archive", "name": "uv (Python tool installer)", "version": UV, "license": "MIT OR Apache-2.0", "homepage": f"{gh}/astral-sh/uv", "platforms": plats, "hidden": True}

    for tid, nm, pkg, ver, script, lic in (("sherlock", "Sherlock", "sherlock-project", SHERLOCK, "sherlock", "MIT"), ("maigret", "Maigret", "maigret", MAIGRET, "maigret", "MIT")):
        reqs = {p: lock(tid, f"{pkg}=={ver}\n", p) for p in PLATS}
        tools[tid] = {"kind": "pypi", "name": nm, "version": ver, "license": lic, "homepage": f"https://pypi.org/project/{pkg}/", "python": PY, "script": script,
                      "platforms": {p: {"requirements": reqs[p]} for p in PLATS}, "needs": ["uv"]}

    url = f"{gh}/laramies/theHarvester/archive/refs/tags/{THEHARVESTER}.tar.gz"
    src = get(url)
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "src.tgz").write_bytes(src)
        with tarfile.open(Path(td) / "src.tgz") as t:
            t.extractall(td, filter="data")
        proj = next(Path(td).glob("theHarvester-*"))
        req = lock("theharvester", "", "linux-x86_64", cwd=proj, target="pyproject.toml")
    tools["theharvester"] = {"kind": "pysrc", "name": "theHarvester", "version": THEHARVESTER, "license": "GPL-2.0-only (separate process, not linked)",
                             "homepage": f"{gh}/laramies/theHarvester", "python": PY, "needs": ["uv"],
                             "platforms": {"linux-x86_64": {"url": url, "sha256": sha(src), "size": len(src), "requirements": req, "entry": "theHarvester.theHarvester:main"}},
                             "unsupported": {"win32-x86_64": "theHarvester does not support native Windows; use WSL or Linux"}}

    ol = json.loads(get("https://api.github.com/repos/ollama/ollama/releases/latest"))
    oa = {a["name"]: a for a in ol["assets"]}
    tools["ollama"] = {"kind": "ollama", "name": "Ollama (local model runtime)", "version": ol["tag_name"].lstrip("v"), "license": "MIT", "homepage": "https://ollama.com",
                       "platforms": {"win32-x86_64": {"url": f"{gh}/ollama/ollama/releases/download/{ol['tag_name']}/OllamaSetup.exe",
                                                       "sha256": oa["OllamaSetup.exe"]["digest"].removeprefix("sha256:"), "size": oa["OllamaSetup.exe"]["size"], "silent_args": ["/VERYSILENT", "/NORESTART"]}},
                       "unsupported": {"linux-x86_64": "Install Ollama with your package manager or https://ollama.com/download (needs administrator rights); then re-run setup"}}

    catalog = {"schema": 1, "generated": datetime.now(UTC).isoformat(timespec="seconds"), "tools": tools,
               "models": [{"id": "huihui_ai/qwen3-abliterated:8b", "label": "Qwen3 8B abliterated (uncensored), Q4", "download_gb": 5.0, "min_ram_gb": 12, "think": False},
                          {"id": "huihui_ai/qwen3-abliterated:4b", "label": "Qwen3 4B abliterated (uncensored), Q4", "download_gb": 2.5, "min_ram_gb": 6, "think": False},
                          {"id": "huihui_ai/qwen3-abliterated:1.7b", "label": "Qwen3 1.7B abliterated (uncensored), Q4", "download_gb": 1.1, "min_ram_gb": 3, "think": False}]}
    (OUT / "catalog.json").write_text(json.dumps(catalog, indent=1), encoding="utf8")
    _ = shutil
    print("wrote", OUT / "catalog.json", "tools:", ", ".join(tools))
    return 0


if __name__ == "__main__":
    sys.exit(main())
