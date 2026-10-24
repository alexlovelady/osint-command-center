"""First-run setup: install the optional OSINT tools and a local model, safely.

Rules (the reasons this is not just `pip install` and `curl | sh`):
* Every artifact is pinned in `catalog.json` with a SHA-256 taken from the publisher's own checksum/digest and re-computed when
  the catalog was built. A download whose hash differs is deleted and nothing is extracted or run.
* Downloads only follow https redirects between an allow-list of publisher hosts, with a size cap.
* Archives are extracted member by member with path-traversal, link and size guards. Nothing is executed during extraction.
* Python tools go into their own virtual environments from hash-locked requirement files (`--require-hashes`), never into the
  application's interpreter.
* Everything lands under `<data dir>/tools/` and is recorded in `installed.json`; no system-wide change, no administrator rights.
* The caller must pass `confirm=True` after being shown the exact URLs (`plan()`); offline mode refuses.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..adapters.cli import run_argv
from ..config import Settings
from .state import load_state, managed_path

HERE = Path(__file__).parent
ALLOWED_HOSTS = {"github.com", "codeload.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "github-releases.githubusercontent.com",
                 "sourceforge.net", "downloads.sourceforge.net"}
ALLOWED_SUFFIXES = (".dl.sourceforge.net",)
MAX_EXTRACT_BYTES = 2 * 1024 ** 3
VERSION_ARGS = {"subfinder": ["-version"], "amass": ["-version"], "exiftool": ["-ver"], "uv": ["--version"], "sherlock": ["--version"],
                "maigret": ["--version"], "theharvester": ["--help"], "ollama": ["--version"]}
Progress = Callable[[dict[str, Any]], None]


class SetupError(Exception):
    pass


def platform_key() -> str | None:
    if platform.machine().lower() not in ("x86_64", "amd64"):
        return None
    return {"win32": "win32-x86_64", "linux": "linux-x86_64"}.get(sys.platform)


def catalog() -> dict[str, Any]:
    return json.loads((HERE / "catalog.json").read_text(encoding="utf8"))


def tools_dir(s: Settings) -> Path:
    return s.data_dir / "tools"


def state_path(s: Settings) -> Path:
    return tools_dir(s) / "installed.json"


def _save_state(s: Settings, tool_id: str, entry: dict[str, Any]) -> None:
    sp = state_path(s)
    sp.parent.mkdir(parents=True, exist_ok=True)
    st = load_state(sp)
    st[tool_id] = entry
    tmp = sp.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=1), encoding="utf8")
    tmp.replace(sp)


# ------------------------------------------------------------------------------------------------ host facts --------
def ram_gb() -> float | None:
    try:
        if sys.platform == "win32":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_ulong), ("m", ctypes.c_ulong), ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong), ("tpf", ctypes.c_ulonglong),
                            ("apf", ctypes.c_ulonglong), ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong), ("ae", ctypes.c_ulonglong)]
            ms = MS()
            ms.l = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            return round(ms.tp / 1024 ** 3, 1)
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / 1024 ** 2, 1)
    except Exception:
        return None
    return None


def recommended_model(ram: float | None) -> dict[str, Any]:
    models = catalog()["models"]
    for m in models:  # ordered largest first
        if ram is not None and ram >= m["min_ram_gb"]:
            return m
    return models[-1]


def ollama_path() -> str | None:
    p = shutil.which("ollama")
    if p:
        return p
    if sys.platform == "win32":
        guess = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe"
        return str(guess) if guess.is_file() else None
    return None


# ------------------------------------------------------------------------------------------------ status / plan ------
def _entry(cat: dict[str, Any], tid: str, plat: str | None) -> dict[str, Any] | None:
    return (cat["tools"][tid]["platforms"].get(plat) if plat else None)


async def _version_of(path: str, tid: str) -> str | None:
    try:
        r = await run_argv([path, *VERSION_ARGS.get(tid, ["--version"])], 20)
    except Exception:
        return None
    text = (r.stdout or r.stderr).decode(errors="replace").strip().splitlines()
    return text[0][:100] if (r.returncode in (0, None) and text) else None


async def status(s: Settings) -> dict[str, Any]:
    cat, plat = catalog(), platform_key()
    st = load_state(state_path(s))
    items = []
    for tid, t in cat["tools"].items():
        if t.get("hidden"):
            continue
        entry = _entry(cat, tid, plat)
        path = managed_path(state_path(s), tid)
        managed = path is not None
        if tid == "ollama":
            path = path or ollama_path()
        else:
            path = path or shutil.which({"theharvester": "theHarvester"}.get(tid, tid))
        reason = None if entry else (t.get("unsupported", {}).get(plat or "") or f"no pinned build for this platform ({plat or sys.platform})")
        items.append({"id": tid, "name": t["name"], "version": t["version"], "license": t["license"], "homepage": t["homepage"], "installed": bool(path),
                      "managed": managed, "path": path, "installable": bool(entry), "reason": reason,
                      "download_mb": round((entry or {}).get("size", 0) / 1e6, 1) if entry and "size" in entry else None,
                      "installed_at": (st.get(tid) or {}).get("installed_at")})
    ram = ram_gb()
    model = recommended_model(ram)
    return {"platform": plat, "ram_gb": ram, "tools": items, "recommended_model": model, "models": cat["models"],
            "ollama_found": ollama_path() is not None, "tools_dir": str(tools_dir(s))}


def plan(s: Settings, ids: list[str]) -> list[dict[str, Any]]:
    """The exact URLs and sizes that installing `ids` would touch (shown to the user before they confirm)."""
    cat, plat = catalog(), platform_key()
    out, seen = [], set()

    def add(tid: str) -> None:
        if tid in seen:
            return
        seen.add(tid)
        t, e = cat["tools"].get(tid), _entry(cat, tid, plat)
        if not t or not e:
            raise SetupError(f"{tid}: not installable on this platform")
        for need in t.get("needs", []):
            if need == "uv" and (managed_path(state_path(s), "uv") or shutil.which("uv")):
                continue
            if need == "uv":
                add("uv")
        urls = [e["url"]] if "url" in e else []
        if t["kind"] in ("pypi", "pysrc"):
            urls.append("https://pypi.org / https://files.pythonhosted.org (hash-locked wheels, installed by uv)")
        out.append({"id": tid, "name": t["name"], "version": t["version"], "urls": urls, "size_mb": round(e.get("size", 0) / 1e6, 1) if "size" in e else None})
    for tid in ids:
        add(tid)
    return out


# ------------------------------------------------------------------------------------------------ download ----------
def host_allowed(host: str) -> bool:
    h = host.lower()
    return h in ALLOWED_HOSTS or h.endswith(ALLOWED_SUFFIXES)


async def download(url: str, dest: Path, sha256: str, max_bytes: int, progress: Progress | None = None,
                   transport: httpx.AsyncBaseTransport | None = None) -> None:
    current, hops = url, 0
    async with httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(60, read=120), follow_redirects=False, trust_env=False) as c:
        while True:
            parts = urlsplit(current)
            if parts.scheme != "https" or not parts.hostname or not host_allowed(parts.hostname):
                raise SetupError(f"refusing to download from {parts.hostname or current!r}: not an allowed https publisher host")
            async with c.stream("GET", current) as r:
                if r.status_code in (301, 302, 303, 307, 308) and "location" in r.headers:
                    hops += 1
                    if hops > 6:
                        raise SetupError("too many redirects")
                    current = str(httpx.URL(current).join(r.headers["location"]))
                    continue
                if r.status_code != 200:
                    raise SetupError(f"download failed: HTTP {r.status_code}")
                h, got = hashlib.sha256(), 0
                dest.parent.mkdir(parents=True, exist_ok=True)
                total = int(r.headers.get("content-length", 0) or 0)
                with dest.open("wb") as f:
                    async for chunk in r.aiter_bytes(1 << 20):
                        got += len(chunk)
                        if got > max_bytes:
                            raise SetupError("download is larger than the pinned size; aborted")
                        h.update(chunk)
                        f.write(chunk)
                        if progress:
                            progress({"phase": "download", "bytes": got, "total": total or max_bytes})
                break
    if h.hexdigest() != sha256:
        dest.unlink(missing_ok=True)
        raise SetupError(f"SHA-256 mismatch (expected {sha256[:16]}…, got {h.hexdigest()[:16]}…); the file was deleted and not used")


# ------------------------------------------------------------------------------------------------ extraction --------
def _target(dest: Path, name: str, strip: int) -> Path | None:
    parts = [p for p in PurePosixPath(name.replace("\\", "/")).parts if p not in ("", ".")]
    if ".." in parts or (parts and (parts[0].endswith(":") or parts[0] == "/")):
        raise SetupError(f"unsafe path in archive: {name}")
    parts = parts[strip:]
    if not parts:
        return None
    out = (dest / Path(*parts)).resolve()
    if dest.resolve() not in out.parents:
        raise SetupError(f"path escapes the install directory: {name}")
    return out


def extract(archive: Path, fmt: str, dest: Path, *, members: list[str] | None = None, strip: int = 0, whole: bool = False,
            rename: dict[str, str] | None = None) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    total = 0

    def put(name: str, opener: Callable[[], Any], size: int) -> None:
        nonlocal total
        if not whole and members is not None and name not in members:
            return
        t = _target(dest, name, strip)
        if t is None:
            return
        total += size
        if total > MAX_EXTRACT_BYTES:
            raise SetupError("archive expands beyond the size limit")
        t.parent.mkdir(parents=True, exist_ok=True)
        with opener() as src, t.open("wb") as out:
            shutil.copyfileobj(src, out)
        written.append(t)

    if fmt == "zip":
        with zipfile.ZipFile(archive) as z:
            for i in z.infolist():
                if i.is_dir():
                    continue
                if (i.external_attr >> 16) & 0o170000 == stat.S_IFLNK:
                    raise SetupError(f"archive contains a symlink: {i.filename}")
                put(i.filename, lambda i=i: z.open(i), i.file_size)  # type: ignore[misc]
    elif fmt == "tar.gz":
        with tarfile.open(archive, "r:gz") as t:
            for m in t:
                if m.isdir():
                    continue
                if not m.isfile():
                    raise SetupError(f"archive contains a non-regular entry: {m.name}")
                f = t.extractfile(m)
                assert f is not None
                put(m.name, lambda f=f: f, m.size)  # type: ignore[misc]
    else:
        raise SetupError(f"unknown archive format {fmt}")
    for old, new in (rename or {}).items():
        for p in written:
            if p.name == old:
                p.replace(p.with_name(new))
    return written


def _chmod_x(p: Path) -> None:
    if sys.platform != "win32":
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# ------------------------------------------------------------------------------------------------ install -----------
def _uv(s: Settings) -> str:
    p = managed_path(state_path(s), "uv") or shutil.which("uv")
    if not p:
        raise SetupError("uv is required for this tool and could not be installed")
    return p


def _uv_env(s: Settings) -> dict[str, str]:
    td = tools_dir(s)
    env = {"UV_CACHE_DIR": str(td / "uv-cache"), "UV_PYTHON_INSTALL_DIR": str(td / "python"), "UV_NO_CONFIG": "1", "UV_PYTHON_PREFERENCE": "managed"}
    for k in ("APPDATA", "LOCALAPPDATA", "USERPROFILE", "HOME", "SYSTEMROOT", "TEMP", "TMP", "PATH"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


async def _run_uv(s: Settings, args: list[str], timeout: float = 1800) -> None:
    r = await run_argv([_uv(s), *args], timeout, extra_env=_uv_env(s))
    if r.timed_out or r.returncode != 0:
        raise SetupError("uv failed: " + (r.stderr or r.stdout).decode(errors="replace")[-600:])


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


async def _make_venv(s: Settings, tid: str, tool: dict[str, Any], req: Path) -> Path:
    venv = tools_dir(s) / "venvs" / tid
    if venv.exists():
        shutil.rmtree(venv)
    await _run_uv(s, ["venv", str(venv), "--python", tool["python"]])
    await _run_uv(s, ["pip", "install", "--python", str(_venv_python(venv)), "--require-hashes", "--no-deps", "-r", str(req)])
    return venv


async def install(s: Settings, tid: str, *, progress: Progress | None = None, transport: httpx.AsyncBaseTransport | None = None,
                  _depth: int = 0) -> dict[str, Any]:
    cat, plat = catalog(), platform_key()
    tool, e = cat["tools"].get(tid), _entry(cat, tid, plat)
    if not tool:
        raise SetupError(f"unknown component {tid}")
    if not e:
        raise SetupError(f"{tool['name']}: {tool.get('unsupported', {}).get(plat or '', 'not available for this platform')}")
    say = progress or (lambda _e: None)
    for need in tool.get("needs", []):
        if need == "uv" and not (managed_path(state_path(s), "uv") or shutil.which("uv")):
            say({"phase": "dependency", "id": "uv"})
            await install(s, "uv", progress=progress, transport=transport, _depth=_depth + 1)
        if need == "perl" and not shutil.which("perl"):
            raise SetupError("ExifTool on Linux needs perl (apt install perl / dnf install perl-interpreter)")
    td = tools_dir(s)
    td.mkdir(parents=True, exist_ok=True)
    kind, path = tool["kind"], None
    with tempfile.TemporaryDirectory(dir=td) as scratch:
        if kind == "archive":
            arc = Path(scratch) / "download"
            say({"phase": "download", "id": tid, "url": e["url"]})
            await download(e["url"], arc, e["sha256"], int(e["size"] * 1.05) + (1 << 20), lambda p: say({**p, "id": tid}), transport)
            dest = td / tid / tool["version"]
            if dest.exists():
                shutil.rmtree(dest)
            say({"phase": "extract", "id": tid})
            await asyncio.to_thread(extract, arc, e["format"], dest, members=e.get("members"), strip=e.get("strip", 0), whole=e.get("whole", False), rename=e.get("rename"))
            main = dest / e["main"]
            if not main.is_file():
                raise SetupError(f"{tool['name']}: expected file {e['main']} was not in the archive")
            _chmod_x(main)
            for extra in dest.glob("*"):
                if extra.is_file() and extra.suffix == "" and extra.name in ("uvx",):
                    _chmod_x(extra)
            path = main
        elif kind == "pypi":
            say({"phase": "python-env", "id": tid})
            venv = await _make_venv(s, tid, tool, HERE / "requirements" / e["requirements"])
            path = venv / ("Scripts" if sys.platform == "win32" else "bin") / (tool["script"] + (".exe" if sys.platform == "win32" else ""))
        elif kind == "pysrc":
            arc = Path(scratch) / "src.tgz"
            say({"phase": "download", "id": tid, "url": e["url"]})
            await download(e["url"], arc, e["sha256"], int(e["size"] * 1.05) + (1 << 20), lambda p: say({**p, "id": tid}), transport)
            src = td / "src" / tid / tool["version"]
            if src.exists():
                shutil.rmtree(src)
            await asyncio.to_thread(extract, arc, "tar.gz", src, whole=True, strip=1)
            say({"phase": "python-env", "id": tid})
            venv = await _make_venv(s, tid, tool, HERE / "requirements" / e["requirements"])
            bindir = td / "bin"
            bindir.mkdir(exist_ok=True)
            mod, func = e["entry"].split(":")
            code = f"import sys; sys.path.insert(0, {str(src)!r}); from {mod} import {func}; sys.exit({func}())"
            shim = bindir / "theHarvester"
            shim.write_text(f"#!/bin/sh\nexec {str(_venv_python(venv))!r} -c {code!r} \"$@\"\n", encoding="utf8")
            _chmod_x(shim)
            path = shim
        elif kind == "ollama":
            existing = ollama_path()
            if existing:
                path = Path(existing)
            else:
                if plat != "win32-x86_64":
                    raise SetupError(tool["unsupported"].get(plat or "", "install Ollama manually"))
                exe = Path(scratch) / "OllamaSetup.exe"
                say({"phase": "download", "id": tid, "url": e["url"]})
                await download(e["url"], exe, e["sha256"], int(e["size"] * 1.02), lambda p: say({**p, "id": tid}), transport)
                say({"phase": "installing", "id": tid})
                r = await run_argv([str(exe), *e["silent_args"]], 900)
                if r.timed_out or r.returncode not in (0, None):
                    raise SetupError("the Ollama installer did not finish successfully")
                found = ollama_path()
                if not found:
                    raise SetupError("Ollama installed but ollama.exe was not found")
                path = Path(found)
        else:
            raise SetupError(f"unsupported component kind {kind}")
    assert path is not None
    version = await _version_of(str(path), tid)
    if tid == "theharvester" and version:  # its --help prints a banner, not a version line
        version = f"theHarvester {tool['version']} (runs)"
    entry = {"version": tool["version"], "path": str(path), "installed_at": datetime.now(UTC).isoformat(timespec="seconds"),
             "reported_version": version, "kind": kind, "sha256": e.get("sha256")}
    if tid != "ollama" or not ollama_path():
        _save_state(s, tid, entry)
    say({"phase": "done", "id": tid, "path": str(path), "reported_version": version})
    return {"id": tid, **entry, "works": version is not None}


# ------------------------------------------------------------------------------------------------ models ------------
OLLAMA = "http://127.0.0.1:11434"


def _spawn_detached(argv: list[str]) -> None:
    flags = 0x08000008 if sys.platform == "win32" else 0  # DETACHED_PROCESS | CREATE_NO_WINDOW
    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
                     start_new_session=sys.platform != "win32")


async def ensure_ollama_running(base: str = OLLAMA, transport: httpx.AsyncBaseTransport | None = None) -> bool:
    async with httpx.AsyncClient(transport=transport, timeout=3, trust_env=False) as c:
        for attempt in range(2):
            try:
                if (await c.get(f"{base}/api/tags")).status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            if attempt == 0:
                exe = ollama_path()
                if not exe:
                    return False
                _spawn_detached([exe, "serve"])
                for _ in range(30):
                    await asyncio.sleep(1)
                    try:
                        if (await c.get(f"{base}/api/tags")).status_code == 200:
                            return True
                    except httpx.HTTPError:
                        continue
    return False


async def pull_model(model: str, progress: Progress | None = None, base: str = OLLAMA, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    """Pull via the local Ollama API (it verifies each blob's digest). Only the model ids in the catalog are accepted."""
    if model not in {m["id"] for m in catalog()["models"]}:
        raise SetupError("model is not in the setup catalog")
    if not await ensure_ollama_running(base, transport):
        raise SetupError("Ollama is not running and could not be started")
    last: dict[str, Any] = {}
    async with httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(30, read=None), trust_env=False) as c:
        async with c.stream("POST", f"{base}/api/pull", json={"model": model, "stream": True}) as r:
            if r.status_code != 200:
                raise SetupError(f"Ollama refused the pull (HTTP {r.status_code})")
            async for line in r.aiter_lines():
                if not line.strip():
                    continue
                try:
                    last = json.loads(line)
                except ValueError:
                    continue
                if last.get("error"):
                    raise SetupError(f"Ollama: {last['error']}")
                if progress:
                    progress({"phase": "model", "status": last.get("status"), "completed": last.get("completed"), "total": last.get("total")})
        tags = (await c.get(f"{base}/api/tags")).json().get("models", [])
    present = any(m.get("name") == model or m.get("model") == model for m in tags)
    if not present:
        raise SetupError("the pull finished but the model is not listed by Ollama")
    return {"model": model, "status": last.get("status")}
