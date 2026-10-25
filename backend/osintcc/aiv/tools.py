"""Optional external tools for AIV: identity-checked health, strict argv builders, bounded parsers, and the reviewed-template allowlist for Nuclei.

Everything an external tool is allowed to do is decided here, in code: argv are built from fixed flag lists plus validated values, never from text a user, a model or
an imported workflow supplied. Flags were checked against the tools' own `-h` output at the pinned versions listed in TOOLS (Nmap 7.98, Nuclei engine v3.11.1,
Naabu 2.6.1, ProjectDiscovery httpx v1.12.0, dnstwist 20240812) on 2026-10-25. A different major version is reported as `unverified_version`, not trusted silently.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.cli import run_argv
from ..policy.ssrf import system_resolver
from . import parsers, policy
from .plans import TEMPLATE_ID
from .policy import Budget, BudgetExceeded

TOOLS_VERIFIED_ON = "2026-10-25"


@dataclass(frozen=True)
class ToolDef:
    id: str
    name: str
    binary_names: tuple[str, ...]
    version_args: tuple[str, ...]
    identity: re.Pattern[str]          # must match the version output, so a same-named program cannot pass
    version: re.Pattern[str]
    verified_major: tuple[int, ...]    # major versions whose flags were checked
    license: str
    source_url: str
    install_hint: str
    role: str
    platforms: tuple[str, ...] = ("linux", "win32")


I = re.IGNORECASE
TOOLS: dict[str, ToolDef] = {t.id: t for t in [
    ToolDef("nmap", "Nmap", ("nmap",), ("--version",), re.compile(r"Nmap version", I), re.compile(r"Nmap version (\d+)\.(\d+)", I), (7,), "Nmap Public Source License (custom; read it before redistributing)",
            "https://nmap.org/", "Kali: `sudo apt install nmap`. Other systems: https://nmap.org/download", "Confirm selected ports (connect scan only, no scripts)"),
    ToolDef("naabu", "ProjectDiscovery Naabu", ("naabu",), ("-version",), re.compile(r"projectdiscovery|naabu", I), re.compile(r"Current Version: v?(\d+)\.(\d+)", I), (2,), "MIT",
            "https://github.com/projectdiscovery/naabu", "Kali: `sudo apt install naabu` where packaged, otherwise the upstream release page", "Fast port check on an approved asset (advanced, off by default)"),
    ToolDef("nuclei", "ProjectDiscovery Nuclei", ("nuclei",), ("-version",), re.compile(r"Nuclei Engine Version|projectdiscovery", I), re.compile(r"Engine Version: v?(\d+)\.(\d+)", I), (3,), "MIT",
            "https://github.com/projectdiscovery/nuclei", "Kali: `sudo apt install nuclei` where packaged, otherwise the upstream release page", "Run reviewed, pinned templates only"),
    ToolDef("httpx_pd", "ProjectDiscovery httpx", ("httpx", "httpx-toolkit"), ("-version",), re.compile(r"projectdiscovery|Current Version", I), re.compile(r"Current Version: v?(\d+)\.(\d+)", I), (1,), "MIT",
            "https://github.com/projectdiscovery/httpx", "Kali: `sudo apt install httpx-toolkit` (the package is named httpx-toolkit because `httpx` is also the Python client)",
            "HTTP probe with metadata (the built-in Python client is used for AIV HTTP checks)"),
    ToolDef("dnstwist", "dnstwist", ("dnstwist",), ("--help",), re.compile(r"dnstwist \d+", I), re.compile(r"dnstwist (\d{4})(\d{2})(\d{2})", I), (2024, 2025, 2026), "Apache-2.0",
            "https://github.com/elceef/dnstwist", "Kali: `sudo apt install dnstwist` or `pipx install dnstwist`", "Generate look-alike domain candidates (offline); never contacts or registers them"),
]}
OWN_CHECKS = {"http_metadata": "built in (Python httpx client; not ProjectDiscovery httpx)", "tls_handshake": "built in (Python ssl; sslscan is not used)", "tcp_connect": "built in (asyncio connect)"}


_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
CACHE_SECONDS = 30.0


def clear_cache() -> None:
    _CACHE.clear()


async def _probe(td: ToolDef) -> dict[str, Any]:
    """Identity-checked health, cached for a few seconds (probing spawns the tool)."""
    import time
    hit = _CACHE.get(td.id)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    out = await _probe_uncached(td)
    _CACHE[td.id] = (time.monotonic(), out)
    return out


async def _probe_uncached(td: ToolDef) -> dict[str, Any]:
    exe = next((p for n in td.binary_names if (p := shutil.which(n))), None)
    base = {"id": td.id, "name": td.name, "role": td.role, "license": td.license, "source_url": td.source_url, "install_hint": td.install_hint, "last_checked": datetime.now(UTC).isoformat(),
            "verified_on": TOOLS_VERIFIED_ON, "verified_major": list(td.verified_major)}
    if not exe:
        return {**base, "status": "not_installed", "path": None, "version": None, "detail": td.install_hint}
    res = await run_argv([exe, *td.version_args], 20)
    text = (res.stdout + b"\n" + res.stderr).decode(errors="replace")
    if not td.identity.search(text):
        why = "this program does not identify itself as the expected tool"
        if td.id == "httpx_pd":
            why = "this `httpx` is not ProjectDiscovery httpx (it is probably the Python HTTP client's command-line tool); it will not be used"
        return {**base, "status": "wrong_program", "path": exe, "version": None, "detail": why}
    m = td.version.search(text)
    ver = ".".join(m.groups()) if m else "unknown"
    major = int(m.group(1)) if m else -1
    if major not in td.verified_major:
        return {**base, "status": "unverified_version", "path": exe, "version": ver, "detail": f"flags were verified for major version(s) {list(td.verified_major)}; this is {ver}. It will not be run until reviewed."}
    return {**base, "status": "healthy", "path": exe, "version": ver, "detail": "installed and identity-checked"}


async def tools_health(st: Any | None = None) -> list[dict[str, Any]]:
    out = [await _probe(t) for t in TOOLS.values()]
    out += [{"id": k, "name": k.replace("_", " "), "status": "healthy", "version": "built-in", "detail": v, "license": "in-house", "source_url": "", "install_hint": "", "path": None,
             "role": "", "last_checked": datetime.now(UTC).isoformat(), "verified_on": TOOLS_VERIFIED_ON, "verified_major": []} for k, v in OWN_CHECKS.items()]
    return out


async def tool_versions(st: Any) -> dict[str, str]:
    h = {t["id"]: t["version"] for t in await tools_health() if t["status"] == "healthy" and t["id"] in TOOLS}
    return {k: v for k, v in h.items() if v}


async def tool_path(tool_id: str) -> str | None:
    p = await _probe(TOOLS[tool_id])
    return p["path"] if p["status"] == "healthy" else None


# ---- reviewed templates (Nuclei) ----------------------------------------------------------------------------------------------------------
ALLOWED_TOP = {"id", "info", "http", "variables"}
ALLOWED_VARS = {"BaseURL", "RootURL", "Hostname", "Host", "Port", "Scheme", "Path", "File"}
_EXPR = re.compile(r"\{\{\s*([^}]*?)\s*\}\}")
OK_REQ_KEYS = {"method", "path", "matchers", "matchers-condition", "extractors", "id", "name", "redirects", "max-redirects"}
OK_MATCHER_TYPES = {"word", "regex", "status", "size"}
OK_PARTS = {"body", "header", "status_code", "all", "response", "content_type", "interactsh_protocol"}
MAX_TEMPLATE_BYTES = 20_000


def review_template(content: str) -> dict[str, Any]:
    """Static review of a template's request semantics. Returns {ok, id, errors, semantics}. A template is acceptable only if it is a plain GET/HEAD fingerprint
    with word/regex/status/size matchers: no payloads, raw requests, bodies, custom headers, fuzzing, OAST, scripting, flows, or other protocols."""
    errors: list[str] = []
    if len(content.encode()) > MAX_TEMPLATE_BYTES:
        return {"ok": False, "id": None, "errors": [f"template is larger than {MAX_TEMPLATE_BYTES} bytes"], "semantics": {}}
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return {"ok": False, "id": None, "errors": ["not valid YAML"], "semantics": {}}
    if not isinstance(doc, dict):
        return {"ok": False, "id": None, "errors": ["a template is a YAML mapping"], "semantics": {}}
    tid = doc.get("id")
    if not isinstance(tid, str) or not re.match(TEMPLATE_ID, tid):
        errors.append("template id must be lowercase letters, digits, '.', '_' or '-'")
    for k in doc:
        if k not in ALLOWED_TOP:
            errors.append(f"top-level key '{k}' is not allowed (only an http request section is permitted)")
    if doc.get("variables"):
        errors.append("template variables are not allowed")
    info: dict[str, Any] = doc["info"] if isinstance(doc.get("info"), dict) else {}
    if not info.get("name") or info.get("severity") not in ("info", "low", "medium", "high", "critical", "unknown"):
        errors.append("info.name and a valid info.severity are required")
    reqs = doc.get("http")
    if not isinstance(reqs, list) or not reqs or len(reqs) > 3:
        errors.append("the http section must be a list of one to three requests")
        reqs = []
    methods: list[str] = []
    paths: list[str] = []
    matchers: list[str] = []
    for i, r in enumerate(reqs):
        if not isinstance(r, dict):
            errors.append(f"request {i + 1} is not a mapping")
            continue
        for k in r:
            if k not in OK_REQ_KEYS:
                errors.append(f"request {i + 1}: key '{k}' is not allowed (raw requests, bodies, headers, payloads, fuzzing, flows, unsafe and similar are refused)")
        m = str(r.get("method", "GET")).upper()
        if m not in ("GET", "HEAD"):
            errors.append(f"request {i + 1}: only GET and HEAD are allowed (found {m})")
        methods.append(m)
        ps = r.get("path")
        if not isinstance(ps, list) or not ps or len(ps) > 3 or not all(isinstance(p, str) for p in ps):
            errors.append(f"request {i + 1}: path must be a list of one to three strings")
            ps = []
        for p in ps:
            if not p.startswith("{{BaseURL}}/") and p != "{{BaseURL}}":
                errors.append(f"request {i + 1}: every path must start with {{{{BaseURL}}}}")
            paths.append(p)
        if r.get("redirects") or r.get("max-redirects"):
            errors.append(f"request {i + 1}: following redirects is not allowed in a template")
        for mt in r.get("matchers") or []:
            if not isinstance(mt, dict) or mt.get("type") not in OK_MATCHER_TYPES:
                errors.append(f"request {i + 1}: matcher types allowed: {', '.join(sorted(OK_MATCHER_TYPES))}")
                continue
            if mt.get("part", "body") not in OK_PARTS - {"interactsh_protocol"}:
                errors.append(f"request {i + 1}: matcher part '{mt.get('part')}' is not allowed")
            matchers.append(f"{mt['type']}:{mt.get('part', 'body')}")
        if not r.get("matchers"):
            errors.append(f"request {i + 1}: at least one matcher is required")
        for ex in r.get("extractors") or []:
            if not isinstance(ex, dict) or ex.get("type") not in ("regex", "kval"):
                errors.append(f"request {i + 1}: extractor types allowed: regex, kval")
    for expr in _EXPR.findall(content):
        if expr.split("(")[0].strip() not in ALLOWED_VARS:
            errors.append(f"template expression '{{{{{expr[:40]}}}}}' is not allowed (only BaseURL, RootURL, Hostname, Host, Port, Scheme, Path, File)")
    if re.search(r"interactsh|oast|\bexec\b|\bsystem\b|base64_decode|\bresolve\(|\bwait_for\(", content, re.IGNORECASE):
        errors.append("out-of-band, command, resolve or timing helpers are not allowed")
    sem = {"template_id": tid, "severity": info.get("severity"), "name": str(info.get("name", ""))[:160], "methods": sorted(set(methods)), "paths": paths, "matchers": sorted(set(matchers)),
           "request_count": sum(len(r.get("path") or []) for r in reqs if isinstance(r, dict)), "reference": [str(x)[:200] for x in (info.get("reference") or [])[:5]] if isinstance(info.get("reference"), list) else []}
    return {"ok": not errors, "id": tid if isinstance(tid, str) else None, "errors": errors[:20], "semantics": sem}


def approved_template_ids(db: Session) -> set[str]:
    from ..db.models import AivTemplateApproval
    return {t.template_id for t in db.scalars(select(AivTemplateApproval).where(AivTemplateApproval.revoked_at.is_(None)))}


def load_approved_template(db: Session, template_id: str) -> tuple[str, str]:
    """(content, sha256) of the approved template; re-hashes the stored content so a tampered row is refused."""
    from ..db.models import AivTemplateApproval
    row = db.scalars(select(AivTemplateApproval).where(AivTemplateApproval.template_id == template_id, AivTemplateApproval.revoked_at.is_(None))
                     .order_by(AivTemplateApproval.reviewed_at.desc())).first()
    if row is None:
        raise ValueError(f"template '{template_id}' is not approved")
    if hashlib.sha256(row.content.encode()).hexdigest() != row.sha256:
        raise ValueError(f"template '{template_id}' no longer matches its approved hash")
    return row.content, row.sha256


# ---- argv builders (fixed flags only) -----------------------------------------------------------------------------------------------------
def nmap_argv(binary: str, ip: str, ports: list[int], *, version_probe: bool = False) -> list[str]:
    argv = [binary, "-Pn", "-n", "-sT", "--open", "-p", ",".join(str(p) for p in ports), "--max-retries", "1", "--max-rate", "10", "--host-timeout", "120s", "-oX", "-"]
    if version_probe:
        argv[4:4] = ["-sV", "--version-light"]
    argv.append(ip)
    return argv


def naabu_argv(binary: str, ip: str, ports: list[int]) -> list[str]:
    return [binary, "-host", ip, "-p", ",".join(str(p) for p in ports), "-s", "c", "-rate", "10", "-c", "1", "-retries", "1", "-timeout", "3000", "-j", "-silent", "-nc", "-duc"]


def nuclei_argv(binary: str, template_file: str, url: str) -> list[str]:
    return [binary, "-t", template_file, "-u", url, "-j", "-silent", "-nc", "-duc", "-ni", "-nmhe", "-rl", "2", "-c", "1", "-timeout", "5", "-retries", "1", "-or"]


def dnstwist_argv(binary: str, domain: str, fuzzers: list[str] | None = None) -> list[str]:
    argv = [binary, "-f", "list"]
    if fuzzers:
        argv += ["--fuzzers", ",".join(fuzzers)]
    return [*argv, domain]


# ---- parsers --------------------------------------------------------------------------------------------------------------------------------
def parse_nmap_xml(xml_bytes: bytes) -> list[dict[str, Any]]:
    text = xml_bytes.decode("utf-8", "replace")
    if "<!ENTITY" in text or re.search(r"<!DOCTYPE[^>]*\[", text):
        raise ValueError("refusing XML with entity declarations")
    text = re.sub(r"<!DOCTYPE[^>]*>", "", text)
    root = ET.fromstring(text)
    out = []
    for port in root.iter("port"):
        st = port.find("state")
        sv = port.find("service")
        out.append({"port": int(port.get("portid", "0")), "protocol": port.get("protocol"), "state": st.get("state") if st is not None else "unknown",
                    "service": sv.get("name") if sv is not None else None, "product": sv.get("product") if sv is not None else None, "version": sv.get("version") if sv is not None else None})
    return out


def parse_jsonl(data: bytes, limit: int = 500) -> list[dict[str, Any]]:
    out = []
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                v = json.loads(line)
            except ValueError:
                continue
            if isinstance(v, dict):
                out.append(v)
        if len(out) >= limit:
            break
    return out


_SEV = {"info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "high", "unknown": "info"}


def nuclei_observations(rows: list[dict[str, Any]]) -> list[parsers.Obs]:
    out = []
    for r in rows:
        info = r.get("info") or {}
        tid = str(r.get("template-id", "unknown"))
        out.append(parsers.Obs("signature", f"sig:{tid}:{r.get('matcher-name', '')}", str(info.get("name", tid))[:200], _SEV.get(str(info.get("severity", "info")).lower(), "info"),
                               {"template_id": tid, "matched_at": str(r.get("matched-at", ""))[:300], "type": r.get("type"), "matcher": r.get("matcher-name"),
                                "extracted": [str(x)[:120] for x in (r.get("extracted-results") or [])[:5]]},
                               str(info.get("remediation") or "Review the matched resource and apply the vendor's guidance."), "observed", "medium"))
    return out


# ---- running a tool step --------------------------------------------------------------------------------------------------------------------
async def run_tool_step(st: Any, step: dict[str, Any], auth: Any, budget: Budget, emit: Callable[[str, dict[str, Any]], None], cancelled: Callable[[], bool],
                        clock: Callable[[], datetime]) -> tuple[dict[str, Any], list[parsers.Obs], dict[str, Any] | None]:
    resolver = getattr(st.aiv, "resolver", system_resolver) if getattr(st, "aiv", None) else system_resolver
    k = step["kind"]
    if k == "service_detect":
        return await _service_detect(st, step, auth, budget, emit, cancelled, clock, resolver)
    if k == "signature_check":
        return await _signature_check(st, step, auth, budget, emit, cancelled, clock, resolver)
    raise ValueError(f"unknown step kind {k}")


async def _resolve_checked(auth: Any, host: str, resolver: Any) -> tuple[str | None, dict[str, Any] | None]:
    from ..adapters.active.http_metadata import _is_ip
    try:
        ips = [host] if _is_ip(host) else await resolver(host)
    except OSError:
        ips = []
    d = policy.check_resolved(auth, host, ips)
    if not d:
        return None, {"code": d.code, "reason": d.reason}
    return ips[0], None


async def _service_detect(st, step, auth, budget, emit, cancelled, clock, resolver):
    tool = step["tool"]
    host, ports = step["host"].lower(), step["ports"]
    result: dict[str, Any] = {"tool": tool, "host": host, "ports": ports, "blocked": None}
    pv = policy.validate_ports(ports, budget.limits["max_ports"])
    if not pv:
        result["blocked"] = {"code": pv.code, "reason": pv.reason}
        return result, [], result["blocked"]
    for p in ports:
        d = policy.check_host_port(auth, "service_detect", host, p, clock())
        if not d:
            result["blocked"] = {"code": d.code, "reason": f"port {p}: {d.reason}"}
            return result, [], result["blocked"]
    exe = await tool_path(tool)
    if not exe:
        result["blocked"] = {"code": "tool_unavailable", "reason": f"{TOOLS[tool].name} is not installed, not identity-checked, or an unverified version"}
        return result, [], result["blocked"]
    ip, bad = await _resolve_checked(auth, host, resolver)
    if bad:
        result["blocked"] = bad
        return result, [], bad
    try:
        budget.charge("service_detect", host, len(ports) * (3 if tool == "nmap" else 1))
    except BudgetExceeded as exc:
        result["blocked"] = {"code": "budget_exceeded", "reason": f"the {exc.what} budget is used up"}
        return result, [], result["blocked"]
    assert ip is not None
    argv = nmap_argv(exe, ip, ports) if tool == "nmap" else naabu_argv(exe, ip, ports)
    emit("tool_start", {"tool": tool, "ports": ports})
    with tempfile.TemporaryDirectory(prefix="osintcc-aiv-") as scratch:
        proc = await run_argv(argv, min(budget.limits["max_runtime_seconds"], 150), cwd=scratch, extra_env={"HOME": scratch, "USERPROFILE": scratch})
    result["exit_code"] = proc.returncode
    if proc.returncode != 0 or proc.timed_out:
        result["error"] = "timeout" if proc.timed_out else f"exit_{proc.returncode}"
        return result, [], {"code": result["error"], "reason": f"{tool} did not complete"}
    if tool == "nmap":
        rows = parse_nmap_xml(proc.stdout)
        states = {r["port"]: ("open" if r["state"] == "open" else r["state"]) for r in rows}
    else:
        rows = parse_jsonl(proc.stdout)
        states = {int(r["port"]): "open" for r in rows if "port" in r}
    for p in ports:
        states.setdefault(p, "closed_or_filtered")
    result["ports_result"] = {str(p): s for p, s in states.items()}
    result["rows"] = rows
    return result, parsers.port_observations(host, states), None


async def _signature_check(st, step, auth, budget, emit, cancelled, clock, resolver):
    from urllib.parse import urlsplit

    from ..adapters.active.http_metadata import _is_ip
    result: dict[str, Any] = {"url": step["url"], "template_ids": step["template_ids"], "blocked": None}
    d = policy.check_url(auth, "signature_check", step["url"], clock())
    if not d:
        result["blocked"] = {"code": d.code, "reason": d.reason}
        return result, [], result["blocked"]
    exe = await tool_path("nuclei")
    if not exe:
        result["blocked"] = {"code": "tool_unavailable", "reason": "Nuclei is not installed, not identity-checked, or an unverified version"}
        return result, [], result["blocked"]
    host = (urlsplit(step["url"]).hostname or "").lower()
    ip, bad = await _resolve_checked(auth, host, resolver)
    if bad:
        result["blocked"] = bad
        return result, [], bad
    obs: list[parsers.Obs] = []
    with tempfile.TemporaryDirectory(prefix="osintcc-aiv-") as scratch:
        for tid in step["template_ids"]:
            with st.sm() as db:
                try:
                    content, sha = load_approved_template(db, tid)
                except ValueError as exc:
                    result["blocked"] = {"code": "template_not_approved", "reason": str(exc)}
                    return result, obs, result["blocked"]
            rv = review_template(content)                       # reviewed again at run time: a stored row cannot be edited into something unsafe
            if not rv["ok"]:
                result["blocked"] = {"code": "template_review_failed", "reason": "; ".join(rv["errors"][:2])}
                return result, obs, result["blocked"]
            try:
                budget.charge("signature_check", host, max(1, rv["semantics"]["request_count"]))
            except BudgetExceeded as exc:
                result["blocked"] = {"code": "budget_exceeded", "reason": f"the {exc.what} budget is used up"}
                return result, obs, result["blocked"]
            f = Path(scratch) / f"{tid}.yaml"
            f.write_text(content, encoding="utf-8")
            emit("tool_start", {"tool": "nuclei", "template": tid, "sha256": sha[:12]})
            proc = await run_argv(nuclei_argv(exe, str(f), step["url"]), min(budget.limits["max_runtime_seconds"], 150), cwd=scratch,
                                  extra_env={"HOME": scratch, "USERPROFILE": scratch, "XDG_CONFIG_HOME": scratch, "XDG_CACHE_HOME": scratch, "APPDATA": scratch, "LOCALAPPDATA": scratch})
            result.setdefault("runs", []).append({"template": tid, "sha256": sha, "exit_code": proc.returncode, "timed_out": proc.timed_out})
            if proc.timed_out or proc.returncode != 0:
                result["blocked"] = {"code": "timeout" if proc.timed_out else f"exit_{proc.returncode}", "reason": f"nuclei did not complete template {tid}"}
                return result, obs, result["blocked"]
            obs += nuclei_observations(parse_jsonl(proc.stdout))
    # the tool resolved the name itself: confirm the destination did not change to something forbidden while it ran
    if not _is_ip(host):
        try:
            again = await resolver(host)
        except OSError:
            again = []
        chk = policy.check_resolved(auth, host, again)
        if not chk or (ip is not None and ip not in again):
            result["blocked"] = {"code": "destination_changed", "reason": "the host name resolved differently after the run started; its results were discarded"}
            return result, [], result["blocked"]
    return result, obs, None


def _noop(*_a: Any) -> None:
    return None
