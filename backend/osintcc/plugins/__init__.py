"""Plugin host (spec 23.7). Plugins are out-of-process Python programs speaking a small JSON protocol (see sdk/).

Safety model, all enforced here:
* OFF until a person reviews it and enables it with the exact tree hash shown at install; hash re-verified before every run.
* The plugin never touches the network: it names URLs, the host checks them against the manifest's declared domains, fetches them
  with SSRF protection/rate limits, and hands responses back. An undeclared destination is refused.
* Minimal environment, scratch working directory, time and output caps (CPU/address-space rlimits on POSIX; not available on Windows).
* Output is validated against a strict schema; provenance URLs it did not fetch are stripped; repeated invalid output quarantines it.
* No dependency installation, no downloads, no arbitrary executables: only .py/.json/.md/.txt files are accepted at install.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..adapters.base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    RelationshipDraft,
    Target,
)
from ..adapters.cli import run_argv
from ..policy.ssrf import DestinationDenied
from ..policy.targets import TARGET_TYPES, domain_of

HOST_API = 1
MAX_FILES, MAX_BYTES = 200, 5 * 1024 * 1024
ALLOWED_EXT = {".py", ".json", ".md", ".txt", ".csv"}
PLATFORM = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
_HOST = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$|^\{target\}$")
QUARANTINE_AFTER = 3


class PluginError(ValueError):
    pass


def safe_rel(p: str) -> str:
    pp = PurePosixPath(p.replace("\\", "/"))
    if not p or pp.is_absolute() or ".." in pp.parts or ":" in p:
        raise PluginError(f"unsafe relative path: {p!r}")
    return str(pp)


class Perms(BaseModel):
    model_config = ConfigDict(extra="forbid")
    network_domains: list[str] = Field(default_factory=list, max_length=10)
    max_requests: int = Field(default=0, ge=0, le=5)
    filesystem: Literal["none"] = "none"


class RateLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    per_minute: int = Field(default=6, ge=1, le=120)


class Health(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phase: Literal["plan"] = "plan"


class PluginManifest(BaseModel):
    """Every field required by spec 23.7, strictly validated; unknown fields are rejected."""
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,39}$")
    version: str = Field(pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}$")
    name: str = Field(min_length=2, max_length=120)
    maintainer: str = Field(min_length=2, max_length=120)
    license: str = Field(min_length=2, max_length=60)
    entrypoint: str
    platforms: list[Literal["windows", "linux", "macos"]] = Field(min_length=1)
    capabilities: list[str] = Field(default_factory=list, max_length=20)
    input_types: list[str] = Field(min_length=1, max_length=8)
    output_schema_version: Literal[1]
    active_network_access: bool
    minimum_permissions: Perms
    required_secrets: list[str] = Field(default_factory=list, max_length=5)
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    dependencies: list[str] = Field(default_factory=list, max_length=20)
    healthcheck: Health = Field(default_factory=Health)
    fixture_path: str
    uninstall_cleanup: list[str] = Field(default_factory=list, max_length=20)
    min_host_api: int = Field(default=1, ge=1)
    timeout_seconds: int = Field(default=20, ge=1, le=120)
    description: str = Field(default="", max_length=1000)


def validate_manifest(raw: Any) -> PluginManifest:
    try:
        m = PluginManifest.model_validate(raw)
    except ValidationError as exc:
        raise PluginError("; ".join(f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors())) from exc
    for t in m.input_types:
        if t not in TARGET_TYPES:
            raise PluginError(f"unknown input type {t!r}")
    for d in m.minimum_permissions.network_domains:
        if not _HOST.match(d):
            raise PluginError(f"network domain {d!r} must be a hostname, '*.hostname' or '{{target}}'")
    if m.minimum_permissions.max_requests and not m.minimum_permissions.network_domains:
        raise PluginError("a plugin that requests URLs must declare network_domains")
    for field, value in [("entrypoint", m.entrypoint), ("fixture_path", m.fixture_path), *[("uninstall_cleanup", c) for c in m.uninstall_cleanup]]:
        try:
            safe_rel(value)
        except PluginError as exc:
            raise PluginError(f"{field}: {exc}") from exc
    if not m.entrypoint.endswith(".py"):
        raise PluginError("entrypoint must be a relative .py path inside the plugin")
    return m


def tree_hash(root: Path) -> str:
    lines = []
    for f in sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        lines.append(f"{f.relative_to(root).as_posix()}\0{hashlib.sha256(f.read_bytes()).hexdigest()}")
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def copy_plugin(src: Path, dest: Path) -> None:
    """Copy with hard limits. Refuses symlinks and anything that is not plain text/Python."""
    files = [p for p in src.rglob("*") if "__pycache__" not in p.parts]
    if len([f for f in files if f.is_file()]) > MAX_FILES:
        raise PluginError("too many files")
    total = 0
    for f in files:
        if f.is_symlink():
            raise PluginError(f"symbolic links are not allowed: {f.name}")
        if f.is_file():
            if f.suffix.lower() not in ALLOWED_EXT:
                raise PluginError(f"file type not allowed in a plugin: {f.name} (only {', '.join(sorted(ALLOWED_EXT))})")
            total += f.stat().st_size
            if total > MAX_BYTES:
                raise PluginError("plugin exceeds the 5 MB limit")
    for f in files:
        rel = f.relative_to(src)
        if f.is_dir():
            (dest / rel).mkdir(parents=True, exist_ok=True)
        else:
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, dest / rel)


# ------------------------------------------------------------------ strict output schema ------------------------------
class _Ent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(pattern=r"^[a-z][a-z_]{1,24}$")
    key: str = Field(min_length=1, max_length=300)
    display: str | None = Field(default=None, max_length=300)


class _Art(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    content_b64: str
    mime_type: str = Field(default="application/octet-stream", max_length=80)
    source_url: str | None = Field(default=None, max_length=2000)
    http_status: int | None = Field(default=None, ge=100, le=599)


class _Find(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: _Ent
    predicate: str = Field(pattern=r"^[a-z][a-z0-9_.]{1,100}$")
    value: Any = None
    confidence: Literal["unknown", "low", "medium", "high"] = "unknown"
    confidence_reason: str = Field(default="", max_length=500)
    artifact_index: int = Field(default=0, ge=0, le=19)


class _Rel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    from_entity: _Ent
    to_entity: _Ent
    relation_type: str = Field(pattern=r"^[a-z][a-z0-9_]{1,60}$")
    confidence: Literal["unknown", "low", "medium", "high"] = "unknown"
    confidence_reason: str = Field(default="", max_length=500)
    artifact_index: int = Field(default=0, ge=0, le=19)


class PluginResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["success", "partial", "skipped", "error"]
    artifacts: list[_Art] = Field(default_factory=list, max_length=20)
    findings: list[_Find] = Field(default_factory=list, max_length=2000)
    relationships: list[_Rel] = Field(default_factory=list, max_length=2000)
    warnings: list[str] = Field(default_factory=list, max_length=50)
    error_code: str | None = Field(default=None, max_length=60)


def adapter_id_for(plugin_id: str) -> str:
    return "plugin_" + plugin_id.replace("-", "_")


def _allowed_host(url: str, patterns: list[str], target_domain: str | None) -> bool:
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    if p.scheme != "https" or not host or p.username or p.password:
        return False
    for pat in patterns:
        pat = pat.lower()
        if pat == "{target}" and target_domain and host == target_domain:
            return True
        if pat.startswith("*.") and host.endswith(pat[1:]) and host != pat[2:]:
            return True
        if host == pat:
            return True
    return False


class PluginAdapter:
    """Adapts an installed plugin to the host's IntelAdapter contract."""

    def __init__(self, manifest: PluginManifest, root: Path, expected_hash: str, on_invalid: Callable[[str, str, str], None]):
        self.pm, self.root, self.expected_hash, self.on_invalid = manifest, root, expected_hash, on_invalid
        net = manifest.minimum_permissions.max_requests > 0
        cls = "active" if manifest.active_network_access else ("passive" if net else "local_only")
        self.manifest = AdapterManifest(
            id=adapter_id_for(manifest.id), name=f"{manifest.name} (plugin)", version=manifest.version,
            supported_target_types=manifest.input_types, operation_class=cls, needs_network=net,
            rate_limit_per_minute=manifest.rate_limits.per_minute, timeout_seconds=manifest.timeout_seconds,
            license=manifest.license, endpoints=manifest.minimum_permissions.network_domains,
            description=manifest.description or f"Third-party plugin by {manifest.maintainer}", default_selected=False,
            disciplines=["OSINT"], access_class="PUBLIC")

    def _verify(self) -> str | None:
        return None if tree_hash(self.root) == self.expected_hash else "plugin files changed since they were reviewed"

    async def _phase(self, phase: str, payload: dict[str, Any]):
        scratch = tempfile.mkdtemp(prefix="osintcc-plugin-")
        try:
            entry = str(self.root / self.pm.entrypoint)
            if getattr(sys, "frozen", False):  # packaged build: no separate python; the sidecar runs the script (see osintcc.server)
                argv = [sys.executable, "--run-script", entry, "--phase", phase]
            else:
                argv = [sys.executable, "-E", "-s", "-S", entry, "--phase", phase]
            return await run_argv(argv, self.pm.timeout_seconds, 4 * 1024 * 1024, stdin_data=json.dumps(payload).encode(), cwd=scratch,
                                  extra_env={"PYTHONIOENCODING": "utf-8"}, limits={"cpu_seconds": self.pm.timeout_seconds + 5,
                                                                                     "address_space": 1024 * 1024 * 1024, "nproc": 64})
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    async def health(self) -> dict:
        bad = self._verify()
        if bad:
            return {"status": "unavailable", "detail": f"tampered: {bad}"}
        fx = json.loads((self.root / self.pm.fixture_path).read_text(encoding="utf8"))
        res = await self._phase("plan", {"protocol": 1, "phase": "plan", "target": fx["target"]})
        try:
            ok = res.returncode == 0 and isinstance(json.loads(res.stdout).get("requests"), list)
        except ValueError:
            ok = False
        return {"status": "healthy" if ok else "degraded", "version": self.pm.version, "detail": "plan phase answered correctly" if ok else "plan phase failed"}

    def _invalid(self, why: str) -> AdapterResult:
        self.on_invalid(self.pm.id, self.pm.version, why)
        return AdapterResult(adapter_id=self.manifest.id, status="error", error_code="plugin_invalid_output", warnings=[f"plugin output rejected: {why}"])

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        bad = self._verify()
        if bad:
            return AdapterResult(adapter_id=aid, status="error", error_code="plugin_tampered", warnings=[bad + "; re-review and re-enable it"])
        if PLATFORM not in self.pm.platforms:
            return AdapterResult(adapter_id=aid, status="skipped", error_code="unsupported_platform", warnings=[f"plugin does not support {PLATFORM}"])
        tgt = {"type": target.type, "raw": target.raw, "canonical": target.canonical}
        plan = await self._phase("plan", {"protocol": 1, "phase": "plan", "target": tgt})
        if plan.timed_out:
            return AdapterResult(adapter_id=aid, status="error", error_code="timeout", retryable=True, warnings=["plugin timed out and was killed"])
        try:
            requests = json.loads(plan.stdout)["requests"] if plan.returncode == 0 else None
            assert isinstance(requests, list) and all(isinstance(r, dict) and set(r) == {"url"} and isinstance(r["url"], str) for r in requests)
        except (ValueError, KeyError, AssertionError, TypeError):
            return self._invalid("plan phase did not return {'requests': [{'url': ...}]}")
        perms = self.pm.minimum_permissions
        if len(requests) > perms.max_requests:
            return self._invalid(f"requested {len(requests)} URLs, manifest allows {perms.max_requests}")
        tdom = domain_of(target.type, target.canonical)
        for r in requests:
            if not _allowed_host(r["url"], perms.network_domains, tdom):
                self.on_invalid(self.pm.id, self.pm.version, "undeclared destination")
                return AdapterResult(adapter_id=aid, status="error", error_code="undeclared_network_destination",
                                     warnings=[f"plugin asked for a destination its manifest does not declare: {urlsplit(r['url']).hostname}; nothing was fetched"])
        responses, fetched = [], set()
        for r in requests:
            try:
                res = await ctx.http.get(r["url"])
            except DestinationDenied as exc:
                responses.append({"url": r["url"], "status": 0, "headers": {}, "body_b64": "", "error": str(exc)[:200]})
                continue
            except Exception as exc:
                return AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True, warnings=[f"{type(exc).__name__}"])
            fetched.add(res.url)
            fetched.add(r["url"])
            responses.append({"url": res.url, "status": res.status, "headers": dict(list(res.headers.items())[:30]),
                              "body_b64": base64.b64encode(res.body[:1_000_000]).decode()})
        out = await self._phase("parse", {"protocol": 1, "phase": "parse", "target": tgt, "responses": responses})
        if out.timed_out:
            return AdapterResult(adapter_id=aid, status="error", error_code="timeout", retryable=True, warnings=["plugin timed out and was killed"])
        if out.returncode != 0:
            return self._invalid(f"exit code {out.returncode}")
        try:
            pr = PluginResult.model_validate_json(out.stdout)
            arts = [RawArtifact(name=a.name, content=base64.b64decode(a.content_b64, validate=True), mime_type=a.mime_type,
                                source_url=a.source_url if a.source_url in fetched else None, http_status=a.http_status) for a in pr.artifacts]
        except (ValidationError, ValueError) as exc:
            return self._invalid(f"schema violation ({type(exc).__name__})")
        warnings = [w[:500] for w in pr.warnings]
        if any(a.source_url and a.source_url not in fetched for a in pr.artifacts):
            warnings.append("The plugin named a source URL it did not fetch; the URL was removed from provenance.")
        if any(f.artifact_index >= max(len(arts), 1) for f in pr.findings) or any(r.artifact_index >= max(len(arts), 1) for r in pr.relationships):
            return self._invalid("a finding refers to an artifact that does not exist")
        return AdapterResult(
            adapter_id=aid, status=pr.status, artifacts=arts, error_code=pr.error_code, warnings=warnings,
            findings=[FindingDraft(subject=EntityRef(**f.subject.model_dump()), predicate=f"{self.pm.id}.{f.predicate}", value=f.value,
                                   confidence=f.confidence, confidence_reason=f.confidence_reason, artifact_index=f.artifact_index) for f in pr.findings],
            relationships=[RelationshipDraft(from_entity=EntityRef(**r.from_entity.model_dump()), to_entity=EntityRef(**r.to_entity.model_dump()),
                                             relation_type=r.relation_type, confidence=r.confidence, confidence_reason=r.confidence_reason,
                                             artifact_index=r.artifact_index) for r in pr.relationships])


async def run_contract_tests(root: Path, manifest: PluginManifest) -> dict[str, Any]:
    """Offline conformance check against the plugin's own fixture (no network, deterministic)."""
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
    try:
        fx = json.loads((root / manifest.fixture_path).read_text(encoding="utf8"))
        target, canned, expected = fx["target"], fx["responses"], fx["expected"]
    except (OSError, ValueError, KeyError) as exc:
        add("fixture is readable and has target/responses/expected", False, type(exc).__name__)
        return {"passed": False, "checks": checks}
    add("fixture present", True)
    add("declares the current host API", manifest.min_host_api <= HOST_API, f"min_host_api={manifest.min_host_api}")
    add("supports this platform", PLATFORM in manifest.platforms, PLATFORM)

    seen_urls: list[str] = []

    class _FixtureHttp:
        async def get(self, url: str, headers=None):
            seen_urls.append(url)
            r = canned.get(url)
            if r is None:
                raise DestinationDenied(f"no fixture response for {url}")
            from ..policy.ssrf import HttpResult
            return HttpResult(r["status"], {}, r["body"].encode(), url)
    tmp_hash = tree_hash(root)
    results = []
    for i in range(2):  # run twice: determinism
        ad = PluginAdapter(manifest, root, tmp_hash, lambda *_: None)
        results.append(await ad.run(Target(**target), AdapterContext(http=_FixtureHttp())))
    r = results[0]
    add("runs to the expected status", r.status == expected["status"], f"status={r.status} codes={r.error_code} {r.warnings[:1]}")
    preds = {f.predicate.split(".", 1)[1] for f in r.findings}
    add("emits the expected predicates", set(expected.get("predicates", [])) <= preds, str(sorted(preds)))
    for k, v in expected.get("values", {}).items():
        got = next((f.value for f in r.findings if f.predicate.endswith("." + k)), None)
        add(f"value of {k}", got == v, f"got {got!r}")
    add("only requests declared destinations", r.error_code != "undeclared_network_destination")
    add("is deterministic", [f.model_dump() for f in results[0].findings] == [f.model_dump() for f in results[1].findings])
    add("provenance URLs were actually fetched", all(a.source_url is None or a.source_url in seen_urls for a in r.artifacts))
    return {"passed": all(c["ok"] for c in checks), "checks": checks, "tree_sha256": tmp_hash}
