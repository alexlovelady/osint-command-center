"""Third-party CLI adapters. Fixed argv templates only; target text is always a single argv element."""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ...setup.state import managed_path
from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    RelationshipDraft,
    Target,
    skipped,
)

MAX_OUTPUT = 4 * 1024 * 1024
MAX_HOSTS = 2000  # a wildcard-heavy domain can report tens of thousands of names; keep the case usable and say so


@dataclass
class ProcResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    truncated: bool = False


async def run_argv(argv: list[str], timeout: float, max_output: int = MAX_OUTPUT, *, stdin_data: bytes | None = None,
                   cwd: str | None = None, extra_env: dict[str, str] | None = None,
                   limits: dict[str, int] | None = None) -> ProcResult:
    """Execute argv (never a shell string), with timeout, output cap and a minimal environment."""
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be a non-empty list of strings")
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "HOME", "USERPROFILE", "TEMP", "TMP")}
    env.update(extra_env or {})
    kwargs: dict = {}
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
        if limits:  # POSIX resource limits (CPU seconds, address space); Windows has no equivalent here and says so in the docs
            def _limit() -> None:
                import resource
                if "cpu_seconds" in limits:
                    resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"], limits["cpu_seconds"]))
                if "address_space" in limits:
                    resource.setrlimit(resource.RLIMIT_AS, (limits["address_space"], limits["address_space"]))
                if "nproc" in limits:
                    resource.setrlimit(resource.RLIMIT_NPROC, (limits["nproc"], limits["nproc"]))
            kwargs["preexec_fn"] = _limit
    proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                                                stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
                                                env=env, cwd=cwd, **kwargs)
    if stdin_data is not None:
        async def feed() -> None:
            assert proc.stdin is not None
            try:
                proc.stdin.write(stdin_data)
                await proc.stdin.drain()
                proc.stdin.close()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass  # the child exited without reading its input; its exit code tells the story
        asyncio.get_running_loop().create_task(feed())

    async def read(stream) -> tuple[bytes, bool]:
        buf, over = bytearray(), False
        while chunk := await stream.read(65536):
            if len(buf) < max_output:
                buf.extend(chunk[: max_output - len(buf)])
            else:
                over = True
        return bytes(buf), over or len(buf) >= max_output

    try:
        (out, trunc), (err, _) = await asyncio.wait_for(
            asyncio.gather(read(proc.stdout), read(proc.stderr)), timeout)
        await asyncio.wait_for(proc.wait(), 5)
        return ProcResult(proc.returncode, out, err, False, trunc)
    except TimeoutError:
        _kill(proc)
        try:
            await asyncio.wait_for(proc.wait(), 5)
        except TimeoutError:
            pass
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.feed_eof()
        if sys.platform == "win32":
            proc._transport.close()  # type: ignore[attr-defined]  # release proactor pipes so no handles leak
        return ProcResult(None, b"", b"", timed_out=True)


def _kill(proc: asyncio.subprocess.Process) -> None:
    try:
        if sys.platform != "win32":
            import signal
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # terminate the whole tree: tools such as amass start helper processes that would otherwise be orphaned
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, check=False, timeout=15)
            proc.kill()
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass


class CliAdapter:
    """Base: locate the binary, smoke-test `--version`, then run a fixed argv."""
    binary_names: tuple[str, ...] = ()
    extra_env_keys: tuple[str, ...] = ()  # host env vars this tool genuinely needs (everything else is stripped)
    version_args: tuple[str, ...] = ("--version",)
    manifest: AdapterManifest

    def __init__(self, binary_path: str | None = None, state_path: Path | None = None):
        self._configured = binary_path
        self._state = state_path
        self._parse_warnings: list[str] = []

    def locate(self) -> str | None:
        if self._configured and os.path.isfile(self._configured):
            return self._configured
        installed = managed_path(self._state, self.manifest.id)  # installed by first-run setup
        if installed:
            return installed
        for n in self.binary_names:
            p = shutil.which(n)
            if p:
                return p
        return None

    async def health(self) -> dict:
        path = self.locate()
        if not path:
            return {"status": "not_installed", "detail": self.manifest.install_hint or "binary not found on PATH"}
        res = await run_argv([path, *self.version_args], 15)
        if res.timed_out or res.returncode not in (0, None):
            return {"status": "degraded", "binary_path": path, "detail": "version smoke test failed"}
        text = (res.stdout or res.stderr).decode(errors="replace").strip().splitlines()
        return {"status": "healthy", "binary_path": path, "version": text[0][:120] if text else "unknown"}

    def build_argv(self, binary: str, target: Target) -> list[str]:
        raise NotImplementedError

    def parse(self, target: Target, stdout: bytes) -> tuple[list[FindingDraft], list[RelationshipDraft]]:
        raise NotImplementedError

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        binary = self.locate()
        if not binary:
            return skipped(aid, "not_installed", f"{self.manifest.name} is not installed. "
                           f"{self.manifest.install_hint or ''}".strip())
        with tempfile.TemporaryDirectory(prefix="osintcc-cli-") as scratch:  # tools that write report files do it here, not in the app's cwd
            res = await run_argv(self.build_argv(binary, target), self.manifest.timeout_seconds, cwd=scratch,
                                 extra_env={k: os.environ[k] for k in self.extra_env_keys if k in os.environ})
        if res.timed_out:
            return AdapterResult(adapter_id=aid, status="error", error_code="timeout", retryable=True,
                                 warnings=[f"timed out after {self.manifest.timeout_seconds}s; process killed"])
        art = RawArtifact(name=f"{aid}-output.txt", content=res.stdout, mime_type="text/plain",
                          note=f"exit={res.returncode}")
        if res.returncode != 0:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"exit_{res.returncode}",
                                 artifacts=[art], warnings=[res.stderr.decode(errors="replace")[:500]])
        self._parse_warnings = []
        try:
            findings, rels = self.parse(target, res.stdout)
        except Exception as exc:  # output contract drift: keep raw, flag degraded
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", artifacts=[art],
                                 warnings=[f"output could not be parsed ({type(exc).__name__}); adapter degraded"])
        warns = (["Output truncated at size limit."] if res.truncated else []) + sorted(set(self._parse_warnings))
        return AdapterResult(adapter_id=aid, status="partial" if res.truncated else "success", artifacts=[art],
                             findings=findings, relationships=rels, warnings=warns)


class SubfinderAdapter(CliAdapter):
    binary_names = ("subfinder",)
    version_args = ("-version",)
    manifest = AdapterManifest(
        id="subfinder", name="Subfinder (passive subdomains)", version="1.0.0", supported_target_types=["domain"],
        operation_class="passive", needs_network=True, timeout_seconds=120, license="MIT (ProjectDiscovery)",
        endpoints=["passive third-party sources chosen by subfinder"],
        install_hint="Install Subfinder from https://github.com/projectdiscovery/subfinder (pin a verified release).",
        description="Passive subdomain enumeration. Runs `subfinder -d <domain> -silent -json`.")

    def build_argv(self, binary: str, target: Target) -> list[str]:
        return [binary, "-d", target.canonical, "-silent", "-json"]

    def parse(self, target, stdout):
        subject = EntityRef(type="domain", key=target.canonical, display=target.canonical)
        findings, rels = [], []
        seen: set[str] = set()
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            host = json.loads(line)["host"].strip().lower().rstrip(".")
            if host in seen or not (host == target.canonical or host.endswith("." + target.canonical)):
                continue
            if len(seen) >= MAX_HOSTS:
                self._parse_warnings.append(f"Only the first {MAX_HOSTS} hostnames were kept; the raw output artifact has them all.")
                continue
            seen.add(host)
            sub = EntityRef(type="domain", key=host, display=host)
            reason = "Reported by a passive third-party source via subfinder; not independently verified"
            findings.append(FindingDraft(subject=sub, predicate="subfinder.discovered", value=host,
                                         confidence="low", confidence_reason=reason))
            if host != target.canonical:
                rels.append(RelationshipDraft(from_entity=sub, to_entity=subject, relation_type="subdomain_of",
                                              confidence="low", confidence_reason=reason))
        return findings, rels


_SHERLOCK_LINE = re.compile(r"^\[\+\]\s+(?P<site>[^:]+):\s+(?P<url>https?://\S+)\s*$")


class SherlockAdapter(CliAdapter):
    binary_names = ("sherlock",)
    manifest = AdapterManifest(
        id="sherlock", name="Sherlock (public username check)", version="1.0.0", supported_target_types=["username"],
        operation_class="public_site_query", needs_network=True, timeout_seconds=300, license="MIT",
        endpoints=["hundreds of third-party public websites"],
        install_hint="Install with `uv tool install sherlock-project` after reviewing the project.",
        description="Checks whether a handle exists on public sites. A match is a LEAD, never proof of one person.")

    def build_argv(self, binary: str, target: Target) -> list[str]:
        return [binary, "--print-found", "--no-color", "--timeout", "10", "--", target.canonical]

    def parse(self, target, stdout):
        subject = EntityRef(type="username", key=target.canonical, display=target.canonical)
        findings, rels = [], []
        for line in stdout.decode(errors="replace").splitlines():
            m = _SHERLOCK_LINE.match(line.strip())
            if not m:
                continue
            prof = EntityRef(type="url", key=m["url"], display=f'{m["site"]}: {m["url"]}')
            reason = "Handle string exists at this URL; no evidence the account belongs to the person of interest"
            findings.append(FindingDraft(subject=prof, predicate="profile.candidate", value={"site": m["site"]},
                                         confidence="low", confidence_reason=reason))
            rels.append(RelationshipDraft(from_entity=subject, to_entity=prof, relation_type="candidate_profile",
                                          confidence="low", confidence_reason=reason))
        return findings, rels


class MaigretAdapter(SherlockAdapter):
    binary_names = ("maigret",)
    manifest = AdapterManifest(
        id="maigret", name="Maigret (public username check)", version="1.0.0", supported_target_types=["username"],
        operation_class="public_site_query", needs_network=True, timeout_seconds=420, license="MIT",
        endpoints=["thousands of third-party public websites"],
        install_hint="Install with `uv tool install maigret` after reviewing the project.",
        description="Broader public-site username check. A match is a LEAD, never proof of one person.")

    def build_argv(self, binary: str, target: Target) -> list[str]:
        # --no-autoupdate: no hidden database download at run time; --no-recursion/--no-extracting: never chase identities beyond the target
        return [binary, "--no-color", "--no-progressbar", "--no-autoupdate", "--no-recursion", "--no-extracting", "--timeout", "10", "--", target.canonical]


_HOST = re.compile(r"(?<![A-Za-z0-9-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![A-Za-z0-9-])")
_MAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,200}\.[A-Za-z]{2,24}")


def _hosts_under(target: Target, text: str) -> list[str]:
    out: list[str] = []
    for h in _HOST.findall(text.lower()):
        if (h == target.canonical or h.endswith("." + target.canonical)) and h not in out:
            out.append(h)
    return out[:2000]


class AmassAdapter(CliAdapter):
    """OWASP Amass v5 passive enumeration."""
    extra_env_keys = ("APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME")
    binary_names = ("amass",)
    version_args = ("-version",)
    manifest = AdapterManifest(
        id="amass", default_selected=False, name="OWASP Amass (passive enumeration)", version="0.1.0-unverified",
        supported_target_types=["domain"], operation_class="passive", needs_network=True, timeout_seconds=300, license="Apache-2.0",
        endpoints=["passive third-party data sources chosen by amass"],
        install_hint="Run first-run Setup, or install an OWASP Amass v5 release from https://github.com/owasp-amass/amass.",
        description="Runs `amass enum -passive -d <domain>` (v5.1.1 accepts these flags). Name parsing is generic (hostnames under the target) and was NOT verified: the real passive run returned nothing within its time limit.")

    def build_argv(self, binary: str, target: Target) -> list[str]:
        workdir = (self._state.parent / "amass-data") if self._state else (Path(tempfile.gettempdir()) / "osintcc-amass")
        workdir.mkdir(parents=True, exist_ok=True)  # amass v5 refuses to start without a writable output directory
        return [binary, "enum", "-passive", "-nocolor", "-silent", "-timeout", "4", "-dir", str(workdir), "-d", target.canonical]

    def parse(self, target, stdout):
        subject = EntityRef(type="domain", key=target.canonical, display=target.canonical)
        reason = "Reported by a passive third-party source via amass; not independently verified"
        findings, rels = [], []
        for host in _hosts_under(target, stdout.decode(errors="replace")):
            sub = EntityRef(type="domain", key=host, display=host)
            findings.append(FindingDraft(subject=sub, predicate="amass.discovered", value=host, confidence="low", confidence_reason=reason))
            if host != target.canonical:
                rels.append(RelationshipDraft(from_entity=sub, to_entity=subject, relation_type="subdomain_of", confidence="low",
                                              confidence_reason=reason))
        return findings, rels


class TheHarvesterAdapter(CliAdapter):
    """theHarvester 4.x passive search. Linux/macOS only (the project does not support native Windows)."""
    binary_names = ("theHarvester", "theharvester")
    version_args = ("--help",)  # it has no --version; a clean --help proves it starts
    manifest = AdapterManifest(
        id="theharvester", default_selected=False, name="theHarvester (passive emails and hosts)", version="0.2.0",
        supported_target_types=["domain"], operation_class="passive", needs_network=True, timeout_seconds=300, license="GPL-2.0 (run as a separate process)",
        endpoints=["passive search sources chosen by theHarvester (crtsh, rapiddns, duckduckgo)"],
        install_hint="Run first-run Setup (Linux) or install theHarvester from https://github.com/laramies/theHarvester after review. Not supported on native Windows.",
        description="Runs `theHarvester -d <domain> -b crtsh,rapiddns,duckduckgo`. Verified on Linux against theHarvester 4.11.1 (two real hostnames parsed for example.com).")

    def build_argv(self, binary: str, target: Target) -> list[str]:
        return [binary, "-d", target.canonical, "-b", "crtsh,rapiddns,duckduckgo", "-l", "200"]

    def parse(self, target, stdout):
        subject = EntityRef(type="domain", key=target.canonical, display=target.canonical)
        reason = "Reported by a passive public source via theHarvester; not independently verified"
        text = stdout.decode(errors="replace")
        findings, rels = [], []
        for host in _hosts_under(target, text):
            if host == target.canonical:
                continue
            sub = EntityRef(type="domain", key=host, display=host)
            findings.append(FindingDraft(subject=sub, predicate="theharvester.host", value=host, confidence="low", confidence_reason=reason))
            rels.append(RelationshipDraft(from_entity=sub, to_entity=subject, relation_type="subdomain_of", confidence="low", confidence_reason=reason))
        for mail in sorted({m.lower() for m in _MAIL.findall(text) if m.lower().endswith("@" + target.canonical)})[:200]:
            findings.append(FindingDraft(subject=EntityRef(type="email", key=mail, display=mail), predicate="theharvester.email", value=mail,
                                         confidence="low", confidence_reason=reason))
        return findings, rels
