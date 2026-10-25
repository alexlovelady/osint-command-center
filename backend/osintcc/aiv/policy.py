"""Deterministic authorization gates for AIV. Pure functions: no network, no database, no clock except what is passed in.

Every network action is judged here (at plan time, at run start and immediately before each request). A decision that is not an explicit yes is a no.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, time
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from ..policy.ssrf import METADATA_IPS, ip_is_public

# What a check may do. Anything else does not exist.
CLASSES = ("http_metadata", "tls_handshake", "tcp_connect", "service_detect", "signature_check")
LAB_CLASS = "lab_network"          # an explicit owner statement that the target is a private lab; never implied
ASSET_TYPES = ("fqdn", "ip", "cidr", "url_prefix")
ATTESTATION_KINDS = ("signed_document", "owner_statement", "email_confirmation", "domain_control_record", "mandate_letter")
DEFAULT_LIMITS: dict[str, Any] = {"max_requests": 100, "max_bytes": 2_000_000, "max_runtime_seconds": 600, "max_ports": 10, "max_concurrent_hosts": 1,
                                  "requests_per_second": 2.0, "max_redirects": 3, "max_retries": 1, "max_hosts_per_run": 1}
_LIMIT_FLOOR = {"max_requests": 1, "max_bytes": 1000, "max_runtime_seconds": 5, "max_ports": 1, "max_concurrent_hosts": 1, "requests_per_second": 0.1, "max_redirects": 0, "max_retries": 0,
                "max_hosts_per_run": 1}
_FQDN = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
_WILD = re.compile(r"^\*\.(?=.{1,250}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str = "ok"
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


OK = Decision(True)


def deny(code: str, reason: str) -> Decision:
    return Decision(False, code, reason)


def aware(d: Any) -> Any:
    """Naive datetimes from the database are UTC."""
    return d if d is None or d.tzinfo else d.replace(tzinfo=UTC)


# ---- scope normalisation ------------------------------------------------------------------------------------------------------------------
def canonical_entry(asset_type: str, value: str) -> str:
    """Validate and canonicalise one scope entry. Raises ValueError with a plain message."""
    v = value.strip()
    if not v or len(v) > 300 or any(c.isspace() for c in v):
        raise ValueError("scope entries must be non-empty, without spaces")
    if asset_type == "fqdn":
        v = v.lower().rstrip(".")
        if not (_FQDN.match(v) or _WILD.match(v)):
            raise ValueError(f"'{value}' is not a fully qualified domain name (a '*.' wildcard covers exactly one label)")
        return v
    if asset_type == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise ValueError(f"'{value}' is not an IP address") from exc
    if asset_type == "cidr":
        try:
            n = ipaddress.ip_network(v, strict=True)
        except ValueError as exc:
            raise ValueError(f"'{value}' is not a CIDR block with a clean network address") from exc
        if (n.version == 4 and n.prefixlen < 24) or (n.version == 6 and n.prefixlen < 64):
            raise ValueError("a CIDR block larger than /24 (IPv4) or /64 (IPv6) is too broad for one authorization")
        return str(n)
    if asset_type == "url_prefix":
        p = urlsplit(v)
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password or p.query or p.fragment:
            raise ValueError("a URL prefix is http(s)://host[:port]/path without credentials, query or fragment")
        host = p.hostname.lower()
        port = f":{p.port}" if p.port and p.port != (443 if p.scheme == "https" else 80) else ""
        return f"{p.scheme}://{host}{port}{p.path.rstrip('/') or ''}"
    raise ValueError(f"asset type must be one of {', '.join(ASSET_TYPES)}")


def scope_snapshot(auth: Any) -> str:
    """Hash of what an authorization permits (scope, ports, paths, classes, exclusions, limits). Dates are not part of it: expiry and revocation are judged live."""
    body = {k: getattr(auth, k) for k in ("asset_type", "canonical_scope", "ports_json", "paths_json", "allowed_classes_json", "exclusions_json", "limits_json")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def effective_limits(auth_limits: dict[str, Any] | None) -> dict[str, Any]:
    """Defaults, lowered (never raised) by the authorization's own limits."""
    out = dict(DEFAULT_LIMITS)
    for k, v in (auth_limits or {}).items():
        if k in out and isinstance(v, int | float) and not isinstance(v, bool):
            out[k] = max(_LIMIT_FLOOR[k], min(out[k], v))
    return out


def validate_limits(limits: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for k, v in limits.items():
        if k in DEFAULT_LIMITS:
            if isinstance(v, bool) or not isinstance(v, int | float) or v < _LIMIT_FLOOR[k]:
                raise ValueError(f"limit '{k}' must be a number of at least {_LIMIT_FLOOR[k]}")
            if v > DEFAULT_LIMITS[k]:
                raise ValueError(f"limit '{k}' cannot be raised above the built-in maximum of {DEFAULT_LIMITS[k]} (it can only be lowered)")
            clean[k] = v
        elif k == "windows":
            clean[k] = _validate_windows(v)
        elif k == "timezone":
            try:
                ZoneInfo(str(v))
            except Exception as exc:
                raise ValueError(f"unknown time zone '{v}'") from exc
            clean[k] = str(v)
        else:
            raise ValueError(f"unknown limit '{k}'")
    return clean


def _validate_windows(w: Any) -> list[dict[str, Any]]:
    if not isinstance(w, list) or not w or len(w) > 14:
        raise ValueError("windows must be a short list of {days, start, end}")
    out = []
    for item in w:
        if not isinstance(item, dict) or set(item) - {"days", "start", "end"}:
            raise ValueError("each window has only days, start and end")
        days = item.get("days")
        if not isinstance(days, list) or not days or any(not isinstance(d, int) or d < 0 or d > 6 for d in days):
            raise ValueError("window days are numbers 0 (Monday) to 6 (Sunday)")
        try:
            s, e = time.fromisoformat(item["start"]), time.fromisoformat(item["end"])
        except (KeyError, ValueError) as exc:
            raise ValueError("window start and end are HH:MM") from exc
        if s >= e:
            raise ValueError("a window must end after it starts")
        out.append({"days": sorted(set(days)), "start": item["start"], "end": item["end"]})
    return out


# ---- the gates -----------------------------------------------------------------------------------------------------------------------------
def authorization_live(auth: Any, now: datetime) -> Decision:
    if auth is None:
        return deny("auth_missing", "no asset authorization covers this action")
    if auth.revoked_at is not None:
        return deny("auth_revoked", "the asset authorization was revoked")
    if now < aware(auth.starts_at):
        return deny("auth_not_started", "the asset authorization has not started yet")
    if now >= aware(auth.expires_at):
        return deny("auth_expired", "the asset authorization has expired")
    win = (auth.limits_json or {}).get("windows")
    if win:
        tz = ZoneInfo((auth.limits_json or {}).get("timezone") or "UTC")
        local = now.astimezone(tz)
        if not any(local.weekday() in w["days"] and time.fromisoformat(w["start"]) <= local.time() < time.fromisoformat(w["end"]) for w in win):
            return deny("window_closed", "outside the permitted time window")
    return OK


def class_allowed(auth: Any, cls: str) -> Decision:
    if cls not in CLASSES:
        return deny("class_unknown", f"'{cls}' is not an AIV check class")
    if cls not in (auth.allowed_classes_json or []):
        return deny("class_not_allowed", f"the authorization does not permit '{cls}'")
    return OK


def _host_matches(entry: str, host: str) -> bool:
    if entry.startswith("*."):
        suffix = entry[1:]                                   # ".example.com"
        return host.endswith(suffix) and "." not in host[: -len(suffix)] and len(host) > len(suffix)
    return host == entry


def _entry_covers(asset_type: str, entry: str, host: str, port: int | None, path: str | None, scheme: str | None) -> bool:
    if asset_type == "fqdn":
        return _host_matches(entry, host)
    if asset_type == "ip":
        return host == entry
    if asset_type == "cidr":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry)
        except ValueError:
            return False
    p = urlsplit(entry)
    ep = p.port or (443 if p.scheme == "https" else 80)
    return (scheme in (None, p.scheme) and host == p.hostname and (port in (None, ep)) and (path is None or path == (p.path or "/") or path.startswith((p.path.rstrip("/") + "/") if p.path else "/")))


def _excluded(auth: Any, host: str, port: int | None, path: str | None) -> bool:
    for ex in auth.exclusions_json or []:
        if ex.startswith("path:"):
            if path is not None and (path == ex[5:] or path.startswith(ex[5:].rstrip("/") + "/")):
                return True
        elif ex.startswith("port:"):
            if port is not None and ex[5:].isdigit() and port == int(ex[5:]):
                return True
        else:
            for typ in ("fqdn", "ip", "cidr"):
                try:
                    if _entry_covers(typ, canonical_entry(typ, ex), host, port, path, None):
                        return True
                except ValueError:
                    continue
    return False


def target_in_scope(auth: Any, host: str, port: int | None = None, path: str | None = None, scheme: str | None = None) -> Decision:
    host = host.lower().rstrip(".")
    if not any(_entry_covers(auth.asset_type, e, host, port, path, scheme) for e in auth.canonical_scope or []):
        return deny("host_out_of_scope", f"{host} is not covered by this authorization")
    if _excluded(auth, host, port, path):
        return deny("excluded", f"{host}{'' if port is None else ':' + str(port)}{path or ''} is explicitly excluded")
    if port is not None and port not in (auth.ports_json or []):
        return deny("port_out_of_scope", f"port {port} is not authorized (allowed: {', '.join(map(str, auth.ports_json or [])) or 'none'})")
    if path is not None:
        prefixes = auth.paths_json or ["/"]
        if not any(path == p or path.startswith(p.rstrip("/") + "/") or p == "/" for p in prefixes):
            return deny("path_out_of_scope", f"path {path} is outside the authorized paths")
    return OK


def check_url(auth: Any, cls: str, url: str, now: datetime) -> Decision:
    """Lexical gate for one HTTP(S) request: live window, class, scheme, host, port and path. No DNS."""
    for step in (authorization_live(auth, now), class_allowed(auth, cls) if auth is not None else OK):
        if not step:
            return step
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return deny("scheme_denied", "only http and https URLs are allowed")
    if p.username or p.password:
        return deny("credentials_in_url", "credentials in a URL are never allowed")
    port = p.port or (443 if p.scheme == "https" else 80)
    return target_in_scope(auth, p.hostname, port, p.path or "/", p.scheme)


def check_host_port(auth: Any, cls: str, host: str, port: int, now: datetime) -> Decision:
    for step in (authorization_live(auth, now), class_allowed(auth, cls) if auth is not None else OK):
        if not step:
            return step
    return target_in_scope(auth, host, port, None, None)


def check_resolved(auth: Any, host: str, ips: list[str]) -> Decision:
    """Runs at connection time on what the name REALLY resolved to (DNS rebinding, internal pivots, metadata endpoints)."""
    if not ips:
        return deny("unresolvable", f"{host} did not resolve")
    lab = LAB_CLASS in (auth.allowed_classes_json or [])
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return deny("resolved_ip_forbidden", f"{host} resolved to something that is not an IP address")
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if str(addr) in METADATA_IPS or addr.is_multicast or addr.is_unspecified or (addr.is_link_local and not lab):
            return deny("resolved_ip_forbidden", f"{host} resolved to {addr}, a forbidden destination")
        if auth.asset_type in ("ip", "cidr"):
            if not any(_entry_covers(auth.asset_type, e, str(addr), None, None, None) for e in auth.canonical_scope or []):
                return deny("resolved_ip_forbidden", f"{host} resolved to {addr}, which is outside the authorized addresses")
        if not ip_is_public(str(addr)) and not lab:
            return deny("resolved_ip_forbidden", f"{host} resolved to non-public {addr}; a private target needs an explicit lab authorization")
    return OK


def check_redirect(auth: Any, cls: str, from_url: str, location: str, now: datetime, hops: int, max_redirects: int) -> Decision:
    from urllib.parse import urljoin
    if hops >= max_redirects:
        return deny("redirect_limit", f"more than {max_redirects} redirects")
    target = urljoin(from_url, location)
    d = check_url(auth, cls, target, now)
    if not d:
        return deny("redirect_out_of_scope", f"redirect to {target[:120]} refused: {d.reason}")
    return OK


def validate_ports(ports: list[int], max_ports: int) -> Decision:
    if not ports:
        return deny("no_ports", "list at least one port")
    if len(ports) > max_ports:
        return deny("too_many_ports", f"at most {max_ports} ports per run")
    if len(set(ports)) != len(ports) or any(not isinstance(p, int) or not 1 <= p <= 65535 for p in ports):
        return deny("invalid_ports", "ports must be unique numbers 1-65535")
    return OK


class BudgetExceeded(Exception):
    def __init__(self, what: str):
        super().__init__(what)
        self.what = what


class Budget:
    """Counts what a run actually does and stops it at the authorized limits."""

    def __init__(self, limits: dict[str, Any], clock: Any = None):
        import time as _t
        self.limits, self.requests, self.bytes = limits, 0, 0
        self.by_class: dict[str, int] = {}
        self._clock = clock or _t.monotonic
        self.started = self._clock()
        self._last: dict[str, float] = {}

    def check_time(self) -> None:
        if self._clock() - self.started > self.limits["max_runtime_seconds"]:
            raise BudgetExceeded("runtime")

    def charge(self, cls: str, host: str, n: int = 1) -> float:
        """Reserve `n` requests; returns the seconds the caller must wait to stay within the per-host rate."""
        self.check_time()
        if self.requests + n > self.limits["max_requests"]:
            raise BudgetExceeded("requests")
        self.requests += n
        self.by_class[cls] = self.by_class.get(cls, 0) + n
        now = self._clock()
        gap = 1.0 / float(self.limits["requests_per_second"])
        wait = max(0.0, self._last.get(host, -1e9) + gap - now)
        self._last[host] = now + wait
        return wait

    def add_bytes(self, n: int) -> None:
        self.bytes += n
        if self.bytes > self.limits["max_bytes"]:
            raise BudgetExceeded("bytes")

    def counts(self) -> dict[str, Any]:
        return {"requests": self.requests, "bytes": self.bytes, "by_class": dict(self.by_class), "elapsed_seconds": round(self._clock() - self.started, 2)}
