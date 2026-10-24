"""Target parsing and canonicalization (spec 3.2, 8.1).

Targets are *data*. Nothing here ever builds a shell string. Anything that does not strictly validate is rejected.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

MAX_INPUT_LEN = 2048
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL_LOCAL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")
_HANDLE_RE = re.compile(r"^[\w.\-]{1,64}$", re.UNICODE)
TARGET_TYPES = ("domain", "ip", "url", "email", "username", "cik", "coordinates", "company")
_COORD_RE = re.compile(r"^\s*(-?\d{1,3}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*$")


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedTarget:
    type: str
    raw: str
    canonical: str
    notes: tuple[str, ...] = ()
    ambiguous_with: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"type": self.type, "raw": self.raw, "canonical": self.canonical,
                "notes": list(self.notes), "ambiguous_with": list(self.ambiguous_with)}


def _has_bad_chars(s: str) -> bool:
    return any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in s)


def canonical_domain(value: str) -> str:
    v = value.strip().rstrip(".")
    if not v or len(v) > 253 or _has_bad_chars(v) or any(c.isspace() for c in v):
        raise TargetError("invalid domain")
    try:
        ascii_name = idna.encode(v, uts46=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError) as exc:
        raise TargetError(f"invalid domain: {exc}") from exc
    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise TargetError("domain needs at least two labels")
    if not all(_LABEL_RE.match(lbl) for lbl in labels):
        raise TargetError("invalid domain label")
    if labels[-1].isdigit():
        raise TargetError("numeric TLD is not a domain (looks like an IP)")
    return ascii_name


def canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError as exc:
        raise TargetError("invalid IP address") from exc


def canonical_url(value: str) -> str:
    v = value.strip()
    if _has_bad_chars(v) or any(c.isspace() for c in v):
        raise TargetError("invalid URL")
    parts = urlsplit(v)
    if parts.scheme not in ("http", "https"):
        raise TargetError("only http/https URLs are accepted")
    if parts.username or parts.password:
        raise TargetError("URLs with embedded credentials are rejected")
    host = parts.hostname
    if not host:
        raise TargetError("URL has no host")
    try:
        host = canonical_ip(host)
        hostpart = f"[{host}]" if ":" in host else host
    except TargetError:
        hostpart = canonical_domain(host)
    port = f":{parts.port}" if parts.port and parts.port not in (80, 443) else ""
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{hostpart}{port}{path}{query}"


def canonical_email(value: str) -> str:
    v = value.strip()
    if _has_bad_chars(v) or v.count("@") != 1:
        raise TargetError("invalid email")
    local, domain = v.split("@")
    if not _EMAIL_LOCAL_RE.match(local) or local.startswith(".") or local.endswith(".") or ".." in local:
        raise TargetError("invalid email local part")
    # Local part case is preserved (not all providers are case-insensitive).
    return f"{local}@{canonical_domain(domain)}"


def canonical_username(value: str) -> str:
    v = unicodedata.normalize("NFC", value.strip().lstrip("@"))
    if not _HANDLE_RE.match(v) or v.startswith("-"):  # a leading '-' would be read as a CLI option
        raise TargetError("invalid username (letters, digits, '.', '_', '-' up to 64 chars)")
    return v  # case is preserved; platform-specific rules are applied by adapters


def canonical_cik(value: str) -> str:
    v = value.strip().lower().removeprefix("cik").lstrip(" :#")
    if not v.isdigit() or not 1 <= len(v) <= 10 or int(v) == 0:
        raise TargetError("a CIK is 1-10 digits")
    return f"cik:{int(v):010d}"


def canonical_coordinates(value: str) -> str:
    m = _COORD_RE.match(value)
    if not m:
        raise TargetError("coordinates must be 'lat,lon' in decimal degrees")
    lat, lon = float(m.group(1)), float(m.group(2))
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise TargetError("coordinates out of range")
    return f"{lat:.6f},{lon:.6f}"


def canonical_company(value: str) -> str:
    v = " ".join(unicodedata.normalize("NFC", value).split())
    if not 2 <= len(v) <= 120 or v.startswith("-") or any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise TargetError("a company name is 2-120 printable characters and cannot start with '-'")
    return v


_CANON = {"domain": canonical_domain, "ip": canonical_ip, "url": canonical_url,
          "email": canonical_email, "username": canonical_username, "cik": canonical_cik,
          "coordinates": canonical_coordinates, "company": canonical_company}


def canonicalize(target_type: str, value: str) -> str:
    if target_type not in _CANON:
        raise TargetError(f"unsupported target type: {target_type}")
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_INPUT_LEN:
        raise TargetError("empty or oversized input")
    return _CANON[target_type](value)


def detect_target(raw: str, explicit_type: str | None = None) -> ParsedTarget:
    """Detect type. Usernames are only accepted when the analyst states the type explicitly."""
    if not isinstance(raw, str) or not raw.strip():
        raise TargetError("empty input")
    if len(raw) > MAX_INPUT_LEN:
        raise TargetError("input too long")
    if explicit_type:
        return ParsedTarget(explicit_type, raw, canonicalize(explicit_type, raw))
    s = raw.strip()
    if _COORD_RE.match(s):
        return ParsedTarget("coordinates", raw, canonicalize("coordinates", s))
    for t in ("url", "email", "ip", "domain"):
        if t == "url" and "://" not in s:
            continue
        if t == "email" and "@" not in s:
            continue
        try:
            c = canonicalize(t, s)
        except TargetError:
            continue
        amb = ("username",) if t in ("email",) else ()
        return ParsedTarget(t, raw, c, ambiguous_with=amb)
    raise TargetError("could not detect a supported target type; choose one explicitly "
                      "(usernames require an explicit type)")


def domain_of(target_type: str, canonical: str) -> str | None:
    if target_type == "domain":
        return canonical
    if target_type == "email":
        return canonical.split("@", 1)[1]
    if target_type == "url":
        h = urlsplit(canonical).hostname or ""
        try:
            ipaddress.ip_address(h)
            return None
        except ValueError:
            return h
    return None
