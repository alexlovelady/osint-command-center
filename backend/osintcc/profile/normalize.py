"""Identifier normalisation, canonical URLs and masking. Pure functions; nothing here touches the network or the database."""
from __future__ import annotations

import hashlib
import re
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..policy.targets import TargetError, detect_target

# Kinds a subject can hold. There is deliberately no phone, national-ID, SSN, account-number, password or token kind.
IDENTIFIER_KINDS = ("name", "alias", "username", "email", "domain", "url", "organization")
_FORBIDDEN_HINT = re.compile(r"\b(ssn|social security|passport|national id|password|passwd|token|secret|credit card|iban)\b", re.IGNORECASE)
_SSN = re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b")
_TRACKING = re.compile(r"^(utm_.*|fbclid|gclid|mc_.*|ref|ref_src|igshid|si)$", re.IGNORECASE)


class IdentifierError(ValueError):
    pass


def _clean_text(v: str, maxlen: int = 300) -> str:
    v = unicodedata.normalize("NFKC", v).strip()
    v = re.sub(r"\s+", " ", v)
    if not v or len(v) > maxlen or any(unicodedata.category(c) in ("Cc", "Cf") for c in v):
        raise IdentifierError("value is empty, too long or contains control characters")
    return v


def normalize_identifier(kind: str, value: str) -> str:
    if kind not in IDENTIFIER_KINDS:
        raise IdentifierError(f"unsupported identifier kind '{kind}' (allowed: {', '.join(IDENTIFIER_KINDS)})")
    if _SSN.search(value) or _FORBIDDEN_HINT.search(value):
        raise IdentifierError("sensitive government/financial identifiers and secrets are never stored as identifiers")
    try:
        if kind in ("name", "alias", "organization"):
            return _clean_text(value).casefold() if False else _clean_text(value)
        if kind == "username":
            return detect_target(value.lstrip("@"), "username").canonical
        if kind == "email":
            return detect_target(value, "email").canonical
        if kind == "domain":
            return detect_target(value, "domain").canonical
        return canonical_url(value)
    except TargetError as exc:
        raise IdentifierError(str(exc)) from exc


def identifier_hash(kind: str, normalized: str) -> str:
    key = normalized.casefold() if kind in ("name", "alias", "organization", "username", "email", "domain") else normalized
    return hashlib.sha256(f"{kind}\x00{key}".encode()).hexdigest()


def canonical_url(url: str) -> str:
    """Stable identity for a public page: https, lowercase host without 'www.', no fragment/tracking parameters, no trailing slash."""
    p = urlsplit(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise TargetError("not an http(s) URL")
    host = p.hostname.lower().removeprefix("www.")
    port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    query = urlencode(sorted((k, v) for k, v in parse_qsl(p.query) if not _TRACKING.match(k)))
    path = re.sub(r"/{2,}", "/", p.path).rstrip("/") or ""
    return urlunsplit(("https", host + port, path, query, ""))


_SECTIONS = re.compile(r"/(about|videos|featured|community|playlists|shorts|streams|releases|channels|posts|followers|following|repositories|stars|likes|media|with_replies)$", re.IGNORECASE)
_SECTION_HOSTS = ("youtube.com", "m.youtube.com", "tiktok.com", "twitter.com", "x.com", "github.com", "gitlab.com", "twitch.tv", "venmo.com", "instagram.com")


def profile_root(url: str) -> str:
    """The profile's own page: `/@handle/about` and `/@handle/videos` are the same account as `/@handle`. The original URL is never altered or discarded."""
    c = canonical_url(url)
    p = urlsplit(c)
    if p.hostname and p.hostname in _SECTION_HOSTS:
        path = p.path
        for _ in range(2):
            path = _SECTIONS.sub("", path, count=1)
        if p.hostname in ("venmo.com", "www.venmo.com"):
            path = re.sub(r"^/u/", "/", path)
        return urlunsplit(("https", p.netloc, path, "", ""))
    return c


def cluster_key(url: str) -> str:
    return hashlib.sha256(profile_root(url).encode()).hexdigest()


def mask_value(kind: str, value: str) -> str:
    """Display form for exports and low-privilege viewers: enough to recognise, not enough to reuse."""
    if kind == "email" and "@" in value:
        local, _, dom = value.partition("@")
        return f"{local[:1]}{'*' * max(1, len(local) - 1)}@{dom}"
    if kind in ("name", "alias"):
        return " ".join(f"{w[:1]}{'*' * max(1, len(w) - 1)}" for w in value.split())
    if kind == "username":
        return f"{value[:2]}{'*' * max(1, len(value) - 2)}"
    return value
