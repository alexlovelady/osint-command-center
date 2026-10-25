"""Redaction and categorisation for DARKINT. Pure functions.

Anything that looks like a secret, a government or card number, a hash, a token or an address:password pair is replaced before it can be indexed, stored,
shown, exported or sent to a model. Data is reduced to CATEGORIES ("email addresses", "credential indicator") and never to values.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime

from ..profile.exposure import _EMAIL, _SECRET_PATTERNS

CATEGORIES = ("email addresses", "credential indicator", "phone numbers", "physical addresses", "names", "dates of birth", "ip addresses", "usernames", "financial data",
              "government identifiers", "security questions", "device information", "organization named on a leak site", "other")
_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("credential indicator", ("password", "credential", "passphrase", "hash", "auth token", "api key", "session")),
    ("email addresses", ("email",)),
    ("phone numbers", ("phone", "mobile", "telephone")),
    ("physical addresses", ("physical address", "street", "postal", "home address", "addresses")),
    ("dates of birth", ("birth", "dob", "age")),
    ("ip addresses", ("ip address", "ip addresses")),
    ("usernames", ("username", "user name", "handle")),
    ("names", ("name",)),
    ("financial data", ("credit card", "bank", "payment", "iban", "financial", "salary", "income")),
    ("government identifiers", ("social security", "passport", "national id", "government", "tax id", "driver")),
    ("security questions", ("security question", "security answer")),
    ("device information", ("device", "browser", "user agent", "imei")),
]


def categorize(raw: list[str] | str | None) -> list[str]:
    """Maps a provider's own data-class labels onto a fixed vocabulary. Unknown labels become 'other'; nothing the provider sent is kept verbatim."""
    items = [raw] if isinstance(raw, str) else list(raw or [])
    out: list[str] = []
    for item in items[:60]:
        low = str(item).casefold()
        hit = next((cat for cat, words in _KEYWORDS if any(w in low for w in words)), "other")
        if hit not in out:
            out.append(hit)
    return out


def sanitize_text(text: str, limit: int = 200) -> tuple[str, bool]:
    """(clean text, whether anything was redacted). Emails are masked, secret-shaped strings are replaced."""
    t = " ".join((text or "").split())
    redacted = False
    for pat, what in _SECRET_PATTERNS:
        t, n = pat.subn(f"[redacted {what}]", t)
        redacted = redacted or n > 0

    def mask(m: re.Match[str]) -> str:
        local = m.group(0).split("@")[0]
        return m.group(0) if "*" in local else f"{local[:1]}***@{m.group(0).split('@', 1)[1]}"
    masked = _EMAIL.sub(mask, t)
    redacted = redacted or masked != t
    return masked[:limit], redacted


def group_key(title: str) -> str:
    """Same incident, different wording: provider names are compared after removing filler words and punctuation."""
    low = re.sub(r"[^a-z0-9 ]+", " ", title.casefold())
    words = [w for w in low.split() if w not in {"breach", "leak", "leaks", "data", "database", "hack", "incident", "ransomware", "attack", "the", "of", "a", "and", "listed", "by", "group", "claimed"}]
    return "".join(words)[:60]


def parse_date(v: object) -> datetime | None:
    if not v:
        return None
    text = str(v).strip()
    for cand in (text, text[:19], text[:10]):
        try:
            d = datetime.fromisoformat(cand.replace("Z", "+00:00"))
        except ValueError:
            continue
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    return None
