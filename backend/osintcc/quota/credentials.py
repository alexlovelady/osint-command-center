"""Credential and configuration checks that need no network: what shape a stored value has, and whether a configuration value is usable at all.

A stored value is not a verified one. These helpers only say 'this could be a credential of that kind' or 'this cannot work'; whether the provider accepts it is learned from the
provider's own answer and recorded by the dispatcher.
"""
from __future__ import annotations

import re

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-']+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")


def censys_kind(value: str | None) -> str:
    """'pat' (a Personal Access Token, sent as a bearer token), 'legacy' (API_ID:API_SECRET, Basic authentication) or 'wrong_format'. Never converts one into the other."""
    v = (value or "").strip()
    if not v or re.search(r"\s", v):
        return "wrong_format"
    if ":" in v:
        a, _, b = v.partition(":")
        return "legacy" if (len(a) >= 8 and len(b) >= 8 and ":" not in b) else "wrong_format"
    return "pat" if len(v) >= 20 else "wrong_format"


def validate_credential(provider: str, value: str) -> str | None:
    """None when the value is plausible; otherwise a plain-language reason. Used when a key is saved, so a pasted token of the wrong kind is caught immediately."""
    v = (value or "").strip()
    if not v:
        return "The value is empty."
    if re.search(r"[\r\n]", v):
        return "The value contains a line break; paste only the key."
    if provider == "censys" and censys_kind(v) == "wrong_format":
        return ("Censys needs a Personal Access Token (one long token, from your Censys account's API Access page) or, for the older API, API_ID:API_SECRET joined by a colon. "
                "This value looks like neither.")
    return None


def validate_contact(value: str | None) -> tuple[str | None, str]:
    """(error, normalised). A SEC contact needs a human name and a syntactically valid email address, e.g. 'Jane Analyst jane@example.org'."""
    v = " ".join((value or "").split())
    if not v:
        return "Enter your name and email, for example: Jane Analyst jane@example.org", ""
    if len(v) > 200 or re.search(r"[<>\"\\]", v):
        return "The contact is too long or contains characters that cannot go in a request header.", ""
    m = re.search(r"([^\s<>()]+@[^\s<>()]+)", v)
    if not m:
        return "Add an email address after your name, for example: Jane Analyst jane@example.org", ""
    email = m.group(1).strip(".,;")
    if not _EMAIL.match(email):
        return f"'{email}' is not a valid email address.", ""
    name = (v.replace(m.group(1), "").replace("<", "").replace(">", "").strip(" ,;()"))
    if len(re.sub(r"[^A-Za-zÀ-￿]", "", name)) < 2:
        return "Add your name before the email address; the SEC asks for a contact it can recognise.", ""
    return None, f"{name} {email}"
