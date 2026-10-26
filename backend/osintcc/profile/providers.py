"""Shared mailbox providers. An address at one of these says nothing about who owns the provider's domain, so the domain is never a research target for the person.

The built-in list is a starting point; an owner can extend it (Setting `shared_email_domains`). A custom domain is not treated as the person's asset either: domain
sources run only on a domain the subject lists as its own input.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from ..db.models import Setting

BUILTIN = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com", "rocketmail.com", "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "pm.me", "aol.com", "gmx.com", "gmx.net", "gmx.de", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "fastmail.com", "tutanota.com", "tuta.io",
    "hey.com", "mail.ru", "qq.com", "163.com", "126.com", "naver.com", "web.de", "t-online.de", "orange.fr", "free.fr", "libero.it", "comcast.net", "verizon.net", "att.net", "sbcglobal.net",
    "btinternet.com", "bigpond.com", "shaw.ca", "rogers.com", "sympatico.ca",
})
SETTING = "shared_email_domains"


def extra(db: Session | None) -> frozenset[str]:
    row = db.get(Setting, SETTING) if db is not None else None
    return frozenset(str(x).lower() for x in (row.value_json if row and isinstance(row.value_json, list) else []))


def is_shared_provider(domain: str, db: Session | None = None) -> bool:
    d = domain.strip().lower().rstrip(".")
    return d in BUILTIN or d in extra(db) or any(d.endswith("." + b) for b in BUILTIN)


def all_domains(db: Session | None) -> list[str]:
    return sorted(BUILTIN | extra(db))


def add_domain(db: Session, domain: str) -> list[str]:
    d = domain.strip().lower().rstrip(".")
    if "." not in d or " " in d or "/" in d or len(d) > 253:
        raise ValueError("enter a domain such as mail.example")
    cur = sorted(extra(db) | {d})
    db.merge(Setting(key=SETTING, value_json=cur))
    return cur
