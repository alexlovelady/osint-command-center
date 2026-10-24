"""Automation settings (one JSON document in the `settings` table). Everything risky defaults OFF."""
from __future__ import annotations

import copy
import re
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from ..db.models import Setting
from . import cron

KEY = "automation.settings"
DEFAULTS: dict[str, Any] = {
    "timezone": "UTC",                         # IANA zone used for new schedules; the UI offers to pick your own (e.g. America/New_York)
    "max_concurrent_runs": 2,
    "notifications": {
        "dedupe_window_hours": 24,
        "quiet_hours": {"enabled": False, "start": "22:00", "end": "07:00", "timezone": "UTC"},
        "digest": {"enabled": False, "time": "08:00"},
        "webhooks": {},                        # name -> https URL, approved here; workflows only reference the name
    },
    "suggestions": {"enabled": False, "disabled_categories": [], "include_sensitive": False},
    "cloud_ai_opt_in": [],                     # AI profile ids that may receive automation diagnostics (case-derived text)
}
_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class SettingsError(ValueError):
    pass


def _merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if k not in base:
            raise SettingsError(f"unknown setting {k!r}")
        if isinstance(base[k], dict) and isinstance(v, dict) and k != "webhooks":
            out[k] = _merge(base[k], v)
        else:
            out[k] = v
    return out


def validate(s: dict[str, Any]) -> None:
    try:
        cron.zone(s["timezone"])
        cron.zone(s["notifications"]["quiet_hours"]["timezone"])
    except cron.CronError as exc:
        raise SettingsError(str(exc)) from exc
    if not isinstance(s["max_concurrent_runs"], int) or not 1 <= s["max_concurrent_runs"] <= 4:
        raise SettingsError("max_concurrent_runs must be 1-4")
    n = s["notifications"]
    if not isinstance(n["dedupe_window_hours"], int) or not 1 <= n["dedupe_window_hours"] <= 168:
        raise SettingsError("dedupe_window_hours must be 1-168")
    for k in ("start", "end"):
        if not _HHMM.match(str(n["quiet_hours"][k])):
            raise SettingsError("quiet hours must look like 22:00")
    if not _HHMM.match(str(n["digest"]["time"])):
        raise SettingsError("digest time must look like 08:00")
    for name, url in n["webhooks"].items():
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", str(name)):
            raise SettingsError(f"webhook name {name!r} is invalid")
        u = urlsplit(str(url))
        loop = u.hostname in ("127.0.0.1", "localhost", "::1")
        if not u.hostname or (u.scheme != "https" and not (u.scheme == "http" and loop)):
            raise SettingsError(f"webhook {name!r} must be an https URL (or http on this computer)")
    if not isinstance(s["suggestions"]["disabled_categories"], list) or not isinstance(s["cloud_ai_opt_in"], list):
        raise SettingsError("disabled_categories and cloud_ai_opt_in must be lists")


def load(db: Session) -> dict[str, Any]:
    row = db.get(Setting, KEY)
    try:
        return _merge(DEFAULTS, row.value_json) if row and isinstance(row.value_json, dict) else copy.deepcopy(DEFAULTS)
    except SettingsError:
        return copy.deepcopy(DEFAULTS)           # a damaged settings document falls back to the safe defaults


def save(db: Session, patch: dict[str, Any]) -> dict[str, Any]:
    cur = load(db)
    new = _merge(cur, patch)
    validate(new)
    db.merge(Setting(key=KEY, value_json=new))
    return new
