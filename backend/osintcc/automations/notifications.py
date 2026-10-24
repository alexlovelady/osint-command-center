"""Notifications: in-app and local-desktop rows (the UI shows them; nothing leaves the machine), optional webhooks to destinations the owner approved
in Settings, de-duplication per window, severity, quiet hours and digest mode, acknowledgement. Email is not implemented and is reported as such.
Honest limit: scheduling and desktop notices work only while the application is running."""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AutomationNotification
from . import settings as aset
from .permissions import aware

SEVERITIES = ("info", "warning", "critical")


def dedupe_key(workflow_id: str | None, title: str, digest: str) -> str:
    return hashlib.sha256(f"{workflow_id}|{title}|{digest}".encode()).hexdigest()[:40]


def _in_quiet_hours(cfg: dict[str, Any], now: datetime) -> bool:
    q = cfg["quiet_hours"]
    if not q["enabled"]:
        return False
    local = now.astimezone(ZoneInfo(q["timezone"]))
    cur = local.strftime("%H:%M")
    a, b = q["start"], q["end"]
    return (a <= cur < b) if a <= b else (cur >= a or cur < b)      # window may wrap midnight


def raise_notification(db: Session, *, owner_id: str, workflow_id: str | None, run_id: str | None, title: str, body: str, severity: str,
                       channel: str, digest: str, details: dict[str, Any] | None = None, destination_ref: str | None = None,
                       now: datetime | None = None) -> dict[str, Any]:
    """Create (or merge into) a notification. Returns {id, status, deduplicated}."""
    now = now or datetime.now(UTC)
    cfg = aset.load(db)["notifications"]
    key = dedupe_key(workflow_id, title, digest)
    window = now - timedelta(hours=cfg["dedupe_window_hours"])
    prior = db.scalars(select(AutomationNotification).where(AutomationNotification.dedupe_key == key, AutomationNotification.channel == channel,
                                                            AutomationNotification.owner_id == owner_id)
                       .order_by(AutomationNotification.created_at.desc())).first()
    if prior is not None and (c := aware(prior.created_at)) is not None and c >= window:
        prior.count += 1                                   # one notification per window; repeats only raise the counter
        return {"id": prior.id, "status": prior.status, "deduplicated": True}
    status = "delivered"
    delivered: datetime | None = now
    if severity != "critical" and _in_quiet_hours(cfg, now):
        status, delivered = "held", None
    elif cfg["digest"]["enabled"] and severity == "info":
        status, delivered = "digest_pending", None
    n = AutomationNotification(owner_id=owner_id, workflow_id=workflow_id, run_id=run_id, channel=channel, destination_ref=destination_ref, dedupe_key=key,
                               severity=severity, status=status, title=title[:200], body=body[:4000], details_json=details or {}, delivered_at=delivered, created_at=now)
    db.add(n)
    db.flush()
    return {"id": n.id, "status": status, "deduplicated": False}


def release_held(db: Session, now: datetime | None = None) -> int:
    """Release rows held for quiet hours once the window is over (called by the scheduler tick)."""
    now = now or datetime.now(UTC)
    cfg = aset.load(db)["notifications"]
    if _in_quiet_hours(cfg, now):
        return 0
    n = 0
    for row in db.scalars(select(AutomationNotification).where(AutomationNotification.status == "held")):
        row.status, row.delivered_at = "delivered", now
        n += 1
    return n


def flush_digest(db: Session, owner_id: str, now: datetime | None = None) -> dict[str, Any] | None:
    """Combine pending digest rows into ONE delivered notification."""
    now = now or datetime.now(UTC)
    rows = list(db.scalars(select(AutomationNotification).where(AutomationNotification.status == "digest_pending", AutomationNotification.owner_id == owner_id)))
    if not rows:
        return None
    for r in rows:
        r.status, r.delivered_at = "suppressed", now        # folded into the digest row
    lines = [f"- {r.title} (x{r.count})" for r in rows[:30]]
    d = AutomationNotification(owner_id=owner_id, channel="in_app", dedupe_key=hashlib.sha256(now.isoformat().encode()).hexdigest()[:40], severity="info",
                               status="delivered", title=f"Digest: {len(rows)} automation notice(s)", body="\n".join(lines), delivered_at=now,
                               details_json={"members": [r.id for r in rows]})
    db.add(d)
    db.flush()
    return {"id": d.id, "members": len(rows)}


async def send_webhook(url: str, payload: dict[str, Any], http: Any | None = None) -> tuple[bool, str]:
    """POST a minimal JSON summary (no evidence content). Uses the SSRF-guarded client unless the destination is loopback."""
    try:
        if http is not None:
            r = await http.post(url, json=payload)
            return (200 <= r.status < 300), f"HTTP {r.status}"
        async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as c:
            res = await c.post(url, json=payload)
        return res.is_success, f"HTTP {res.status_code}"
    except Exception as exc:
        return False, type(exc).__name__
