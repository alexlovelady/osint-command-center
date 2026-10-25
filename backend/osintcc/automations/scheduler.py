"""Triggers: IANA-zone cron schedules with a missed-run policy, event triggers, expiry of approvals, held-notification release, and the run queue.
`tick` is deterministic and testable (the clock is a parameter). Runs only while the application runs: after a restart missed slots are handled by
the trigger's policy (default coalesce: ONE catch-up run, never a replay storm)."""
from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from ..db.models import (
    AutomationApproval,
    AutomationRun,
    AutomationTrigger,
    AutomationVersion,
    AutomationWorkflow,
    Finding,
    Setting,
)
from ..telemetry import audit
from . import cron, permissions
from . import notifications as notes
from . import settings as aset
from .executor import AutomationEngine
from .graph_validator import validate

log = logging.getLogger("osintcc.automations")
GRACE_S = 120
CATCH_UP_MAX = 10


class AutomationScheduler:
    def __init__(self, st: Any, engine: AutomationEngine, poll_seconds: float = 15.0, clock: Any = lambda: datetime.now(UTC)):
        self.st, self.engine, self.poll, self.clock = st, engine, poll_seconds, clock
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                log.warning("automation scheduler stopped with %s", type(exc).__name__)

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception as exc:
                log.warning("automation tick failed: %s", type(exc).__name__)
            await asyncio.sleep(self.poll)

    async def tick(self, now: datetime | None = None) -> dict[str, int]:
        now = now or self.clock()
        from ..profile import consent as profile_consent
        with self.st.sm() as db:
            profile_consent.sweep_expired(db, now)
            db.commit()
        fired = self._fire_due(now)
        fired += self._fire_events(now)
        with self.st.sm() as db:
            released = notes.release_held(db, now)
            self._digest(db, now)
            db.commit()
        ran = await self.engine.drain()
        return {"fired": fired, "released": released, "started": ran}

    # ----------------------------------------------------------------------------------------------------- schedules
    def _fire_due(self, now: datetime) -> int:
        n = 0
        with self.st.sm() as db:
            due = [t for t in db.scalars(select(AutomationTrigger).where(AutomationTrigger.enabled.is_(True), AutomationTrigger.type == "schedule"))
                   if (nd := permissions.aware(t.next_due_at)) is not None and nd <= now]
            for t in due:
                wf = db.get(AutomationWorkflow, t.workflow_id)
                v = db.get(AutomationVersion, t.version_id)
                if wf is None or v is None or wf.deleted_at is not None or wf.active_version_id != v.id:
                    t.enabled = False
                    continue
                if permissions.valid_approval(db, wf.id, v.id, "activation", now) is None:      # an expired approval stops the schedule; it never keeps running silently
                    t.enabled = False
                    wf.state = "disabled"
                    wf.active_version_id = None
                    notes.raise_notification(db, owner_id=wf.owner_id, workflow_id=wf.id, run_id=None, title=f"Automation paused: {wf.name}",
                                             body="Its activation approval expired, so the schedule was switched off. Request approval again to resume.", severity="warning",
                                             channel="in_app", digest="approval-expired", now=now)
                    audit.record(db, "automation.approval_expired", actor="scheduler", case_id=wf.case_id, resource_id=wf.id)
                    continue
                spec, tz = cron.validate(t.schedule or "", t.timezone)
                nd0 = permissions.aware(t.next_due_at)
                assert nd0 is not None
                start = nd0 - timedelta(seconds=1)
                fires = cron.fires_between(spec, start, now, tz, limit=500)
                t.next_due_at = cron.next_fire(spec, now, tz)
                if not fires:
                    continue
                pick: list[datetime]
                if t.missed_run_policy == "skip":
                    pick = [fires[-1]] if (now - fires[-1]).total_seconds() <= GRACE_S else []
                elif t.missed_run_policy == "catch_up":
                    pick = fires[-CATCH_UP_MAX:]
                else:
                    pick = [fires[-1]]                                                           # coalesce: one run for however many slots were missed
                raw = v.definition_json
                offline_block = self.st.settings.offline and validate(raw, self.st.adapters)["permissions"]["network"]
                for f in pick:
                    if offline_block:
                        audit.record(db, "automation.trigger_skipped_offline", actor="scheduler", case_id=wf.case_id, resource_id=wf.id)
                        continue
                    run = self.engine.enqueue(db, wf, v, trigger_type="schedule", inputs={}, dry_run=False, idem=f"trigger:{t.id}:{int(f.timestamp())}", actor="scheduler",
                                              case_id=wf.case_id, event_id=f.isoformat(), queue_anyway=t.missed_run_policy == "catch_up")
                    if run is not None:
                        n += 1
                t.last_fired_at = now
            db.commit()
        return n

    # ------------------------------------------------------------------------------------------------------- events
    def _fire_events(self, now: datetime) -> int:
        n = 0
        with self.st.sm() as db:
            for t in db.scalars(select(AutomationTrigger).where(AutomationTrigger.enabled.is_(True), AutomationTrigger.type == "event")):
                wf = db.get(AutomationWorkflow, t.workflow_id)
                v = db.get(AutomationVersion, t.version_id)
                if wf is None or v is None or wf.case_id is None or wf.active_version_id != v.id:
                    continue
                if permissions.valid_approval(db, wf.id, v.id, "activation", now) is None:
                    t.enabled = False
                    continue
                since = datetime.fromisoformat((t.config_json or {}).get("last_seen") or now.isoformat())
                newest = db.scalar(select(func.max(Finding.observed_at)).where(Finding.case_id == wf.case_id))
                newest = permissions.aware(newest)
                if newest is None or newest <= since:
                    continue
                cnt = db.scalar(select(func.count()).select_from(Finding).where(Finding.case_id == wf.case_id, Finding.observed_at > since)) or 0
                run = self.engine.enqueue(db, wf, v, trigger_type="event", inputs={}, dry_run=False, idem=f"event:{t.id}:{newest.isoformat()}", actor="scheduler",
                                          case_id=wf.case_id, event_id=f"new_finding:{cnt}")
                t.config_json = {**(t.config_json or {}), "last_seen": newest.isoformat()}
                if run is not None:
                    n += 1
            db.commit()
        return n

    def _digest(self, db: Any, now: datetime) -> None:
        cfg = aset.load(db)["notifications"]["digest"]
        if not cfg["enabled"]:
            return
        tz = cron.zone(aset.load(db)["timezone"])
        local = now.astimezone(tz)
        if local.strftime("%H:%M") < cfg["time"]:
            return
        key = "automation.digest_last"
        row = db.get(Setting, key)
        today = local.date().isoformat()
        if row and row.value_json == today:
            return
        for (owner,) in db.execute(select(AutomationRun.created_by).distinct()):
            notes.flush_digest(db, owner, now)
        for owner in {o for (o,) in db.execute(select(AutomationWorkflow.owner_id).distinct())}:
            notes.flush_digest(db, owner, now)
        db.merge(Setting(key=key, value_json=today))


_ = (AutomationApproval,)
