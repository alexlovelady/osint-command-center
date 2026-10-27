"""The durable resumer: wakes deferred provider work when its reset time arrives and re-launches investigations that were parked waiting for provider limits.

State lives in the database (jobs and investigation runs), so a restart loses nothing. Authorization and case state are checked again by the job runner as each job starts.
"""
from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from ..db.models import InvestigationRun


def _now() -> datetime:
    return datetime.now(UTC)


class Resumer:
    def __init__(self, st: Any, interval: float = 3.0):
        self.st, self.interval = st, interval
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        while True:
            with contextlib.suppress(Exception):            # a failed tick must never kill the loop; the next one starts from the database again
                await self.tick()
            await asyncio.sleep(self.interval)

    async def tick(self) -> dict[str, int]:
        st = self.st
        st.quota.expire_stale()
        if st.quota.is_paused():
            return {"ran": 0, "resumed": 0, "paused": 1}
        ran = await st.runner.run_due()
        return {"ran": ran, "resumed": resume_waiting(st), "paused": 0}


def resume_waiting(st: Any) -> int:
    """Investigations parked in `waiting_limits` continue once none of their research is still waiting on a provider."""
    from ..profile import investigate
    n = 0
    with st.sm() as db:
        ids = [r.id for r in db.scalars(select(InvestigationRun).where(InvestigationRun.status == "waiting_limits"))]
    for rid in ids:
        if investigate.wake(st, rid):
            n += 1
    return n

