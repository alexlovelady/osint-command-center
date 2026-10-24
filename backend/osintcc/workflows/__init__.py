"""Workflow DAGs and the durable scheduler (spec 10).

Definitions are data only (strict schema, `extra=forbid`): there is no way to express code, shell or arbitrary URLs.
Every node is either a registered adapter or one of two built-in tasks. Policy is re-evaluated by the normal search
machinery for every wave, so a workflow can never do more than a person could do by hand in the UI.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..db.models import (
    Alert,
    Case,
    Entity,
    Finding,
    Job,
    Schedule,
    SearchRun,
    Snapshot,
    Target,
    Workflow,
    WorkflowRun,
)
from ..policy.targets import TargetError, detect_target
from ..search import service
from ..telemetry import audit

log = logging.getLogger("osintcc.scheduler")
MAX_NODES = 20
MIN_INTERVAL_S = 15 * 60
TASKS = ("summarize", "diff")
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
_INTERVAL = re.compile(r"^(\d{1,4})([mhd])$")


class WorkflowError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


class Node(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    adapter: str | None = None
    task: Literal["summarize", "diff"] | None = None
    input: Literal["target"] = "target"
    depends_on: list[str] = Field(default_factory=list, max_length=MAX_NODES)


class WPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active_allowed: bool = False
    max_concurrency: int = Field(default=3, ge=1, le=3)
    max_depth: int = Field(default=3, ge=1, le=5)


class Definition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    id: str
    name: str = Field(min_length=1, max_length=200)
    nodes: list[Node] = Field(min_length=1, max_length=MAX_NODES)
    policy: WPolicy = Field(default_factory=WPolicy)


def parse_definition(raw: Any, adapters: dict) -> Definition:
    try:
        d = Definition.model_validate(raw)
    except ValidationError as exc:
        raise WorkflowError([f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors()]) from exc
    problems: list[str] = []
    if not _ID.match(d.id):
        problems.append("id must match [a-z][a-z0-9_-]{0,39}")
    ids = [n.id for n in d.nodes]
    if len(set(ids)) != len(ids):
        problems.append("duplicate node ids")
    for n in d.nodes:
        if not _ID.match(n.id):
            problems.append(f"node id {n.id!r} is invalid")
        if (n.adapter is None) == (n.task is None):
            problems.append(f"node {n.id}: set exactly one of adapter or task")
        if n.adapter and n.adapter not in adapters:
            problems.append(f"node {n.id}: unknown adapter {n.adapter!r}")
        elif n.adapter and adapters[n.adapter].manifest.operation_class == "active" and not d.policy.active_allowed:
            problems.append(f"node {n.id}: active adapter requires policy.active_allowed=true")
        for dep in n.depends_on:
            if dep not in ids:
                problems.append(f"node {n.id}: depends_on unknown node {dep!r}")
            if dep == n.id:
                problems.append(f"node {n.id}: depends on itself")
    if not problems:
        try:
            depth = max(depths(d).values())
        except WorkflowError as exc:
            problems += exc.problems
        else:
            if depth > d.policy.max_depth:
                problems.append(f"dependency depth {depth} exceeds policy.max_depth {d.policy.max_depth}")
    if problems:
        raise WorkflowError(problems)
    return d


def depths(d: Definition) -> dict[str, int]:
    """Longest-path level per node (1-based). Raises on cycles."""
    deps = {n.id: n.depends_on for n in d.nodes}
    level: dict[str, int] = {}
    visiting: set[str] = set()

    def visit(i: str) -> int:
        if i in level:
            return level[i]
        if i in visiting:
            raise WorkflowError(["dependency cycle detected"])
        visiting.add(i)
        level[i] = 1 + max((visit(x) for x in deps[i]), default=0)
        visiting.discard(i)
        return level[i]
    for i in deps:
        visit(i)
    return level


def waves(d: Definition) -> list[list[Node]]:
    lv = depths(d)
    out: dict[int, list[Node]] = {}
    for n in d.nodes:
        out.setdefault(lv[n.id], []).append(n)
    return [out[k] for k in sorted(out)]


def parse_interval(s: str) -> timedelta:
    m = _INTERVAL.match(s or "")
    if not m:
        raise WorkflowError(["interval must look like 15m, 6h or 1d"])
    sec = int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if sec < MIN_INTERVAL_S:
        raise WorkflowError([f"interval must be at least {MIN_INTERVAL_S // 60} minutes (provider courtesy)"])
    return timedelta(seconds=sec)


def load_templates(directory: Path) -> list[dict[str, Any]]:
    out = []
    for p in sorted(directory.glob("*.json")):
        out.append(json.loads(p.read_text(encoding="utf8")))
    return out


def _aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=UTC) if d is not None and d.tzinfo is None else d


# ------------------------------------------------------------------ execution -----------------------------------------
async def execute(st, workflow_id: str, case_id: str, target_raw: str, target_type: str | None, confirmed: list[str],
                  trigger: str = "manual", slot_key: str | None = None, actor: str = "local") -> dict[str, Any]:
    """Runs one workflow instance. Policy is evaluated for every wave by the shared search machinery."""
    with st.sm() as db:
        wf = db.get(Workflow, workflow_id)
        case = db.get(Case, case_id)
        if not wf or not wf.enabled:
            raise WorkflowError(["workflow not found or disabled"])
        if case.status != "open":
            raise WorkflowError(["case must be open"])
        d = parse_definition(wf.definition_json, st.adapters)  # re-validated on every run
        parsed = detect_target(target_raw, target_type)
        tgt = service.get_or_create_target(db, case, parsed)
        wr = WorkflowRun(workflow_id=wf.id, case_id=case_id, target_id=tgt.id, trigger=trigger, slot_key=slot_key)
        db.add(wr)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return {"status": "duplicate_slot", "workflow_run_id": None}
        audit.record(db, "workflow.run", actor=actor, case_id=case_id, resource_type="workflow_run", resource_id=wr.id,
                     metadata={"workflow": wf.name, "trigger": trigger, "nodes": len(d.nodes)})
        db.commit()
        wr_id, tgt_id = wr.id, tgt.id
    run_ids: list[str] = []
    node_status: dict[str, str] = {}
    step = 0
    for wave in waves(d):
        adapter_nodes = [n for n in wave if n.adapter]
        for i in range(0, len(adapter_nodes), d.policy.max_concurrency):  # honour the workflow's concurrency cap
            chunk = adapter_nodes[i:i + d.policy.max_concurrency]
            ids = [n.adapter for n in chunk if n.adapter]
            with st.sm() as db:
                case = db.get(Case, case_id)
                mode = "active" if any(st.adapters[a].manifest.operation_class == "active" for a in ids) else "passive"
                try:
                    plan = service.build_plan(db, case, parsed, st.adapters, st.settings, selected=ids, mode=mode)
                    run = service.create_run(db, case, parsed, plan, confirmed=confirmed, mode=mode)
                    db.commit()
                    run_id = run.id
                except service.PlanError as exc:
                    for n in chunk:
                        node_status[n.id] = f"refused: {exc}"
                    audit.record(db, "workflow.wave_refused", actor=actor, case_id=case_id, decision="deny",
                                 metadata={"adapters": ids, "reason": str(exc)[:150]})
                    db.commit()
                    continue
            run_ids.append(run_id)
            await st.runner.run_until_idle(run_id)
            with st.sm() as db:
                for j in db.scalars(select(Job).where(Job.run_id == run_id)):
                    node_status[next(n.id for n in chunk if n.adapter == j.adapter_id)] = j.status
        for n in wave:
            if n.task == "summarize":
                node_status[n.id] = "done"
            elif n.task == "diff":
                step += 1
                node_status[n.id] = _diff_task(st, wf_id=workflow_id, case_id=case_id, target_id=tgt_id, run_ids=run_ids,
                                               wr_id=wr_id, actor=actor)
        step += 1
    with st.sm() as db:
        jobs = [j for r in run_ids for j in db.scalars(select(Job).where(Job.run_id == r))]
        ok = sum(1 for j in jobs if j.status in ("succeeded", "skipped"))
        wr = db.get(WorkflowRun, wr_id)
        wr.status = "succeeded" if jobs and ok == len(jobs) else ("partial" if ok else "failed")
        wr.ended_at = datetime.now(UTC)
        wr.run_ids_json = run_ids
        wr.summary_json = {"nodes": node_status, "jobs": {s: sum(1 for j in jobs if j.status == s) for s in {j.status for j in jobs}},
                           "findings_returned": sum(len(j.result_keys_json or []) for j in jobs)}
        db.commit()
        return {"status": wr.status, "workflow_run_id": wr_id, "run_ids": run_ids, "summary": wr.summary_json}


def _diff_task(st, *, wf_id: str, case_id: str, target_id: str, run_ids: list[str], wr_id: str, actor: str) -> str:
    with st.sm() as db:
        keys = sorted({k for r in run_ids for j in db.scalars(select(Job).where(Job.run_id == r)) for k in (j.result_keys_json or [])})
        fp = hashlib.sha256(json.dumps(keys).encode()).hexdigest()
        prev = db.scalars(select(Snapshot).where(Snapshot.workflow_id == wf_id, Snapshot.target_id == target_id)
                          .order_by(Snapshot.created_at.desc())).first()
        db.add(Snapshot(case_id=case_id, workflow_id=wf_id, target_id=target_id, fingerprint=fp, keys_json=keys, workflow_run_id=wr_id))
        if prev is None:
            db.commit()
            return "baseline_created"
        if prev.fingerprint == fp:
            db.commit()
            return "no_change"
        added, removed = sorted(set(keys) - set(prev.keys_json)), sorted(set(prev.keys_json) - set(keys))

        def describe(ks: list[str]) -> list[str]:
            out = []
            for f in db.scalars(select(Finding).where(Finding.case_id == case_id, Finding.dedup_key.in_(ks[:50]))):
                subj = db.get(Entity, f.subject_entity_id)
                out.append(f"{subj.display_name if subj else '?'} {f.predicate}={json.dumps(f.value_json, default=str)[:80]}")
            return sorted(out)[:10]
        db.add(Alert(case_id=case_id, type="change_detected", severity="info", old_fingerprint=prev.fingerprint, new_fingerprint=fp,
                     message=f"{len(added)} new and {len(removed)} no-longer-observed findings since the previous snapshot. "
                             "A finding no longer being observed does not prove it never existed.",
                     details_json={"added": describe(added), "no_longer_observed": describe(removed),
                                   "added_count": len(added), "removed_count": len(removed)}))
        audit.record(db, "alert.change_detected", actor=actor, case_id=case_id, metadata={"added": len(added), "removed": len(removed)})
        db.commit()
        return "change_alert_created"


# ------------------------------------------------------------------ scheduler -----------------------------------------
class Scheduler:
    """Durable, bounded, restart-safe. State lives in the DB; `tick` is deterministic and unit-testable."""

    def __init__(self, st, poll_seconds: float = 30.0, clock=lambda: datetime.now(UTC)):
        self.st, self.poll, self.clock = st, poll_seconds, clock
        self._task: asyncio.Task | None = None
        self._busy: set[str] = set()

    def recover(self) -> int:
        n = 0
        with self.st.sm() as db:
            for wr in db.scalars(select(WorkflowRun).where(WorkflowRun.status == "running")):
                wr.status, wr.ended_at = "interrupted", self.clock()
                n += 1
            db.commit()
        return n

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
                log.warning("scheduler stopped with %s", type(exc).__name__)

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception as exc:  # a failing tick must never kill the scheduler; per-schedule failures are in the DB
                log.warning("scheduler tick failed: %s", type(exc).__name__)
            await asyncio.sleep(self.poll)

    async def tick(self, now: datetime | None = None) -> list[str]:
        now = now or self.clock()
        with self.st.sm() as db:
            due = [s.id for s in db.scalars(select(Schedule).where(Schedule.enabled.is_(True)))
                   if (nra := _aware(s.next_run_at)) is not None and nra <= now]
        ran = []
        for sid in due:
            if sid in self._busy:
                continue
            self._busy.add(sid)
            try:
                if await self._run_one(sid, now):
                    ran.append(sid)
            finally:
                self._busy.discard(sid)
        return ran

    async def _run_one(self, sid: str, now: datetime) -> bool:
        with self.st.sm() as db:
            s = db.get(Schedule, sid)
            nra = _aware(s.next_run_at)
            slot = f"{sid}:{int(nra.timestamp()) if nra else 0}"
            interval = parse_interval(s.cron_or_interval)
            # Advance BEFORE running: a crash mid-run can never replay the slot (at-most-once effects). Missed slots are
            # collapsed into a single catch-up run.
            s.next_run_at = now + interval
            s.last_run_at = now
            case = db.get(Case, s.case_id)
            wf_id, case_id, raw, ttype, confirmed = s.workflow_id, s.case_id, s.target_raw, s.target_type, list(s.confirmed_adapters_json)
            if case is None or case.status != "open":
                s.last_status = "skipped_case_not_open"
                db.commit()
                return False
            if self.st.settings.offline:
                s.last_status = "skipped_offline"  # nothing queued for later: the next slot re-checks everything
                db.commit()
                return False
            db.commit()
        try:
            res = await execute(self.st, wf_id, case_id, raw, ttype, confirmed, "schedule", slot, actor="scheduler")
            status = res["status"]
            failed = status == "failed"
        except (WorkflowError, TargetError, service.PlanError) as exc:
            status, failed = f"error: {str(exc)[:120]}", True
        except Exception as exc:
            status, failed = f"error: {type(exc).__name__}", True
        with self.st.sm() as db:
            s = db.get(Schedule, sid)
            s.last_status = status
            s.consecutive_failures = s.consecutive_failures + 1 if failed else 0
            if failed:
                s.next_run_at = now + interval * (2 ** min(s.consecutive_failures, 4))  # exponential backoff
            if s.consecutive_failures >= 5:
                s.enabled, s.last_status = False, "disabled_after_failures"
                db.add(Alert(case_id=s.case_id, type="monitor_disabled", severity="warning",
                             message="Scheduled monitoring was switched off after 5 consecutive failures. Review and re-enable it."))
            audit.record(db, "schedule.run", actor="scheduler", case_id=s.case_id, resource_id=sid, metadata={"status": status[:60]})
            db.commit()
        return not failed


_ = (Target, SearchRun)
