"""Run orchestration: durable runs, ordered execution of the typed graph, retries, cancellation, checkpoints and crash recovery.

Delivery is at-least-once: every run has a unique idempotency key, side-effecting nodes carry their own idempotency (notifications are de-duplicated,
evidence is content-addressed), and after a crash only nodes marked replay-safe are re-run automatically."""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from ..copilot import context as cx
from ..db.models import (
    AutomationNodeRun,
    AutomationRun,
    AutomationVersion,
    AutomationWorkflow,
    Case,
)
from ..telemetry import audit
from . import handlers as h
from . import notifications as notes
from . import permissions
from .graph_validator import parse_ref, topo_levels, validate
from .models import CONFIGS, Definition, canonical
from .registry import ERROR_CODES, HANDLERS, SPECS, NodeError

ACTIVE_STATES = ("queued", "running", "paused", "waiting_for_approval", "retrying")
TERMINAL = ("completed", "completed_with_warnings", "failed", "cancelled")
MAX_OUTPUT_BYTES = 1_000_000


def _now() -> datetime:
    return datetime.now(UTC)


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode()).hexdigest()


class AutomationEngine:
    def __init__(self, st: Any, backoff_scale: float = 1.0):
        self.st = st
        self.backoff_scale = backoff_scale
        self._cancel: set[str] = set()
        self._running: set[str] = set()

    # ------------------------------------------------------------------------------------------------------------ queue
    def enqueue(self, db: Any, wf: AutomationWorkflow, version: AutomationVersion | None, *, trigger_type: str, inputs: dict[str, Any], dry_run: bool, idem: str,
                actor: str, case_id: str | None, event_id: str | None = None, definition: dict[str, Any] | None = None,
                fixture: dict[str, Any] | None = None, confirmed: list[str] | None = None, queue_anyway: bool = False) -> AutomationRun | None:
        """Create a queued run unless one with this idempotency key exists (a trigger firing twice never double-runs)."""
        if not dry_run and trigger_type != "manual" and not queue_anyway:
            pol = (version.definition_json if version else wf.draft_json).get("policy", {}).get("reentrancy", "skip")
            busy = db.scalar(select(func.count()).select_from(AutomationRun).where(AutomationRun.workflow_id == wf.id, AutomationRun.state.in_(ACTIVE_STATES),
                                                                                    AutomationRun.dry_run.is_(False)))
            queued = db.scalar(select(func.count()).select_from(AutomationRun).where(AutomationRun.workflow_id == wf.id, AutomationRun.state == "queued"))
            if (pol == "skip" and busy) or (pol == "coalesce" and queued):
                audit.record(db, "automation.run_skipped", actor="scheduler", case_id=case_id, resource_id=wf.id, metadata={"reason": f"reentrancy={pol}"})
                return None
        payload = {"inputs": inputs, "confirmed_adapters": confirmed or []}
        if dry_run:
            payload["definition"] = definition or (version.definition_json if version else wf.draft_json)
            payload["fixture"] = fixture or {}
        run = AutomationRun(workflow_id=wf.id, version_id=version.id if version else None, case_id=case_id, trigger_type=trigger_type, trigger_event_id=event_id,
                            state="queued", dry_run=dry_run, idempotency_key=idem, inputs_json=payload, created_by=actor)
        db.add(run)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return None
        audit.record(db, "automation.run_queued", actor=actor, case_id=case_id, resource_id=run.id, metadata={"workflow": wf.id, "trigger": trigger_type, "dry_run": dry_run})
        return run

    async def drain(self, limit: int | None = None) -> int:
        """Run queued runs, at most `max_concurrent_runs` at a time. Returns how many were started."""
        with self.st.sm() as db:
            from . import settings as aset
            cap = limit or aset.load(db)["max_concurrent_runs"]
            running = db.scalar(select(func.count()).select_from(AutomationRun).where(AutomationRun.state == "running")) or 0
            busy_wf = {w for (w,) in db.execute(select(AutomationRun.workflow_id).where(AutomationRun.state == "running"))}
            ids: list[str] = []
            for rid, wid in db.execute(select(AutomationRun.id, AutomationRun.workflow_id).where(AutomationRun.state == "queued").order_by(AutomationRun.queued_at)):
                if wid in busy_wf or len(ids) >= max(0, cap - running):
                    continue
                busy_wf.add(wid)                                  # one run of a workflow at a time: its baseline snapshot must not race itself
                ids.append(rid)
        if not ids:
            return 0
        await asyncio.gather(*(self.execute(i) for i in ids))
        return len(ids)

    def request_cancel(self, run_id: str) -> None:
        self._cancel.add(run_id)
        with self.st.sm() as db:
            r = db.get(AutomationRun, run_id)
            if r and r.state in ("queued", "paused", "waiting_for_approval"):
                r.state, r.ended_at, r.error_code = "cancelled", _now(), "RUN_CANCELLED"
            elif r:
                r.cancel_requested = True
            audit.record(db, "automation.run_cancel", actor="user", case_id=r.case_id if r else None, resource_id=run_id)
            db.commit()

    def _cancelled(self, run_id: str) -> bool:
        return run_id in self._cancel

    # --------------------------------------------------------------------------------------------------------- recovery
    def recover(self) -> dict[str, int]:
        """After a restart: running runs are resumed from their checkpoints if every interrupted node is replay-safe, otherwise paused for a person."""
        resumed = paused = 0
        with self.st.sm() as db:
            for r in db.scalars(select(AutomationRun).where(AutomationRun.state == "running")):
                interrupted = list(db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == r.id, AutomationNodeRun.state == "running")))
                defn = (r.inputs_json or {}).get("definition")
                if defn is None and r.version_id:
                    v = db.get(AutomationVersion, r.version_id)
                    defn = v.definition_json if v else None
                types = {n["id"]: n["type"] for n in (defn or {}).get("nodes", [])}
                for nr in interrupted:
                    nr.state, nr.ended_at, nr.error_code = "interrupted", _now(), "INTERRUPTED"
                safe = all(SPECS[types.get(nr.node_id, "delay")].replay_safe for nr in interrupted)
                if safe:
                    r.state = "queued"
                    resumed += 1
                else:
                    r.state, r.error_code = "paused", "INTERRUPTED"
                    paused += 1
                audit.record(db, "automation.run_recovered", actor="system", case_id=r.case_id, resource_id=r.id, metadata={"resumed": safe, "interrupted_nodes": len(interrupted)})
            db.commit()
        return {"resumed": resumed, "paused": paused}

    # ------------------------------------------------------------------------------------------------------- execution
    async def execute(self, run_id: str) -> str:
        if run_id in self._running:
            return "running"
        self._running.add(run_id)
        try:
            return await self._execute(run_id)
        except Exception as exc:                                  # an engine bug must never leave a run "running" forever
            self._finish(run_id, "failed", "INTERNAL", {"error": type(exc).__name__})
            return "failed"
        finally:
            self._running.discard(run_id)
            self._cancel.discard(run_id)

    def _finish(self, run_id: str, state: str, code: str | None, summary: dict[str, Any]) -> None:
        with self.st.sm() as db:
            r = db.get(AutomationRun, run_id)
            if r is None:
                return
            r.state, r.error_code, r.ended_at = state, code, _now()
            r.summary_json = (r.summary_json or {}) | summary
            audit.record(db, "automation.run_finished", actor="system", case_id=r.case_id, resource_id=run_id, metadata={"state": state, "code": code, "dry_run": r.dry_run})
            db.commit()

    async def _execute(self, run_id: str) -> str:
        st = self.st
        with st.sm() as db:
            r = db.get(AutomationRun, run_id)
            if r is None or r.state not in ("queued",):
                return r.state if r else "missing"
            wf = db.get(AutomationWorkflow, r.workflow_id)
            version = db.get(AutomationVersion, r.version_id) if r.version_id else None
            payload = dict(r.inputs_json or {})
            raw_def = payload.get("definition") or (version.definition_json if version else None)
            r.state, r.started_at = "running", r.started_at or _now()
            r.lease_until = _now() + timedelta(minutes=5)
            dry, case_id, trigger, actor = r.dry_run, r.case_id, r.trigger_type, r.created_by
            version_id = r.version_id
            db.commit()
        if wf is None or raw_def is None:
            self._finish(run_id, "failed", "INVALID_GRAPH", {"error": "workflow or definition is missing"})
            return "failed"
        health = {a: (await cx._health(ad)).get("status", "unknown") for a, ad in st.adapters.items()}
        v = validate(raw_def, st.adapters, health)
        if not v["valid"]:
            self._finish(run_id, "failed", "INVALID_GRAPH", {"problems": v["errors"][:5]})
            return "failed"
        defn = Definition.model_validate(raw_def)
        confirmed: set[str] = set(payload.get("confirmed_adapters", []))
        gate_note: dict[str, Any] = {}
        if not dry:
            try:
                with st.sm() as db:
                    gate = permissions.run_gate(db, wf, version_id, trigger, defn.policy.network_mode, db.get(Case, case_id) if case_id else None)
                confirmed |= set(gate["confirmed_adapters"])
                gate_note = {"approval": "checked"}
            except NodeError as exc:
                self._finish(run_id, "failed", exc.code, {"error": exc.message})
                self._notify_failure(wf, run_id, trigger, f"{exc.code}: {exc.message}")
                return "failed"
            if st.settings.offline and v["permissions"]["network"]:
                self._finish(run_id, "paused", "OFFLINE", {"error": "offline mode is on; network steps pause. Retry when you are online."})
                return "paused"

        loop = asyncio.get_running_loop()
        deadline = loop.time() + defn.policy.max_duration_seconds
        deps = {n.id: list(n.depends_on) for n in defn.nodes}
        levels = topo_levels(deps) or {}
        order = sorted(defn.nodes, key=lambda n: (levels[n.id], n.id))
        waves: dict[int, list] = {}
        for n in order:
            waves.setdefault(levels[n.id], []).append(n)
        outputs: dict[str, Any] = {}
        states: dict[str, str] = {}
        failures: list[dict[str, Any]] = []
        warnings: list[str] = []
        quota: Counter = Counter()
        search_runs: list[str] = []
        with st.sm() as db:                                       # checkpoints from an earlier (interrupted) attempt of THIS run
            for nr in db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == run_id, AutomationNodeRun.state == "succeeded").order_by(AutomationNodeRun.attempt)):
                outputs[nr.node_id] = nr.output_json
                states[nr.node_id] = "succeeded"
        run_inputs = {**{k: val for k, val in defn.inputs.items()}, **{k: val for k, val in (payload.get("inputs") or {}).items() if k in defn.inputs or k in ("evidence_id", "duplicate")}}
        fixture = payload.get("fixture", {})
        sem = asyncio.Semaphore(defn.policy.max_concurrent_nodes)
        parked = False
        optional_ids = {x.id for x in defn.nodes if x.optional}

        def cancelled() -> bool:
            if self._cancelled(run_id):
                return True
            with st.sm() as db:
                rr = db.get(AutomationRun, run_id)
                return bool(rr and rr.cancel_requested)

        async def run_node(n) -> None:
            nonlocal parked
            async with sem:
                if states.get(n.id) == "succeeded":
                    return
                up_failed = [d for d in n.depends_on if states.get(d) in ("failed", "skipped_failed") and d not in optional_ids]
                any_failure = any(not f.get("optional") for f in failures)
                if n.run_on == "failure" and not any_failure:
                    states[n.id] = "skipped"
                    self._record_skip(run_id, n.id, "no failure to handle")
                    return
                up_skipped = [d for d in n.depends_on if states.get(d) == "skipped"]
                if n.run_on == "success" and up_skipped and not up_failed:
                    states[n.id] = "skipped"
                    self._record_skip(run_id, n.id, f"upstream {', '.join(up_skipped)} was skipped")
                    return
                if n.run_on == "success" and up_failed:
                    states[n.id] = "skipped_failed"
                    self._record_skip(run_id, n.id, f"upstream {', '.join(up_failed)} did not succeed", "UPSTREAM_FAILED")
                    return
                if n.when is not None:
                    try:
                        left = outputs_resolve(n.when.ref)
                    except NodeError:
                        states[n.id] = "skipped_failed"
                        self._record_skip(run_id, n.id, "its condition input is unavailable", "UPSTREAM_FAILED")
                        return
                    if not h.compare(left, n.when.op, n.when.value):
                        states[n.id] = "skipped"
                        self._record_skip(run_id, n.id, "condition not met")
                        return
                node_cfg = CONFIGS[n.type].model_validate(n.config).model_dump()
                ctx = h.Ctx(st=st, run_id=run_id, wf=wf, case_id=case_id, actor=actor, dry=dry, definition=defn, node=n, cfg=node_cfg, inputs=run_inputs, outputs=outputs,
                            fixture=fixture, confirmed=confirmed, quota=quota, cancelled=cancelled, deadline=deadline, health=self._health_fn(), failures=failures)
                if n.type == "analyst_review" and not dry:
                    try:
                        res = self._review_state(run_id, n, defn)
                    except NodeError as exc:                       # the analyst rejected, or nobody decided in time
                        states[n.id] = "failed"
                        failures.append({"node": n.id, "code": exc.code if exc.code in ERROR_CODES else "INTERNAL", "message": exc.message[:300], "optional": n.optional})
                        return
                    if res == "park":
                        parked = True
                        states[n.id] = "waiting"
                        return
                    ctx.review = res
                await self._run_with_retries(run_id, n, ctx, defn, states, outputs, failures, warnings, search_runs)

        def outputs_resolve(ref: str) -> Any:
            p = parse_ref(ref)
            if p is None:
                raise NodeError("INVALID_GRAPH", "bad reference")
            kind, name, fld = p
            if kind == "inputs":
                return run_inputs.get(name)
            if name not in outputs:
                raise NodeError("UPSTREAM_FAILED", "no output")
            o = outputs[name]
            return o.get(fld) if fld and isinstance(o, dict) else o

        try:
            async with asyncio.timeout(defn.policy.max_duration_seconds):
                for lvl in sorted(waves):
                    if cancelled():
                        break
                    await asyncio.gather(*(run_node(n) for n in waves[lvl]))
                    if parked:
                        break
        except TimeoutError:
            failures.append({"node": "*", "code": "TIMEOUT", "message": f"the run exceeded its {defn.policy.max_duration_seconds}s budget"})
        evidence = {i.get("evidence_id") for o in outputs.values() if isinstance(o, dict) for i in o.get("items", []) if isinstance(i, dict) and i.get("evidence_id")}
        evidence |= {o["evidence_id"] for o in outputs.values() if isinstance(o, dict) and isinstance(o.get("evidence_id"), str)}
        evidence = {e for e in evidence if not str(e).startswith("sim")}
        summary = {"nodes": {k: val for k, val in states.items()}, "warnings": warnings[:20], "failures": failures[:10], "requests": dict(quota), "search_runs": search_runs,
                   "simulated": dry, "gate": gate_note, "inputs": run_inputs, "health": {k: val for k, val in health.items() if val != "healthy"}}
        with st.sm() as db:
            rr = db.get(AutomationRun, run_id)
            if rr:
                rr.evidence_count = len(evidence)
                db.commit()
        if cancelled():
            self._finish(run_id, "cancelled", "RUN_CANCELLED", summary)
            return "cancelled"
        if parked:
            self._finish_waiting(run_id, summary)
            return "waiting_for_approval"
        hard = [f for f in failures if not f.get("optional")]
        if hard:
            self._finish(run_id, "failed", hard[0]["code"], summary)
            if not dry:
                self._notify_failure(wf, run_id, trigger, "; ".join(f"{f['node']}: {f['code']}" for f in hard[:4]))
            return "failed"
        state = "completed_with_warnings" if (warnings or failures) else "completed"
        self._finish(run_id, state, "PARTIAL_RESULT" if state != "completed" else None, summary)
        return state

    def _health_fn(self) -> Any:
        async def f(aid: str) -> str:
            return (await cx._health(self.st.adapters[aid])).get("status", "unknown")
        return f

    def _record_skip(self, run_id: str, node_id: str, why: str, code: str | None = None) -> None:
        with self.st.sm() as db:
            db.add(AutomationNodeRun(run_id=run_id, node_id=node_id, attempt=1, state="skipped", ended_at=_now(), error_code=code, diagnostics_json={"why": why}))
            db.commit()

    def _finish_waiting(self, run_id: str, summary: dict[str, Any]) -> None:
        with self.st.sm() as db:
            r = db.get(AutomationRun, run_id)
            if r:
                r.state, r.summary_json = "waiting_for_approval", (r.summary_json or {}) | summary
                db.commit()

    def _review_state(self, run_id: str, n: Any, defn: Definition) -> Any:
        """'park' (create/keep a waiting node run) or the decision dict once a person decided."""
        with self.st.sm() as db:
            nr = db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == run_id, AutomationNodeRun.node_id == n.id,
                                                            AutomationNodeRun.state == "waiting")).first()
            if nr is None:
                db.add(AutomationNodeRun(run_id=run_id, node_id=n.id, attempt=1, state="waiting", diagnostics_json={"prompt": n.config.get("prompt", "")}))
                db.commit()
                return "park"
            dec = (nr.diagnostics_json or {}).get("decision")
            if dec is None:
                hours = int(n.config.get("timeout_hours", 72))
                started = permissions.aware(nr.started_at)
                if started and _now() > started + timedelta(hours=hours):
                    nr.state, nr.ended_at, nr.error_code = "failed", _now(), "TIMEOUT"
                    db.commit()
                    raise NodeError("TIMEOUT", "nobody reviewed this step in time")
                return "park"
            nr.state, nr.ended_at = "succeeded", _now()
            nr.output_json = {"approved": bool(dec.get("approved")), "decided_by": dec.get("by")}
            db.commit()
            if not dec.get("approved"):
                raise NodeError("APPROVAL_REQUIRED", "the analyst rejected this step")
            return dec

    def decide_review(self, db: Any, run_id: str, node_id: str, approve: bool, by: str) -> bool:
        nr = db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == run_id, AutomationNodeRun.node_id == node_id, AutomationNodeRun.state == "waiting")).first()
        r = db.get(AutomationRun, run_id)
        if nr is None or r is None or r.state != "waiting_for_approval":
            return False
        nr.diagnostics_json = {**(nr.diagnostics_json or {}), "decision": {"approved": approve, "by": by, "at": _now().isoformat()}}
        r.state = "queued"
        audit.record(db, "automation.review", actor=by, case_id=r.case_id, resource_id=run_id, metadata={"node": node_id, "approved": approve})
        return True

    async def _run_with_retries(self, run_id: str, n: Any, ctx: h.Ctx, defn: Definition, states: dict[str, str], outputs: dict[str, Any],
                                failures: list[dict[str, Any]], warnings: list[str], search_runs: list[str]) -> None:
        max_attempts = defn.error_policy.transient_retries + 1
        attempt = 0
        while True:
            attempt += 1
            ctx.warnings, ctx.diagnostics = [], {}
            inp = digest({"type": n.type, "cfg": ctx.cfg, "refs": {k: digest(v) for k, v in outputs.items() if k in n.depends_on}})
            with self.st.sm() as db:
                nr = AutomationNodeRun(run_id=run_id, node_id=n.id, attempt=attempt, state="running", input_digest=inp)
                db.add(nr)
                db.commit()
                nr_id = nr.id
            try:
                ctx.check_cancel()
                out = await HANDLERS[n.type](ctx)
                blob = json.dumps(out, default=str)
                if len(blob) > MAX_OUTPUT_BYTES:
                    out = {"truncated": True, "note": "output too large to store inline", "count": out.get("count") if isinstance(out, dict) else None}
                outputs[n.id] = out
                states[n.id] = "succeeded"
                warnings += [f"{n.id}: {w}" for w in ctx.warnings]
                search_runs += ctx.search_runs
                ctx.search_runs = []
                self._end_node(nr_id, "succeeded", out, None, {"warnings": ctx.warnings, **ctx.diagnostics, "search_runs": list(search_runs)})
                return
            except NodeError as exc:
                self._end_node(nr_id, "failed", None, exc.code, {"message": exc.message, "details": exc.details, **ctx.diagnostics})
                if exc.code == "RUN_CANCELLED":
                    states[n.id] = "failed"
                    return
                if exc.retryable and attempt < max_attempts and not ctx.cancelled():
                    delay = min(30.0, 2 ** (attempt - 1) + random.uniform(0, 1))                 # bounded exponential backoff with jitter
                    if exc.retry_after:
                        delay = max(delay, min(60.0, exc.retry_after))
                    await asyncio.sleep(delay * self.backoff_scale)
                    continue
                states[n.id] = "failed"
                failures.append({"node": n.id, "code": exc.code if exc.code in ERROR_CODES else "INTERNAL", "message": exc.message[:300], "optional": n.optional})
                if n.optional:
                    warnings.append(f"{n.id}: optional step failed ({exc.code})")
                    outputs[n.id] = {"items": [], "count": 0, "adapters": [], "partial": bool(exc.retryable) or exc.code in ("TIMEOUT", "RATE_LIMITED", "INTERNAL"),
                                     "simulated": ctx.dry, "skipped_optional": True, "reason": exc.code, "warnings": []}   # a tool that is simply not installed is a stable configuration, not a partial result
                return
            except asyncio.CancelledError:
                self._end_node(nr_id, "interrupted", None, "INTERRUPTED", {})
                raise
            except Exception as exc:                                                              # a handler bug: fail the node, keep the engine alive
                self._end_node(nr_id, "failed", None, "INTERNAL", {"message": type(exc).__name__})
                states[n.id] = "failed"
                failures.append({"node": n.id, "code": "INTERNAL", "message": f"unexpected {type(exc).__name__}", "optional": n.optional})
                return

    def _end_node(self, nr_id: str, state: str, out: Any, code: str | None, diag: dict[str, Any]) -> None:
        with self.st.sm() as db:
            nr = db.get(AutomationNodeRun, nr_id)
            if nr:
                nr.state, nr.ended_at, nr.output_json, nr.error_code, nr.diagnostics_json = state, _now(), out, code, diag
                db.commit()

    def _notify_failure(self, wf: AutomationWorkflow, run_id: str, trigger: str, summary: str) -> None:
        if trigger == "manual":
            return                                                                              # the person who started it is looking at it
        with self.st.sm() as db:
            notes.raise_notification(db, owner_id=wf.owner_id, workflow_id=wf.id, run_id=run_id, title=f"Automation failed: {wf.name}", body=summary[:500],
                                     severity="warning", channel="in_app", digest=summary[:200])
            db.commit()
