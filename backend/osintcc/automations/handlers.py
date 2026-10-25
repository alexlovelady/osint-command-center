"""Runtime handlers, one per registered node type. A handler gets a `Ctx`, returns a JSON-serialisable output and raises `NodeError` for failures the
engine understands. In a dry run (`ctx.dry`) handlers use the template's fixture, perform NO network access and NO writes, and label results simulated."""
from __future__ import annotations

import asyncio
import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from ..db.models import (
    AutomationWorkflow,
    Case,
    Entity,
    Evidence,
    Finding,
    Job,
    Observation,
    ReportRun,
)
from ..search import service
from ..telemetry import audit
from . import notifications as notes
from . import permissions, snapshots
from . import settings as aset
from .graph_validator import parse_ref
from .models import Definition, Node
from .registry import NodeError, handler

CONF_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
MAX_OUTPUT_ITEMS = 1500


@dataclass
class Ctx:
    st: Any
    run_id: str
    wf: AutomationWorkflow
    case_id: str | None
    actor: str
    dry: bool
    definition: Definition
    node: Node
    cfg: dict[str, Any]
    inputs: dict[str, Any]
    outputs: dict[str, Any]
    fixture: dict[str, Any] = field(default_factory=dict)
    confirmed: set[str] = field(default_factory=set)
    quota: Counter = field(default_factory=Counter)
    warnings: list[str] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    cancelled: Any = None                 # callable -> bool
    deadline: float | None = None         # loop.time() when the run must end
    search_runs: list[str] = field(default_factory=list)
    review: dict[str, Any] | None = None
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    has_failure: bool = False
    failures: list[dict[str, Any]] = field(default_factory=list)
    health: Any = None                    # async callable adapter_id -> status string

    def resolve(self, ref: str | None) -> Any:
        if ref is None:
            return None
        p = parse_ref(ref)
        if p is None:
            raise NodeError("INVALID_GRAPH", f"malformed reference {ref!r}")
        kind, name, fld = p
        if kind == "inputs":
            return self.inputs.get(name)
        out = self.outputs.get(name)
        if out is None:
            raise NodeError("UPSTREAM_FAILED", f"{name!r} produced no output")
        return out.get(fld) if fld is not None and isinstance(out, dict) else out

    def check_cancel(self) -> None:
        if self.cancelled and self.cancelled():
            raise NodeError("RUN_CANCELLED", "the run was cancelled")

    def time_left(self) -> float | None:
        return None if self.deadline is None else self.deadline - asyncio.get_running_loop().time()


def _items(v: Any) -> list[dict[str, Any]]:
    return list(v.get("items", [])) if isinstance(v, dict) else []


def _target_value(v: Any) -> str:
    t = v.get("target") if isinstance(v, dict) else v
    if not isinstance(t, str) or not t.strip():
        raise NodeError("INVALID_GRAPH", "the target reference did not resolve to text")
    return t.strip()


def item_key(it: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps([it.get("entity_type"), it.get("entity"), it.get("predicate"), it.get("value")], sort_keys=True, default=str).encode()).hexdigest()[:20]


def _sim_items(ctx: Ctx, adapter: str) -> list[dict[str, Any]]:
    rows = (ctx.fixture.get("adapter_findings") or {}).get(adapter) or []
    if not rows:
        ctx.warnings.append(f"no fixture data for {adapter}: the simulated result is empty")
    out = []
    for i, r in enumerate(rows):
        out.append({"id": f"sim:{adapter}:{i}", "entity": r["entity"], "entity_type": r.get("entity_type", "domain"), "predicate": r["predicate"], "value": r["value"],
                    "confidence": r.get("confidence", "medium"), "adapter": adapter, "evidence_id": f"sim-evidence:{adapter}:{i}", "simulated": True})
    return out


def _findings_out(items: list[dict[str, Any]], *, adapters: list[str], partial: bool = False, simulated: bool = False, warnings: list[str] | None = None) -> dict[str, Any]:
    trunc = len(items) > MAX_OUTPUT_ITEMS
    return {"items": items[:MAX_OUTPUT_ITEMS], "count": len(items), "adapters": adapters, "partial": partial, "simulated": simulated, "truncated": trunc,
            "warnings": warnings or []}


# ----------------------------------------------------------------------------------------------------------------------- scope
@handler("authorization_check")
async def authorization_check(ctx: Ctx) -> Any:
    raw = ctx.resolve(ctx.cfg["target_ref"])
    mode = "active" if ctx.cfg["mode"] == "active" else "passive_only"
    with ctx.st.sm() as db:
        case = db.get(Case, ctx.case_id) if ctx.case_id else None
        if case is None and ctx.dry:                                  # a dry run before any case exists still proves the target is a public, well-formed one
            parsed = permissions.check_public_only(_target_value(raw), ctx.cfg.get("target_type"), ctx.st.settings)
            return {"target": parsed.canonical, "type": parsed.type, "allowed": True, "mode": mode, "simulated": True}
        if case is None:
            raise NodeError("SCOPE_DENIED", "no case: collection needs a case to hold its evidence")
        parsed = permissions.check_target(db, case, _target_value(raw), ctx.cfg.get("target_type"), ctx.st.settings, mode=mode)
    return {"target": parsed.canonical, "type": parsed.type, "allowed": True, "mode": mode}


# ----------------------------------------------------------------------------------------------------------------------- sources
_CODE_MAP = {"not_installed": ("SOURCE_UNAVAILABLE", False), "requires_key": ("CREDENTIAL_MISSING", False), "requires_config": ("CREDENTIAL_MISSING", False),
             "timeout": ("TIMEOUT", True), "network_error": ("SOURCE_UNAVAILABLE", True), "rate_limited": ("RATE_LIMITED", True),
             "policy_denied": ("SCOPE_DENIED", False)}


async def _availability(ctx: Ctx, aid: str) -> None:
    ad = ctx.st.adapters.get(aid)
    if ad is None:
        raise NodeError("UNSUPPORTED_ADAPTER", f"adapter {aid!r} is not registered")
    status = await ctx.health(aid) if ctx.health else (await ad.health()).get("status")
    m = ad.manifest
    if status == "not_installed":
        raise NodeError("SOURCE_UNAVAILABLE", f"{m.name} is not installed. {m.install_hint or 'Install it from Setup.'}")
    if status == "requires_key":
        raise NodeError("CREDENTIAL_MISSING", f"{m.name} needs an API key; add it in Setup -> API keys.")
    if status in ("unsupported", "disabled"):
        raise NodeError("SOURCE_UNAVAILABLE", f"{m.name} is {status} on this system.")


def _charge(ctx: Ctx, aid: str, n: int = 1) -> None:
    ctx.quota[aid] += n
    if ctx.quota[aid] > ctx.definition.policy.max_requests_per_provider_per_run:
        raise NodeError("RATE_LIMITED", f"the per-run request budget for {aid} ({ctx.definition.policy.max_requests_per_provider_per_run}) is used up; no credential or provider is rotated to get around it")


async def _run_adapter(ctx: Ctx, aid: str, raw_target: str, ttype: str | None) -> tuple[list[dict[str, Any]], bool, list[str]]:
    """One real search run for one adapter, through the same plan/policy/runner path a person's click uses. Returns (items, partial, warnings)."""
    await _availability(ctx, aid)
    ad = ctx.st.adapters[aid]
    m = ad.manifest
    _charge(ctx, aid)
    mode = "active" if m.operation_class == "active" else "passive"
    with ctx.st.sm() as db:
        case = db.get(Case, ctx.case_id)
        parsed = permissions.check_target(db, case, raw_target, ttype, ctx.st.settings, mode="active" if mode == "active" else "passive_only", manifest=m)
        try:
            plan = service.build_plan(db, case, parsed, ctx.st.adapters, ctx.st.settings, selected=[aid], mode=mode)
        except service.PlanError as exc:
            raise NodeError("SCOPE_DENIED", str(exc)) from exc
        step = next((s for s in plan["steps"] if s["adapter_id"] == aid), None)
        if step is None or not step["runnable"]:
            reason = (step or {}).get("reason", "not supported for this target type")
            raise NodeError("OFFLINE" if "offline" in reason else "SCOPE_DENIED", f"{m.name} cannot run: {reason}")
        if step.get("requires_confirmation") and aid not in ctx.confirmed:
            raise NodeError("APPROVAL_REQUIRED", f"{m.name} contacts many third-party sites; confirm it in the approval (or when you start the run)")
        try:
            run = service.create_run(db, case, parsed, plan, confirmed=[aid] if aid in ctx.confirmed else [], mode=mode)
        except service.PlanError as exc:
            raise NodeError("SCOPE_DENIED", str(exc)) from exc
        db.commit()
        rid = run.id
    ctx.search_runs.append(rid)
    task = asyncio.create_task(ctx.st.runner.run_until_idle(rid))
    try:
        while not task.done():
            ctx.check_cancel()
            left = ctx.time_left()
            if left is not None and left <= 0:
                raise NodeError("TIMEOUT", "the run's time budget ended")
            await asyncio.wait({task}, timeout=0.2)
        await task
    except BaseException:
        if not task.done():
            task.cancel()                               # stops the executing job; subprocess adapters kill their whole process tree on cancellation
            await asyncio.gather(task, return_exceptions=True)
        ctx.st.runner.abort_run(rid)
        raise
    with ctx.st.sm() as db:
        jobs = list(db.scalars(select(Job).where(Job.run_id == rid)))
        keys = sorted({k for j in jobs for k in (j.result_keys_json or [])})
        items = []
        if keys:
            rows = db.execute(select(Finding, Entity).join(Entity, Entity.id == Finding.subject_entity_id)
                              .where(Finding.case_id == ctx.case_id, Finding.dedup_key.in_(keys))).all()
            for f, e in rows:
                items.append({"id": f.id, "entity": e.display_name, "entity_type": e.type, "predicate": f.predicate, "value": f.value_json, "confidence": f.confidence,
                              "adapter": f.adapter_id, "evidence_id": f.evidence_id, "observed_at": f.observed_at.isoformat() if f.observed_at else None, "run": rid})
        bad = [j for j in jobs if j.status not in ("succeeded", "skipped")]
        skipped = [j for j in jobs if j.status == "skipped"]
        warn = [w for j in jobs for w in (j.warnings_json or [])][:5]
    if bad or (skipped and not items):
        j = (bad or skipped)[0]
        code, retryable = _CODE_MAP.get((j.last_error_code or "").lower(), ("SOURCE_UNAVAILABLE", False))
        if not items:
            raise NodeError(code, f"{m.name} failed ({j.last_error_code or j.status}). {'; '.join(warn)}"[:300], retryable=retryable)
        return items, True, [f"{m.name} returned partial results ({j.last_error_code or j.status})"]
    return items, False, warn


@handler("adapter_query")
async def adapter_query(ctx: Ctx) -> Any:
    aid = ctx.cfg["adapter"]
    if ctx.dry:
        await _availability_dry(ctx, aid)
        return _findings_out(_sim_items(ctx, aid), adapters=[aid], simulated=True, warnings=ctx.warnings)
    raw = _target_value(ctx.resolve(ctx.cfg["target_ref"]))
    items, partial, warns = await _run_adapter(ctx, aid, raw, ctx.cfg.get("target_type"))
    if partial:
        ctx.warnings += warns
    return _findings_out(items, adapters=[aid], partial=partial, warnings=warns)


async def _availability_dry(ctx: Ctx, aid: str) -> None:
    if aid not in ctx.st.adapters:
        raise NodeError("UNSUPPORTED_ADAPTER", f"adapter {aid!r} is not registered")
    try:
        await _availability(ctx, aid)
    except NodeError as exc:                 # a dry run still uses the fixture, but tells the truth about availability
        ctx.warnings.append(f"{exc.code}: {exc.message} (the dry run used fixture data)")


@handler("enrich")
async def enrich(ctx: Ctx) -> Any:
    aid = ctx.cfg["adapter"]
    src = _items(ctx.resolve(ctx.cfg["from_ref"]))
    want = set(ctx.cfg["entity_types"])
    seen: list[str] = []
    for it in src:
        if it.get("entity_type") in want and it.get("entity") and it["entity"] not in seen:
            seen.append(it["entity"])
    chosen = seen[: ctx.cfg["max_targets"]]
    if len(seen) > len(chosen):
        ctx.warnings.append(f"{len(seen) - len(chosen)} discovered target(s) were not enriched (limit {ctx.cfg['max_targets']})")
    if ctx.dry:
        await _availability_dry(ctx, aid)
        return _findings_out(_sim_items(ctx, aid), adapters=[aid], simulated=True, warnings=ctx.warnings)
    out: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    partial = False
    for t in chosen:
        ctx.check_cancel()
        try:
            items, p, w = await _run_adapter(ctx, aid, t, None)       # scope is re-checked for EVERY discovered target before any request
        except NodeError as exc:
            if exc.code in ("SCOPE_DENIED", "SCOPE_EXPIRED"):
                skipped.append({"target": t, "code": exc.code, "reason": exc.message[:160]})
                continue
            raise
        out += items
        partial = partial or p
        ctx.warnings += w
    if skipped:
        ctx.diagnostics["skipped_targets"] = skipped
        ctx.warnings.append(f"{len(skipped)} discovered target(s) were refused by scope checks and skipped")
        partial = True
    return _findings_out(out, adapters=[aid], partial=partial, warnings=ctx.warnings)


# ----------------------------------------------------------------------------------------------------------------------- pure transforms
@handler("transform")
async def transform(ctx: Ctx) -> Any:
    src = ctx.resolve(ctx.cfg["ref"])
    srcs = [src] + [ctx.resolve(r) for r in ctx.cfg["extra_refs"]]
    items = [i for s in srcs for i in _items(s)]
    adapters = sorted({a for s in srcs for a in (s or {}).get("adapters", [])})
    src = {"adapters": adapters, "partial": any((s or {}).get("partial") for s in srcs), "simulated": any((s or {}).get("simulated") for s in srcs)}
    op, vals = ctx.cfg["op"], set(ctx.cfg["values"])
    if op == "merge":
        pass
    elif op == "pick_predicates":
        items = [i for i in items if i.get("predicate") in vals]
    elif op == "exclude_predicates":
        items = [i for i in items if i.get("predicate") not in vals]
    else:
        floor = CONF_RANK[ctx.cfg.get("min_confidence") or "low"]
        items = [i for i in items if CONF_RANK.get(i.get("confidence", "unknown"), 0) >= floor]
    return _findings_out(items, adapters=(src or {}).get("adapters", []), partial=bool((src or {}).get("partial")), simulated=bool((src or {}).get("simulated")))


@handler("deduplicate")
async def deduplicate(ctx: Ctx) -> Any:
    src = ctx.resolve(ctx.cfg["ref"])
    seen: set[str] = set()
    out = []
    for i in _items(src):
        k = (item_key(i) if ctx.cfg["key"] == "entity_predicate_value" else snapshots.group_id(i))
        if k in seen:
            continue
        seen.add(k)
        out.append(i)
    return _findings_out(out, adapters=(src or {}).get("adapters", []), partial=bool((src or {}).get("partial")), simulated=bool((src or {}).get("simulated")))


@handler("correlate")
async def correlate(ctx: Ctx) -> Any:
    by_val: dict[str, dict[str, Any]] = {}
    for idx, ref in enumerate(ctx.cfg["refs"]):
        for i in _items(ctx.resolve(ref)):
            v = json.dumps(i.get("value"), sort_keys=True, default=str)
            slot = by_val.setdefault(v, {"value": i.get("value"), "datasets": set(), "entities": set()})
            slot["datasets"].add(idx)
            slot["entities"].add(i.get("entity"))
    links = [{"value": s["value"], "entities": sorted(map(str, s["entities"]))[:10], "datasets": sorted(s["datasets"])} for s in by_val.values()
             if len(s["datasets"]) > 1 or len(s["entities"]) > 1]
    return {"items": links[:200], "count": len(links), "note": "suggested links only: nothing was merged; confirm each one by hand", "simulated": ctx.dry}


@handler("condition")
async def condition(ctx: Ctx) -> Any:
    v = ctx.resolve(ctx.cfg["ref"])
    return {"value": compare(v, ctx.cfg["op"], ctx.cfg.get("value"))}


def compare(left: Any, op: str, right: Any) -> bool:
    if isinstance(left, dict):
        left = next((left[k] for k in ("changed", "value", "count") if k in left), None)
    if op == "truthy":
        return bool(left)
    try:
        return {"eq": left == right, "ne": left != right, "gt": left > right, "ge": left >= right, "lt": left < right, "le": left <= right}[op]
    except TypeError:
        return False


# ----------------------------------------------------------------------------------------------------------------------- snapshots
@handler("snapshot_diff")
async def snapshot_diff(ctx: Ctx) -> Any:
    src = ctx.resolve(ctx.cfg["dataset_ref"])
    items = _items(src)
    partial = bool((src or {}).get("partial"))
    cur = snapshots.to_snapshot(items, ctx.cfg["ignore_predicates"])
    if ctx.dry:
        prev = ctx.fixture.get("previous_snapshot")
        prev_groups = snapshots.to_snapshot(prev, ctx.cfg["ignore_predicates"]) if prev else None
        out = snapshots.compare(prev_groups, cur, partial=partial, ignore=ctx.cfg["ignore_predicates"])
        return out | {"simulated": True, "dataset_hash": snapshots.snapshot_hash(cur)}
    sources = sorted((src or {}).get("adapters", []))
    with ctx.st.sm() as db:
        prev_row = snapshots.latest(db, ctx.wf.id, ctx.case_id, ctx.node.id)
        prev_items = {k: v for k, v in (prev_row.items_json if prev_row else {}).items() if k != snapshots.SOURCES_KEY} if prev_row else None
        prev_sources = (prev_row.items_json or {}).get(snapshots.SOURCES_KEY) if prev_row else None
        if prev_row is not None and prev_sources is not None and prev_sources != sources and not partial:
            # a tool was installed or removed between runs: comparing would report the whole difference as news, so this run becomes the new baseline
            out = snapshots.compare(None, cur) | {"sources_changed": True, "note": f"the set of sources changed ({', '.join(prev_sources) or 'none'} -> {', '.join(sources) or 'none'}); this run is the new baseline"}
            ctx.warnings.append(out["note"])
        else:
            out = snapshots.compare(prev_items, cur, partial=partial, ignore=ctx.cfg["ignore_predicates"])
        if not partial:                           # only a complete dataset becomes the next baseline ("latest successful")
            snapshots.save(db, ctx.wf.id, ctx.case_id, ctx.node.id, cur, ctx.run_id, sources)
        else:
            ctx.warnings.append("the dataset is partial, so it was not stored as a new baseline")
        db.commit()
    return out | {"dataset_hash": snapshots.snapshot_hash(cur)}


# ----------------------------------------------------------------------------------------------------------------------- outputs
@handler("evidence_save")
async def evidence_save(ctx: Ctx) -> Any:
    data = ctx.resolve(ctx.cfg["ref"])
    body = json.dumps(data, sort_keys=True, default=str, indent=1).encode()
    if ctx.dry:
        return {"evidence_id": "sim-evidence", "sha256": hashlib.sha256(body).hexdigest(), "simulated": True}
    now = datetime.now(UTC)
    with ctx.st.sm() as db:
        sha256, sha512, rel, size = ctx.st.vault.store(body)
        ev = db.scalars(select(Evidence).where(Evidence.case_id == ctx.case_id, Evidence.sha256 == sha256, Evidence.kind == "automation.dataset")).first()
        if ev is None:
            ev = Evidence(case_id=ctx.case_id, kind="automation.dataset", title=ctx.cfg["title"], sha256=sha256, sha512=sha512, byte_size=size, mime_type="application/json",
                          vault_relpath=rel, retrieved_at=now, observed_at=now, capture_method="automation", sensitivity="INTERNAL", created_by=f"automation:{ctx.actor}"[:80],
                          description=f"saved by workflow {ctx.wf.name} (run {ctx.run_id[:8]}, node {ctx.node.id})",
                          chain_of_custody_json=[{"event": "saved_by_automation", "at": now.isoformat(), "run": ctx.run_id, "sha256": sha256}])
            db.add(ev)
            db.flush()
        out = {"evidence_id": ev.id, "sha256": sha256}
        db.commit()
    return out


@handler("report")
async def report(ctx: Ctx) -> Any:
    if ctx.dry:
        return {"report_id": "sim-report", "simulated": True, "profile": ctx.cfg["profile"], "format": ctx.cfg["format"]}
    from ..reporting import build as report_build
    from ..reporting import store as report_store
    assert ctx.case_id is not None
    with ctx.st.sm() as db:
        data = report_build.collect(db, ctx.case_id, ctx.cfg["profile"], redact_sensitive=True)
        rr = ReportRun(case_id=ctx.case_id, template=ctx.cfg["profile"], redaction_profile="default", evidence_manifest_sha256=data["evidence_manifest_sha256"], status="running")
        db.add(rr)
        db.flush()
        try:
            path = await asyncio.to_thread(report_build.write_report, data, ctx.cfg["format"], ctx.st.settings.export_dir, f"report-{ctx.case_id[:8]}-{rr.id[:8]}")
            path, digest = await asyncio.to_thread(report_store.seal, ctx.st.vault, rr.id, path)
        except Exception as exc:
            rr.status = "failed"
            db.commit()
            raise NodeError("INTERNAL", f"report generation failed ({type(exc).__name__})") from exc
        rr.export_path, rr.status, rr.sha256 = path.name, "done", digest
        db.commit()
        return {"report_id": rr.id, "sha256": digest, "file": path.name}


@handler("delay")
async def delay(ctx: Ctx) -> Any:
    if ctx.dry:
        return {"waited": 0, "simulated": True}
    end = asyncio.get_running_loop().time() + ctx.cfg["seconds"]
    while (rem := end - asyncio.get_running_loop().time()) > 0:
        ctx.check_cancel()
        await asyncio.sleep(min(0.25, rem))
    return {"waited": ctx.cfg["seconds"]}


@handler("analyst_review")
async def analyst_review(ctx: Ctx) -> Any:
    if ctx.dry:
        return {"approved": True, "simulated": True, "note": "a real run would pause here until a person decides"}
    if ctx.review is None:
        raise NodeError("INTERNAL", "analyst_review is driven by the engine")           # never reached: the engine parks the run first
    return {"approved": bool(ctx.review.get("approved")), "decided_by": ctx.review.get("by")}


@handler("file_ingest")
async def file_ingest(ctx: Ctx) -> Any:
    if ctx.dry:
        f = ctx.fixture.get("file") or {"kind": "eml", "count": 1}
        return {"evidence_id": "sim-evidence", "kind": f.get("kind"), "count": f.get("count", 1), "sha256": f.get("sha256", "0" * 64), "simulated": True, "preview": f.get("preview", [])}
    eid = ctx.resolve(ctx.cfg.get("evidence_ref")) or ctx.inputs.get("evidence_id")
    if not isinstance(eid, str):
        raise NodeError("INVALID_GRAPH", "no file was supplied: start this workflow with a file (Run with file) or an evidence id")
    with ctx.st.sm() as db:
        ev = db.get(Evidence, eid)
        if ev is None or ev.case_id != ctx.case_id:
            raise NodeError("SCOPE_DENIED", "that evidence item does not belong to this case")
        obs = list(db.scalars(select(Observation).where(Observation.raw_evidence_id == ev.id)))
        preview = [{"kind": o.kind, "discipline": o.discipline_id, "sensitivity": o.sensitivity,
                    "data": ({"withheld": "restricted: shown only in the Imports tab"} if o.sensitivity in ("RESTRICTED", "SECRET") else _short(o.data_json))} for o in obs[:8]]
        return {"evidence_id": ev.id, "kind": ev.kind.removeprefix("import."), "sha256": ev.sha256, "size": ev.byte_size, "count": len(obs), "title": ev.title,
                "imported_at": ev.retrieved_at.isoformat() if ev.retrieved_at else None, "duplicate": bool(ctx.inputs.get("duplicate")), "disciplines": sorted({o.discipline_id for o in obs}), "preview": preview,
                "sensitivity": ev.sensitivity}


def _short(d: Any) -> Any:
    s = json.dumps(d, default=str)
    return d if len(s) <= 400 else {"truncated": s[:400]}


# ----------------------------------------------------------------------------------------------------------------------- notifications
def _changed(v: Any) -> tuple[bool, dict[str, Any]]:
    if isinstance(v, dict) and "changed" in v:
        return bool(v["changed"]), v
    if isinstance(v, dict) and "value" in v:
        return bool(v["value"]), v
    if isinstance(v, dict) and "count" in v:
        return v["count"] > 0, v
    return bool(v), {}


def _describe(d: dict[str, Any]) -> str:
    if "added_count" in d:
        return (f"{d.get('added_count', 0)} new, {d.get('removed_count', 0)} no longer observed, {d.get('changed_count', 0)} changed, {len(d.get('uncertain', []))} uncertain "
                "(no longer observed does not prove it never existed)")
    return f"{d.get('count', 0)} item(s)"


@handler("notification")
async def notification(ctx: Ctx) -> Any:
    cfg = ctx.cfg
    changed, detail = _changed(ctx.resolve(cfg.get("change_ref"))) if cfg.get("change_ref") else (True, {})
    if cfg["only_if_changed"] and not changed:
        return {"sent": False, "reason": "no meaningful change", "simulated": ctx.dry}
    if ctx.dry:
        return {"sent": True, "simulated": True, "channel": cfg["channel"], "title": cfg["title"]}
    digest = hashlib.sha256(json.dumps({k: detail.get(k) for k in ("added", "removed", "changed_items", "uncertain", "count")}, sort_keys=True, default=str).encode()).hexdigest()
    body = f"{ctx.wf.name}: {_describe(detail)}"
    with ctx.st.sm() as db:
        res = notes.raise_notification(db, owner_id=ctx.wf.owner_id, workflow_id=ctx.wf.id, run_id=ctx.run_id, title=cfg["title"], body=body, severity=cfg["severity"],
                                       channel="in_app" if cfg["channel"] == "webhook" else cfg["channel"], digest=digest,
                                       details={k: detail.get(k) for k in ("added", "removed", "changed_items", "uncertain") if detail.get(k)} if detail else {})
        webhook_url = None
        if cfg["channel"] == "webhook":
            webhook_url = aset.load(db)["notifications"]["webhooks"].get(cfg.get("webhook_ref"))
        audit.record(db, "automation.notify", actor=f"automation:{ctx.actor}"[:80], case_id=ctx.case_id, resource_id=ctx.wf.id, metadata={"dedup": res["deduplicated"], "channel": cfg["channel"]})
        db.commit()
    if cfg["channel"] == "webhook":
        if not webhook_url:
            raise NodeError("CREDENTIAL_MISSING", f"webhook destination {cfg.get('webhook_ref')!r} is not approved in Settings")
        if not res["deduplicated"]:
            ok, detail_s = await notes.send_webhook(webhook_url, {"workflow": ctx.wf.name, "title": cfg["title"], "severity": cfg["severity"], "summary": body, "run_id": ctx.run_id})
            if not ok:
                raise NodeError("SOURCE_UNAVAILABLE", f"webhook delivery failed ({detail_s})", retryable=True)
    return {"sent": not res["deduplicated"], "notification_id": res["id"], "deduplicated": res["deduplicated"], "status": res["status"]}


@handler("error_handler")
async def error_handler(ctx: Ctx) -> Any:
    summary = "; ".join(f"{f['node']}: {f['code']}" for f in ctx.failures[:6]) or "a step failed"
    if ctx.dry:
        return {"sent": False, "simulated": True, "would_say": summary}
    with ctx.st.sm() as db:
        res = notes.raise_notification(db, owner_id=ctx.wf.owner_id, workflow_id=ctx.wf.id, run_id=ctx.run_id, title=ctx.cfg["title"], body=f"{ctx.wf.name}: {summary}",
                                       severity="warning", channel="in_app", digest=summary)
        db.commit()
    return {"sent": not res["deduplicated"], "notification_id": res["id"], "deduplicated": res["deduplicated"]}


# ----------------------------------------------------------------------------------------------------------------------- local readers
@handler("case_findings")
async def case_findings(ctx: Ctx) -> Any:
    if ctx.dry:
        rows = ctx.fixture.get("case_findings") or []
        items = [{"id": f"sim:case:{i}", "evidence_id": f"sim-evidence:case:{i}", "adapter": "case", "confidence": "medium", "entity_type": "domain", **r, "simulated": True}
                 for i, r in enumerate(rows)]
        if not items:
            ctx.warnings.append("no fixture data for the case findings: the simulated result is empty")
        return _findings_out(items, adapters=["case"], simulated=True, warnings=ctx.warnings)
    with ctx.st.sm() as db:
        q = (select(Finding, Entity, Evidence).join(Entity, Entity.id == Finding.subject_entity_id).join(Evidence, Evidence.id == Finding.evidence_id)
             .where(Finding.case_id == ctx.case_id).order_by(Finding.observed_at.desc()).limit(ctx.cfg["limit"] * 2))
        if ctx.cfg["entity_types"]:
            q = q.where(Entity.type.in_(ctx.cfg["entity_types"]))
        if ctx.cfg["predicates"]:
            q = q.where(Finding.predicate.in_(ctx.cfg["predicates"]))
        items = []
        for f, e, ev in db.execute(q):
            if ev.sensitivity in ("RESTRICTED", "SECRET") or e.sensitivity in ("RESTRICTED", "SECRET"):
                continue                                                        # restricted material never enters an automation dataset
            items.append({"id": f.id, "entity": e.display_name, "entity_type": e.type, "predicate": f.predicate, "value": f.value_json, "confidence": f.confidence,
                          "adapter": f.adapter_id, "evidence_id": f.evidence_id, "observed_at": f.observed_at.isoformat() if f.observed_at else None})
    return _findings_out(items[: ctx.cfg["limit"]], adapters=["case"])


@handler("sensor_health")
async def sensor_health(ctx: Ctx) -> Any:
    if ctx.dry:
        rows = ctx.fixture.get("devices") or []
        items = [{"id": f"sim:dev:{i}", "entity": r["name"], "entity_type": "device", "predicate": "device.status", "value": r["status"], "confidence": "high",
                  "adapter": "hardware", "evidence_id": f"sim-evidence:dev:{i}", "simulated": True} for i, r in enumerate(rows)]
        return _findings_out(items, adapters=["hardware"], simulated=True)
    from ..db.models import HardwareDevice
    with ctx.st.sm() as db:
        items = []
        for d in db.scalars(select(HardwareDevice)):
            if d.simulated and not ctx.cfg["include_simulated"]:
                continue
            items.append({"id": d.id, "entity": d.logical_name, "entity_type": "device", "predicate": "device.status", "value": "present" if d.present else "absent",
                          "confidence": "high", "adapter": "hardware", "evidence_id": None, "simulated": d.simulated, "driver": d.driver_id})
    note = ["only simulated/replay devices have been exercised in this application; owned receivers were not tested"] if any(i["simulated"] for i in items) else []
    return _findings_out(items, adapters=["hardware"], warnings=note)


@handler("case_gaps")
async def case_gaps(ctx: Ctx) -> Any:
    if ctx.dry:
        rows = ctx.fixture.get("gaps") or []
        items = [{"id": f"sim:gap:{i}", "entity": "requirement", "entity_type": "requirement", "predicate": "gap.open_requirement", "value": r, "confidence": "high",
                  "adapter": "case", "evidence_id": None, "simulated": True} for i, r in enumerate(rows)]
        return _findings_out(items, adapters=["case"], simulated=True)
    from ..graph import fusion
    with ctx.st.sm() as db:
        g = fusion.gap_assessment(db, ctx.case_id or "")
    items = [{"id": f"gap:{u['id']}", "entity": "requirement", "entity_type": "requirement", "predicate": "gap.open_requirement",
              "value": f"{u['question']} ({u['answer_status']}, {u['priority']})", "confidence": "high", "adapter": "case", "evidence_id": None}
             for u in g["unanswered_requirements"]]
    if g["unverified_claims"]:
        items.append({"id": "gap:unverified", "entity": "claims", "entity_type": "claim", "predicate": "gap.unverified_claims", "value": g["unverified_claims"],
                      "confidence": "high", "adapter": "case", "evidence_id": None})
    if g["disputed_claims"]:
        items.append({"id": "gap:disputed", "entity": "claims", "entity_type": "claim", "predicate": "gap.disputed_claims", "value": g["disputed_claims"],
                      "confidence": "high", "adapter": "case", "evidence_id": None})
    return _findings_out(items, adapters=["case"])


@handler("aiv_authorizations")
async def aiv_authorizations(ctx: Ctx) -> Any:
    if ctx.dry:
        rows = ctx.fixture.get("aiv_authorizations") or []
        items = [{"id": f"sim:aivauth:{i}", "entity": r.get("scope", "lab.example"), "entity_type": "domain", "predicate": "aiv.authorization", "value": r.get("status", "live"), "confidence": "high",
                  "adapter": "aiv", "evidence_id": None, "simulated": True} for i, r in enumerate(rows)]
        return _findings_out(items, adapters=["aiv"], simulated=True)
    from ..aiv import policy as aivp
    from ..db.models import AssetAuthorization
    items = []
    with ctx.st.sm() as db:
        for a in db.scalars(select(AssetAuthorization).where(AssetAuthorization.case_id == ctx.case_id).order_by(AssetAuthorization.created_at.desc()).limit(200)):
            live = aivp.authorization_live(a, ctx.now)
            if ctx.cfg["only_live"] and not live:
                continue
            items.append({"id": a.id, "entity": ", ".join((a.canonical_scope or [])[:3]), "entity_type": "domain", "predicate": "aiv.authorization",
                          "value": "live" if live else live.code, "confidence": "high", "adapter": "aiv", "evidence_id": None,
                          "classes": list(a.allowed_classes_json or []), "expires_at": a.expires_at.isoformat() if a.expires_at else None})
    return _findings_out(items, adapters=["aiv"])


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


@handler("aiv_observations")
async def aiv_observations(ctx: Ctx) -> Any:
    if ctx.dry:
        rows = ctx.fixture.get("aiv_observations") or []
        items = [{"id": f"sim:aivobs:{i}", "entity": r.get("asset", "lab.example"), "entity_type": "domain", "predicate": f"aiv.{r.get('check', 'http_metadata')}", "value": r.get("title", "observation"),
                  "confidence": "medium", "adapter": "aiv", "evidence_id": f"sim-evidence:aiv:{i}", "severity": r.get("severity", "low"), "simulated": True} for i, r in enumerate(rows)]
        if not items:
            ctx.warnings.append("no fixture data for AIV observations: the simulated result is empty")
        return _findings_out(items, adapters=["aiv"], simulated=True, warnings=ctx.warnings)
    from ..db.models import AivObservation
    floor = _SEV_RANK[ctx.cfg["min_severity"]]
    items = []
    with ctx.st.sm() as db:
        q = select(AivObservation).where(AivObservation.case_id == ctx.case_id).order_by(AivObservation.observed_at.desc()).limit(ctx.cfg["limit"] * 2)
        for o in db.scalars(q):
            if _SEV_RANK.get(o.severity, 0) < floor or o.review_status in ctx.cfg["exclude_reviewed"]:
                continue
            title = (o.observed_value_json or {}).get("title") or o.finding_key or o.check_type
            items.append({"id": o.id, "entity": o.target_asset, "entity_type": "domain", "predicate": f"aiv.{o.check_type}", "value": str(title)[:200], "confidence": o.confidence,
                          "adapter": "aiv", "evidence_id": o.evidence_id, "severity": o.severity, "review_status": o.review_status, "basis": o.basis,
                          "observed_at": o.observed_at.isoformat() if o.observed_at else None})
    return _findings_out(items[: ctx.cfg["limit"]], adapters=["aiv"])


# ---- DARKINT --------------------------------------------------------------------------------------------------------------------------------
def _event_items(rows: list[Any]) -> list[dict[str, Any]]:
    return [{"id": e.id, "entity": "exposure", "entity_type": "exposure", "predicate": f"darkint.{e.event_type}", "value": e.title, "confidence": e.confidence, "adapter": e.provider_id,
             "evidence_id": e.evidence_id, "categories": list(e.categories_json), "claim_status": e.claim_status,
             "observed_at": e.reported_last_seen.isoformat() if e.reported_last_seen else None} for e in rows]


def _sim_exposure(ctx: Ctx) -> list[dict[str, Any]]:
    rows = ctx.fixture.get("darkint_events") or []
    return [{"id": f"sim:darkint:{i}", "entity": "exposure", "entity_type": "exposure", "predicate": f"darkint.{r.get('type', 'breach')}", "value": r.get("title", "Reported incident"),
             "confidence": r.get("confidence", "low"), "adapter": r.get("provider", "hibp"), "evidence_id": f"sim-evidence:darkint:{i}", "categories": r.get("categories", []),
             "claim_status": "reported", "simulated": True} for i, r in enumerate(rows)]


@handler("darkint_check")
async def darkint_check(ctx: Ctx) -> Any:
    if ctx.dry:
        ctx.warnings.append("simulated: no provider was contacted and no consent was exercised")
        return _findings_out(_sim_exposure(ctx), adapters=["darkint"], simulated=True, warnings=ctx.warnings)
    from ..darkint import service as dsvc
    from ..db.models import ExposureEvent, ExposureMonitorConfig
    mid = ctx.resolve(ctx.cfg["monitor_ref"])
    if not isinstance(mid, str) or not mid:
        raise NodeError("SCOPE_DENIED", "no exposure monitor is bound to this automation: create a monitor in the Exposure tab and enter its id as the input")
    with ctx.st.sm() as db:
        m = db.get(ExposureMonitorConfig, mid)
        if m is None or m.case_id != ctx.case_id:
            raise NodeError("SCOPE_DENIED", "that monitor does not belong to this case")
        out = await dsvc.run_monitor(db, ctx.st, m, ctx.actor, force=True)
        db.commit()
        if not out["ran"]:
            raise NodeError("SCOPE_DENIED", out["reason"])
        failed = [r for r in out["results"] if r["outcome"] not in ("match", "no_match")]
        if out["results"] and len(failed) == len(out["results"]):
            code = next((r["code"] for r in failed if r["code"] in ("CREDENTIAL_MISSING", "RATE_LIMITED", "SOURCE_UNAVAILABLE", "UNSUPPORTED", "OFFLINE")), "SOURCE_UNAVAILABLE")
            raise NodeError(code, "; ".join(sorted({r["detail"] for r in failed if r["detail"]}))[:300] or "no provider could be checked", retryable=False)
        ctx.warnings += [f"{r['provider_id']}: {r['outcome'].replace('_', ' ')}: {r['detail']}"[:240] for r in failed]
        rows = [e for e in db.scalars(select(ExposureEvent).where(ExposureEvent.case_id == ctx.case_id, ExposureEvent.subject_id == m.subject_id, ExposureEvent.identifier_id.in_(m.identifier_ids_json)))
                if e.claim_status != "retracted"]
        return _findings_out(_event_items(rows)[:500], adapters=["darkint"], partial=bool(failed), warnings=ctx.warnings)


@handler("darkint_events")
async def darkint_events(ctx: Ctx) -> Any:
    if ctx.dry:
        return _findings_out(_sim_exposure(ctx), adapters=["darkint"], simulated=True, warnings=["simulated"])
    from ..db.models import ExposureEvent, ExposureReview
    with ctx.st.sm() as db:
        q = select(ExposureEvent).where(ExposureEvent.case_id == ctx.case_id).order_by(ExposureEvent.created_at.desc()).limit(ctx.cfg["limit"] * 2)
        if ctx.cfg["event_types"]:
            q = q.where(ExposureEvent.event_type.in_(ctx.cfg["event_types"]))
        rows = []
        for e in db.scalars(q):
            if e.claim_status == "retracted":
                continue
            if ctx.cfg["exclude_dismissed"]:
                last = db.scalars(select(ExposureReview).where(ExposureReview.event_id == e.id).order_by(ExposureReview.created_at.desc())).first()
                if last and last.status == "not_relevant":
                    continue
            rows.append(e)
        return _findings_out(_event_items(rows[: ctx.cfg["limit"]]), adapters=["darkint"])


@handler("darkint_remediation")
async def darkint_remediation(ctx: Ctx) -> Any:
    if ctx.dry:
        n = len(ctx.fixture.get("darkint_events") or [])
        items = [{"id": f"sim:task:{i}", "entity": "remediation", "entity_type": "task", "predicate": "darkint.remediation_task", "value": a, "confidence": "high", "adapter": "darkint",
                  "evidence_id": None, "simulated": True} for i, a in enumerate(ctx.cfg["actions"][: max(n, 1)])]
        return _findings_out(items, adapters=["darkint"], simulated=True, warnings=["simulated: no task was created and nothing was sent"])
    from ..darkint import service as dsvc
    from ..db.models import ExposureEvent, RemediationTask, Subject
    created: list[dict[str, Any]] = []
    with ctx.st.sm() as db:
        for e in db.scalars(select(ExposureEvent).where(ExposureEvent.case_id == ctx.case_id).order_by(ExposureEvent.created_at)):
            if e.claim_status == "retracted" or e.subject_id is None or len(created) >= ctx.cfg["max_tasks"]:
                continue
            s = db.get(Subject, e.subject_id)
            if s is None:
                continue
            for act in dsvc.suggest_actions(e):
                if act not in ctx.cfg["actions"] or len(created) >= ctx.cfg["max_tasks"]:
                    continue
                if db.scalars(select(RemediationTask).where(RemediationTask.exposure_event_id == e.id, RemediationTask.action_type == act)).first():
                    continue
                t = dsvc.create_remediation(db, s, e, act, ctx.actor)
                created.append({"id": t.id, "entity": "remediation", "entity_type": "task", "predicate": "darkint.remediation_task", "value": f"{act}: {t.issue}"[:200], "confidence": "high",
                                "adapter": "darkint", "evidence_id": e.evidence_id})
        db.commit()
    return _findings_out(created, adapters=["darkint"], warnings=["tasks only: no message was sent and no takedown was submitted"])


@handler("associated_emails")
async def associated_emails_node(ctx: Ctx) -> Any:
    if ctx.dry:
        rows = ctx.fixture.get("associated_emails") or []
        items = [{"id": f"sim:email:{i}", "entity": r.get("address", "j***@example.org"), "entity_type": "email", "predicate": "profile.associated_email", "value": r.get("classification", "possible"),
                  "confidence": "low", "adapter": "profile", "evidence_id": f"sim-evidence:email:{i}", "simulated": True} for i, r in enumerate(rows)]
        return _findings_out(items, adapters=["profile"], simulated=True, warnings=["simulated: no source was contacted"])
    from ..db.models import AssociatedEmail
    from ..profile.normalize import mask_value
    items = []
    with ctx.st.sm() as db:
        for r in db.scalars(select(AssociatedEmail).where(AssociatedEmail.case_id == ctx.case_id).order_by(AssociatedEmail.discovered_at)):
            if r.state == "rejected" or r.classification not in ctx.cfg["classes"]:
                continue
            ev = next((s["evidence_id"] for s in r.sources if s.get("evidence_id")), None)
            items.append({"id": r.id, "entity": mask_value("email", r.address), "entity_type": "email", "predicate": "profile.associated_email", "value": r.classification,
                          "confidence": {"confirmed": "high", "likely": "medium"}.get(r.classification, "low"), "adapter": "profile", "evidence_id": ev, "state": r.state})
    return _findings_out(items[: ctx.cfg["limit"]], adapters=["profile"])
