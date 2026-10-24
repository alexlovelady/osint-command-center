"""Deterministic validation of a workflow definition. Independent of any AI: a model's output is accepted only if this says it is valid,
and nothing here can be loosened by the definition itself (scope checks, active-mode rules and bounds are enforced, not requested)."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from pydantic import ValidationError

from . import cron
from .models import CONFIGS, MAX_NODES, REF_RE, Definition
from .registry import OUT_FIELDS, SPECS

MAX_DEPTH = 12
MAX_FANOUT = 8


def _issue(code: str, message: str, node: str | None = None) -> dict[str, Any]:
    return {"code": code, "node": node, "message": message}


def parse_ref(ref: str) -> tuple[str, str, str | None] | None:
    """('inputs', name, None) | ('nodes', id, field|None) | None when malformed."""
    if not REF_RE.match(ref):
        return None
    parts = ref[1:].split(".")
    if parts[0] == "inputs":
        return "inputs", parts[1], None
    return "nodes", parts[1], (parts[3] if len(parts) > 3 else None)


def config_refs(node_type: str, cfg: dict[str, Any]) -> list[tuple[str, str]]:
    """(field, ref) for every reference-typed value in a node config."""
    out = []
    for fld in SPECS[node_type].ref_types:
        v = cfg.get(fld)
        if isinstance(v, str):
            out.append((fld, v))
        elif isinstance(v, list):
            out += [(fld, x) for x in v if isinstance(x, str)]
    if node_type == "notification" and isinstance(cfg.get("change_ref"), str) and ("change_ref", cfg["change_ref"]) not in out:
        out.append(("change_ref", cfg["change_ref"]))
    return out


def topo_levels(deps: dict[str, list[str]]) -> dict[str, int] | None:
    """Longest-path level per node (1-based) or None if there is a cycle."""
    level: dict[str, int] = {}
    state: dict[str, int] = {}

    def visit(n: str) -> bool:
        if state.get(n) == 2:
            return True
        if state.get(n) == 1:
            return False
        state[n] = 1
        best = 0
        for d in deps.get(n, []):
            if d not in deps:
                continue
            if not visit(d):
                return False
            best = max(best, level[d])
        level[n] = best + 1
        state[n] = 2
        return True
    for n in deps:
        if not visit(n):
            return None
    return level


def ancestors(deps: dict[str, list[str]]) -> dict[str, set[str]]:
    memo: dict[str, set[str]] = {}

    def anc(n: str, seen: tuple[str, ...] = ()) -> set[str]:
        if n in memo:
            return memo[n]
        out: set[str] = set()
        for d in deps.get(n, []):
            if d in seen or d not in deps:
                continue
            out |= {d} | anc(d, (*seen, n))
        memo[n] = out
        return out
    return {n: anc(n) for n in deps}


def validate(raw: Any, adapters: dict[str, Any], health: dict[str, str] | None = None, *, for_activation: bool = False) -> dict[str, Any]:
    """Returns {valid, errors, warnings, nodes, permissions, estimated_requests}. `health` maps adapter id -> status for availability warnings."""
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    try:
        d = Definition.model_validate(raw)
    except ValidationError as exc:
        for e in exc.errors():
            loc = ".".join(str(x) for x in e["loc"])
            errors.append(_issue("INVALID_GRAPH", f"{loc}: {e['msg']}"))
        return {"valid": False, "errors": errors, "warnings": warnings, "nodes": {}, "permissions": {}, "estimated_requests": {}}
    ids = [n.id for n in d.nodes]
    if len(set(ids)) != len(ids):
        errors.append(_issue("INVALID_GRAPH", "duplicate node ids"))
    byid = {n.id: n for n in d.nodes}
    deps = {n.id: list(n.depends_on) for n in d.nodes}
    for n in d.nodes:
        for dep in n.depends_on:
            if dep not in byid:
                errors.append(_issue("INVALID_GRAPH", f"depends on unknown node {dep!r}", n.id))
            elif dep == n.id:
                errors.append(_issue("INVALID_GRAPH", "a node cannot depend on itself", n.id))
        if len(set(n.depends_on)) != len(n.depends_on):
            errors.append(_issue("INVALID_GRAPH", "duplicate dependency", n.id))
    levels = topo_levels(deps)
    if levels is None:
        errors.append(_issue("INVALID_GRAPH", "the graph has a cycle; cycles are not allowed (bounded fan-out is expressed with `enrich.max_targets`)"))
    elif max(levels.values()) > MAX_DEPTH:
        errors.append(_issue("INVALID_GRAPH", f"dependency depth {max(levels.values())} exceeds {MAX_DEPTH}"))
    fan: dict[str, int] = defaultdict(int)
    for n in d.nodes:
        for dep in n.depends_on:
            fan[dep] += 1
    for k, v in fan.items():
        if v > MAX_FANOUT:
            errors.append(_issue("INVALID_GRAPH", f"{v} nodes depend on {k}; at most {MAX_FANOUT} (unbounded fan-out is rejected)", k))
    if len(d.nodes) > MAX_NODES:
        errors.append(_issue("INVALID_GRAPH", f"at most {MAX_NODES} nodes"))
    anc = ancestors(deps) if levels is not None else {n: set() for n in byid}

    # ---- per-node config, references, adapters
    node_info: dict[str, dict[str, Any]] = {}
    est: dict[str, int] = defaultdict(int)
    auth_checks: dict[str, list[str]] = defaultdict(list)       # node id -> target_refs of upstream scope checks
    for n in d.nodes:
        spec = SPECS[n.type]
        cfg_model = CONFIGS[n.type]
        try:
            cfg = cfg_model.model_validate(n.config).model_dump()
        except ValidationError as exc:
            for e in exc.errors():
                errors.append(_issue("INVALID_GRAPH", f"config.{'.'.join(str(x) for x in e['loc'])}: {e['msg']}", n.id))
            continue
        # references
        refs = config_refs(n.type, cfg) + ([("when", n.when.ref)] if n.when else [])
        for fld, ref in refs:
            p = parse_ref(ref)
            if p is None:
                errors.append(_issue("INVALID_GRAPH", f"{fld}: malformed reference {ref!r}", n.id))
                continue
            kind, name, field = p
            allowed = spec.ref_types.get(fld) if fld != "when" else None
            if kind == "inputs":
                if name not in d.inputs:
                    errors.append(_issue("INVALID_GRAPH", f"{fld}: unknown input {name!r}", n.id))
                elif allowed is not None and "input" not in allowed:
                    errors.append(_issue("INVALID_GRAPH", f"{fld}: an input is not accepted here (needs {'/'.join(allowed)} output)", n.id))
                continue
            if name not in byid:
                errors.append(_issue("INVALID_GRAPH", f"{fld}: references unknown node {name!r}", n.id))
                continue
            if name not in anc.get(n.id, set()):
                errors.append(_issue("INVALID_GRAPH", f"{fld}: {name!r} is not upstream of this node (add it to depends_on)", n.id))
                continue
            out_t = SPECS[byid[name].type].out_type
            if field is not None and field not in OUT_FIELDS[out_t]:
                errors.append(_issue("INVALID_GRAPH", f"{fld}: {name!r} produces {out_t}; it has no field {field!r}", n.id))
            elif allowed is not None and out_t not in allowed:
                errors.append(_issue("INVALID_GRAPH", f"{fld}: type mismatch, needs {'/'.join(allowed)} but {name!r} produces {out_t}", n.id))
        # adapters
        if n.type in ("adapter_query", "enrich"):
            aid = cfg["adapter"]
            if aid not in adapters:
                errors.append(_issue("UNSUPPORTED_ADAPTER", f"adapter {aid!r} is not registered in this installation", n.id))
            else:
                m = adapters[aid].manifest
                if m.operation_class == "active" and d.policy.network_mode == "passive_only":
                    errors.append(_issue("INVALID_GRAPH", f"adapter {aid!r} is an active probe; the workflow policy is passive_only", n.id))
                h = (health or {}).get(aid)
                if h == "not_installed":
                    warnings.append(_issue("SOURCE_UNAVAILABLE", f"{m.name} is not installed. {m.install_hint or 'Install it from Setup.'}", n.id))
                elif h == "requires_key":
                    warnings.append(_issue("CREDENTIAL_MISSING", f"{m.name} needs an API key (Setup -> API keys).", n.id))
                elif h in ("unavailable", "degraded", "disabled", "unsupported"):
                    warnings.append(_issue("SOURCE_UNAVAILABLE", f"{m.name} is {h}.", n.id))
                est[aid] += cfg.get("max_targets", 1) if n.type == "enrich" else 1
            ups = [x for x in anc.get(n.id, set()) if byid[x].type == "authorization_check"]
            if not ups:
                errors.append(_issue("INVALID_GRAPH", "network step has no scope check upstream (add an authorization_check and depend on it)", n.id))
            elif n.type == "adapter_query":
                tgt_ok = any(byid[u].config.get("target_ref") == cfg["target_ref"] or cfg["target_ref"] == f"$nodes.{u}.output.target" for u in ups)
                if not tgt_ok:
                    errors.append(_issue("INVALID_GRAPH", "the upstream scope check is for a different target than this query", n.id))
        if n.type == "authorization_check":
            auth_checks[n.id].append(cfg["target_ref"])
            if cfg["mode"] == "active" and d.policy.network_mode == "passive_only":
                errors.append(_issue("INVALID_GRAPH", "an active scope check needs policy.network_mode=active_with_approval", n.id))
        if n.type == "notification":
            if cfg["channel"] == "webhook" and not cfg.get("webhook_ref"):
                errors.append(_issue("INVALID_GRAPH", "webhook notifications need webhook_ref (a destination name approved in Settings)", n.id))
            if cfg["only_if_changed"] and not cfg.get("change_ref"):
                errors.append(_issue("INVALID_GRAPH", "only_if_changed needs change_ref", n.id))
        if n.type == "error_handler" and n.run_on != "failure":
            warnings.append(_issue("INVALID_GRAPH", "error_handler nodes should use run_on=failure", n.id))
        node_info[n.id] = {"type": n.type, "title": spec.title, "risk": spec.risk, "side_effects": spec.side_effects, "network": spec.network,
                           "out_type": spec.out_type, "level": (levels or {}).get(n.id, 0)}
    for aid, cnt in est.items():
        if cnt > d.policy.max_requests_per_provider_per_run:
            errors.append(_issue("INVALID_GRAPH", f"the graph needs about {cnt} requests to {aid}; the policy allows {d.policy.max_requests_per_provider_per_run} per run"))

    # ---- trigger
    t = d.trigger
    if t.type == "schedule":
        if not t.schedule:
            errors.append(_issue("INVALID_GRAPH", "a schedule trigger needs a cron schedule"))
        else:
            try:
                cron.validate(t.schedule, t.timezone)
            except cron.CronError as exc:
                errors.append(_issue("INVALID_GRAPH", f"trigger: {exc}"))
    elif t.schedule:
        warnings.append(_issue("INVALID_GRAPH", "trigger.schedule is ignored unless trigger.type is schedule"))
    if t.type == "event" and t.event != "new_finding":
        errors.append(_issue("UNSUPPORTED", "event triggers support only event=new_finding"))
    if t.type == "file" and not any(n.type == "file_ingest" for n in d.nodes):
        errors.append(_issue("INVALID_GRAPH", "a file trigger needs a file_ingest node"))
    if t.enabled:
        warnings.append(_issue("APPROVAL_REQUIRED", "trigger.enabled is ignored in a definition: activation is a separate, approved action"))
    if for_activation and not errors:
        for aid in est:
            if (health or {}).get(aid) in ("not_installed", "requires_key"):
                errors.append(_issue("SOURCE_UNAVAILABLE", f"cannot activate: {aid} is not available"))
    perms = {"network": any(i["network"] for i in node_info.values()), "network_mode": d.policy.network_mode,
             "adapters": sorted(est), "writes_local": any(i["side_effects"] == "write_local" for i in node_info.values()),
             "external": any(i["side_effects"] == "external" for i in node_info.values()),
             "active": any(adapters[a].manifest.operation_class == "active" for a in est if a in adapters)}
    return {"valid": not errors, "errors": errors, "warnings": warnings, "nodes": node_info, "permissions": perms, "estimated_requests": dict(est)}
