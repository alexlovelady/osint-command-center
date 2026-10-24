"""AI Automation Builder: propose / explain / diagnose.

The model only ever returns a DRAFT as structured data. Everything it says is parsed by the strict models and checked by the deterministic validator;
authorisation, scope and approvals are enforced elsewhere and cannot be influenced by what a model recommends. With no model the builder falls back to the
closest bundled template (clearly labelled) and the manual editor keeps working."""
from __future__ import annotations

import json
import re
from typing import Any

from ..ai.providers import Message, ProviderError
from ..copilot import context as cx
from ..copilot.kb import Chunk, Index
from . import catalog
from . import settings as aset
from .graph_validator import validate
from .models import CONFIGS, Definition, json_schema
from .registry import SPECS
from .service import ServiceError, normalise

DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.IGNORECASE)


def capability_registry(st: Any, status: dict[str, str]) -> dict[str, Any]:
    return {
        "adapters": [{"id": a, "name": ad.manifest.name, "class": ad.manifest.operation_class, "targets": ad.manifest.supported_target_types, "status": status.get(a, "unknown"),
                      "needs_key": ad.manifest.api_key_name} for a, ad in sorted(st.adapters.items())],
        "node_types": [{"type": t, "title": s.title, "does": s.description, "produces": s.out_type, "config": sorted(CONFIGS[t].model_fields)} for t, s in SPECS.items()],
        "triggers": ["manual", "schedule (5-field cron + IANA timezone)", "event (new_finding)", "file"],
        "templates": [{"key": t["key"], "name": t["name"], "category": t["category"]} for t in catalog.load_all()],
    }


SYSTEM = """You design OSINT automation workflows for a local application. Reply with ONE JSON object and nothing else.
The object must follow the workflow schema: {schema_version:1, workflow_key, name, description, owner_scope:"investigation", status:"draft", tags, trigger, inputs, policy, nodes, error_policy}.
Rules (a validator enforces them; anything else is rejected):
- Use ONLY node types and adapters listed in the registry. Never invent an adapter, a node type, code, shell commands, SQL or URLs.
- References are only "$inputs.<name>" or "$nodes.<node_id>.output" (optionally ".<field>"). A node may reference only nodes it depends on.
- Every network step (adapter_query, enrich) needs an upstream authorization_check on the same target, and the check must be listed in depends_on.
- Scheduled workflows are DRAFTS: set trigger.enabled=false and policy.network_mode="passive_only" unless the user explicitly needs authorised active collection.
- Prefer passive sources, few requests, snapshot_diff + notification for monitoring, evidence_save for results. Do not add steps the user did not ask for.
- Set unknown inputs to null instead of guessing them (the user will be asked).
REGISTRY:
{registry}
EXAMPLE (monitoring pattern):
{example}
"""


def _extract_json(text: str) -> Any:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in the reply")
    depth = 0
    for i in range(start, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return json.loads(text[start:i + 1])
    raise ValueError("unterminated JSON object")


def _template_index() -> Index:
    chunks = [Chunk(t["slug"], "template", t["name"], t["description"] + " " + " ".join(t["tags"]) + " " + t["category"], t["slug"], {"keywords": t["tags"] + [t["key"]]})
              for t in catalog.load_all()]
    return Index(chunks)


def match_template(goal: str) -> dict[str, Any] | None:
    hits = _template_index().search(goal, 3)
    if not hits or hits[0].score < 5.0 or hits[0].coverage < 0.2:
        return None
    return catalog.get(hits[0].chunk.id)


def explain(defn: dict[str, Any], st: Any, status: dict[str, str]) -> dict[str, Any]:
    """Plain-language walk through a definition, derived ONLY from the definition, the node registry and adapter manifests (nothing is guessed)."""
    d = Definition.model_validate(defn)
    rep = validate(defn, st.adapters, status)
    steps = []
    for n in d.nodes:
        spec = SPECS[n.type]
        line = spec.description
        contacts: list[str] = []
        if n.type in ("adapter_query", "enrich"):
            a = st.adapters.get(n.config.get("adapter", ""))
            if a:
                contacts = list(a.manifest.endpoints) or (["its provider"] if a.manifest.needs_network else [])
                line = f"{a.manifest.name}: {a.manifest.description or spec.description}"
        steps.append({"id": n.id, "type": n.type, "title": n.label or spec.title, "what": line, "after": n.depends_on, "risk": spec.risk, "side_effects": spec.side_effects,
                      "contacts": contacts, "optional": n.optional, "only_if": n.when.model_dump() if n.when else None,
                      "can_fail_with": [w["code"] for w in rep["warnings"] if w.get("node") == n.id]})
    t = d.trigger
    when = {"manual": "only when you press Run", "file": "when you run it with a file", "event": "when a new finding is stored in the case"}.get(
        t.type, f"on schedule '{t.schedule}' ({t.timezone}); missed runs: {t.missed_run_policy}")
    return {"name": d.name, "runs": when, "starts_disabled": True, "network_mode": d.policy.network_mode, "limits": {"requests_per_provider": d.policy.max_requests_per_provider_per_run,
            "seconds": d.policy.max_duration_seconds, "parallel_steps": d.policy.max_concurrent_nodes}, "steps": steps, "permissions": rep["permissions"],
            "validation": {"valid": rep["valid"], "errors": rep["errors"], "warnings": rep["warnings"]},
            "note": "Derived from the workflow definition and tool manifests. Nothing here has been run."}


def fill_inputs_from_goal(defn: dict[str, Any], goal: str) -> list[str]:
    """Fill obvious domain inputs from the goal text; returns the assumptions made."""
    notes = []
    dom = DOMAIN_RE.findall(goal)
    for k, v in list(defn.get("inputs", {}).items()):
        if k in ("domain",) and dom:
            defn["inputs"][k] = dom[0].lower()
            notes.append(f"I used {dom[0].lower()} as the domain because your goal mentions it. Confirm you own it or are authorised to examine it.")
        elif v is None and k not in ("evidence_id", "evidence_a", "evidence_b"):
            pass
    return notes


async def propose(st: Any, engine: Any, user: str, goal: str, case_id: str | None, profile_id: str | None, status: dict[str, str]) -> dict[str, Any]:
    goal = " ".join(goal.split())[:1500]
    if len(goal) < 8:
        raise ServiceError(422, "INVALID", "describe what the automation should do in a sentence")
    with st.sm() as db:
        profile, why = engine.select_profile(db, profile_id)
        opted = set(aset.load(db)["cloud_ai_opt_in"])
    provider, reason = (None, why)
    if profile is not None:
        if not profile.local_only and profile.id not in opted:
            reason = "this is a cloud model and you have not allowed it for automations (Settings -> Automations -> cloud AI). Nothing was sent."
        else:
            provider, reason = await engine.model_ready(profile)
    reg = capability_registry(st, status)
    attempts: list[dict[str, Any]] = []
    draft: dict[str, Any] | None = None
    source = "template_match"
    template = None
    rep: dict[str, Any] | None = None
    if provider is not None:
        example = json.dumps(next(t for t in catalog.load_all() if t["key"] == "CY-02")["definition"], separators=(",", ":"))
        sysmsg = SYSTEM.replace("{registry}", json.dumps(reg, separators=(",", ":"))[:6000]).replace("{example}", example[:2500])
        msgs = [Message("system", sysmsg), Message("user", f"Goal: {goal}\nSchema keys: {sorted(json_schema()['properties'])}")]
        for attempt in range(3):                                                         # bounded correction loop
            try:
                raw = await provider.chat(msgs, max_tokens=2200, temperature=0.1)
                cand = _extract_json(raw)
                cand = normalise(cand)
            except (ValueError, ServiceError, ProviderError) as exc:
                msg = exc.message if isinstance(exc, ServiceError) else str(exc)
                det = json.dumps(exc.details)[:600] if isinstance(exc, ServiceError) else ""
                attempts.append({"attempt": attempt + 1, "problem": f"{msg} {det}"[:400]})
                if isinstance(exc, ProviderError):
                    break
                msgs += [Message("assistant", "(invalid)"), Message("user", f"That was rejected: {msg} {det}. Return a corrected JSON object only.")]
                continue
            rep = validate(cand, st.adapters, status)
            if rep["valid"]:
                draft, source = cand, "model"
                break
            attempts.append({"attempt": attempt + 1, "problem": "; ".join(f"[{e['code']}] {e['message']}" for e in rep["errors"][:4])})
            draft = cand
            msgs += [Message("assistant", json.dumps(cand)[:3000]), Message("user", "The validator rejected it: " + "; ".join(f"[{e['code']}] {e['node'] or ''} {e['message']}" for e in rep["errors"][:6])
                                                   + ". Fix exactly these problems and return the corrected JSON object only.")]
        if draft is not None and (rep is None or not rep["valid"]):
            source = "model_invalid"
    if draft is None:
        template = match_template(goal)
        if template is not None:
            draft = json.loads(json.dumps(template["definition"]))
            source = "template_match"
    assumptions: list[str] = []
    if draft is None:
        return {"draft": None, "source": "none", "valid": False, "model": {"used": False, "reason": reason}, "attempts": attempts,
                "message": "I could not build a workflow from that. " + (f"No AI model is available ({reason}); " if provider is None else "") + "Browse the library for a close template, or describe the goal in terms of sources, a target and what should be reported.",
                "questions": []}
    if source != "model":
        assumptions.append(("No AI model answered (" + reason + "): " if provider is None else "") + (f"this is the closest bundled template, '{template['name']}' ({template['key']}); adjust it in the editor." if template else "the model's draft did not pass validation; fix the listed problems in the editor."))
    assumptions += fill_inputs_from_goal(draft, goal)
    rep = validate(draft, st.adapters, status)
    questions = [f"Which {k.replace('_', ' ')} should it use?" for k, v in draft["inputs"].items() if v is None and k not in ("evidence_id", "evidence_a", "evidence_b")]
    if draft["trigger"]["type"] == "schedule":
        assumptions.append(f"Schedule '{draft['trigger']['schedule']}' ({draft['trigger']['timezone']}) is only a suggestion: it stays off until you approve and activate it.")
    return {"draft": draft, "source": source, "template_slug": template["slug"] if template else None, "valid": rep["valid"], "validation": {"errors": rep["errors"], "warnings": rep["warnings"],
            "permissions": rep["permissions"]}, "explanation": explain(draft, st, status) if rep["valid"] or source != "model_invalid" else None, "assumptions": assumptions, "questions": questions,
            "attempts": attempts, "model": {"used": source.startswith("model"), "reason": "" if provider else reason, "profile": profile.name if profile else None},
            "note": "A draft only. Nothing is saved, scheduled, approved or run until you do it."}


# -------------------------------------------------------------------------------------------------------------------- diagnose
FIX = {
    "SOURCE_UNAVAILABLE": "The source could not be used (not installed, offline or failing). Install/repair it in Setup, retry later, or switch to an alternative.",
    "CREDENTIAL_MISSING": "A key or approved destination is missing. Add it in Setup -> API keys (or Settings -> Automations for webhooks).",
    "SCOPE_DENIED": "The target was refused by scope policy (private, local, unauthorised or invalid). It was NOT retried; widening scope is your decision.",
    "SCOPE_EXPIRED": "The scope authorization expired or was revoked. Renew it, then request approval again.",
    "APPROVAL_REQUIRED": "An approval is missing or expired for this exact version. Request and grant approval, then run again.",
    "RATE_LIMITED": "The provider asked to slow down or the per-run budget was used up. Wait; keys are never rotated to avoid limits.",
    "TIMEOUT": "The step took too long. Retry later or raise max_duration_seconds if the source is slow.",
    "OFFLINE": "Offline mode is on, so network steps pause. Turn offline mode off and retry.",
    "UPSTREAM_FAILED": "An earlier step failed, so this one was skipped. Fix the earlier step first.",
    "INVALID_GRAPH": "The workflow definition is invalid; open it in the editor to see the exact problems.",
    "INTERRUPTED": "The application stopped while this step ran. Check for partial effects, then retry.",
}


def diagnose(db: Any, st: Any, run: Any, status: dict[str, str]) -> dict[str, Any]:
    """Real diagnostics from the run's own node records, with documented fixes and (never auto-applied) repair proposals."""
    from sqlalchemy import select

    from ..db.models import AutomationNodeRun, AutomationVersion
    nodes = list(db.scalars(select(AutomationNodeRun).where(AutomationNodeRun.run_id == run.id).order_by(AutomationNodeRun.started_at)))
    defn = (run.inputs_json or {}).get("definition") or (db.get(AutomationVersion, run.version_id).definition_json if run.version_id else {})
    types = {n["id"]: n for n in defn.get("nodes", [])}
    problems, proposals = [], []
    for nr in nodes:
        if nr.state != "failed" and nr.error_code is None:
            continue
        code = nr.error_code or "INTERNAL"
        node = types.get(nr.node_id, {})
        problems.append({"node": nr.node_id, "attempt": nr.attempt, "code": code, "message": (nr.diagnostics_json or {}).get("message"), "fix": FIX.get(code, "See the node details.")})
        if code in ("SOURCE_UNAVAILABLE", "CREDENTIAL_MISSING") and node.get("type") in ("adapter_query", "enrich"):
            a = node["config"]["adapter"]
            tgts = set(st.adapters[a].manifest.supported_target_types) if a in st.adapters else set()
            alts = [k for k, ad in st.adapters.items() if k != a and set(ad.manifest.supported_target_types) & tgts and status.get(k) == "healthy"
                    and ad.manifest.operation_class == st.adapters[a].manifest.operation_class][:3] if a in st.adapters else []
            for alt in alts:
                proposals.append({"op": "replace_adapter", "node": nr.node_id, "from": a, "to": alt, "why": f"{alt} supports the same target type and is healthy now"})
            proposals.append({"op": "set_optional", "node": nr.node_id, "why": f"let the run continue without {a} (the result is then marked partial)"})
    return {"run": run.id, "state": run.state, "error_code": run.error_code, "problems": problems, "proposals": proposals,
            "note": "From this run's own records. Proposals change only a DRAFT after you apply them; publishing and approval stay with you. No tool is claimed to have worked.",
            "healthy_run": run.state in ("completed",) and not problems}


def apply_repairs(defn: dict[str, Any], ops: list[dict[str, Any]], st: Any, status: dict[str, str]) -> dict[str, Any]:
    """Apply a bounded set of repair operations to a copy of the definition and validate the result. Raises ServiceError for anything else."""
    new = json.loads(json.dumps(defn))
    byid = {n["id"]: n for n in new["nodes"]}
    changes = []
    for op in ops[:10]:
        node = byid.get(op.get("node"))
        if node is None:
            raise ServiceError(422, "INVALID", f"unknown node {op.get('node')!r}")
        if op.get("op") == "replace_adapter":
            if node["type"] not in ("adapter_query", "enrich") or op.get("to") not in st.adapters:
                raise ServiceError(422, "UNSUPPORTED_ADAPTER", "that replacement is not possible")
            changes.append({"node": node["id"], "from": node["config"]["adapter"], "to": op["to"]})
            node["config"]["adapter"] = op["to"]
        elif op.get("op") == "set_optional":
            node["optional"] = True
            changes.append({"node": node["id"], "optional": True})
        else:
            raise ServiceError(422, "INVALID", f"unsupported repair operation {op.get('op')!r}")
    new = normalise(new)
    rep = validate(new, st.adapters, status)
    return {"definition": new, "changes": changes, "validation": {"valid": rep["valid"], "errors": rep["errors"], "warnings": rep["warnings"]}}


_ = cx
