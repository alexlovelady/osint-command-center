"""Typed verification plans and their preview. A plan is data: a short list of strictly typed steps. There is no field that can carry a command, a script,
a header, a body, a credential, a template path or an arbitrary destination, and unknown fields are rejected.

Preview is offline (no DNS, no packets). It judges each step lexically against the authorization, estimates what the run would do, and produces the hash that an
approval is bound to.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import policy

MAX_STEPS = 12
TEMPLATE_ID = r"^[a-z0-9][a-z0-9._-]{1,118}$"
HOST_RE = r"^[A-Za-z0-9.:\[\]-]{1,255}$"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HttpStep(Strict):
    kind: Literal["http_metadata"]
    url: str = Field(max_length=2000)
    method: Literal["HEAD", "GET"] = "HEAD"
    follow_redirects: bool = False


class TlsStep(Strict):
    kind: Literal["tls_handshake"]
    host: str = Field(pattern=HOST_RE)
    port: int = Field(default=443, ge=1, le=65535)


class PortStep(Strict):
    kind: Literal["tcp_connect"]
    host: str = Field(pattern=HOST_RE)
    ports: list[int] = Field(min_length=1, max_length=10)


class ServiceStep(Strict):
    kind: Literal["service_detect"]
    host: str = Field(pattern=HOST_RE)
    ports: list[int] = Field(min_length=1, max_length=10)
    tool: Literal["nmap", "naabu"] = "nmap"


class SignatureStep(Strict):
    kind: Literal["signature_check"]
    url: str = Field(max_length=2000)
    template_ids: list[Annotated[str, Field(pattern=TEMPLATE_ID)]] = Field(min_length=1, max_length=5)


Step = Annotated[HttpStep | TlsStep | PortStep | ServiceStep | SignatureStep, Field(discriminator="kind")]


class PlanSteps(Strict):
    steps: list[Step] = Field(min_length=1, max_length=MAX_STEPS)


class PlanError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def parse_steps(raw: Any) -> list[dict[str, Any]]:
    """Strict parse. Anything that is not exactly a list of known steps (extra keys included) is refused."""
    try:
        parsed = PlanSteps.model_validate({"steps": raw})
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(x) for x in first["loc"][1:])
        raise PlanError("invalid_plan", f"step {loc}: {first['msg']}") from exc
    return [s.model_dump() for s in parsed.steps]


def host_of(step: dict[str, Any]) -> str:
    if "url" in step:
        return (urlsplit(step["url"]).hostname or "").lower()
    return step["host"].lower().strip("[]")


def plan_hash(auth_id: str, auth_snapshot: str, steps: list[dict[str, Any]], limits: dict[str, Any], tools: dict[str, str]) -> str:
    body = {"authorization": auth_id, "scope": auth_snapshot, "steps": steps, "limits": limits, "tools": tools}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def estimate(step: dict[str, Any]) -> tuple[int, str]:
    """(requests, impact class) for one step."""
    k = step["kind"]
    if k == "http_metadata":
        return (1 + (3 if step.get("follow_redirects") else 0) + (1 if step["method"] == "HEAD" else 0)), "low"
    if k == "tls_handshake":
        return 5, "low"
    if k == "tcp_connect":
        return len(step["ports"]), "low"
    if k == "service_detect":
        return len(step["ports"]) * 3, "medium"
    return 10 * len(step["template_ids"]), "medium"


def preview(auth: Any, raw_steps: Any, now: datetime | None = None, *, tool_versions: dict[str, str] | None = None, approved_templates: set[str] | None = None,
            offline: bool = False) -> dict[str, Any]:
    """Judge a plan without touching the network. `ok` is true only if every step is allowed and the plan fits the limits."""
    now = now or datetime.now(UTC)
    steps = parse_steps(raw_steps)
    limits = policy.effective_limits(auth.limits_json)
    live = policy.authorization_live(auth, now)
    rows: list[dict[str, Any]] = []
    hosts: set[str] = set()
    total_requests = 0
    tools_needed: dict[str, str] = {}
    for i, s in enumerate(steps):
        k = s["kind"]
        host = host_of(s)
        hosts.add(host)
        d = policy.class_allowed(auth, k) if live else live
        if d:
            if k in ("http_metadata", "signature_check"):
                d = policy.check_url(auth, k, s["url"], now)
            elif k == "tls_handshake":
                d = policy.check_host_port(auth, k, s["host"], s["port"], now)
            else:
                d = policy.validate_ports(s["ports"], limits["max_ports"])
                for port in s["ports"] if d else []:
                    d = policy.check_host_port(auth, k, s["host"], port, now)
                    if not d:
                        break
        if d and k == "signature_check":
            missing = [t for t in s["template_ids"] if t not in (approved_templates or set())]
            if missing:
                d = policy.deny("template_not_approved", "template(s) not approved by id and content hash: " + ", ".join(missing))
        if d and k in ("service_detect",):
            tools_needed[s["tool"]] = (tool_versions or {}).get(s["tool"], "unknown")
        if d and k == "signature_check":
            tools_needed["nuclei"] = (tool_versions or {}).get("nuclei", "unknown")
        n, impact = estimate(s)
        total_requests += n
        rows.append({"index": i, "kind": k, "target": host, "detail": {x: s[x] for x in s if x not in ("kind",)}, "allowed": bool(d), "code": d.code, "reason": d.reason,
                     "estimated_requests": n, "impact": impact})
    problems: list[str] = []
    if len(hosts) > limits["max_hosts_per_run"]:
        problems.append(f"{len(hosts)} different hosts in one plan; the limit is {limits['max_hosts_per_run']} per run")
    if total_requests > limits["max_requests"]:
        problems.append(f"the plan would make about {total_requests} requests; the limit is {limits['max_requests']}")
    if offline:
        problems.append("offline mode is on: remote checks are blocked (the plan can still be reviewed)")
    if not live:
        problems.append(live.reason)
    ok = all(r["allowed"] for r in rows) and not problems
    return {"ok": ok, "steps": rows, "problems": problems, "estimated_requests": total_requests, "limits": limits, "hosts": sorted(hosts),
            "impact": "medium" if any(r["impact"] == "medium" for r in rows) else "low", "tools": tools_needed,
            "plan_hash": plan_hash(auth.id, policy.scope_snapshot(auth), steps, limits, tools_needed), "normalized_steps": steps,
            "scope_snapshot_hash": policy.scope_snapshot(auth),
            "disclosure": {"external_services": [], "data_retention": auth.retention_terms or "kept in the case until you delete it",
                           "what_is_sent": "Only the requests listed above, from this machine, with a fixed identifying User-Agent. No cookies, credentials, custom headers or bodies."},
            "evaluated_at": now.isoformat()}
