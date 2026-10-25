"""Typed workflow contract (addendum §5). Workflows are DATA: strict Pydantic models with `extra=forbid`; there is no field that can carry code, a
shell string, SQL or a free URL. Node configs are validated per node type; references (`$inputs.x`, `$nodes.id.output[.field]`) are checked by
`graph_validator`. Anything the model (or a template file) produces is parsed through these classes before it can be stored or run."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = 1
MAX_NODES = 40
ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
KEY_RE = re.compile(r"^[a-z][a-z0-9-]{0,59}$")
REF_RE = re.compile(r"^\$(inputs\.[A-Za-z_][A-Za-z0-9_]{0,39}|nodes\.[a-z][a-z0-9_]{0,39}\.output(\.[a-z_]{1,24})?)$")
TRIGGER_TYPES = ("manual", "schedule", "event", "file")
Ref = Annotated[str, Field(pattern=REF_RE.pattern)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------------------------------------------- node configs
class AuthorizationCheck(Strict):
    target_ref: Ref
    target_type: str | None = Field(default=None, pattern=r"^[a-z_]{2,20}$")
    mode: Literal["passive_only", "active"] = "passive_only"


class AdapterQuery(Strict):
    adapter: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    operation: str = Field(default="query", pattern=r"^[a-z_]{1,24}$")
    target_ref: Ref
    target_type: str | None = Field(default=None, pattern=r"^[a-z_]{2,20}$")


class Enrich(Strict):
    adapter: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    from_ref: Ref
    entity_types: list[Literal["domain", "ip", "email", "url"]] = Field(default=["domain"], min_length=1, max_length=4)
    max_targets: int = Field(default=5, ge=1, le=10)           # bounded fan-out; every discovered target is re-checked against scope before use


class Transform(Strict):
    ref: Ref
    extra_refs: list[Ref] = Field(default_factory=list, max_length=5)     # datasets merged into `ref` first
    op: Literal["merge", "pick_predicates", "exclude_predicates", "min_confidence"] = "merge"
    values: list[str] = Field(default_factory=list, max_length=40)
    min_confidence: Literal["low", "medium", "high"] | None = None


class Deduplicate(Strict):
    ref: Ref
    key: Literal["entity_predicate_value", "entity_predicate"] = "entity_predicate_value"


class Correlate(Strict):
    refs: list[Ref] = Field(min_length=2, max_length=6)
    by: Literal["shared_value"] = "shared_value"


class SnapshotDiff(Strict):
    dataset_ref: Ref
    baseline: Literal["latest_successful"] = "latest_successful"
    ignore_predicates: list[str] = Field(default_factory=list, max_length=40)


class Condition(Strict):
    ref: Ref
    op: Literal["truthy", "eq", "ne", "gt", "ge", "lt", "le"] = "truthy"
    value: int | float | str | bool | None = None


class AnalystReview(Strict):
    prompt: str = Field(min_length=3, max_length=500)
    timeout_hours: int = Field(default=72, ge=1, le=168)


class EvidenceSave(Strict):
    ref: Ref
    title: str = Field(min_length=1, max_length=200)


class Notification(Strict):
    change_ref: Ref | None = None
    channel: Literal["in_app", "local_desktop", "webhook"] = "local_desktop"
    webhook_ref: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{0,39}$")   # a NAME from Settings; URLs never live in workflows
    severity: Literal["info", "warning", "critical"] = "info"
    title: str = Field(min_length=1, max_length=160)
    only_if_changed: bool = True


class Report(Strict):
    profile: Literal["executive", "technical", "evidence_pack", "multi_int"] = "technical"
    format: Literal["html", "markdown", "json", "pdf"] = "html"


class CaseFindings(Strict):
    entity_types: list[str] = Field(default_factory=list, max_length=10)
    predicates: list[str] = Field(default_factory=list, max_length=40)
    limit: int = Field(default=500, ge=1, le=1000)


class SensorHealth(Strict):
    include_simulated: bool = True


class CaseGaps(Strict):
    pass


class AivAuthorizations(Strict):
    """Read-only: lists this case's asset authorizations and whether each is live. It cannot create, widen or use one."""
    only_live: bool = True


class AivObservations(Strict):
    """Read-only: reads stored AIV observations of this case. It cannot start a run, approve a plan or send a request."""
    min_severity: Literal["info", "low", "medium", "high"] = "info"
    exclude_reviewed: list[Literal["confirmed", "false_positive", "accepted_risk"]] = Field(default_factory=list, max_length=3)
    limit: int = Field(default=200, ge=1, le=1000)


class DarkintCheck(Strict):
    """Runs the checks of ONE monitor configuration (providers, identifiers, expiry and authorization live in the monitor, never in the workflow)."""
    monitor_ref: Ref


class DarkintEvents(Strict):
    """Read-only: reported exposure events already stored for this case (redacted titles and categories only)."""
    exclude_dismissed: bool = True
    event_types: list[Literal["breach", "paste", "darkweb_mention", "ransomware_listing", "advisory", "manual_report"]] = Field(default_factory=list, max_length=6)
    limit: int = Field(default=200, ge=1, le=1000)


DarkAction = Literal["mfa", "password_reset", "domain_hygiene", "takedown", "notify", "follow_up_check"]


def _default_actions() -> list[DarkAction]:
    return ["password_reset", "mfa", "follow_up_check"]


class DarkintRemediation(Strict):
    """Creates remediation TASKS for reported events that have none. Never sends a message or submits a takedown."""
    actions: list[DarkAction] = Field(default_factory=_default_actions, min_length=1, max_length=6)
    max_tasks: int = Field(default=20, ge=1, le=50)


class Delay(Strict):
    seconds: int = Field(ge=1, le=300)


class FileIngest(Strict):
    evidence_ref: Ref | None = None
    kind: str = Field(default="auto", pattern=r"^[a-z_0-9]{2,24}$")


class ErrorHandler(Strict):
    action: Literal["notify"] = "notify"
    title: str = Field(default="Automation failed", min_length=1, max_length=160)


CONFIGS: dict[str, type[Strict]] = {
    "authorization_check": AuthorizationCheck, "adapter_query": AdapterQuery, "enrich": Enrich, "transform": Transform,
    "deduplicate": Deduplicate, "correlate": Correlate, "snapshot_diff": SnapshotDiff, "condition": Condition,
    "analyst_review": AnalystReview, "evidence_save": EvidenceSave, "notification": Notification, "report": Report,
    "case_findings": CaseFindings, "sensor_health": SensorHealth, "case_gaps": CaseGaps, "aiv_authorizations": AivAuthorizations, "aiv_observations": AivObservations,
    "darkint_check": DarkintCheck, "darkint_events": DarkintEvents, "darkint_remediation": DarkintRemediation,
    "delay": Delay, "file_ingest": FileIngest, "error_handler": ErrorHandler,
}
NodeType = Literal["authorization_check", "adapter_query", "enrich", "transform", "deduplicate", "correlate", "snapshot_diff", "condition",
                   "analyst_review", "evidence_save", "notification", "report", "delay", "file_ingest", "error_handler", "case_findings", "sensor_health", "case_gaps",
                   "aiv_authorizations", "aiv_observations", "darkint_check", "darkint_events", "darkint_remediation"]


# ---------------------------------------------------------------------------------------------------------------- the definition
class When(Strict):
    ref: Ref
    op: Literal["truthy", "eq", "ne", "gt", "ge", "lt", "le"] = "truthy"
    value: int | float | str | bool | None = None


class Node(Strict):
    id: str
    type: NodeType
    depends_on: list[str] = Field(default_factory=list, max_length=8)
    config: dict[str, Any] = Field(default_factory=dict)
    when: When | None = None
    run_on: Literal["success", "failure", "always"] = "success"
    optional: bool = False                    # a failing optional node is a warning, not a failed run
    label: str | None = Field(default=None, max_length=80)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not ID_RE.match(v):
            raise ValueError("id must match [a-z][a-z0-9_]{0,39}")
        return v


class Trigger(Strict):
    type: Literal["manual", "schedule", "event", "file"] = "manual"
    schedule: str | None = Field(default=None, max_length=80)           # 5-field cron, evaluated in `timezone`
    timezone: str = Field(default="UTC", max_length=64)                # IANA name
    enabled: bool = False                                              # templates and imports are ALWAYS disabled; activation is a separate approved action
    missed_run_policy: Literal["skip", "coalesce", "catch_up"] = "coalesce"
    event: Literal["new_finding"] | None = None


class Policy(Strict):
    network_mode: Literal["passive_only", "active_with_approval"] = "passive_only"
    max_requests_per_provider_per_run: int = Field(default=50, ge=1, le=500)
    max_duration_seconds: int = Field(default=600, ge=10, le=3600)
    max_concurrent_nodes: int = Field(default=2, ge=1, le=4)
    reentrancy: Literal["skip", "queue", "coalesce"] = "skip"


class ErrorPolicy(Strict):
    transient_retries: int = Field(default=2, ge=0, le=5)
    backoff: Literal["exponential_jitter"] = "exponential_jitter"
    fail_closed_on_scope_error: Literal[True] = True                   # cannot be switched off


class Definition(Strict):
    schema_version: Literal[1] = 1
    workflow_key: str
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    owner_scope: Literal["investigation", "global"] = "investigation"
    status: Literal["draft"] = "draft"
    tags: list[str] = Field(default_factory=list, max_length=12)
    trigger: Trigger = Field(default_factory=Trigger)
    inputs: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    policy: Policy = Field(default_factory=Policy)
    nodes: list[Node] = Field(min_length=1, max_length=MAX_NODES)
    error_policy: ErrorPolicy = Field(default_factory=ErrorPolicy)

    @field_validator("workflow_key")
    @classmethod
    def _key(cls, v: str) -> str:
        if not KEY_RE.match(v):
            raise ValueError("workflow_key must match [a-z][a-z0-9-]{0,59}")
        return v


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def content_hash(defn: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(defn).encode()).hexdigest()


def json_schema() -> dict[str, Any]:
    """JSON Schema of the definition (exported for the typed frontend client and for the AI builder prompt)."""
    s = Definition.model_json_schema()
    s["x-node-configs"] = {k: v.model_json_schema() for k, v in CONFIGS.items()}
    return s
