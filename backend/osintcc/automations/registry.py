"""Node registry: the ONLY place that says what a node type is, what it accepts and produces, and what it can touch.
A node type exists in the UI, the validator and the AI prompt only if it is registered here AND has a runtime handler in `handlers.py`
(a test enforces both directions), so no node can claim a capability that cannot run."""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

# output "types" that references are checked against
FINDINGS, SCOPE, LINKS, DIFF, BOOL, REVIEW, EVIDENCE, NOTE, REPORT, NONE, FILE = (
    "findings", "scope", "links", "diff", "bool", "review", "evidence", "notification", "report", "none", "evidence_file")

# which fields can be read from each output type via `$nodes.x.output.<field>`
OUT_FIELDS: dict[str, tuple[str, ...]] = {
    FINDINGS: ("count",), SCOPE: ("target", "allowed"), LINKS: ("count",), DIFF: ("changed", "added", "removed", "changed_count", "uncertain", "count"),
    BOOL: ("value",), REVIEW: ("approved",), EVIDENCE: ("evidence_id",), NOTE: ("sent",), REPORT: ("report_id",), NONE: (), FILE: ("evidence_id", "kind", "count", "duplicate", "sha256"),
}


@dataclass(frozen=True)
class NodeSpec:
    type: str
    title: str
    description: str
    out_type: str
    side_effects: str                 # none | read_network | write_local | external
    risk: str                         # low | medium | high
    # config field -> output types it may reference ("input" means $inputs.*)
    ref_types: dict[str, tuple[str, ...]] = field(default_factory=dict)
    network: bool = False
    replay_safe: bool = True          # may be re-run automatically after a crash
    fields: tuple[dict[str, Any], ...] = ()   # editor hints for the inspector


SPECS: dict[str, NodeSpec] = {s.type: s for s in [
    NodeSpec("authorization_check", "Scope check", "Resolves the target against policy and fails closed if it is private, unauthorised or out of scope.", SCOPE,
             "none", "low", {"target_ref": ("input",)},
             fields=({"name": "target_ref", "kind": "ref"}, {"name": "mode", "kind": "enum", "options": ["passive_only", "active"]})),
    NodeSpec("adapter_query", "Source query", "Runs ONE registered source adapter against the checked target through the normal search machinery (policy applied again).", FINDINGS,
             "read_network", "medium", {"target_ref": ("input", SCOPE)}, network=True,
             fields=({"name": "adapter", "kind": "adapter"}, {"name": "target_ref", "kind": "ref"}, {"name": "target_type", "kind": "text"})),
    NodeSpec("enrich", "Enrich discovered targets", "Runs one adapter on targets discovered upstream (bounded, each re-checked against scope before use).", FINDINGS,
             "read_network", "medium", {"from_ref": (FINDINGS,)}, network=True,
             fields=({"name": "adapter", "kind": "adapter"}, {"name": "from_ref", "kind": "ref"}, {"name": "max_targets", "kind": "int", "min": 1, "max": 10})),
    NodeSpec("transform", "Transform / merge", "Merges datasets and/or filters findings by predicate or confidence. Pure and local.", FINDINGS, "none", "low", {"ref": (FINDINGS,), "extra_refs": (FINDINGS,)},
             fields=({"name": "ref", "kind": "ref"}, {"name": "extra_refs", "kind": "list"}, {"name": "op", "kind": "enum", "options": ["merge", "pick_predicates", "exclude_predicates", "min_confidence"]},
                     {"name": "values", "kind": "list"}, {"name": "min_confidence", "kind": "enum", "options": ["low", "medium", "high"]})),
    NodeSpec("case_findings", "Read case findings", "Reads findings already stored in this case (local; restricted items are never included).", FINDINGS, "none", "low", {},
             fields=({"name": "entity_types", "kind": "list"}, {"name": "predicates", "kind": "list"}, {"name": "limit", "kind": "int", "min": 1, "max": 1000})),
    NodeSpec("sensor_health", "Read sensor health", "Reads the status of devices registered in the Hardware module (simulated, replay or owned receivers). Never transmits.", FINDINGS, "none", "low", {},
             fields=({"name": "include_simulated", "kind": "bool"},)),
    NodeSpec("case_gaps", "Read intelligence gaps", "Lists open requirements and unverified claims of this case as items.", FINDINGS, "none", "low", {}, fields=()),
    NodeSpec("aiv_authorizations", "Read asset authorizations", "Lists this case's asset authorizations and whether each is live (AIV). Read only: it cannot create, widen or use one, and sends nothing.", FINDINGS,
             "none", "low", {}, fields=({"name": "only_live", "kind": "bool"},)),
    NodeSpec("aiv_observations", "Read verification observations", "Reads stored AIV observations of this case. Read only: it cannot start a run, approve a plan or send any request. Active checks are run from the Verification workspace after a person approves an exact plan.", FINDINGS,
             "none", "low", {}, fields=({"name": "min_severity", "kind": "enum", "options": ["info", "low", "medium", "high"]}, {"name": "exclude_reviewed", "kind": "list"}, {"name": "limit", "kind": "int", "min": 1, "max": 1000})),
    NodeSpec("darkint_check", "Run exposure monitor checks", "Runs the provider checks of one DARKINT monitor. Every lookup passes the same consent, provider and domain-control gates as a manual check; a revoked or expired authorization stops it. Returns redacted events only.", FINDINGS,
             "read_network", "high", {"monitor_ref": ("input",)}, network=True, replay_safe=False, fields=({"name": "monitor_ref", "kind": "ref"},)),
    NodeSpec("darkint_events", "Read reported exposure events", "Reads exposure events already stored for this case: redacted titles, data categories, provider and dates. Read only.", FINDINGS, "none", "low", {},
             fields=({"name": "exclude_dismissed", "kind": "bool"}, {"name": "event_types", "kind": "list"}, {"name": "limit", "kind": "int", "min": 1, "max": 1000})),
    NodeSpec("darkint_remediation", "Create remediation tasks", "Creates remediation tasks (MFA, password reset, domain hygiene, takedown, notification, follow-up check) for reported events that have none. Sends nothing and submits nothing.", FINDINGS,
             "write_local", "low", {}, replay_safe=False, fields=({"name": "actions", "kind": "list"}, {"name": "max_tasks", "kind": "int", "min": 1, "max": 50})),
    NodeSpec("deduplicate", "Deduplicate", "Removes repeated findings by a stable key. Pure and local.", FINDINGS, "none", "low", {"ref": (FINDINGS,)},
             fields=({"name": "ref", "kind": "ref"}, {"name": "key", "kind": "enum", "options": ["entity_predicate_value", "entity_predicate"]})),
    NodeSpec("correlate", "Correlate", "Suggests links between datasets that share a value. Suggestions only: nothing is merged.", LINKS, "none", "low", {"refs": (FINDINGS,)},
             fields=({"name": "refs", "kind": "list"},)),
    NodeSpec("snapshot_diff", "Compare with previous run", "Compares a dataset with the last successful baseline: new, removed, changed and uncertain.", DIFF, "write_local", "low",
             {"dataset_ref": (FINDINGS,)}, fields=({"name": "dataset_ref", "kind": "ref"}, {"name": "ignore_predicates", "kind": "list"})),
    NodeSpec("condition", "Condition", "Evaluates a comparison; downstream nodes may depend on it through `when`.", BOOL, "none", "low", {"ref": ("input", DIFF, FINDINGS, BOOL, LINKS, FILE)},
             fields=({"name": "ref", "kind": "ref"}, {"name": "op", "kind": "enum", "options": ["truthy", "eq", "ne", "gt", "ge", "lt", "le"]}, {"name": "value", "kind": "text"})),
    NodeSpec("analyst_review", "Analyst review", "Pauses the run until a person approves or rejects.", REVIEW, "none", "low", {},
             fields=({"name": "prompt", "kind": "text"}, {"name": "timeout_hours", "kind": "int", "min": 1, "max": 168})),
    NodeSpec("evidence_save", "Save as evidence", "Stores a dataset as a hashed evidence item in the case.", EVIDENCE, "write_local", "low", {"ref": (FINDINGS, LINKS, DIFF, FILE)}, replay_safe=False,
             fields=({"name": "ref", "kind": "ref"}, {"name": "title", "kind": "text"})),
    NodeSpec("notification", "Notify", "Raises an in-app/desktop notification (or a webhook to a destination approved in Settings), de-duplicated.", NOTE, "external", "low",
             {"change_ref": (DIFF, BOOL, FINDINGS)}, replay_safe=False,
             fields=({"name": "title", "kind": "text"}, {"name": "change_ref", "kind": "ref"}, {"name": "channel", "kind": "enum", "options": ["in_app", "local_desktop", "webhook"]},
                     {"name": "severity", "kind": "enum", "options": ["info", "warning", "critical"]}, {"name": "only_if_changed", "kind": "bool"})),
    NodeSpec("report", "Generate report", "Writes an encrypted case report (restricted material withheld).", REPORT, "write_local", "low", {}, replay_safe=False,
             fields=({"name": "profile", "kind": "enum", "options": ["executive", "technical", "evidence_pack", "multi_int"]}, {"name": "format", "kind": "enum", "options": ["html", "markdown", "json", "pdf"]})),
    NodeSpec("delay", "Delay", "Waits a bounded time (at most 5 minutes).", NONE, "none", "low", {}, fields=({"name": "seconds", "kind": "int", "min": 1, "max": 300},)),
    NodeSpec("file_ingest", "Process file", "Parses a user-supplied file offline, stores it hashed, extracts observations and classifies it.", FILE, "write_local", "low", {"evidence_ref": ("input",)},
             fields=({"name": "evidence_ref", "kind": "ref"}, {"name": "kind", "kind": "text"})),
    NodeSpec("error_handler", "On failure", "Runs only when another step failed; raises a notification.", NOTE, "external", "low", {}, replay_safe=False,
             fields=({"name": "title", "kind": "text"},)),
]}


class NodeError(Exception):
    """A node failed in a way the engine understands. `retryable` marks transient classes only (never policy, scope or credential errors)."""

    def __init__(self, code: str, message: str, retryable: bool = False, details: dict[str, Any] | None = None, retry_after: float | None = None):
        super().__init__(message)
        self.code, self.message, self.retryable, self.details, self.retry_after = code, message, retryable, details or {}, retry_after


Handler = Callable[[Any], Awaitable[Any]]
HANDLERS: dict[str, Handler] = {}


def handler(node_type: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        HANDLERS[node_type] = fn
        return fn
    return deco


TRANSIENT = frozenset({"TIMEOUT", "SOURCE_UNAVAILABLE_TRANSIENT", "RATE_LIMITED"})
ERROR_CODES = ("UNSUPPORTED_ADAPTER", "INVALID_GRAPH", "SCOPE_EXPIRED", "APPROVAL_REQUIRED", "RATE_LIMITED", "CREDENTIAL_MISSING", "SOURCE_UNAVAILABLE",
               "TIMEOUT", "RUN_CANCELLED", "PARTIAL_RESULT", "SCOPE_DENIED", "OFFLINE", "UPSTREAM_FAILED", "INTERRUPTED", "INTERNAL", "UNSUPPORTED")
