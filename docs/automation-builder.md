# AI Automation Builder & Workflow Library

Implements addendum A1.0 on top of the existing application (adapters, policy, job runner, AI providers, Copilot, evidence, reports, backup). Nothing was rebuilt:
the older `workflows` module (interval schedules, adapter/summarize/diff nodes) is untouched and still works; the new engine lives in `backend/osintcc/automations/`.

## What you can do

* **Library**: 42 bundled templates (CY-01..07, ID-01..06, CO-01..05, GEO-01..06, CASE-01..06, and TP-01..12 for the Target Profile workstation). Each shows purpose, sources, availability, quota, legal notes, example output and known gaps. Installed **disabled**.
* **AI builder**: describe a goal; get a *typed draft* checked by a deterministic validator. A local model is used by default; with none, the closest template is offered and labelled. The manual editor always works.
* **Canvas**: pan/zoom, minimap, keyboard arrows, inspector, validation markers, run overlay. A view of the definition only: positions are derived, so visual edits cannot change meaning.
* **Lifecycle**: draft -> validate -> dry-run (simulated) -> **publish** (immutable numbered version) -> **request approval** (bound to that exact version, with an expiry) -> **activate** (schedule) / run by hand.
* **Console**: runs, step timeline with attempts, input digests, source URLs, evidence counts, the version used, stop / retry safe failures / review / diagnose / compare.
* **Inbox**: notifications (merged, quiet hours, digest), opt-in suggestions, approvals waiting.

## Safety model (enforced in code, not by the model)

| Rule | Where |
|---|---|
| Workflows are data: strict models, `extra=forbid`; no script, shell, SQL, free URL or credential field exists | `automations/models.py`; `service.normalise` also validates every node's config before storing |
| Every network step needs an upstream scope check for the same target; scope is **re-checked before each network call at run time**, including every target discovered during a run | `graph_validator.py`, `permissions.check_target`, `handlers.enrich` |
| Private, local, malformed or unauthorised targets fail closed and are never retried; redirects, discovered subdomains and DNS rebinding arrive as new targets | `permissions.py`, SSRF guard |
| Drafts, templates and imports never schedule themselves; a schedule needs an approved, unexpired approval for that exact version | `service.activate`, `permissions.run_gate`, scheduler |
| Active or many-site collection needs a separate collection approval tied to a current scope authorization and never outlives it | `service.decide_approval` |
| Changing an active workflow makes a new version that needs its own approval; old versions are immutable (content hash) | `service.publish` |
| Per-run request budget per provider; no key or provider rotation | `handlers._charge` |
| Retries only for transient classes, bounded, exponential backoff with jitter; policy/scope/credential errors are never retried | `executor._run_with_retries` |
| Crash recovery: checkpoints are reused; only replay-safe steps re-run; others pause for a person; notifications and evidence are idempotent | `executor.recover` |
| Cancellation stops the in-flight source job (adapter process trees are killed by the runner) | `runner.abort_run` |
| Cloud models receive nothing from automations unless that profile is opted in; they get goals and the capability registry, never evidence | `ai.propose` |
| Secrets are never in definitions, exports or logs; webhook addresses live in Settings and workflows reference only a name | `models.py`, `settings.py` |
| Suggestions: off by default, application events only, personal investigations excluded unless opted in, never turn anything on | `suggestions.py` |
| Hardware: the engine can only read the status of registered (simulated/replay/owned) devices; it never transmits | `handlers.sensor_health` |

## Scheduling

5-field cron in an IANA time zone (UTC by default; choose yours, e.g. `America/New_York`). Instants are stored in UTC. A local time that does not exist (spring forward) runs once, at the first valid instant after the gap; a repeated time (fall back) runs once. Never more often than every 15 minutes. **Schedules run only while this application is running**; after downtime each trigger's policy decides: `skip`, `coalesce` (default: one catch-up run) or `catch_up` (max 10). Offline mode skips network triggers instead of piling runs up.

## Honest limits

* Email notifications and inbound webhook triggers are not implemented. Desktop notices appear while the app is open.
* Templates marked *partial* have documented gaps (for example CVE Intelligence has no advisory feed; Imagery Change Review has no automatic image comparison; Sensor Health reads registration status of simulated/replay devices only, no physical receiver was tested).
* Only CY-01, ID-05 and CASE-01 were run end to end through the real engine in tests (network mocked); live results are in `docs/progress.md`. All 42 pass their fixture dry runs.
* The AI builder was exercised with one local model (see `scripts/automation_live_check.py`); small models sometimes need the bounded correction loop or fall back to a template.
* Keyed sources (VirusTotal, urlscan, Shodan, Censys, OpenCorporates) and Sherlock/Maigret/Subfinder/Amass are only used when installed/configured; otherwise the template says *setup required* and a run fails with a clear code instead of faking output.

## API (`/api/v1/automations`; the addendum's `/api/automations` uses the project's existing `/api/v1` prefix)

`GET templates`, `GET templates/{slug}`, `POST from-template`, `GET|POST workflows`, `GET|PATCH|DELETE workflows/{id}` (ETag / `If-Match`), `POST workflows/{id}/validate | dry-run | publish | request-approval | activate | deactivate | run | run-file | repair`, `GET workflows/{id}/export`, `POST import`, `POST workflows/{id}/versions/{rev}/clone`, `GET approvals`, `POST approvals/{id}/decide | revoke`, `GET scope-authorizations`, `GET runs`, `GET runs/{id}`, `POST runs/{id}/cancel | retry | review`, `GET runs/{id}/compare/{other}`, `GET runs/{id}/events` (SSE), `GET workflows/{id}/runs`, `POST ai/propose | explain | diagnose`, `GET suggestions`, `POST suggestions/{id}/dismiss | snooze`, `GET notifications`, `PATCH notifications/{id}`, `GET|PATCH settings`, `GET node-types | schema | capabilities`. Error codes: `UNSUPPORTED_ADAPTER, INVALID_GRAPH, SCOPE_EXPIRED, APPROVAL_REQUIRED, RATE_LIMITED, CREDENTIAL_MISSING, SOURCE_UNAVAILABLE, TIMEOUT, RUN_CANCELLED, PARTIAL_RESULT` (plus `SCOPE_DENIED, OFFLINE, UPSTREAM_FAILED, INTERRUPTED, PRECONDITION_FAILED`). OpenAPI is in `docs/api.md` / `docs/openapi.json`; the JSON Schema of a workflow is at `GET /automations/schema`.

## Data (migration `0011`)

`automation_workflows, automation_versions, automation_triggers, automation_approvals, automation_runs, automation_node_runs, automation_snapshots, automation_notifications, automation_suggestions`. The addendum's `automation_templates` is a set of checksummed files (no duplicate table), and `automation_audit` reuses the existing hash-chained audit log (`automation.*` events). Deleting a case removes its workflows, runs, snapshots (foreign-key cascade). Backups carry all of it; restoring needs the backup passphrase and writes into a new folder.

## Tests and evidence

`docs/test-results.md` (generated) maps every AUT-01..24 criterion to its tests. `docs/automation-capabilities.md` (generated) is the capability matrix. Browser tests: `apps/web/e2e/automations.spec.ts` (keyboard canvas, approvals flow, axe in light and dark).
