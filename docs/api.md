# HTTP API reference

Generated from the application's OpenAPI document by `scripts/gen_docs.py` (the full machine-readable file is `docs/openapi.json`; a running backend also serves it at `/api/openapi.json` and interactive docs at `/api/docs`).

**Conventions**

- Loopback only (`127.0.0.1`). Every request needs `Authorization: Bearer <per-launch token>`; the desktop shell receives the token over a private stdout handshake. A browser origin must be on the allow-list.
- Errors use one envelope: `{code, message, request_id, retryable, details_safe}`.
- Case-scoped routes check case membership; global routes (settings, plugins, AI profiles, vault, updates, backup) need the admin role.
- Time values are ISO-8601 UTC. Nothing returned is a conclusion: findings, claims and suggestions carry confidence labels and evidence ids.

231 operations in 37 groups.

## ai

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/ai/action/preview` | Deterministic permission/cost preview of an AI-proposed action. It never starts anything. |
| POST | `/api/v1/ai/ask` | Ask |
| POST | `/api/v1/ai/preflight` | Reports readiness without sending any case content. |
| GET | `/api/v1/ai/profiles` | List Profiles |
| POST | `/api/v1/ai/profiles` | Create Profile |
| DELETE | `/api/v1/ai/profiles/{pid}` | Delete Profile |

## alerts

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/alerts/{aid}/acknowledge` | Ack Alert |

## authorizations

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/authorizations/{auth_id}/revoke` | Revoke Auth |

## automations

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/automations/ai/diagnose` | Ai Diagnose |
| POST | `/api/v1/automations/ai/explain` | Ai Explain |
| POST | `/api/v1/automations/ai/propose` | Ai Propose |
| GET | `/api/v1/automations/approvals` | Approvals |
| POST | `/api/v1/automations/approvals/{aid}/decide` | Decide |
| POST | `/api/v1/automations/approvals/{aid}/revoke` | Revoke |
| GET | `/api/v1/automations/capabilities` | Capabilities |
| POST | `/api/v1/automations/from-template` | From Template |
| POST | `/api/v1/automations/import` | Import Wf |
| GET | `/api/v1/automations/node-types` | Node Types |
| GET | `/api/v1/automations/notifications` | Notifications |
| PATCH | `/api/v1/automations/notifications/{nid}` | Patch Note |
| GET | `/api/v1/automations/runs` | List Runs |
| GET | `/api/v1/automations/runs/{rid}` | Get Run |
| POST | `/api/v1/automations/runs/{rid}/cancel` | Cancel |
| GET | `/api/v1/automations/runs/{rid}/compare/{other}` | Compare Runs |
| GET | `/api/v1/automations/runs/{rid}/events` | Server-sent events: node records as they appear, then the final state. |
| POST | `/api/v1/automations/runs/{rid}/retry` | Retry |
| POST | `/api/v1/automations/runs/{rid}/review` | Review |
| GET | `/api/v1/automations/schema` | Schema |
| GET | `/api/v1/automations/scope-authorizations` | Scope Auths |
| GET | `/api/v1/automations/settings` | Get Settings |
| PATCH | `/api/v1/automations/settings` | Patch Settings |
| GET | `/api/v1/automations/suggestions` | Suggestions |
| POST | `/api/v1/automations/suggestions/{sid}/dismiss` | Dismiss |
| POST | `/api/v1/automations/suggestions/{sid}/snooze` | Snooze |
| GET | `/api/v1/automations/templates` | Templates |
| GET | `/api/v1/automations/templates/{slug}` | Template |
| GET | `/api/v1/automations/workflows` | List Wf |
| POST | `/api/v1/automations/workflows` | Create Wf |
| DELETE | `/api/v1/automations/workflows/{wid}` | Delete Wf |
| GET | `/api/v1/automations/workflows/{wid}` | Get Wf |
| PATCH | `/api/v1/automations/workflows/{wid}` | Patch Wf |
| POST | `/api/v1/automations/workflows/{wid}/activate` | Activate |
| POST | `/api/v1/automations/workflows/{wid}/deactivate` | Deactivate |
| POST | `/api/v1/automations/workflows/{wid}/dry-run` | Runs the DRAFT against the template's fixture: no network, no writes. Every output is labelled simulated. |
| GET | `/api/v1/automations/workflows/{wid}/export` | Export Wf |
| POST | `/api/v1/automations/workflows/{wid}/publish` | Publish |
| POST | `/api/v1/automations/workflows/{wid}/repair` | Apply diagnostic repair proposals to the DRAFT (never to a published version). Returns the diff and validation; publishing stays yours. |
| POST | `/api/v1/automations/workflows/{wid}/request-approval` | Request Approval |
| POST | `/api/v1/automations/workflows/{wid}/run` | Run Wf |
| POST | `/api/v1/automations/workflows/{wid}/run-file` | File-triggered workflows: the file is parsed offline and stored like an import, then the workflow runs on it. |
| GET | `/api/v1/automations/workflows/{wid}/runs` | Wf Runs |
| POST | `/api/v1/automations/workflows/{wid}/validate` | Validate Wf |
| POST | `/api/v1/automations/workflows/{wid}/versions/{rev}/clone` | Clone Version |

## backups

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/backups` | Make Backup |
| POST | `/api/v1/backups/restore` | Restore |
| POST | `/api/v1/backups/restore/preview` | Restore Preview |
| POST | `/api/v1/backups/verify` | Verify Backup |

## captures

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/captures` | List Captures |
| POST | `/api/v1/captures` | Start Capture |
| GET | `/api/v1/captures/active` | The session indicator: anything still recording, visible from anywhere in the UI. |
| POST | `/api/v1/captures/replay` | `import_capture` via the replay driver: bring an existing recording in through the device pipeline (raw body). |
| POST | `/api/v1/captures/{sid}/stop` | Stop Capture |

## cases

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/cases` | List Cases |
| POST | `/api/v1/cases` | Create Case |
| GET | `/api/v1/cases/{case_id}` | Get Case |
| PATCH | `/api/v1/cases/{case_id}` | Patch Case |

## cases (case-scoped)

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/cases/{case_id}/ai-policy` | Get Policy |
| PUT | `/api/v1/cases/{case_id}/ai-policy` | Put Policy |
| GET | `/api/v1/cases/{case_id}/alerts` | List Alerts |
| POST | `/api/v1/cases/{case_id}/archive` | Archive Case |
| POST | `/api/v1/cases/{case_id}/authorizations` | Add Auth |
| GET | `/api/v1/cases/{case_id}/contradictions` | Get Contradictions |
| GET | `/api/v1/cases/{case_id}/cross-links` | Cross Links |
| POST | `/api/v1/cases/{case_id}/cross-links/decision` | Decide |
| GET | `/api/v1/cases/{case_id}/entities` | Entities |
| GET | `/api/v1/cases/{case_id}/entity-links` | List Links |
| POST | `/api/v1/cases/{case_id}/entity-links` | Logical merge for views/analysis only. Underlying entities, claims and evidence are never altered. |
| GET | `/api/v1/cases/{case_id}/evidence` | List Evidence |
| POST | `/api/v1/cases/{case_id}/evidence/import` | Import Evidence |
| GET | `/api/v1/cases/{case_id}/export/stix` | Export Stix |
| GET | `/api/v1/cases/{case_id}/findings` | Findings |
| GET | `/api/v1/cases/{case_id}/gaps` | Get Gaps |
| POST | `/api/v1/cases/{case_id}/geo/change` | Geo Change |
| GET | `/api/v1/cases/{case_id}/geo/layers` | Geo Layers |
| GET | `/api/v1/cases/{case_id}/geo/points` | Points for the map. Each carries its accuracy statement; 'unknown' is shown, never invented. |
| GET | `/api/v1/cases/{case_id}/graph` | Graph |
| POST | `/api/v1/cases/{case_id}/graph/proposals` | Create Proposal |
| POST | `/api/v1/cases/{case_id}/graph/proposals/{pid}/decision` | Accepting never merges entities: it records a manual, evidence-backed `same_as` assertion that is reversible. |
| GET | `/api/v1/cases/{case_id}/human-sources` | List Sources |
| POST | `/api/v1/cases/{case_id}/human-sources` | Create Source |
| GET | `/api/v1/cases/{case_id}/humint/corroboration` | Claims touched by human sources, with how many independent source groups back each. Single-source claims are |
| POST | `/api/v1/cases/{case_id}/ingest` | Import-only: parse first, store second. A malformed file is rejected (422) and nothing is written. |
| POST | `/api/v1/cases/{case_id}/members` | Add Member |
| GET | `/api/v1/cases/{case_id}/notes` | Get Notes |
| POST | `/api/v1/cases/{case_id}/notes` | Add Note |
| GET | `/api/v1/cases/{case_id}/observations` | Observations |
| POST | `/api/v1/cases/{case_id}/purge` | Purge Case |
| GET | `/api/v1/cases/{case_id}/purge/preview` | Purge Preview |
| POST | `/api/v1/cases/{case_id}/relationships/{rel_id}/reject` | Reversible: rejection only flips status; the row and its evidence stay. |
| POST | `/api/v1/cases/{case_id}/reports` | Make Report |
| POST | `/api/v1/cases/{case_id}/reports/multi-int` | Multi Int Report |
| POST | `/api/v1/cases/{case_id}/reports/preview` | What an export would contain and withhold, shown BEFORE anything is written (spec 13). |
| GET | `/api/v1/cases/{case_id}/requirements` | Get Reqs |
| POST | `/api/v1/cases/{case_id}/requirements` | Add Req |
| GET | `/api/v1/cases/{case_id}/runs` | List Runs |
| POST | `/api/v1/cases/{case_id}/sanctions/screen` | Name-similarity SUGGESTIONS only: each hit becomes a pending graph proposal for the analyst. Nothing is merged |
| GET | `/api/v1/cases/{case_id}/search` | Full-text search (SQLite FTS5) across findings, notes, evidence titles and observations of ONE case. |
| POST | `/api/v1/cases/{case_id}/searches` | Search Launch |
| POST | `/api/v1/cases/{case_id}/searches/preview` | Search Preview |
| POST | `/api/v1/cases/{case_id}/sensor/series/analyze` | Sensor Series |
| POST | `/api/v1/cases/{case_id}/signal/spectrogram` | Offline: recompute the spectrum of a stored SigMF archive with bounded FFT parameters. Stores nothing. |
| GET | `/api/v1/cases/{case_id}/subjects` | For a people case this lazily upgrades an existing case (idempotent, read-only on old tables) and returns its subject(s). |
| POST | `/api/v1/cases/{case_id}/subjects` | Create Subject |
| GET | `/api/v1/cases/{case_id}/targets` | List Targets |
| GET | `/api/v1/cases/{case_id}/timeline` | Three distinct times per item; `time_unknown` is explicit rather than silently substituted. |
| GET | `/api/v1/cases/{case_id}/timeline/unified` | Unified |

## claims

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/claims` | List Claims |
| POST | `/api/v1/claims` | Create Claim |
| POST | `/api/v1/claims/from-finding` | Promote an adapter finding to an analyst-owned claim. The adapter becomes the source group. |
| GET | `/api/v1/claims/{claim_id}/provenance` | claim -> sources -> evidence -> acquisition record, so every statement can be traced to a hashed artifact. |
| POST | `/api/v1/claims/{claim_id}/sources` | Add Claim Source |
| POST | `/api/v1/claims/{claim_id}/verification` | Only an analyst can mark a claim verified; models and adapters cannot. Reversible (set back to unverified). |

## collection-plans

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/collection-plans` | Plan Create |
| POST | `/api/v1/collection-plans/preview` | Plan Preview |
| GET | `/api/v1/collection-plans/{pid}` | Plan Get |
| POST | `/api/v1/collection-plans/{pid}/approve` | Plan Approve |
| POST | `/api/v1/collection-plans/{pid}/cancel` | Plan Cancel |

## copilot

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/copilot/chat` | Chat |
| GET | `/api/v1/copilot/conversation` | The conversation for this investigation (or the general one) with its messages and proposals. Damaged rows are skipped and counted. |
| GET | `/api/v1/copilot/conversations` | Conversations |
| POST | `/api/v1/copilot/conversations` | New Conversation |
| DELETE | `/api/v1/copilot/conversations/{cid}` | Delete Conversation |
| GET | `/api/v1/copilot/docs/search` | Docs Search |
| GET | `/api/v1/copilot/docs/{chunk_id}` | Docs Get |
| POST | `/api/v1/copilot/next-steps` | Prioritised recommendations computed from the case's stored data. Deterministic: works with no model. |
| POST | `/api/v1/copilot/proposals/{pid}/approve` | Approve |
| POST | `/api/v1/copilot/proposals/{pid}/reject` | Reject |
| PUT | `/api/v1/copilot/settings` | Put Settings |
| GET | `/api/v1/copilot/status` | Status |
| GET | `/api/v1/copilot/suggestions` | Suggestions |
| GET | `/api/v1/copilot/tutorials` | Tutorials |
| GET | `/api/v1/copilot/tutorials/{tid}` | Tutorial |

## correlations

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/correlations/{cid}/revoke` | Revoke |

## devices

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/devices` | Devices |
| GET | `/api/v1/devices/{did}/capabilities` | Capabilities |
| POST | `/api/v1/devices/{did}/disconnect` | Disconnect |

## disciplines

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/disciplines` | Disciplines |

## entity-links

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/entity-links/{lid}/revert` | Revert Link |

## evidence

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/evidence/{ev_id}` | Get Evidence |
| GET | `/api/v1/evidence/{ev_id}/download` | Download Evidence |

## fusion

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/fusion/heuristics` | Heuristics |

## hardware

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/hardware/diagnostics` | Non-blocking: every driver reports independently; missing libraries/drivers never affect anything else. |

## health

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/health/live` | Live |
| GET | `/api/v1/health/ready` | Ready |

## human-sources

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/human-sources/{sid}/assessment` | Assess Source |
| POST | `/api/v1/human-sources/{sid}/reports` | Add Report |
| POST | `/api/v1/human-sources/{sid}/revoke` | Withdraws consent immediately. With delete_content the source's reports, derived claims and index entries are |

## hypotheses

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/hypotheses` | List Hypotheses |
| POST | `/api/v1/hypotheses` | Create Hypothesis |
| PATCH | `/api/v1/hypotheses/{hid}` | Set Hypothesis Status |
| POST | `/api/v1/hypotheses/{hid}/claims` | Link Hypothesis Claim |

## mcp

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/mcp/approvals` | List Approvals |
| POST | `/api/v1/mcp/approvals/{aid}/approve` | Approve |
| POST | `/api/v1/mcp/approvals/{aid}/deny` | Deny |

## overview

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/overview` | Overview |

## plugins

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/plugins` | List Plugins |
| POST | `/api/v1/plugins/install` | Install |
| POST | `/api/v1/plugins/{pid}/disable` | Disable |
| POST | `/api/v1/plugins/{pid}/{version}/activate` | Activate |
| POST | `/api/v1/plugins/{pid}/{version}/contract-test` | Contract Test |
| POST | `/api/v1/plugins/{pid}/{version}/enable` | Enable |
| POST | `/api/v1/plugins/{pid}/{version}/uninstall` | Uninstall |

## reports

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/reports/generate` | Spec 23.8 alias of POST /cases/{id}/reports. |
| GET | `/api/v1/reports/{rid}` | Get Report |
| GET | `/api/v1/reports/{rid}/download` | Download Report |

## requirements

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/requirements` | List Requirements |
| POST | `/api/v1/requirements` | Create Requirement |
| PATCH | `/api/v1/requirements/{rid}` | Patch Requirement |
| POST | `/api/v1/requirements/{rid}/evidence` | Link Requirement Evidence |

## schedules

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/schedules` | List Schedules |
| POST | `/api/v1/schedules` | Created DISABLED. Monitoring individuals needs an explicit acknowledgement and a documented case purpose. |
| DELETE | `/api/v1/schedules/{sid}` | Delete Schedule |
| POST | `/api/v1/schedules/{sid}/disable` | Disable Schedule |
| POST | `/api/v1/schedules/{sid}/enable` | Enable Schedule |

## search-runs

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/search-runs/{run_id}` | Get Run |
| POST | `/api/v1/search-runs/{run_id}/cancel` | Cancel Run |
| GET | `/api/v1/search-runs/{run_id}/events` | Run Events |

## secrets

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/secrets` | List Secrets |
| DELETE | `/api/v1/secrets/{provider}` | Delete Secret |
| POST | `/api/v1/secrets/{provider}` | Save Secret |

## settings

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/settings` | Get Settings |
| PUT | `/api/v1/settings` | Put Settings |

## setup

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/setup/complete` | Setup Complete |
| POST | `/api/v1/setup/install` | Setup Install |
| POST | `/api/v1/setup/model` | Setup Model |
| POST | `/api/v1/setup/plan` | Setup Plan |
| GET | `/api/v1/setup/status` | Setup Status |
| GET | `/api/v1/setup/tasks/{task_id}` | Setup Task |

## subjects

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/subjects/{subject_id}` | Get Subject |
| PATCH | `/api/v1/subjects/{subject_id}` | Patch Subject |
| GET | `/api/v1/subjects/{subject_id}/candidates` | List Candidates |
| POST | `/api/v1/subjects/{subject_id}/candidates/bulk-review` | Bulk Review |
| POST | `/api/v1/subjects/{subject_id}/candidates/reverse` | Reverse Review |
| POST | `/api/v1/subjects/{subject_id}/claims` | Add Claim |
| POST | `/api/v1/subjects/{subject_id}/claims/{claim_id}/verify` | Verify Claim |
| GET | `/api/v1/subjects/{subject_id}/consent` | Get Consent |
| POST | `/api/v1/subjects/{subject_id}/consent` | Add Consent |
| POST | `/api/v1/subjects/{subject_id}/consent/revoke` | Revoke Consent |
| GET | `/api/v1/subjects/{subject_id}/identifiers` | List Identifiers |
| POST | `/api/v1/subjects/{subject_id}/identifiers` | Add Identifier |
| DELETE | `/api/v1/subjects/{subject_id}/identifiers/{identifier_id}` | Remove Identifier |
| GET | `/api/v1/subjects/{subject_id}/profile` | Get Profile |
| GET | `/api/v1/subjects/{subject_id}/review-history` | Review History |
| GET | `/api/v1/subjects/{subject_id}/timeline` | Get Timeline |

## system

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/system/database/remove-plaintext-leftovers` | Overwrite-and-delete the plaintext copies left by the one-time encryption migration (and pre-migration .bak files). |
| GET | `/api/v1/system/doctor` | Doctor |
| GET | `/api/v1/system/egress-check` | Result of the start-up self-check: did the app's own processes open outside connections while idle? |
| GET | `/api/v1/system/retention/due` | Lists sources past their retention date. Nothing is deleted automatically. |
| POST | `/api/v1/system/shutdown` | Graceful stop requested by the desktop shell (lifespan then cancels jobs and checkpoints the WAL). |
| GET | `/api/v1/system/vault` | Vault Status |
| POST | `/api/v1/system/vault/encrypt-existing` | Vault Encrypt Existing |

## tools

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/tools` | Tools |
| POST | `/api/v1/tools/{tool_id}/healthcheck` | Tool Health |

## updates

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/updates/check` | Check |
| POST | `/api/v1/updates/download` | Download |

## workflow-templates

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/workflow-templates` | Templates |

## workflows

| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/workflows` | List Workflows |
| POST | `/api/v1/workflows` | Create Workflow |
| POST | `/api/v1/workflows/{wid}/preview` | Validation + every request the whole DAG would make. Contacts nothing. |
| POST | `/api/v1/workflows/{wid}/run` | Run Workflow |
| GET | `/api/v1/workflows/{wid}/runs` | Workflow Runs |

