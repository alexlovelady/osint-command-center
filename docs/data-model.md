# Data model

Generated from the SQLAlchemy models by `scripts/gen_docs.py`. SQLite in WAL mode with foreign keys on; schema changes only through Alembic migrations (`backend/osintcc/db/migrations`). FTS5 `search_index` is maintained by triggers and is not an ORM table.

90 tables.

## ai_calls

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| actor_id | VARCHAR(80) | no |  |
| provider_type | VARCHAR(20) | no |  |
| model_id | VARCHAR(200) | no |  |
| evidence_refs_json | JSON | no |  |
| cloud_transfer_approved | BOOLEAN | no |  |
| payload_sha256 | VARCHAR(64) | no |  |
| outcome | VARCHAR(30) | no |  |
| created_at | DATETIME | no |  |

## ai_profiles

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| name | VARCHAR(80) | no |  |
| provider_type | VARCHAR(20) | no |  |
| model_id | VARCHAR(200) | no |  |
| local_only | BOOLEAN | no |  |
| config_json | JSON | no |  |
| created_at | DATETIME | no |  |

## aiv_approvals

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| plan_id | VARCHAR(36) | no | FK → aiv_plans |
| plan_version | INTEGER | no |  |
| plan_hash | VARCHAR(64) | no |  |
| approver_id | VARCHAR(80) | no |  |
| approved_at | DATETIME | no |  |
| expires_at | DATETIME | no |  |
| maximum_uses | INTEGER | no |  |
| uses | INTEGER | no |  |
| revoked_at | DATETIME | yes |  |

## aiv_observations

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| run_id | VARCHAR(36) | no | FK → aiv_runs |
| asset_authorization_id | VARCHAR(36) | no | FK → asset_authorizations |
| target_asset | VARCHAR(300) | no |  |
| check_type | VARCHAR(40) | no |  |
| finding_key | VARCHAR(64) | no |  |
| observed_value_json | JSON | no |  |
| severity | VARCHAR(12) | no |  |
| confidence | VARCHAR(12) | no |  |
| basis | VARCHAR(12) | no |  |
| remediation | TEXT | no |  |
| evidence_id | VARCHAR(36) | yes | FK → evidence |
| observed_at | DATETIME | no |  |
| review_status | VARCHAR(16) | no |  |
| reviewer | VARCHAR(80) | yes |  |
| review_note | TEXT | no |  |
| reviewed_at | DATETIME | yes |  |

## aiv_plans

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| target_profile_id | VARCHAR(36) | yes | FK → subjects |
| asset_authorization_id | VARCHAR(36) | no | FK → asset_authorizations |
| plan_hash | VARCHAR(64) | no |  |
| version | INTEGER | no |  |
| supersedes_id | VARCHAR(36) | yes |  |
| steps_json | JSON | no |  |
| projected_limits_json | JSON | no |  |
| status | VARCHAR(16) | no |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |

## aiv_run_events

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| run_id | VARCHAR(36) | no | FK → aiv_runs |
| seq | INTEGER | no |  |
| kind | VARCHAR(32) | no |  |
| payload_json | JSON | no |  |
| at | DATETIME | no |  |

## aiv_runs

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| plan_id | VARCHAR(36) | no | FK → aiv_plans |
| case_id | VARCHAR(36) | no | FK → cases |
| approval_id | VARCHAR(36) | yes |  |
| actor_id | VARCHAR(80) | no |  |
| status | VARCHAR(16) | no |  |
| started_at | DATETIME | no |  |
| finished_at | DATETIME | yes |  |
| actual_request_counts_json | JSON | no |  |
| tool_versions_json | JSON | no |  |
| abort_reason | TEXT | no |  |
| scope_snapshot_hash | VARCHAR(64) | no |  |

## aiv_template_approvals

A reviewed signature template, pinned by id AND content hash. Anything else is refused.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| template_id | VARCHAR(120) | no |  |
| sha256 | VARCHAR(64) | no |  |
| content | TEXT | no |  |
| semantics_json | JSON | no |  |
| reviewed_by | VARCHAR(80) | no |  |
| reviewed_at | DATETIME | no |  |
| revoked_at | DATETIME | yes |  |
| notes | TEXT | no |  |

## alerts

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| type | VARCHAR(40) | no |  |
| severity | VARCHAR(10) | no |  |
| subject_entity_id | VARCHAR(36) | yes | FK → entities |
| old_fingerprint | VARCHAR(64) | yes |  |
| new_fingerprint | VARCHAR(64) | yes |  |
| message | TEXT | no |  |
| details_json | JSON | no |  |
| acknowledged_at | DATETIME | yes |  |
| created_at | DATETIME | no |  |

## asset_authorizations

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| owner_subject_id | VARCHAR(36) | yes | FK → subjects |
| asset_type | VARCHAR(12) | no |  |
| canonical_scope | JSON | no |  |
| ports_json | JSON | no |  |
| paths_json | JSON | no |  |
| allowed_classes_json | JSON | no |  |
| exclusions_json | JSON | no |  |
| limits_json | JSON | no |  |
| authorized_by | VARCHAR(200) | no |  |
| authority_role | VARCHAR(120) | no |  |
| source_of_authority | TEXT | no |  |
| attestation_kind | VARCHAR(32) | no |  |
| attestation_ref | VARCHAR(36) | yes | FK → evidence |
| domain_verifications | JSON | no |  |
| starts_at | DATETIME | no |  |
| expires_at | DATETIME | no |  |
| revoked_at | DATETIME | yes |  |
| retention_terms | TEXT | no |  |
| notes | TEXT | no |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |

## associated_emails

An email address that sources associate with the subject. Evidence-linked and never a fact until a person decides.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| address | VARCHAR(254) | no |  |
| dedupe_key | VARCHAR(254) | no |  |
| origin | VARCHAR(16) | no |  |
| state | VARCHAR(12) | no |  |
| classification | VARCHAR(10) | no |  |
| explanation | JSON | no |  |
| confirmation_kind | VARCHAR(24) | yes |  |
| sources | JSON | no |  |
| associations | JSON | no |  |
| conflicts | JSON | no |  |
| aliases | JSON | no |  |
| depth | INTEGER | no |  |
| origin_path | JSON | no |  |
| entity_id | VARCHAR(36) | yes |  |
| identifier_id | VARCHAR(36) | yes |  |
| note | TEXT | no |  |
| discovered_at | DATETIME | no |  |
| last_verified_at | DATETIME | yes |  |
| reviewed_by | VARCHAR(80) | yes |  |
| reviewed_at | DATETIME | yes |  |
| review_basis | TEXT | no |  |

## audit_events

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| seq | INTEGER | no |  |
| actor_id | VARCHAR(80) | no |  |
| case_id | VARCHAR(36) | yes |  |
| action | VARCHAR(80) | no |  |
| resource_type | VARCHAR(40) | yes |  |
| resource_id | VARCHAR(80) | yes |  |
| decision | VARCHAR(20) | no |  |
| metadata_json | JSON | no |  |
| ts | DATETIME | no |  |
| prev_hash | VARCHAR(64) | no |  |
| event_hash | VARCHAR(64) | no |  |

## automation_approvals

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| workflow_id | VARCHAR(36) | no | FK → automation_workflows |
| version_id | VARCHAR(36) | no | FK → automation_versions |
| kind | VARCHAR(12) | no |  |
| authorization_id | VARCHAR(36) | yes |  |
| approver_id | VARCHAR(80) | yes |  |
| action_scope_json | JSON | no |  |
| status | VARCHAR(12) | no |  |
| requested_at | DATETIME | no |  |
| approved_at | DATETIME | yes |  |
| expires_at | DATETIME | yes |  |
| revoked_at | DATETIME | yes |  |

## automation_node_runs

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| run_id | VARCHAR(36) | no | FK → automation_runs |
| node_id | VARCHAR(40) | no |  |
| attempt | INTEGER | no |  |
| state | VARCHAR(16) | no |  |
| started_at | DATETIME | no |  |
| ended_at | DATETIME | yes |  |
| input_digest | VARCHAR(64) | yes |  |
| output_json | JSON | yes |  |
| error_code | VARCHAR(40) | yes |  |
| diagnostics_json | JSON | no |  |

## automation_notifications

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| run_id | VARCHAR(36) | yes |  |
| workflow_id | VARCHAR(36) | yes |  |
| owner_id | VARCHAR(80) | no |  |
| channel | VARCHAR(20) | no |  |
| destination_ref | VARCHAR(200) | yes |  |
| dedupe_key | VARCHAR(80) | no |  |
| severity | VARCHAR(10) | no |  |
| status | VARCHAR(16) | no |  |
| title | VARCHAR(200) | no |  |
| body | TEXT | no |  |
| details_json | JSON | no |  |
| count | INTEGER | no |  |
| created_at | DATETIME | no |  |
| delivered_at | DATETIME | yes |  |
| acknowledged_at | DATETIME | yes |  |

## automation_runs

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| workflow_id | VARCHAR(36) | no | FK → automation_workflows |
| version_id | VARCHAR(36) | yes |  |
| case_id | VARCHAR(36) | yes |  |
| trigger_type | VARCHAR(16) | no |  |
| trigger_event_id | VARCHAR(80) | yes |  |
| state | VARCHAR(24) | no |  |
| dry_run | BOOLEAN | no |  |
| queued_at | DATETIME | no |  |
| started_at | DATETIME | yes |  |
| ended_at | DATETIME | yes |  |
| idempotency_key | VARCHAR(160) | no |  |
| error_code | VARCHAR(40) | yes |  |
| evidence_count | INTEGER | no |  |
| inputs_json | JSON | no |  |
| summary_json | JSON | no |  |
| cancel_requested | BOOLEAN | no |  |
| lease_until | DATETIME | yes |  |
| created_by | VARCHAR(80) | no |  |

## automation_snapshots

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| workflow_id | VARCHAR(36) | no | FK → automation_workflows |
| case_id | VARCHAR(36) | yes |  |
| node_id | VARCHAR(40) | no |  |
| dataset_type | VARCHAR(30) | no |  |
| content_hash | VARCHAR(64) | no |  |
| items_json | JSON | no |  |
| taken_at | DATETIME | no |  |
| source_run_id | VARCHAR(36) | yes |  |

## automation_suggestions

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| owner_id | VARCHAR(80) | no |  |
| case_id | VARCHAR(36) | yes |  |
| rationale | TEXT | no |  |
| basis_json | JSON | no |  |
| proposed_template_key | VARCHAR(40) | no |  |
| category | VARCHAR(20) | no |  |
| state | VARCHAR(12) | no |  |
| snooze_until | DATETIME | yes |  |
| created_at | DATETIME | no |  |
| dismissed_at | DATETIME | yes |  |

## automation_triggers

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| workflow_id | VARCHAR(36) | no | FK → automation_workflows |
| version_id | VARCHAR(36) | no | FK → automation_versions |
| type | VARCHAR(16) | no |  |
| schedule | VARCHAR(80) | yes |  |
| timezone | VARCHAR(64) | no |  |
| enabled | BOOLEAN | no |  |
| missed_run_policy | VARCHAR(12) | no |  |
| next_due_at | DATETIME | yes |  |
| last_fired_at | DATETIME | yes |  |
| config_json | JSON | no |  |

## automation_versions

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| workflow_id | VARCHAR(36) | no | FK → automation_workflows |
| revision | INTEGER | no |  |
| definition_json | JSON | no |  |
| schema_version | INTEGER | no |  |
| content_hash | VARCHAR(64) | no |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |
| published_at | DATETIME | yes |  |

## automation_workflows

An editable draft plus a pointer to the active immutable version. owner_id/team_id leave room for multiuser sharing.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | yes | FK → cases |
| owner_id | VARCHAR(80) | no |  |
| team_id | VARCHAR(80) | yes |  |
| name | VARCHAR(200) | no |  |
| template_slug | VARCHAR(40) | yes |  |
| draft_json | JSON | no |  |
| draft_rev | INTEGER | no |  |
| active_version_id | VARCHAR(36) | yes |  |
| state | VARCHAR(16) | no |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |
| deleted_at | DATETIME | yes |  |

## capture_sessions

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| device_id | VARCHAR(36) | no | FK → hardware_devices |
| case_id | VARCHAR(36) | no | FK → cases |
| status | VARCHAR(20) | no |  |
| capture_scope_json | JSON | no |  |
| started_at | DATETIME | no |  |
| ended_at | DATETIME | yes |  |
| artifact_id | VARCHAR(36) | yes | FK → evidence |
| started_by | VARCHAR(80) | no |  |
| clock_sync | VARCHAR(30) | no |  |
| detail | TEXT | no |  |

## case_ai_policies

| Column | Type | Null | Key |
|---|---|---|---|
| case_id | VARCHAR(36) | no | PK |
| allow_cloud | BOOLEAN | no |  |
| require_preview | BOOLEAN | no |  |
| deny_sensitive_cloud | BOOLEAN | no |  |

## case_members

| Column | Type | Null | Key |
|---|---|---|---|
| case_id | VARCHAR(36) | no | PK |
| user_id | VARCHAR(36) | no | PK |
| access_role | VARCHAR(20) | no |  |

## cases

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| title | VARCHAR(300) | no |  |
| description | TEXT | no |  |
| category | VARCHAR(50) | no |  |
| status | VARCHAR(20) | no |  |
| purpose | TEXT | no |  |
| legal_basis_notes | TEXT | no |  |
| scope_json | JSON | no |  |
| retention_days | INTEGER | yes |  |
| owner_id | VARCHAR(36) | yes | FK → users |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |
| archived_at | DATETIME | yes |  |

## claim_sources

| Column | Type | Null | Key |
|---|---|---|---|
| claim_id | VARCHAR(36) | no | PK |
| evidence_id | VARCHAR(36) | no | PK |
| method | VARCHAR(60) | no |  |
| independent_source_group | VARCHAR(80) | no |  |

## claims

A statement about the world supported by evidence. Facts a source reported are claims, never truths.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| subject_entity_id | VARCHAR(36) | no | FK → entities |
| predicate | VARCHAR(120) | no |  |
| object_entity_id | VARCHAR(36) | yes | FK → entities |
| value_json | JSON | yes |  |
| epistemic_status | VARCHAR(20) | no |  |
| confidence_label | VARCHAR(12) | no |  |
| verification_status | VARCHAR(20) | no |  |
| observed_at | DATETIME | yes |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |

## collection_plans

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| created_by | VARCHAR(80) | no |  |
| reason | TEXT | no |  |
| policy_status | VARCHAR(24) | no |  |
| status | VARCHAR(20) | no |  |
| run_id | VARCHAR(36) | yes | FK → search_runs |
| created_at | DATETIME | no |  |
| plan_json | JSON | no |  |

## collection_steps

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| plan_id | VARCHAR(36) | no | FK → collection_plans |
| adapter_id | VARCHAR(80) | no |  |
| scope_json | JSON | no |  |
| status | VARCHAR(20) | no |  |
| started_at | DATETIME | yes |  |
| finished_at | DATETIME | yes |  |
| error_code | VARCHAR(60) | yes |  |

## consent_authorizations

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| basis | VARCHAR(40) | no |  |
| authorizing_party | VARCHAR(200) | no |  |
| scope_json | JSON | no |  |
| expires_at | DATETIME | yes |  |
| revoked_at | DATETIME | yes |  |
| supporting_evidence_id | VARCHAR(36) | yes | FK → evidence |
| created_at | DATETIME | no |  |

## copilot_conversations

A Copilot chat. One per investigation per user (plus general ones); history survives restarts.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| user_id | VARCHAR(80) | no |  |
| case_id | VARCHAR(36) | yes | FK → cases |
| title | VARCHAR(200) | no |  |
| mode | VARCHAR(20) | no |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |

## copilot_messages

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| conversation_id | VARCHAR(36) | no | FK → copilot_conversations |
| seq | INTEGER | no |  |
| role | VARCHAR(12) | no |  |
| mode | VARCHAR(20) | no |  |
| content | TEXT | no |  |
| meta_json | JSON | no |  |
| created_at | DATETIME | no |  |

## copilot_proposals

An action the Copilot suggested. Nothing runs until a person approves exactly this proposal.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| conversation_id | VARCHAR(36) | no | FK → copilot_conversations |
| case_id | VARCHAR(36) | yes | FK → cases |
| tool | VARCHAR(40) | no |  |
| args_json | JSON | no |  |
| preview_json | JSON | no |  |
| status | VARCHAR(12) | no |  |
| result_json | JSON | no |  |
| created_at | DATETIME | no |  |
| decided_at | DATETIME | yes |  |
| decided_by | VARCHAR(80) | yes |  |

## correlations

An analyst decision about a suggested coincidence between two observations. Coincidence is not a relationship.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| obs_a_id | VARCHAR(36) | no | FK → observations |
| obs_b_id | VARCHAR(36) | no | FK → observations |
| kind | VARCHAR(12) | no |  |
| status | VARCHAR(12) | no |  |
| note | TEXT | no |  |
| delta_s | DOUBLE | yes |  |
| distance_m | DOUBLE | yes |  |
| decided_by | VARCHAR(80) | no |  |
| decided_at | DATETIME | no |  |

## disciplines

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(20) | no | PK |
| label | VARCHAR(80) | no |  |
| parent_id | VARCHAR(20) | yes | FK → disciplines |
| enabled | BOOLEAN | no |  |

## entities

Case-namespaced (privacy by default): never auto-merged across cases.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| type | VARCHAR(30) | no |  |
| canonical_key | TEXT | no |  |
| display_name | TEXT | no |  |
| metadata_json | JSON | no |  |
| sensitivity | VARCHAR(20) | no |  |
| first_seen_at | DATETIME | no |  |
| last_seen_at | DATETIME | no |  |
| created_at | DATETIME | no |  |

## entity_links

Reversible analyst merge decision: `entity_id` is treated as `canonical_entity_id` in merged views only.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| entity_id | VARCHAR(36) | no | FK → entities |
| canonical_entity_id | VARCHAR(36) | no | FK → entities |
| decided_by | VARCHAR(80) | no |  |
| reason | TEXT | no |  |
| status | VARCHAR(12) | no |  |
| created_at | DATETIME | no |  |
| reverted_at | DATETIME | yes |  |

## evidence

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| source_id | VARCHAR(36) | yes | FK → sources |
| kind | VARCHAR(40) | no |  |
| title | TEXT | no |  |
| description | TEXT | no |  |
| sha256 | VARCHAR(64) | no |  |
| sha512 | VARCHAR(128) | no |  |
| byte_size | INTEGER | no |  |
| mime_type | VARCHAR(100) | yes |  |
| vault_relpath | TEXT | yes |  |
| original_url | TEXT | yes |  |
| retrieved_at | DATETIME | no |  |
| observed_at | DATETIME | yes |  |
| published_at | DATETIME | yes |  |
| created_by | VARCHAR(80) | no |  |
| capture_method | VARCHAR(60) | no |  |
| sensitivity | VARCHAR(20) | no |  |
| redacted | BOOLEAN | no |  |
| chain_of_custody_json | JSON | no |  |
| created_at | DATETIME | no |  |

## expansion_runs

One pass of the shared cross-INT expansion: which identifiers were considered, what was planned, what ran, and why it stopped.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| depth | INTEGER | no |  |
| policy_json | JSON | no |  |
| plan_json | JSON | no |  |
| status | VARCHAR(12) | no |  |
| stop_reason | VARCHAR(40) | no |  |
| started | INTEGER | no |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |

## exposure_checks

One attempt to ask one provider about one identifier, and how it ended. This is what makes 'not checked', 'unknown' and 'no match' distinguishable.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| subject_id | VARCHAR(36) | no | FK → subjects |
| identifier_id | VARCHAR(36) | yes |  |
| provider_id | VARCHAR(40) | no |  |
| operation | VARCHAR(32) | no |  |
| outcome | VARCHAR(24) | no |  |
| events_found | INTEGER | no |  |
| evidence_id | VARCHAR(36) | yes | FK → evidence |
| detail | VARCHAR(300) | no |  |
| actor | VARCHAR(80) | no |  |
| checked_at | DATETIME | no |  |

## exposure_events

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| subject_id | VARCHAR(36) | yes | FK → subjects |
| indicator_id | VARCHAR(36) | yes | FK → exposure_indicators |
| identifier_id | VARCHAR(36) | yes | FK → subject_identifiers |
| identifier_token | VARCHAR(32) | no |  |
| provider_id | VARCHAR(40) | no |  |
| event_type | VARCHAR(24) | no |  |
| incident_key | VARCHAR(160) | no |  |
| group_key | VARCHAR(80) | no |  |
| title | VARCHAR(200) | no |  |
| categories_json | JSON | no |  |
| reported_first_seen | DATETIME | yes |  |
| reported_last_seen | DATETIME | yes |  |
| claim_status | VARCHAR(16) | no |  |
| confidence | VARCHAR(10) | no |  |
| evidence_id | VARCHAR(36) | yes | FK → evidence |
| provider_ref | VARCHAR(300) | no |  |
| redacted | BOOLEAN | no |  |
| dedupe_key | VARCHAR(64) | no |  |
| created_at | DATETIME | no |  |

## exposure_indicators

Status, class, provider and a masked descriptor. There is intentionally no field that could hold a secret or raw dump.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| cls | VARCHAR(32) | no |  |
| provider | VARCHAR(60) | no |  |
| exposure_date | DATETIME | yes |  |
| last_checked | DATETIME | no |  |
| status | VARCHAR(32) | no |  |
| risk | VARCHAR(12) | no |  |
| masked_descriptor | VARCHAR(200) | no |  |
| verification_basis | VARCHAR(80) | no |  |
| remediation_state | VARCHAR(16) | no |  |
| evidence_id | VARCHAR(36) | yes | FK → evidence |
| created_at | DATETIME | no |  |

## exposure_monitor_configs

A bounded, expiring scope that a scheduled workflow may use. It holds references to identifiers and an authorization, never values.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| subject_id | VARCHAR(36) | no | FK → subjects |
| name | VARCHAR(120) | no |  |
| identifier_ids_json | JSON | no |  |
| providers_json | JSON | no |  |
| cadence_hours | INTEGER | no |  |
| consent_id | VARCHAR(36) | yes |  |
| expires_at | DATETIME | no |  |
| enabled | BOOLEAN | no |  |
| disabled_reason | VARCHAR(200) | no |  |
| last_run_at | DATETIME | yes |  |
| last_outcome_json | JSON | no |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |

## exposure_reviews

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| event_id | VARCHAR(36) | no | FK → exposure_events |
| reviewer | VARCHAR(80) | no |  |
| status | VARCHAR(20) | no |  |
| rationale | TEXT | no |  |
| action_items_json | JSON | no |  |
| review_source | VARCHAR(40) | no |  |
| created_at | DATETIME | no |  |

## exposure_sources

Operator state per provider. Static facts (licence, terms, coverage limits) live in code; this row holds only what the operator decided and what was last observed.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| provider_id | VARCHAR(40) | no |  |
| enabled | BOOLEAN | no |  |
| last_verification_json | JSON | no |  |
| terms_acknowledged_at | DATETIME | yes |  |
| terms_acknowledged_by | VARCHAR(80) | yes |  |
| updated_at | DATETIME | no |  |

## findings

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| subject_entity_id | VARCHAR(36) | no | FK → entities |
| predicate | VARCHAR(120) | no |  |
| value_type | VARCHAR(30) | no |  |
| value_json | JSON | no |  |
| confidence | VARCHAR(12) | no |  |
| confidence_reason | TEXT | no |  |
| evidence_id | VARCHAR(36) | no | FK → evidence |
| source_id | VARCHAR(36) | yes | FK → sources |
| adapter_id | VARCHAR(80) | no |  |
| adapter_version | VARCHAR(40) | no |  |
| observed_at | DATETIME | no |  |
| source_published_at | DATETIME | yes |  |
| status | VARCHAR(20) | no |  |
| run_id | VARCHAR(36) | yes | FK → search_runs |
| dedup_key | VARCHAR(64) | no |  |
| created_at | DATETIME | no |  |

## geospatial_layers

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| file_evidence_id | VARCHAR(36) | no | FK → evidence |
| coordinate_system | VARCHAR(40) | yes |  |
| bounds_json | JSON | yes |  |
| acquisition_time | DATETIME | yes |  |
| imagery_licence | TEXT | yes |  |
| precision_class | VARCHAR(20) | no |  |
| pixel_size | DOUBLE | yes |  |
| width | INTEGER | yes |  |
| height | INTEGER | yes |  |

## graph_proposals

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| proposal_type | VARCHAR(30) | no |  |
| subject_id | VARCHAR(36) | no | FK → entities |
| candidate_id | VARCHAR(36) | no | FK → entities |
| reason | TEXT | no |  |
| status | VARCHAR(20) | no |  |
| created_at | DATETIME | no |  |
| decided_at | DATETIME | yes |  |

## hardware_devices

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| driver_id | VARCHAR(40) | no |  |
| device_kind | VARCHAR(20) | no |  |
| logical_name | VARCHAR(120) | no |  |
| hw_key | VARCHAR(160) | no |  |
| permission_scope | VARCHAR(30) | no |  |
| receive_only | BOOLEAN | no |  |
| simulated | BOOLEAN | no |  |
| present | BOOLEAN | no |  |
| last_seen_at | DATETIME | no |  |
| metadata_json | JSON | no |  |

## human_sources

A source known to the case ONLY by alias. Reliability/credibility are analyst judgements, never computed.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| alias | VARCHAR(80) | no |  |
| consent_id | VARCHAR(36) | no | FK → consent_authorizations |
| reliability_assessment | VARCHAR(1) | yes |  |
| retention_until | DATETIME | yes |  |
| restricted | BOOLEAN | no |  |
| revoked_at | DATETIME | yes |  |
| created_at | DATETIME | no |  |

## hypotheses

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| statement | TEXT | no |  |
| status | VARCHAR(20) | no |  |
| rationale | TEXT | no |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |

## hypothesis_claims

| Column | Type | Null | Key |
|---|---|---|---|
| hypothesis_id | VARCHAR(36) | no | PK |
| claim_id | VARCHAR(36) | no | PK |
| stance | VARCHAR(12) | no |  |

## image_assets

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| evidence_id | VARCHAR(36) | no | FK → evidence |
| sha256 | VARCHAR(64) | no |  |
| phash | VARCHAR(16) | no |  |
| dhash | VARCHAR(16) | no |  |
| ahash | VARCHAR(16) | no |  |
| width | INTEGER | no |  |
| height | INTEGER | no |  |
| format | VARCHAR(12) | no |  |
| ownership | VARCHAR(16) | no |  |
| source_url | TEXT | yes |  |
| metadata_json | JSON | no |  |
| has_gps | BOOLEAN | no |  |
| created_at | DATETIME | no |  |

## image_matches

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| asset_id | VARCHAR(36) | no | FK → image_assets |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| other_asset_id | VARCHAR(36) | yes | FK → image_assets |
| match_type | VARCHAR(24) | no |  |
| provider | VARCHAR(40) | yes |  |
| matched_url | TEXT | yes |  |
| distance | FLOAT | yes |  |
| score | FLOAT | yes |  |
| review_state | VARCHAR(16) | no |  |
| reviewer | VARCHAR(80) | yes |  |
| note | TEXT | no |  |
| evidence_ids | JSON | no |  |
| observed_at | DATETIME | no |  |

## intelligence_requirements

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| question | TEXT | no |  |
| objective | TEXT | no |  |
| information_requirement | TEXT | no |  |
| collection_constraint | TEXT | no |  |
| assigned_actor | VARCHAR(80) | yes |  |
| answer_status | VARCHAR(20) | no |  |
| priority | VARCHAR(10) | no |  |
| status | VARCHAR(20) | no |  |
| due_at | DATETIME | yes |  |
| created_by | VARCHAR(80) | no |  |
| answered_at | DATETIME | yes |  |

## investigation_events

Append-only activity log for a run: the replayable record behind the progress view.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| run_id | VARCHAR(36) | no | FK → investigation_runs |
| seq | INTEGER | no |  |
| kind | VARCHAR(24) | no |  |
| message | TEXT | no |  |
| detail_json | JSON | no |  |
| at | DATETIME | no |  |

## investigation_runs

One-click investigation: a durable, bounded orchestration over the existing research, expansion and review services. It owns no results of its own.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| subject_id | VARCHAR(36) | no | FK → subjects |
| kind | VARCHAR(12) | no |  |
| status | VARCHAR(24) | no |  |
| phase | VARCHAR(24) | no |  |
| pass_no | INTEGER | no |  |
| policy_json | JSON | no |  |
| approved_sources | JSON | no |  |
| excluded_sources | JSON | no |  |
| manifest_json | JSON | no |  |
| counts_json | JSON | no |  |
| stop_reason | VARCHAR(40) | no |  |
| last_error | TEXT | no |  |
| requested_by | VARCHAR(80) | no |  |
| idempotency_key | VARCHAR(64) | yes |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |
| started_at | DATETIME | yes |  |
| finished_at | DATETIME | yes |  |
| deadline_at | DATETIME | yes |  |

## job_events

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| job_id | VARCHAR(36) | no | FK → jobs |
| run_id | VARCHAR(36) | no |  |
| sequence | INTEGER | no |  |
| event_type | VARCHAR(40) | no |  |
| payload_json | JSON | no |  |
| occurred_at | DATETIME | no |  |

## jobs

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| run_id | VARCHAR(36) | no | FK → search_runs |
| adapter_id | VARCHAR(80) | no |  |
| status | VARCHAR(20) | no |  |
| idempotency_key | VARCHAR(128) | no |  |
| attempts | INTEGER | no |  |
| max_attempts | INTEGER | no |  |
| next_retry_at | DATETIME | yes |  |
| lease_until | DATETIME | yes |  |
| last_heartbeat | DATETIME | yes |  |
| last_error_code | VARCHAR(60) | yes |  |
| result_status | VARCHAR(20) | yes |  |
| warnings_json | JSON | no |  |
| result_keys_json | JSON | no |  |
| created_at | DATETIME | no |  |
| started_at | DATETIME | yes |  |
| finished_at | DATETIME | yes |  |

## mcp_approvals

A state-changing MCP request waits here until the person approves it in the app (not through MCP).

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| tool | VARCHAR(40) | no |  |
| args_json | JSON | no |  |
| case_id | VARCHAR(36) | yes |  |
| client | VARCHAR(120) | no |  |
| status | VARCHAR(12) | no |  |
| created_at | DATETIME | no |  |
| decided_at | DATETIME | yes |  |
| used_at | DATETIME | yes |  |

## notes

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| entity_id | VARCHAR(36) | yes | FK → entities |
| evidence_id | VARCHAR(36) | yes | FK → evidence |
| body_markdown | TEXT | no |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |

## observations

Canonical multi-INT observation envelope (spec 21.3). Facts from a parser; never a verified conclusion.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| discipline_id | VARCHAR(20) | no | FK → disciplines |
| kind | VARCHAR(60) | no |  |
| access_class | VARCHAR(20) | no |  |
| observed_at | DATETIME | yes |  |
| ingested_at | DATETIME | no |  |
| data_json | JSON | no |  |
| raw_evidence_id | VARCHAR(36) | no | FK → evidence |
| derived_from_json | JSON | no |  |
| sensitivity | VARCHAR(20) | no |  |
| confidence | VARCHAR(12) | no |  |
| review_status | VARCHAR(20) | no |  |
| parser_version | VARCHAR(40) | no |  |

## plugin_manifests

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| plugin_id | VARCHAR(60) | no |  |
| version | VARCHAR(30) | no |  |
| enabled | BOOLEAN | no |  |
| is_active | BOOLEAN | no |  |
| license | VARCHAR(80) | no |  |
| entry_sha256 | VARCHAR(64) | no |  |
| capabilities_json | JSON | no |  |
| permission_manifest_json | JSON | no |  |
| manifest_json | JSON | no |  |
| health_status | VARCHAR(20) | no |  |
| invalid_outputs | INTEGER | no |  |
| reviewed_by | VARCHAR(80) | yes |  |
| reviewed_at | DATETIME | yes |  |
| installed_at | DATETIME | no |  |

## profile_candidate_links

A hypothesis that a public account/page belongs to the subject. Never a fact until a person decides.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| from_identifier_id | VARCHAR(36) | yes | FK → subject_identifiers |
| to_entity_id | VARCHAR(36) | yes | FK → entities |
| cluster_key | VARCHAR(64) | no |  |
| canonical_url | TEXT | no |  |
| site | VARCHAR(120) | no |  |
| hypothesis | TEXT | no |  |
| adapters | JSON | no |  |
| source_independence | INTEGER | no |  |
| evidence_ids | JSON | no |  |
| finding_ids | JSON | no |  |
| first_seen_at | DATETIME | no |  |
| last_seen_at | DATETIME | no |  |
| state | VARCHAR(12) | no |  |
| reviewed_by | VARCHAR(80) | yes |  |
| reviewed_at | DATETIME | yes |  |
| review_basis | TEXT | no |  |

## profile_claims

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| field | VARCHAR(40) | no |  |
| structured_value | JSON | no |  |
| sensitivity | VARCHAR(12) | no |  |
| validation_state | VARCHAR(20) | no |  |
| observed_from | DATETIME | yes |  |
| observed_to | DATETIME | yes |  |
| evidence_ids | JSON | no |  |
| assertion_source | VARCHAR(20) | no |  |
| reviewer | VARCHAR(80) | yes |  |
| reviewed_at | DATETIME | yes |  |
| reason | TEXT | no |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |

## profile_items

One fact in the Master Profile Editor. Inputs, claims and discovered leads share this shape; competing and contradictory items are all kept.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| category | VARCHAR(24) | no |  |
| type | VARCHAR(32) | no |  |
| custom_type | VARCHAR(60) | no |  |
| value | TEXT | no |  |
| normalized_value | VARCHAR(600) | no |  |
| attributes | JSON | no |  |
| source_id | VARCHAR(80) | no |  |
| evidence_ids | JSON | no |  |
| collection_method | VARCHAR(40) | no |  |
| origin | VARCHAR(20) | no |  |
| recorded_by | VARCHAR(80) | no |  |
| observed_at | DATETIME | yes |  |
| last_verified_at | DATETIME | yes |  |
| confidence | VARCHAR(10) | no |  |
| verification_state | VARCHAR(14) | no |  |
| self_attested | BOOLEAN | no |  |
| sensitivity | VARCHAR(12) | no |  |
| scope_id | VARCHAR(36) | yes |  |
| retention_policy | JSON | no |  |
| is_input | BOOLEAN | no |  |
| backing_kind | VARCHAR(12) | yes |  |
| backing_id | VARCHAR(36) | yes |  |
| reference_token | VARCHAR(64) | yes |  |
| merged_into | VARCHAR(36) | yes |  |
| supersedes_id | VARCHAR(36) | yes |  |
| version | INTEGER | no |  |
| status | VARCHAR(10) | no |  |
| note | TEXT | no |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |

## profile_review_events

Append-only history of ownership/validation decisions; reversal writes a new event that restores `from_state`.

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| target_type | VARCHAR(12) | no |  |
| target_id | VARCHAR(36) | no |  |
| from_state | VARCHAR(20) | no |  |
| to_state | VARCHAR(20) | no |  |
| reviewer | VARCHAR(80) | no |  |
| basis | TEXT | no |  |
| attestation | VARCHAR(12) | no |  |
| evidence_ids | JSON | no |  |
| bulk_id | VARCHAR(36) | yes |  |
| reverts_event_id | VARCHAR(36) | yes |  |
| created_at | DATETIME | no |  |

## relationship_evidence

| Column | Type | Null | Key |
|---|---|---|---|
| relationship_id | VARCHAR(36) | no | PK |
| evidence_id | VARCHAR(36) | no | PK |

## relationships

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| from_entity_id | VARCHAR(36) | no | FK → entities |
| to_entity_id | VARCHAR(36) | no | FK → entities |
| relation_type | VARCHAR(80) | no |  |
| confidence | VARCHAR(12) | no |  |
| confidence_reason | TEXT | no |  |
| status | VARCHAR(20) | no |  |
| asserted_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |

## remediation_tasks

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| indicator_id | VARCHAR(36) | yes | FK → exposure_indicators |
| issue | TEXT | no |  |
| priority | VARCHAR(8) | no |  |
| guidance | TEXT | no |  |
| owner | VARCHAR(80) | yes |  |
| due_at | DATETIME | yes |  |
| recheck_at | DATETIME | yes |  |
| state | VARCHAR(12) | no |  |
| resolution_evidence_id | VARCHAR(36) | yes | FK → evidence |
| exposure_event_id | VARCHAR(36) | yes |  |
| action_type | VARCHAR(24) | yes |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |

## report_runs

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| template | VARCHAR(40) | no |  |
| export_path | TEXT | yes |  |
| redaction_profile | VARCHAR(30) | no |  |
| generated_at | DATETIME | no |  |
| sha256 | VARCHAR(64) | yes |  |
| evidence_manifest_sha256 | VARCHAR(64) | yes |  |
| status | VARCHAR(20) | no |  |

## requirement_evidence

| Column | Type | Null | Key |
|---|---|---|---|
| requirement_id | VARCHAR(36) | no | PK |
| evidence_id | VARCHAR(36) | no | PK |
| claim_id | VARCHAR(36) | yes | FK → claims |
| relevance_note | TEXT | no |  |

## research_tasks

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| category | VARCHAR(40) | no |  |
| source_id | VARCHAR(80) | no |  |
| identifier_id | VARCHAR(36) | yes | FK → subject_identifiers |
| workflow_id | VARCHAR(36) | yes |  |
| run_id | VARCHAR(36) | yes |  |
| status | VARCHAR(16) | no |  |
| last_attempt | DATETIME | yes |  |
| last_success | DATETIME | yes |  |
| limitations | TEXT | no |  |
| approval_reference | VARCHAR(80) | yes |  |
| result_count | INTEGER | no |  |
| created_at | DATETIME | no |  |

## retention_actions

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no |  |
| case_id | VARCHAR(36) | no | FK → cases |
| action | VARCHAR(20) | no |  |
| status | VARCHAR(12) | no |  |
| summary_json | JSON | no |  |
| performed_by | VARCHAR(80) | no |  |
| event_time | DATETIME | no |  |
| audit_seq | INTEGER | yes |  |

## roles

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| name | VARCHAR(40) | no |  |

## schedules

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| workflow_id | VARCHAR(36) | no | FK → workflows |
| case_id | VARCHAR(36) | no | FK → cases |
| target_raw | TEXT | no |  |
| target_type | VARCHAR(20) | yes |  |
| cron_or_interval | VARCHAR(20) | no |  |
| next_run_at | DATETIME | no |  |
| enabled | BOOLEAN | no |  |
| last_run_at | DATETIME | yes |  |
| last_status | VARCHAR(40) | yes |  |
| consecutive_failures | INTEGER | no |  |
| confirmed_adapters_json | JSON | no |  |
| target_policy_snapshot_json | JSON | no |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |

## scope_authorizations

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| scope_type | VARCHAR(30) | no |  |
| scope_value | TEXT | no |  |
| authorization_type | VARCHAR(40) | no |  |
| authorized_by | TEXT | no |  |
| document_ref | TEXT | yes |  |
| allowed_classes_json | JSON | no |  |
| expires_at | DATETIME | yes |  |
| created_at | DATETIME | no |  |
| revoked_at | DATETIME | yes |  |

## search_runs

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| target_id | VARCHAR(36) | no | FK → targets |
| mode | VARCHAR(20) | no |  |
| selected_adapters_json | JSON | no |  |
| permission_snapshot_json | JSON | no |  |
| status | VARCHAR(20) | no |  |
| started_at | DATETIME | no |  |
| ended_at | DATETIME | yes |  |
| summary_json | JSON | no |  |

## settings

| Column | Type | Null | Key |
|---|---|---|---|
| key | VARCHAR(100) | no | PK |
| value_json | JSON | no |  |
| updated_at | DATETIME | no |  |

## snapshots

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| workflow_id | VARCHAR(36) | no | FK → workflows |
| target_id | VARCHAR(36) | no | FK → targets |
| fingerprint | VARCHAR(64) | no |  |
| keys_json | JSON | no |  |
| workflow_run_id | VARCHAR(36) | yes | FK → workflow_runs |
| created_at | DATETIME | no |  |

## sources

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| adapter_id | VARCHAR(80) | no |  |
| source_type | VARCHAR(40) | no |  |
| source_url | TEXT | yes |  |
| provider_record_id | TEXT | yes |  |
| retrieved_at | DATETIME | no |  |
| published_at | DATETIME | yes |  |
| terms_url | TEXT | yes |  |
| license_notes | TEXT | yes |  |
| rate_class | VARCHAR(40) | yes |  |
| metadata_json | JSON | no |  |

## subject_consents

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| mode | VARCHAR(16) | no |  |
| verification_method | VARCHAR(40) | no |  |
| verifier | VARCHAR(200) | no |  |
| scope_json | JSON | no |  |
| source_classes | JSON | no |  |
| permitted_purposes | JSON | no |  |
| obtained_at | DATETIME | no |  |
| expires_at | DATETIME | yes |  |
| revoked_at | DATETIME | yes |  |
| revoked_reason | TEXT | no |  |
| proof_evidence_id | VARCHAR(36) | yes | FK → evidence |
| retention_policy | JSON | no |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |

## subject_corrections

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| target_type | VARCHAR(16) | no |  |
| target_id | VARCHAR(36) | yes |  |
| request_text | TEXT | no |  |
| justification | TEXT | no |  |
| requested_by | VARCHAR(200) | no |  |
| status | VARCHAR(12) | no |  |
| resolution | TEXT | no |  |
| event_time | DATETIME | no |  |
| audit_seq | INTEGER | yes |  |

## subject_identifiers

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| subject_id | VARCHAR(36) | no | FK → subjects |
| case_id | VARCHAR(36) | no | FK → cases |
| kind | VARCHAR(16) | no |  |
| value | TEXT | no |  |
| value_hash | VARCHAR(64) | no |  |
| status | VARCHAR(12) | no |  |
| source_evidence_id | VARCHAR(36) | yes | FK → evidence |
| recorded_at | DATETIME | no |  |

## subjects

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| type | VARCHAR(24) | no |  |
| display_name | VARCHAR(300) | no |  |
| mode | VARCHAR(16) | no |  |
| purpose | TEXT | no |  |
| status | VARCHAR(16) | no |  |
| owner | VARCHAR(80) | yes |  |
| sensitivity | VARCHAR(12) | no |  |
| retention_days | INTEGER | yes |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |

## targets

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | no | FK → cases |
| type | VARCHAR(30) | no |  |
| raw_input | TEXT | no |  |
| canonical_value | TEXT | no |  |
| scope_status | VARCHAR(30) | no |  |
| owner_or_authority | TEXT | yes |  |
| created_at | DATETIME | no |  |

## user_roles

| Column | Type | Null | Key |
|---|---|---|---|
| user_id | VARCHAR(36) | no | PK |
| role_id | VARCHAR(36) | no | PK |

## users

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| display_name | VARCHAR(200) | no |  |
| status | VARCHAR(20) | no |  |
| created_at | DATETIME | no |  |

## workflow_runs

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| workflow_id | VARCHAR(36) | no | FK → workflows |
| case_id | VARCHAR(36) | no | FK → cases |
| target_id | VARCHAR(36) | no | FK → targets |
| trigger | VARCHAR(20) | no |  |
| slot_key | VARCHAR(120) | yes |  |
| status | VARCHAR(20) | no |  |
| started_at | DATETIME | no |  |
| ended_at | DATETIME | yes |  |
| run_ids_json | JSON | no |  |
| summary_json | JSON | no |  |

## workflows

| Column | Type | Null | Key |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| case_id | VARCHAR(36) | yes | FK → cases |
| name | VARCHAR(200) | no |  |
| definition_json | JSON | no |  |
| enabled | BOOLEAN | no |  |
| created_by | VARCHAR(80) | no |  |
| created_at | DATETIME | no |  |
| updated_at | DATETIME | no |  |

