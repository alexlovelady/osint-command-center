# Data model

Generated from the SQLAlchemy models by `scripts/gen_docs.py`. SQLite in WAL mode with foreign keys on; schema changes only through Alembic migrations (`backend/osintcc/db/migrations`). FTS5 `search_index` is maintained by triggers and is not an ORM table.

51 tables.

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

