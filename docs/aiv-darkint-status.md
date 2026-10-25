# AIV, DARKINT and rebrand (addendum v1.1): status, evidence and limits

Written after the work, from the code and the tests in this repository. Labels: **live-verified** (run against the real service or tool), **fixture-tested** (proven against recorded or synthetic responses, a stand-in program, or a local lab server), **mocked**, **simulated** (dry run), **not installed**, **not implemented**. Nothing is called "working" without a test that ran.

The gap analysis written before any code changed is `docs/aiv-darkint-gap-analysis.md`; decisions are D-074 onward in `docs/decision-log.md`.

## Headline truths

- **No third-party service or tool was exercised live in this build.** Every AIV check was run against local lab servers on `127.0.0.1` (real sockets, real TLS handshakes with a generated CA). Every DARKINT provider was exercised through recorded or synthetic responses. A live low-volume test needs your approval and your credentials (DARKINT criterion 14) and was **not** run.
- **Paid or credentialed providers.** Have I Been Pwned needs your paid API key. Ransomware.live's free v2 interface is labelled *personal use only* by the provider; read its terms before using it for corporate work. Intelligence X needs a commercial licence and has **no automated integration** here (its response format could not be verified); MISP is **file import only** (no live server connector). Each is shown with one honest state (`live`, `mocked`, `manual_only`, `disabled`) and a separate `verification` field.
- **Tools.** Nmap, Naabu, Nuclei and dnstwist are optional, are never downloaded by this application, and run only when installed and identity/version-verified. Their command-line flags were checked against the real tools' own help output on 2026-10-25 (Nmap 7.98, Nuclei engine 3.11.1, Naabu 2.6.1, ProjectDiscovery httpx 1.12.0, dnstwist 20240812) and real captured output is the parser fixture. ZAP passive import is **not implemented**. `sslscan` is not used (a built-in TLS check is). ProjectDiscovery httpx is detected and reported but not used (the built-in Python client does the HTTP checks).
- **The display name is unchanged** until you approve a change in Settings. `Fusion Intelligence Command Center` exists only as a labelled, provisional preset; it is not a cleared trademark, domain or business name.

## Feature status

| Feature | Label | Evidence |
|---|---|---|
| Asset authorization (separate from person consent), fail-closed gates, budgets | fixture-tested (lab) | `tests/unit/test_aiv_policy.py`, `tests/integration/test_aiv_core.py` |
| HTTP metadata, TLS posture, bounded TCP connect | fixture-tested (lab, real sockets and handshakes) | `test_aiv_core.py` |
| DNS pinning and redirect re-judging | fixture-tested (scripted resolver) | `test_aiv_core.py`, `test_aiv_policy.py` |
| Nmap / Naabu service detection | fixture-tested (real captured output, stand-in program end to end); real-binary tests skip when the tool is absent | `test_aiv_tools.py` |
| Nuclei reviewed templates (id + SHA-256, GET/HEAD only) | fixture-tested (static review, real captured output); live scan against a lab target not run | `test_aiv_tools.py` |
| dnstwist permutations (adapter, offline) | fixture-tested | `test_aiv_tools.py` |
| Automation nodes and templates AIV-01..05 | simulated (dry runs) + fixture-tested | `test_aiv_automation.py`, `test_automations*.py` |
| Copilot explain / propose (AIV, DARKINT) | fixture-tested with the fixture model | `test_aiv_copilot.py`, `test_darkint_copilot.py` |
| AIV report, PHANTOM handoff export | fixture-tested | `test_aiv_reports.py` |
| Verification workbench, DARKINT tab and page, product-name card | vitest + typecheck + lint; browser walk-through noted below | `verification.test.tsx`, `darkint.test.tsx` |
| DARKINT provider framework, consent scopes, gates, events, coverage, reviews, monitors | fixture-tested | `test_darkint.py` |
| HIBP account and domain lookups | fixture-tested, **not live-verified** | `test_darkint.py` |
| Ransomware.live victim search | fixture-tested, **not live-verified** | `test_darkint.py` |
| Pwned Passwords range relay | fixture-tested (existing TP5 feature, reused) | `test_profile_exposure.py`, `test_darkint.py` |
| Manual intake, CSV / JSON / MISP-export import | fixture-tested | `test_darkint.py` |
| Intelligence X | **not implemented** (manual intake only) | `GET /darkint/sources` |
| MISP live server connector | **not implemented** (file import only) | `GET /darkint/sources` |
| ZAP passive report import | **not implemented** | – |
| DARK-01..05 templates | simulated (dry runs) + fixture-tested | `test_darkint_automation.py` |
| Migrations 0013 (AIV) and 0014 (DARKINT): upgrade, rollback, backup/restore | fixture-tested | `test_aiv_foundation.py`, `test_darkint_data.py`, `test_aiv_reports.py` |

## AIV test matrix (addendum section 12)

| # | Scenario | Tests |
|---|---|---|
| 1 | Existing cases, claims, evidence and 30 workflows survive migration | `test_upgrade_from_0012_keeps_cases_profiles_and_thirty_workflows`, `test_the_aiv_migration_round_trips_without_touching_older_tables` |
| 2 | Legacy API and MCP read-only calls stay compatible | the pre-existing suites (API, MCP, plugins) pass unchanged |
| 3 | Off by default; an unapproved run sends zero packets | `test_aiv_is_off_by_default_and_nothing_connects`, `test_preview_and_plan_creation_make_no_dns_queries_and_no_connections` |
| 4 | Person consent does not authorize an associated domain | `test_person_consent_does_not_authorize_an_associated_domain` |
| 5 | Exact unexpired authorization permits only designated actions | `test_exact_authorization_runs_only_the_designated_request_and_stores_evidence`, `test_a_class_that_was_not_granted_is_refused_even_for_an_in_scope_host` |
| 6 | Expired / revoked scope, wrong port, path or host fails closed | `test_expiry_revocation_and_scope_edits_between_approval_and_run_fail_closed`, `test_wrong_host_port_and_path_never_reach_the_network` |
| 7 | Redirects to external / internal / loopback / metadata blocked | `test_redirects_out_of_scope_are_reported_and_not_followed`, policy unit tests |
| 8 | DNS rebinding / private resolution fails closed at connection time | `test_dns_answers_in_private_or_metadata_space_fail_closed_at_connection_time`, `test_the_checked_address_is_the_address_that_is_used` |
| 9 | Narrow TLS/HTTP checks return real parsed evidence | `test_tls_posture_from_real_handshakes`, `test_tls_findings_for_expired_self_signed_and_mismatched_certificates` |
| 10 | Port scan limited to an explicit list; no NSE / aggressive / stealth | `test_port_checks_touch_only_authorized_ports`, `test_argv_builders_use_fixed_flags_and_keep_the_target_as_a_single_element` |
| 11 | Nuclei allowlist: exact id, content hash, reviewed semantics, no paths or payloads | `test_templates_with_risky_semantics_are_rejected_statically`, `test_template_approval_is_by_id_and_hash_and_needs_the_reviewer_to_confirm`, `test_a_plan_naming_an_unapproved_template_is_refused_before_any_request` |
| 12 | Importing a definition with a command, credentials, hidden active step or schedule is rejected | `test_importing_a_definition_with_a_command_credentials_or_hidden_active_step_is_rejected`, `test_aiv_node_config_has_no_field_for_a_command_url_template_path_or_credential` |
| 13 | AI suggestions issue no requests and grant no approvals | `test_there_is_no_tool_that_authorizes_approves_or_runs`, `test_a_proposal_stores_only_a_draft_after_approval_and_sends_nothing` |
| 14 | Versions and approvals cannot be reused after edits | `test_approvals_are_explicit_single_use_expiring_and_bound_to_the_exact_plan` |
| 15 | Rate, concurrency and time budgets stop runs; cancel kills descendants | policy unit tests, `test_cancel_stops_a_run_in_flight`, `test_cancelling_a_tool_run_kills_the_whole_process_tree` |
| 16 | Crash recovery never replays an active request | `test_a_run_interrupted_by_a_restart_is_never_replayed` |
| 17 | Missing binaries, bad versions, unavailable APIs give truthful states | `test_tool_health_states_are_truthful`, `test_service_detection_is_blocked_when_the_name_resolves_into_forbidden_space` |
| 18 | Profile linking never infers ownership from a name | `test_target_profile_view_lists_only_explicitly_linked_assets_never_by_name` |
| 19 | Reports omit passwords, full SSNs and unrelated private details | `test_the_report_states_authorization_approval_runs_findings_limits_and_the_audit_chain` (cookie values), `test_sanitizer_redacts_secret_shaped_values_and_masks_addresses`, `test_manual_intake_and_imports_redact_and_never_keep_the_upload` |
| 20 | Consent revocation stops future collection and scheduled tasks | `test_no_consent_a_weak_consent_a_provider_outside_the_scope_and_revocation_all_block`, `test_monitors_need_live_consent_stop_on_revocation_and_exclude_owner_only_checks`, `test_revoking_the_consent_stops_the_workflow_before_any_request` |
| 21 | Encrypted database / vault / backup integrity and restore with AIV data | `test_backup_and_restore_keep_authorizations_plans_approvals_runs_observations_and_templates` |
| 22 | New CLI adapters tested against pinned fixtures and a local lab | `test_aiv_tools.py` (real captured output; stand-in programs; real-binary tests run where installed, e.g. the Linux image) |
| 23 | Windows and Kali build, smoke and packaging | see "Builds" below |
| 24 | Display-name change preserves path, config, identity, keys, repository | `test_the_display_name_never_touches_identity_data_or_keys` and the other branding tests |
| 25 | All five AIV templates ship inactive; preview and simulated runs work | `test_every_aiv_template_is_valid_manual_only_and_passive`, `test_every_template_passes_its_fixture_dry_run_with_no_network_and_no_writes[AIV-0x]` |
| 26 | Sherlock/Maigret explicit confirmations unchanged | the pre-existing username-flow and adapter tests pass unchanged |

## DARKINT acceptance criteria (section 14.7)

| # | Criterion | Tests |
|---|---|---|
| 1 | Unentitled adapters labelled; no unapproved external traffic | `test_providers_report_one_honest_state_and_nothing_is_called_until_enabled`, `test_enabling_needs_admin_terms_and_an_automated_integration` |
| 2 | Unverified / expired consent blocks sensitive queries and monitoring; revocation cancels pending work | `test_no_consent_a_weak_consent_a_provider_outside_the_scope_and_revocation_all_block`, monitor tests |
| 3 | Domain-wide lookups need provider domain verification | `test_domain_wide_lookup_needs_the_provider_domain_verification_attestation` (you attest; this application cannot perform the provider's verification) |
| 4 | No plaintext passwords, hashes, SSNs, documents, dumps, tokens or card numbers in records, prompts, logs, notifications, exports | `test_sanitizer_redacts_secret_shaped_values_and_masks_addresses`, `test_manual_intake_and_imports_redact_and_never_keep_the_upload`, `test_audit_records_every_lookup_without_identifier_values`, `test_a_cloud_model_sees_counts_and_generic_text_only` |
| 5 | Manual password check leaves no persistent material | `test_password_range_check_keeps_no_password_or_hash_material` |
| 6 | Duplicates grouped, originals and provenance auditable | `test_duplicate_reports_group_but_every_original_and_its_provenance_stay` |
| 7 | A ransomware listing is not presented as proven compromise | `test_a_ransomware_listing_is_an_unverified_claim_and_says_so` |
| 8 | "Not checked" is never "no exposure"; negatives name providers and times | `test_not_checked_unknown_no_match_and_match_are_four_different_states`, `darkint.test.tsx` |
| 9 | Five templates validate, dry-run, ship disabled; live triggers need approval | `test_every_darkint_template_validates_ships_disabled_and_states_its_limits`, `test_dry_runs_are_simulated_contact_nothing_and_create_nothing` |
| 10 | Rate limits, missing credentials, offline, outages are truthful partial failures with no illicit fallback | `test_outage_rate_limit_and_offline_are_reported_as_such_with_partial_accounting`, `test_the_providers_documented_rate_limit_is_paced_locally_before_any_request`, `test_provider_problems_surface_as_the_specified_error_codes_not_as_empty_results` |
| 11 | Cross-case permissions, redaction, audit, consent-based retention and deletion | `test_other_users_and_viewers_cannot_use_or_see_another_cases_exposure_data`, `test_audit_records_every_lookup_without_identifier_values`, `test_purging_the_subject_removes_events_checks_monitors_and_reviews` |
| 12 | Encryption, rollback, upgrade from existing profile data, backup/restore | `test_darkint_data.py` (Windows here; Linux via the container run below) |
| 13 | Reports and AI cite evidence and give remediation without fabricating contents | `test_report_cites_evidence_names_sources_and_suggests_practical_steps_without_inventing_contents`, `test_summary_and_event_explanations_need_no_model_cite_evidence_and_never_invent_contents` |
| 14 | An authorized low-volume live test, only with approval | **not run** (needs your approval and your key) |

## Phases

| Phase | Status |
|---|---|
| AIV-0 / DARK-P0 | done: `docs/aiv-darkint-gap-analysis.md`, tag `pre-aiv-darkint` |
| AIV-1 | done: branding module, migration 0013, authorizations |
| AIV-2 | done: deterministic policy, typed plans, approvals |
| AIV-3 | done: HTTP/TLS/connect adapters, workbench UI |
| AIV-4 | done except ZAP import (not implemented); Nmap/Naabu/Nuclei/dnstwist fixture-tested |
| AIV-5 | done: five disabled templates, Copilot, profile tab |
| AIV-6 | done: report, handoff export, backup/restore test; builds below |
| DARK-P1 | done: migration 0014, consent provider scope, purge and retention |
| DARK-P2 | done: HIBP, Ransomware.live, manual / import; Intelligence X and MISP live not implemented |
| DARK-P3 | done: tab, dashboard, grouping, four-state coverage |
| DARK-P4 | done: DARK-01..05, monitors, remediation tasks |
| DARK-P5 | done: Copilot summaries, reports; live evaluation not run |

## What a reader should not infer

- "State: live" on a provider means *the next check will call its documented API*. It does not mean the integration was seen working against the real service.
- A green dry run proves the workflow shape and that nothing is sent; it proves nothing about a provider.
- The AIV checks describe an asset's observable posture from this machine at one time. They are not a penetration test and they are not exploitation.
