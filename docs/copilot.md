# AI Investigation Copilot & Interactive Tutor

A panel on every page (button **Copilot**, top bar or bottom right). It is built on the existing AI layer (profiles, case policy, consent tokens,
citation checks) and adds a knowledge base, live-state facts, tools with approval, per-investigation history and a tutorial overlay.
It is **not** a general chatbot: for questions about the application it answers only from documentation the app ships, and it says so when it has none.

## Modes

| Mode | For | Works from |
|---|---|---|
| **General** | OSINT concepts, methodology, how the app works | the knowledge base (modules, tutorials, glossary, error codes, synced docs, live tool manifests) |
| **Investigation** (inside a case) | summarise, compare sources, conflicts, gaps, confidence, next steps, timeline | the case's stored findings / notes / evidence / observations (restricted items withheld), live state |
| **Tutor** | walkthroughs, "how do I", troubleshooting | tutorials, module docs, real tool status and run errors; highlights the real controls (`data-tour`) |

Switching modes keeps the conversation (history is per user and per investigation). Beginner/Advanced changes the explanation and the tutorial text.

## What it can do

* **Explain** every page and case tab, terms (glossary), errors (every API error code a person can act on), and tools (descriptions come from each adapter's manifest and live health, never from the model).
* **Recommend next steps** (button, or "what should I do next"): prioritised, each with the numbers it is based on and a *Go to* link. Rule-based over case state (no purpose, no targets, failed/partial runs, unhealthy tools that were used, unanswered requirements, conflicts, single-source statements, low confidence, unverified claims, alerts, withheld items, stale data, no report). Works with no model.
* **Find conflicts** (same subject + predicate, different values, side by side; never resolved automatically), **timeline** (published vs observed time stated), **case summary**, **confidence explanation** (from the stored reason).
* **Diagnose** a tool or a run from its health check, key presence and recent job error codes, then the documented fix and healthy alternatives for the same target type.
* **Guided walkthroughs** for first-run setup, creating a case, first search, judging evidence, imports, reports, models, backups. Each step navigates and highlights the actual control; if the control is not on screen it says so.
* **Search the documentation** (panel -> *Search docs*) and open any source it cited.
* **Propose actions** (nothing runs without you): `start_search`, `create_note`, `create_requirement`, `generate_report` (restricted material withheld), `run_workflow`. Read tools (`list_tools`, `tool_status`, `search_docs`, `case_summary`, `search_evidence`, `find_conflicts`, `timeline`, `recommend_next_steps`, `preview_search`, `run_status`) run immediately because they only read local state.

## Safety rules (enforced in code, not by the model)

1. Actions are **proposals** with a preview (for a search: each source, what it contacts, why it will or will not run). Approving is a separate authenticated request; it runs the **stored** arguments, needs the editor role, re-evaluates policy and case status, requires you to tick the confirmation for sources that need one, is single use, and is audited (`copilot.propose / execute / reject / refused`).
2. Hardware captures, API keys, secrets and settings are **not exposed** to the Copilot. It explains them and links to the page.
3. The model's text is checked: citations that do not match a record it was shown are removed; wording that claims an action was taken is flagged and a notice is appended; a reply with no citations is marked unverified and lists what the model was shown.
4. If the knowledge base does not cover an app question, or the case has no stored findings, the answer is deterministic ("not documented" / "no stored findings") and **the model is not called**.
5. Everything retrieved is wrapped as untrusted data; an uncensored model changes nothing about what the app allows.
6. Cloud models: only if you pick one **and** the case allows cloud **and** you approve the exact payload shown for that one message (token bound to the payload hash); restricted items never go; no tool rounds. A warning banner shows while a cloud model is selected.

## Models

Local by default (Ollama or llama.cpp on loopback; any installed open-weight model, including minimally restricted ones). The panel shows the active model, whether it is ready and why not; a picker switches per user (stored in the browser) and `PUT /api/v1/copilot/settings {profile_id}` sets the default. Streaming is NDJSON. Context is budgeted (`copilot_context_chars`, default 18 000 characters, oldest turns dropped first and counted) and Ollama requests ask for `num_ctx=8192`. No model, a missing model, or a model that dies mid-reply degrades to documentation/stored-data answers, labelled as such. No cloud key is ever required.

## Acceptance tests (all in `tests/integration/test_copilot.py` unless stated)

| # | Criterion | Tests |
|---|---|---|
| 1 | Works with a local model without internet | `test_local_model_streams_without_any_outside_connection` (Ollama protocol over a mock, only loopback contacted), `test_works_with_no_model_at_all_and_says_so`; **real model:** `scripts/copilot_live_check.py` |
| 2 | Explains every major module | `test_explains_every_module_from_its_documentation[...]` (one case per module: 7 pages + 16 tabs + concepts), `test_every_page_and_case_tab_has_documentation`, `test_import_documentation_lists_every_parser_the_backend_has`, `test_web_tab_list_matches_the_backend_tab_list` |
| 3 | Guides creation and management of investigations | `test_tutor_guides_investigation_creation_and_the_walkthrough_endpoint`, `test_tutorial_steps_point_at_real_routes_and_tabs`, `test_every_tutorial_highlight_target_exists_in_the_web_ui`; browser: `e2e/copilot.spec.ts` (tutor highlights the real input) |
| 4 | Analyses stored evidence with source references | `test_investigation_answer_cites_real_records_and_drops_invented_citations`, `test_other_cases_records_never_reach_the_model`, `test_evidence_text_cannot_inject_instructions_or_close_the_data_envelope` |
| 5 | Relevant next-step recommendations | `test_next_steps_are_relevant_prioritised_and_explained`, `test_requirement_gaps_and_conflicts_drive_recommendations`; browser: next steps + *Go to* link |
| 6 | Explains tool failures with real diagnostics | `test_explains_tool_failure_from_health_check_job_errors_and_real_alternatives`, `test_diagnosis_cites_only_documented_fixes`, `test_error_explanations_cover_codes_the_api_can_raise` |
| 7 | Never claims an action it has not performed | `test_a_reply_that_claims_an_action_is_flagged_and_nothing_ran`, `test_action_claim_detector_flags_claims_but_not_proposals` |
| 8 | Asks approval before sensitive tool operations | `test_start_search_is_only_a_proposal_until_a_person_approves_it`, `test_rejecting_does_nothing_and_proposals_cannot_be_widened_or_cross_cases`, `test_policy_is_rechecked_at_approval_and_offline_blocks`, `test_read_only_tools_run_without_approval_and_hardware_is_not_exposed`, `test_cloud_models_need_case_permission_and_an_exact_payload_approval`; UI: `copilot.test.tsx` |
| 9 | Preserves history across restarts | `test_history_is_stored_per_investigation_and_survives_a_restart`, `test_history_is_private_per_user_and_removed_with_the_case`; browser: history survives a reload |
| 10 | Windows and Linux | the whole suite runs on both in CI and the Linux container; frozen smoke includes a Copilot answer on both |
| 11 | Missing models, failed inference, corrupted records | `test_missing_model_is_reported_and_answers_degrade_gracefully`, `test_inference_failing_mid_stream_*`, `test_failure_before_any_output_falls_back_to_documentation`, `test_corrupted_conversation_records_are_skipped_not_fatal`, `test_unknown_conversation_and_hostile_context_are_rejected_or_ignored` |
| 12 | Does not invent features, tool capabilities or evidence | `test_undocumented_features_get_a_not_documented_answer_without_calling_the_model`, `test_empty_case_gets_no_invented_findings_and_no_model_call`, `test_tool_descriptions_come_from_manifests_not_from_the_model`, `test_uncited_model_answers_are_marked_unverified`, `test_search_ranks_and_flags_undocumented_topics` |

## API (all under `/api/v1/copilot`)

`GET status`, `GET suggestions`, `PUT settings` (admin), `GET conversations`, `POST conversations`, `GET conversation`, `DELETE conversations/{id}`,
`POST chat` (NDJSON events: `meta`, `tool`, `proposal`, `delta`, `final`, `approval_required`, `done`, `error`), `POST next-steps`,
`POST proposals/{id}/approve`, `POST proposals/{id}/reject`, `GET docs/search`, `GET docs/{id}`, `GET tutorials`, `GET tutorials/{id}`.

## Keeping it truthful

The knowledge base is data in `backend/osintcc/copilot/kb/` (`modules.json`, `tutorials.json`, `glossary.json`, `errors.json`) plus copies of user-facing docs
(`scripts/sync_copilot_docs.py`; a test fails if they drift). Tool descriptions are read from adapter manifests at runtime. Tutorial targets and tab names are
checked against the web source by tests, so renaming a control without updating its tutorial fails the build.

## Limits

Retrieval is lexical, so a question phrased with words the knowledge base never uses can get "not documented" even if the feature exists. Small local models
sometimes ignore the citation rule (the app then marks the reply unverified). Only Ollama with one model was exercised against a real model; llama.cpp and
cloud paths are covered by mocks. Hardware operations and settings are intentionally not available to the assistant.
