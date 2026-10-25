# Associated Email Discovery and Cross-INT Correlation: audit, design and status

Addendum: `Fusion_Associated_Email_Cross_INT_Correlation.md`. Labels: **fixture-tested** (proven against recorded or synthetic responses and a mock transport), **simulated** (dry run), **not implemented**. Nothing here was exercised against a live third-party service in this build.

## Audit before the change (what already existed)

| Need in the addendum | Existing component | Gap |
|---|---|---|
| Authorized target, consent, scope, expiry, revocation | `profile/consent.py`, `subject_consents`, research execution gate | none; reused unchanged |
| Evidence vault, hashes, provenance | `jobs/runner.persist_result`, `Evidence`, `Finding` | none; reused |
| Shared entity graph and timeline | `Entity`, `Relationship`, `RelationshipEvidence`, `profile/timeline.py` | emails were not entities of the profile graph or on its timeline |
| Candidate -> review -> confirm pattern | `profile/candidates.py` (accounts), `ProfileReviewEvent` | no equivalent for email addresses |
| Source registry and planning | `profile/registry.py`, `profile/research.py` | explicitly **no recursion**; no adapter that surfaces contact addresses; theHarvester emails only as unlisted leads |
| Exposure for an identifier | `darkint/*`, `profile/exposure.py` | not connected to addresses found elsewhere; a candidate must never reach a provider |
| Automation, Copilot | automation registry, `copilot/*_tools.py` | no email or cross-discipline planning tool |

## What was added (reusing the above; no second graph, scheduler or breach store)

- **Discovery adapters** (`adapters/http/contacts.py`): `github_public` (profile contact field and commit author addresses; GitHub's anonymous `noreply` addresses are dropped; classed as a public-site query, so it always needs an explicit confirmation like Sherlock) and `page_contacts` (one public page: `mailto:` links, written and "name [at] host [dot] tld" addresses, each with its own sentence; scripts are not read). Both report real status (`rate_limited`, `partial`, "no account" is not a negative result).
- **Associated emails** (`profile/emails.py`, table `associated_emails`, migration 0015): evidence-linked candidates with a derived, explainable classification **Confirmed / Likely / Possible / Rejected**; per-source independence groups; conflicts (a source attributing the address to another name, or another subject in the case already holding it); deduplication (case, Gmail dots and `+tags`) and merge that keeps every source; analyst confirm/reject/annotate/reopen, individually or in bulk, recording `analyst_attested` or `independently_corroborated`; a confirmed address can be added as an input; graph entity and relationship status follow the decision; timeline entries. Passages around an address are redacted for secrets and other people's addresses before being stored.
- **Cross-INT expansion** (`profile/expansion.py`, table `expansion_runs`): seeds are the subject's inputs and CONFIRMED addresses only; Likely addresses appear as "confirm first", Possible as "lead only", Rejected are counted and ignored. Steps come from the existing source registry and the existing consent gate for each exact identifier; exposure checks (DARKINT) and active verification (AIV) appear as proposals that need their own approval and are never started here. Limits: depth (1-4, default 2), total source runs (default 20, max 100), runs per pass (default 6), authorization, offline mode, closed case; every pass records why it stopped. Free-mail domains do not trigger domain lookups. Execution goes through `research.approve`, so SSRF, rate limits, hashing and the run-time authorization re-check are the ones every search uses.
- **Copilot** (`copilot/email_tools.py`): `associated_emails_summary` and `plan_cross_int` (read), `propose_expansion_run` (approval-gated, one bounded pass). No tool can confirm, reject, merge or promote. Cloud models see counts only.
- **Automation:** node `associated_emails` (read-only) and template TP-13 (disabled, manual).
- **UI:** Target profile > Associated emails (table, why/evidence/conflicts, bulk decisions, duplicates, manual add, research plan, limits).

## Limits and honest gaps

- **Email-only start:** from one email the system can use public domain records (RDAP, DNS, certificate logs) when the domain is not a free-mail provider, and the stored evidence in the case. It has **no search engine or social-graph source**, so it cannot by itself discover a username or page tied to the email; an analyst adds a handle or a page URL, and the plan then offers the GitHub and page steps. Authorized breach providers are used for **exposure** of confirmed inputs, not to discover other addresses (domain breach lookups deliberately drop the local parts).
- GitHub and page extraction are **fixture-tested, not live-verified**. A commit author address is self-declared. Anonymous GitHub access is limited to 60 requests per hour.
- Exposure for an address appears only after it was confirmed, added as an input and checked through DARKINT under its own consent and provider rules.
- Image and document correlation reuse the existing image workbench and document importer; this change does not add automatic cross-matching beyond sweeping imported records that also name the subject.

## Acceptance tests (addendum section 8)

| # | Test | Where |
|---|---|---|
| 1 | Email-only investigations initiate permitted discovery | `test_email_only_investigation_initiates_permitted_discovery`, `test_a_free_mail_address_does_not_trigger_domain_lookups` |
| 2 | Evidence-backed associated addresses appear in the profile | `test_associated_addresses_appear_with_evidence_and_never_as_facts` |
| 3 | Cross-INT findings connect through the shared graph | `test_findings_from_several_disciplines_connect_in_one_graph_and_timeline` |
| 4 | Verified identifiers generate follow-up tasks | `test_unconfirmed_matches_never_trigger_expansion_and_confirmed_ones_do` |
| 5 | Unsupported matches cannot trigger expansion | same test; `test_a_speculative_pattern_is_labelled_stored_only_on_request_and_never_confirmable_without_evidence` |
| 6 | Recursion respects budgets, depth, rate limits, authorization | `test_recursion_respects_depth_budget_per_pass_and_ends_with_a_stop_reason`, `test_revoking_authorization_stops_expansion_before_any_request`, `test_offline_mode_and_a_closed_case_stop_expansion`, `test_a_new_address_is_not_covered_by_a_client_consent_that_names_its_identifiers` |
| 7 | Duplicates merge without losing provenance | `test_duplicate_spellings_merge_without_losing_any_source` |
| 8 | Rejected associations stop generating tasks | `test_rejected_associations_stop_generating_work_and_stay_rejected` |
| 9 | DARKINT receives only authorized identifiers | `test_exposure_checks_only_ever_receive_authorized_identifiers` |
| 10 | Sensitive credential material is not stored | `test_sensitive_material_near_an_address_is_never_stored_or_shown` |
| 11 | AI recommendations carry citations | `test_summary_separates_facts_hypotheses_and_rejected_and_cites_real_evidence`, `test_the_example_request_gets_a_scoped_plan_with_approvals_marked` |
| 12 | Adapters report real status and limits | `test_adapters_report_real_status_and_limits` |
| 13 | Existing cases, tools and workflows keep working | the pre-existing suites pass unchanged (counts in the commit) |
| 14 | Several disciplines contribute to one profile | `test_existing_evidence_from_other_modules_is_folded_in_only_when_it_names_the_subject`, the graph test above |

Negative cases covered: identity collision (another subject's input or confirmed address), scope revocation, a client consent that does not name the new address, a conflicting claim (a commit author with a different name), missing consent for exposure checks, viewer redaction, and rate-limited or absent sources.

## Results (Windows, 2026-10-25)

Backend 1036 passed / 2 skipped; ruff and mypy clean; vitest 73/73; Playwright 28/28 (axe light and dark where the specs run both); frozen backend smoke 60/60. The Linux clean-checkout build result is recorded in the commit that follows if it differs.
