# Master Target Profile Enrichment: audit, design and status

Addendum: `Fusion_Master_Target_Profile_Enrichment_Spec.md`. Labels: **fixture-tested** (proven against synthetic responses and a mock transport), **not implemented**. Nothing here was exercised against a live third-party service in this build.

## TPM0: gap matrix (what existed, what changed)

| Spec requirement | Existing component | Change |
|---|---|---|
| Authorized inputs, consent, scope | `SubjectIdentifier`, `profile/consent.py` | reused; the editor writes inputs through `add_identifier`, so there is no second entry |
| Claims with review (employment, education, publications) | `ProfileClaim`, `review_claim` | reused as the backing store for those item types |
| Candidates, images, exposure, associated emails | `ProfileCandidateLink`, `ImageAsset`, `ExposureIndicator`, `AssociatedEmail` | shown read-only in the editor with their own state and a link to their tab (nothing copied) |
| Multi-value items with provenance | none | **new** `profile_items` (migration 0016) for facts without a store of their own |
| Email-first research | domain sources accepted emails (gmail.com offered RDAP/DNS/crt.sh) | **fixed**, see below |
| Cross-INT gaps and next actions | coverage matrix, expansion plan | **new** `profile/gaps.py` per-category status and "why missing" |
| Restricted fields | DARKINT sanitizer, masking | reused patterns; server-side filtering, owner-only audited reveal, token-only references |

## The email-first defect (confirmed bug)

Cause: the profile source registry listed `rdap`, `dns` and `crtsh` as accepting `email` identifiers, so the planner derived the address's domain and researched it. For `@gmail.com` that researched Google. For a custom domain it treated an email string as authorization to probe infrastructure.

Fix (central, not per screen):
- `rdap`, `dns`, `crtsh` accept `domain` only. A domain is researched only when the subject lists it as theirs (owned domain input).
- `profile/providers.py` holds an updateable shared-provider list (built in plus the `shared_email_domains` setting, admin-editable at `/profile/shared-email-providers`). Generic search planning and the expansion planner skip domain sources for such addresses.
- Four exact-email discovery adapters (`adapters/http/email_first.py`): `gravatar_email` (hash only is sent), `github_email_search`, `keyserver_email` (OpenPGP key server), and `web_search_email` (Brave Search, needs the user's key). They are public-site queries, so each run needs an explicit confirmation naming the third party, they never appear in generic username searches, and results are cited candidates, never inputs.
- When no adapter is configured the message is exactly **"No supported email-first discovery source configured."** The product never says "Nothing found" or "Research complete" for a source that did not run.
- Password-reset and login probing are not implemented and not planned.

## What was added

- **Master Profile Editor** (`profile/master.py`, `api/v1/profile_master.py`, UI `MasterProfile.tsx`): 13 categories; every item shows value, state, origin, source, evidence, confidence, dates; states Unassessed / Candidate / Corroborated / Conflicting / Rejected / Not available; inline edit, add form, batch input and CSV/JSON import (bad rows reported, good rows kept), redacted export, duplicate review with reversible merge and undo, confirm/reject/needs-review with a recorded reason. Competing values are kept (a date of birth entered twice differently is shown as Conflicting). Self-attestation can never become corroboration (`self_attestation_only`).
- **Unified starting inputs:** an email, username, domain, URL, name, alias or organization entered once is a subject identifier; Associated Emails shows it under "Your inputs" and the research planner uses it. Discovered values are candidates and not inputs until a person chooses "Use as input" with a reason; a rejected candidate stays rejected and does not expand.
- **Gap analysis** (`profile/gaps.py`, `GET /subjects/{id}/master/gaps`): per category Has data / Needs verification / Searched, no match / Source unavailable / Awaiting authorization / Not attempted / Needs manual entry / Restricted, each with the reason; coverage is a count of categories with an attempted authorized method, labeled as not a percentage of what exists; ranked next actions.
- **Restricted data:** date of birth, phone, residential address, location history and identity references are masked server-side; viewers receive none of them; editors see masked values; only the case owner can reveal one, with a reason of at least ten characters, and the reveal is audited; identity-document and SSN references are stored as a masked form plus an HMAC token under a local key, can be compared but never revealed, and are omitted from exports, search, logs and model payloads. A revoked or expired authorization blocks recording and revealing restricted values.
- **Devices:** an inventory entry never causes a request. It is shown with whether a live asset authorization names the host; otherwise "an inventory entry is not permission to test it".

## Limits and honest gaps

- The four email-first adapters are fixture-tested against documented response shapes, not live-verified; GitHub anonymous search is rate limited; Brave needs the user's key.
- No face recognition, no covert device scanning, no password-reset/login probing, no automatic cloud-AI use of sensitive values.
- Images and documents: provenance is the imported file and hashes; reverse-image providers remain manual link-outs.
- Playwright coverage for the new editor is limited to the existing Profile tab flow; the component is covered by vitest.

## Migration 0016 and rollback

`0016_profile_items` adds only `profile_items`. Existing identifiers, claims, candidates, findings and evidence are untouched; the editor mirrors them on read and writes an item row only when a person adds a fact. Rollback: `alembic downgrade 0015` drops the table and nothing else (tested in `tests/integration/test_master_profile_data.py`); take the usual encrypted-data backup before upgrading.

## Acceptance tests (spec section 9)

| # | Test | Where |
|---|---|---|
| 1 | An owned email entered once feeds Associated Emails and research | `test_an_owned_email_added_once_appears_everywhere_without_re_entry` |
| 2 | Free-mail address never researches the provider's domain | `test_free_mail_inputs_never_research_the_providers_domain`, `test_the_shared_provider_list_is_updateable_and_applies_to_planning` |
| 3 | Custom-domain email does not authorize infrastructure research | `test_a_custom_domain_email_does_not_authorize_infrastructure_research` |
| 4 | Exact-email discovery yields cited candidates | `test_exact_email_discovery_returns_cited_candidates_and_never_inputs` |
| 5 | No provider -> clear warning, not "nothing found" | `test_no_provider_means_a_clear_warning_not_nothing_found` |
| 6 | Candidates are not inputs; rejected never expand | `test_discovered_values_start_as_candidates_and_rejected_ones_never_become_inputs` |
| 7 | Competing claims retained; merges reversible | `test_competing_values_are_kept_and_merges_can_be_undone` |
| 8 | Self-attestation is not corroboration | `test_self_attestation_is_not_corroboration` |
| 9 | Unresearched is not "not found" | `test_categories_without_research_are_never_reported_as_not_found` |
| 10 | Restricted values do not leak (API, export, audit, logs, search) | `test_restricted_values_do_not_leak_through_api_export_audit_logs_or_search` |
| 11 | Roles and authorization gate restricted fields | `test_roles_and_authorization_gate_restricted_fields` |
| 12 | Research contacts only what the preview listed | `test_research_contacts_only_what_the_preview_listed` |
| 13 | Images and documents show provenance and limits | `test_images_and_documents_show_provenance_and_provider_limits` |
| 14 | Device inventory cannot target unrelated devices | `test_a_device_inventory_cannot_target_unrelated_devices` |
| 15 | Existing data preserved, reads add nothing | `test_existing_identifiers_and_claims_appear_without_being_changed` |
| 16 | Batch/import behaviour | `test_batch_and_file_import_keep_good_rows_and_report_bad_ones` |
| 17 | Migration upgrade/rollback | `tests/integration/test_master_profile_data.py` |
| UI | Editor behaviour | `masterProfile.test.tsx` |
