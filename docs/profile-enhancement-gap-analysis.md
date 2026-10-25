# Target Profile & Exposure Assessment (addendum TP-1.0): gap analysis and roadmap

Phase **TP0**, written before any code changed. Method: read the models (`backend/osintcc/db/models/__init__.py`, migrations 0001–0011), the API modules, the adapters, the Copilot tools, the automation engine, the web app and the tests. "Done" below means a test in this repository exercises it; nothing is marked done because a mock passed when the addendum asks for a live integration.

## 1. What already exists and will be reused (not rebuilt)

| Addendum need | Existing component | Reuse decision |
|---|---|---|
| Case, roles, case-scoped access, 404 on non-members | `cases`, `case_members`, `case_for()` | Every new route uses `case_for()`; viewer reads, editor writes, owner revokes/purges |
| Evidence vault, hashes, chain of custody | `evidence`, `evidence/vault.py` (AES-GCM) | Images, consent proofs and report citations are ordinary `Evidence` rows |
| Encrypted storage at rest | SQLCipher database (HKDF subkey of the vault master key); `OSINTCC_VAULT_KEY`/keyring; fail-closed without key | All new tables live in the same encrypted database; no second store |
| Tamper-evident audit | `audit_events` hash chain, `telemetry/audit.py` | Every sensitive read, export, verification, approval and deletion calls `audit.record` |
| Username lookups | `SherlockAdapter`, `MaigretAdapter` (`public_site_query`, confirmation-gated), previews fixed this week | They emit `profile.candidate` findings with `url` entities: the input to the candidate queue |
| Passive domain/org sources | RDAP, DNS, crt.sh, Wayback, Subfinder, Amass, SEC EDGAR, OpenCorporates adapters | Registered in the category-aware source registry |
| Plan → approve → run | `search/service.py` (`build_plan`, `create_run`), `collection_plans`, runner, SSRF `SafeHttp`, egress self-check | Research plans call the same functions per identifier; no parallel network path |
| Scope/authorization | `scope_authorizations` (infrastructure scope), policy engine | Unchanged. Infrastructure scope stays separate from person consent (addendum 7) |
| Claims, verification, reversible links | `claims` (`unverified/analyst_verified/disputed/rejected`), `entity_links` (reversible merge) | The profile reuses the *pattern* (analyst-only verification, reversible); person claims need more states, see §3 |
| Findings with confidence labels | `findings`, `graph/fusion.py` (`confidence_label`) | Candidates are derived from findings; confidence rules are not changed |
| Document metadata | `ingest/docs.py` (PDF/DOCX static inspection, no execution), `ingest/exiftool.py` | Reused for the published-document disclosure review |
| Automations (typed, approval-gated, DST-aware) | `backend/osintcc/automations/*`, 30 templates, fixtures, validator | The 12 TP templates are authored in the same format and run by the same engine |
| Copilot (tools, proposals, honesty guard, cloud transfer token) | `copilot/*` | New read tools and one approval-gated proposal are added to `TOOLS`; no new chatbot |
| Reports with redaction | `reporting/build.py`, `report_runs`, restricted-item withholding | Subject reports build on it and add citation verification |
| Backup/restore, retention listing | `backup.py`, `/system/retention/due` | New tables travel in the encrypted backup automatically; a retention-action table is added |
| Theme | `theme.css` tokens (`--c-*`) | New screens use existing classes (`card`, `badge`, `banner`, `tabs`) and tokens only |

## 2. Gaps (what is missing today)

| ID | Gap | Phase | Notes |
|---|---|---|---|
| G1 | No subject/profile concept: a person case is a bag of targets and findings | TP1 | `subjects`, `subject_identifiers`, `profile_claims` |
| G2 | No person-case landing page; `CaseView` opens on **Search** | TP1 | Target Profile becomes default for `people`/`identity` cases; old tabs kept under **Advanced workbench** |
| G3 | Username hits are only graph edges/findings: no queue, no ownership decision, no dedup across tools by canonical URL | TP2 | `profile_candidate_links` + review events |
| G4 | No per-person consent/authorization record with proof, expiry, revocation, source classes | TP5 (model in TP1) | The existing `consent_authorizations` table is **HUMINT source consent**, a different concept; see D-067 |
| G5 | No category-aware source registry (data classes, privacy class, cost, maturity) | TP3 | `profile/registry.py` |
| G6 | No bounded research plan per subject, no coverage grid | TP3 | `research_tasks` |
| G7 | No person-oriented templates | TP3 | 12 templates (TP-01..TP-12 in the library) |
| G8 | No image handling beyond EXIF in generic ingest; **Pillow is not a dependency** | TP4 | Pillow added; hashes implemented in-house on numpy (no `imagehash`, no OpenCV, see D-069) |
| G9 | No exposure model, no remediation tracking, no breach provider | TP5 | `exposure_indicators`, `remediation_tasks`, provider adapters |
| G10 | No correction/dispute or retention-action records | TP5 | `subject_corrections`, `retention_actions`, purge preview |
| G11 | Copilot has no profile-aware tools | TP6 | Deterministic tools; a model only phrases results |
| G12 | Reports do not distinguish analyst vs subject-visible content or verify citations | TP6 | Subject report builder with `verify_citations()` |
| G13 | No synthetic consented-client scenario, no Kali field check for these features | TP7 | Scenario test runs in CI; Kali check is the owner's step and stays *unchecked* until done |

## 3. Design decisions that depart from the addendum's literal text

1. **Table names.** `consent_authorizations` already means HUMINT source consent, so subject consent is stored in **`subject_consents`**. Same fields as the addendum. (D-067)
2. **Claim states.** The addendum's states (`verified`, `subject-confirmed`, `candidate`, `conflicting`, `rejected`, `not assessed`) are stored in `profile_claims.validation_state`; the existing `claims` table is not altered because other features and exports depend on its three-value check constraint. (D-068)
3. **No `imagehash`/OpenCV.** Average, difference and DCT hashes are ~60 lines on numpy + Pillow and avoid SciPy/PyWavelets/OpenCV (large, hard to package into the 71 MB sidecar). The cost is no feature-point matching: heavily cropped, rotated or composited copies are *not* found, and the UI says so. (D-069)
4. **Sensitive values are never stored in cleartext columns beyond what is needed.** The database is already encrypted. Identifier values live in `subject_identifiers.value` (needed to run searches); *exposure* rows have **no value column at all** (only a masked descriptor validated against a mask pattern). (D-070)
5. **Password exposure check runs in the browser.** The browser hashes locally and sends only a 5-character prefix to the backend, which relays the range query. The backend never receives the password or the full hash and persists nothing. (D-071)
6. **Existing people cases are upgraded lazily and idempotently** (first open of the profile) with the same function that the migration test calls; nothing in the old tables is modified. (D-072)
7. **No auto-pivot.** New identifiers found during collection (emails in documents, handles in profiles) become *unresolved leads*; they only become research inputs when a person adds them.

## 4. Provider and legal restrictions that shape the build

| Provider / activity | What the addendum allows | What this build does | Status |
|---|---|---|---|
| Sherlock / Maigret | Public handle checks | Existing adapters; results are leads; dedup by canonical URL | Live-tested earlier |
| Have I Been Pwned (account breaches) | Owner-verified, licensed API key | Keyed adapter + domain-verification note; **no key available here** | Mock-tested only; **not marked live** |
| Pwned Passwords range API | k-anonymity | Prefix-only relay; free; no key | Fixture-tested; live call not exercised in CI |
| Google Lens / Bing Visual Search / TinEye | Interactive or commercial access only | **Link-out and manual result entry only**; no scraping, no automation, no CAPTCHA handling | By design, never "automated" |
| SSN / national ID lookups | Only verified-owner checks by a legitimate provider | **Not implemented.** No field, route or adapter exists | Intentionally absent |
| Face recognition / identity from faces | Forbidden | **Not implemented**; a test scans the code base for biometric terms | Intentionally absent |
| Background-check / people-search brokers | Not listed | Not integrated | Out of scope |
| LinkedIn and other authenticated sites | No scraping behind authentication | Not integrated; claims from such pages are entered manually with a citation | Manual only |

## 5. Phase roadmap (dependency order) and acceptance mapping

| Phase | Delivers | Acceptance tests |
|---|---|---|
| **TP1** | Migration 0012 (all addendum tables), lazy upgrade of existing person cases, subject/identifier/claim API, **Target Profile** page as default for person cases, Advanced workbench | TP-01, TP-02 |
| **TP2** | Candidate queue from Sherlock/Maigret findings, canonical-URL clustering, bulk review with reversal, timeline/graph link | TP-05, TP-06, TP-07 |
| **TP3** | Source registry, research preview/approve with bounded budget, coverage grid, 12 templates + fixtures | TP-03, TP-08, TP-23, TP-25 |
| **TP4** | Safe image import, EXIF, perceptual matching, manual reverse-search flow, privacy-aware GPS | TP-11, TP-12, TP-13, TP-14, TP-21 |
| **TP5** | Verified consent (self/client/organization), fail-closed gates, exposure indicators, password prefix check, remediation, corrections, retention | TP-04, TP-15, TP-16, TP-17, TP-19, TP-26 (part) |
| **TP6** | Copilot tools, subject/analyst reports with citation verification | TP-09, TP-10, TP-18, TP-20, TP-22 |
| **TP7** | Regression, Linux clean-checkout build, docs, Kali instructions | TP-24 (Kali physical check stays with the owner) |

Anything not finished is listed in `docs/progress.md` under "TP-1.0 status" and in `docs/backlog.md`.
