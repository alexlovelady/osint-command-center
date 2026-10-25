# AIV, DARKINT and rebrand (addendum v1.1): gap analysis and roadmap

Phases **AIV-0** and **DARK-P0**, written before code changed. Baseline: tag `pre-aiv-darkint` (commit `364c475`), 797 backend tests, 57 vitest and 24 Playwright tests green, Linux clean-checkout build `BUILD OK`. Nothing below is marked done unless a test in this repository exercises it.

## 1. What already exists and is reused

| Addendum need | Existing component | Decision |
|---|---|---|
| Deterministic policy, SSRF, DNS pinning | `policy/ssrf.py` (`validate_host`, `ip_is_public`, pinned-IP `SafeHttp`), `policy/engine.py` | Reuse the primitives. AIV adds a *scope-aware* gate on top (`aiv/policy.py`); `SafeHttp` follows redirects without scope knowledge, so AIV uses its own one-hop-at-a-time client |
| Bounded subprocess with process-group kill | `adapters/cli.run_argv` | Reused for every CLI tool; cancellation is added (kill on `CancelledError`) |
| Evidence, hashes, vault, audit chain, encrypted reports | `evidence/vault.py`, `telemetry/audit.py`, `reporting/store.py` | Reused unchanged |
| Active module | `adapters/active.TcpConnectAdapter` + `scope_authorizations` | Kept for legacy search runs. AIV does **not** reuse `scope_authorizations`: the addendum requires asset-owner proof, ports, paths, budgets and windows that table cannot hold (D-074) |
| Workflow engine, versions, approvals, run console, snapshots | `automations/*` | Reused. AIV/DARKINT add node types and templates to the same registry; no third scheduler. AIV nodes are manual-trigger only |
| Consent for a person | `subject_consents`, `profile/consent.py` | Reused for DARKINT (new source classes). Person consent never authorizes an asset (tested) |
| Exposure indicators, HIBP account check, Pwned Passwords relay, remediation, descriptor screening | `profile/exposure.py`, `lifecycle.py`, `exposure_indicators`, `remediation_tasks` | Reused. DARKINT adds provider framework + event/dedupe tables; the TP5 endpoints keep working. Remediation reuses `remediation_tasks` (new nullable `exposure_event_id`), not a second table (D-076) |
| Copilot, cloud reduced view, proposals | `copilot/*`, `profile_tools.py` | Reused: new read tools and one new proposal |
| Tool health / setup catalog | `copilot/context.tool_status`, `setup/catalog.json` | AIV tools get health records and install hints. **No download entries are added**: upstream checksums were not verified against live release assets here (D-075) |
| Theme tokens | `theme.css` | Reused; no new colours |

## 2. Gaps

| ID | Gap | Phase |
|---|---|---|
| A1 | No typed branding definition; "OSINT Command Center" is hard-coded in `App.tsx`, `Boot.tsx`, Tauri config | AIV-1 |
| A2 | No asset authorization with owner proof, ports, paths, exclusions, budgets, windows | AIV-1 |
| A3 | No plan/approval/run records; no version-bound single-use approval | AIV-1/2 |
| A4 | No scope-aware HTTP/TLS/port checks with per-hop redirect and resolved-IP enforcement | AIV-2/3 |
| A5 | No tool manifest/identity check (Python `httpx` is on this machine's PATH and is **not** ProjectDiscovery httpx) | AIV-3/4 |
| A6 | No Nmap/Naabu/Nuclei/dnstwist/ZAP adapters; no template allowlist by ID + hash | AIV-4 |
| A7 | No AIV node types, templates, workbench UI, Copilot explanation | AIV-5 |
| A8 | No AIV report or PHANTOM handoff export | AIV-6 |
| D1 | No provider registry with truthful states; no Ransomware.live, Intelligence X, MISP, manual intake | DARK-P2 |
| D2 | No cross-source incident grouping, four-state coverage ("not checked" vs "no match from checked sources") | DARK-P1/P3 |
| D3 | No monitor configs, DARK-01..05 templates | DARK-P4 |
| D4 | No cross-case dashboard, DARKINT report/AI summary | DARK-P3/P5 |

## 3. Decisions that depart from the addendum's literal text

1. **`asset_authorizations` is new and separate from `scope_authorizations`** (D-074). Both are checked independently; AIV never consults the legacy table.
2. **Added columns/tables beyond the addendum's list**, each justified: `aiv_approvals.uses` (single-use enforcement), `aiv_run_events` (the events endpoint needs a log), `aiv_template_approvals` (the Nuclei allowlist by ID + hash needs somewhere to live).
3. **No installer download entries** for Nmap, Naabu, Nuclei, dnstwist, ZAP, ProjectDiscovery httpx (D-075). The Tools page shows identity-checked health and the install hint (`apt install nmap` on Kali, upstream release page otherwise). Reason: pinned URLs and SHA-256 values must come from the upstream release assets, and copying unverified values would be a false claim.
4. **sslscan is not integrated**; TLS posture uses a built-in Python `ssl` adapter, which the addendum allows. Stated plainly in the tool matrix.
5. **AIV automation nodes accept manual triggers only.** The addendum allows a recurring approval with a maximum end date; v1 refuses schedules and events for any workflow containing an AIV node (stricter than required).
6. **DARKINT remediation reuses `remediation_tasks`** (D-076) instead of a new `exposure_remediation` table.
7. **Domain-wide breach lookups** need a recorded provider-side domain verification attestation on an asset authorization of type `domain` (the application cannot verify the provider's side). The record is labelled *attested by operator*, never *verified by the application*.
8. **Branding is configuration only.** Display name, short name, tagline and edition come from one typed definition. The Tauri `productName`, window title, publisher, bundle identifier, repository, package, data directory, environment variables and update keys are **not** changed in this addendum (owner approval checkpoint recorded; nothing renamed).

## 4. Provider and tool facts that shape the build

| Item | What the addendum allows | What this build does | Status label |
|---|---|---|---|
| Have I Been Pwned | account/domain indicators with consent and key | Existing TP5 account check moved behind the provider framework; domain search needs domain-verification attestation | mock-tested; **not live-verified**; paid key |
| Pwned Passwords | user-initiated k-anonymity | Existing TP5 relay (prefix only, nothing stored) | mock-tested; free |
| Ransomware.live | public feeds/API | Adapter against the documented API using fixtures captured from the published response shape; exact current endpoint terms checked at implementation | fixture-tested; live call only with owner approval |
| Intelligence X | licensed metadata search | Adapter present, returns `CREDENTIAL_MISSING` without a key; no raw content retrieval | not live-verified; paid |
| MISP | sanitised import from an authorised server | Import of sanitised STIX/MISP JSON exports plus a server connector that needs a URL and key | fixture-tested |
| Nmap, Naabu, Nuclei, dnstwist, ProjectDiscovery httpx | optional CLI adapters | Argv builders with allowlisted flags, pinned output fixtures; real runs against a local lab where the tool can be run in a container | per-tool label in `docs/integration-matrix.md` |
| ZAP | passive import only | Import of a ZAP report file; ZAP is never started by this application | fixture-tested |

## 5. Roadmap (dependency order; existing numbering untouched)

| Phase | Delivers | Acceptance tests (addendum section 12 / 14.7) |
|---|---|---|
| AIV-0 / DARK-P0 | this document, baseline tag | baseline green |
| AIV-1 | branding definition and API, migration 0013 (authorizations, plans, approvals, runs, observations, template approvals), authorization CRUD | 1, 2, 21, 24 |
| AIV-2 | `aiv/policy.py`, plan preview/create/approve/run API, budgets, single-use approvals | 3, 4, 5, 6, 7, 8, 14, 15, 16 |
| AIV-3 | HTTP metadata, TLS posture, bounded port adapters; Verification UI | 9, 10, 17, 22 |
| AIV-4 | Nmap, Naabu, Nuclei (ID + hash), dnstwist, ZAP import; tool health | 10, 11, 12, 17, 22 |
| AIV-5 | node types, AIV-01..05, Copilot, profile linking | 12, 13, 18, 25, 26 |
| AIV-6 | AIV report, PHANTOM export, packaging, backup/restore | 19, 21, 23 |
| DARK-P1 | migration 0014 (sources, events, reviews, monitors), consent scopes | DARK 2, 11, 12 |
| DARK-P2 | provider adapters, manual intake | DARK 1, 3, 4, 10 |
| DARK-P3 | profile tab, dashboard, grouping, four-state coverage | DARK 6, 7, 8 |
| DARK-P4 | DARK-01..05, monitors, remediation | DARK 2, 5, 9 |
| DARK-P5 | AI summaries, reports, evaluation | DARK 13, 14 |

Anything not finished is listed in `docs/progress.md` and `docs/backlog.md`.
