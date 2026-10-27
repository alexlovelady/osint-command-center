# Provider quotas, the durable queue and credentials

Addendum PQ-1.0. This page is the operator guide, the call-site inventory, the verification report and the migration notes. The enforced limits are in
[provider-limit-matrix.md](provider-limit-matrix.md) (generated from the code, so it cannot drift).

**In one sentence:** every request to a metered provider is reserved in a shared, persistent budget *before* it is sent; when a budget is full the work waits and says so, it is never
dropped, never shown as finished, and never turned into a "no match".

## What you will see

| Where | What |
|---|---|
| Investigation → Overview | `completed · no match · running · queued · waiting for limits · blocked by key or plan · failed · remaining`, and (when relevant) a banner: *N checks are waiting for a provider's limit to reset… earliest around HH:MM UTC (an estimate, not a promise)*. The status reads **Waiting for provider limits**, never **Complete**. |
| Home | The same counts on each investigation card. |
| Settings → SEC EDGAR contact | `Unsaved changes` → `Saving…` → `Saved at …` (read back from the database), or `Failed to save` with the reason. The value is shown, not masked, and is still there after a reload or restart. |
| Settings → Provider usage | Per provider: credential state, the four separate checks (stored / verified by a real call / endpoint supported / quota available), what is left in each window and when it resets (UTC), queued work, the last response, **Test**, **Try again**, **Turn off**, **Pause all provider work**, and the **$0 spend guard**. |
| Advanced mode → Provider usage → *queue and activity ledger* | Every queued task with its status, attempts and earliest run time; the last requests with provider, action, time, HTTP status and whether the provider counted it. No keys, no searched identifiers. |

### Credential states (plain language)

| State | Meaning |
|---|---|
| Not configured | No value is stored. Nothing is sent. |
| Stored (not yet tested) | A value exists. **This is not a claim that it works.** |
| Verified by a real call | The provider accepted a real request made with it; the time is shown. |
| Rejected by the provider | HTTP 401. Fusion will not retry it until you replace it (a new key is a new identity) or press *Try again*. |
| Wrong format | The value is not a kind this adapter can send (for Censys: neither a Personal Access Token nor an `API_ID:API_SECRET` pair). |
| Plan restricted | HTTP 403: the account's plan does not include the operation. Not retried. |
| Quota used up (waiting for reset) | A window is empty. Work queues and resumes by itself. |
| Disabled by you / Disabled — paid provider | Switched off. Queued work for it is not sent. |

## Setting up each provider

1. **VirusTotal.** Settings → API keys → VirusTotal. Public (free) API only, which VirusTotal restricts to personal, non-commercial use. Fusion therefore uses it automatically only for a personal self-audit; a business, client or organization investigation shows it as **blocked** until you tick *I hold a VirusTotal licence that covers business or client use* (Fusion cannot check that; it only stops blocking). The tick is re-checked when queued work resumes. Pacing: 4 per rolling minute, ≥16 s apart, 500 per UTC day. Twelve lookups take about three minutes.
2. **urlscan.io.** Add the key, then **Test**: this reads *your account's* quota table and replaces the default limits with your real ones. Searches, result retrievals and (never used) scans have separate budgets. Fusion never submits a scan.
3. **Censys.** Create a **Personal Access Token** (Censys account menu → API Access) and paste it under *Censys*. Fusion sends it as `Authorization: Bearer …` to `api.platform.censys.io`. It is never converted into an ID:secret pair; a legacy `API_ID:API_SECRET` still works through the older endpoint if you have one. Free plan: 100 credits per month, one request at a time, lookups only; search is never called.
4. **Brave Search.** Add the key. Brave reports your plan's per-second and per-month limits in the response headers, so *quota available* stays "unknown" until the first request. Paid overflow is never enabled.
5. **SEC EDGAR.** Type your name and email (e.g. `Jane Analyst jane@example.org`) and press Save. It is sent as the User-Agent. Paced at 5 requests/second across the whole application (the SEC's ceiling is 10). Without a valid contact no request is sent and the check is shown as blocked, not completed.
6. **Shodan.** Not used. It shows **Disabled — paid provider**, is excluded from automatic planning and is never contacted, even if a key is stored.
7. **OpenCorporates and others.** No quota is assumed to be free or commercial; unknown limits are reported as unknown.

### Controls

- **Pause all provider work** holds every queued task (nothing is lost) until you press Resume.
- **Turn off** a single provider. Queued tasks for it show `disabled` and are not sent.
- **Stop** an investigation cancels its queued provider tasks. **Cancel queued work** (Provider usage) cancels every waiting check in every investigation, after a confirmation; those investigations finish *complete with limits* ("queued checks were cancelled"), never "complete", and **Refresh results** runs the cancelled checks again.
- A queued task is **re-authorized when it runs**: if the case is closed, offline mode is on, or the authorization was withdrawn or expired meanwhile, it is not sent and shows *awaiting authorization*.
- **Caching.** Fusion does not ask a source about the same input again unless you press *Check for more* or *Refresh results*; every answer is stored as evidence with its retrieval time, so repeating a question only to see the same answer never spends quota.
- Nothing ever purchases credits, upgrades a plan, or enables overflow. There is no code path that could.

## Task statuses

`planned, queued, running, completed, no_match, partial, deferred_rate_limit, deferred_daily_quota, deferred_credits, blocked_credentials, blocked_plan, awaiting_authorization,
transient_error, permanent_error, cancelled` and one addition, `disabled_provider` (a source you or the app switched off; needed so it is not confused with a setup failure).

| Provider said | Task becomes | Retried? |
|---|---|---|
| 200 with data | completed | — |
| 200 / 404 with nothing, from a source that really answered | no_match | — |
| 401 | blocked_credentials | never, until the key changes |
| 403 | blocked_plan | never, until the plan/key changes |
| 402 / no credits | deferred_credits | at the next monthly reset |
| 429 | deferred_rate_limit / deferred_daily_quota | at the reset the provider states (`Retry-After`, `X-Rate-Limit-Reset…`, body), otherwise bounded exponential back-off with jitter (30 s doubling to 1 h, at most 8 waits) |
| timeout, network error, 5xx | transient_error | up to the job's attempt limit (3), then it stays failed and visible |
| budget full locally | deferred_* | automatically, at the computed reset |

## How it works (short)

- `backend/osintcc/quota/` holds the catalogue (`catalog.py`), the dispatcher (`service.py`), the HTTP gate (`gate.py`), outcome classification (`outcome.py`), the durable resumer (`resume.py`) and credential/contact checks.
- Every adapter already talks through `ctx.http`. The application wraps **every** context it hands out (including test and plugin seams) in `GatedHttp`, which asks the dispatcher first. Nothing had to be edited in the adapters to be rate limited, and an adapter cannot opt out.
- A reservation is written to `provider_ledger` (encrypted database) under one lock *before* the request; windows are computed from that ledger, so counters survive a restart. The provider's own headers override the local estimate. If the ledger is busy the answer is "not now", never "go ahead".
- A refused or deferred job keeps its place in `jobs` (status `deferred`, `next_retry_at`, `quota_status`). A background resumer (3 s tick) re-runs jobs whose reset time has passed and relaunches investigations parked in `waiting_limits`. The investigation's 30-minute allowance counts working time, not time spent waiting.
- `provider_state` records, per provider and credential *fingerprint* (a truncated one-way hash, never the key), what the provider taught us and what you switched off. Changing the key starts a clean slate.
- Counts are Fusion's own estimate. If the same account is used elsewhere the provider's headers (when sent) take precedence; otherwise an outside user can still exhaust a quota, and the resulting 429 is handled as above.

## Call-site inventory (no bypass)

Everything that can reach a metered provider goes through `ctx.http`: the job runner, expansion/one-click research, Advanced searches, workflows and automations (they run jobs), the exposure and DARKINT checks (`st.runner.ctx_factory()`), the MCP server and Copilot tools (they start runs). The only other HTTP clients in the code base, and why they are outside the dispatcher:

| Module | Purpose | Metered provider? |
|---|---|---|
| `policy/ssrf.py` | the SSRF-safe client the dispatcher wraps | — |
| `adapters/active/http_metadata.py` | AIV check of an asset the operator owns | no |
| `ai/providers.py` | local Ollama and optional cloud model endpoints | no (LLM, separate consent) |
| `api/v1/updates.py` | signed update manifest and download | no |
| `automations/notifications.py` | operator-approved webhooks | no |
| `setup/installer.py` | pinned tool and model downloads | no |

Two automated tests keep this true: a file that names a metered provider's host may not also build its own HTTP client, and the set of modules that build HTTP clients is fixed.

## Verification report

Run on 2026-10-27 with the fake clock and mock transports described below.

| Requirement | Evidence (tests in `tests/integration/test_provider_quota.py`) | Live? |
|---|---|---|
| 12 VirusTotal lookups spread safely; never 4 at once | `test_twelve_virustotal_lookups…` (≥16 s gaps, ≤4 in any 60 s, ≈3 min total) | fixture |
| 501st daily request waits for UTC reset; survives restart | `test_the_501st_daily…`, `test_deferred_work_resumes_by_itself_after_a_restart…` | fixture |
| Two investigations cannot oversubscribe one credential | `test_two_investigations_sharing…` (8 threads, 1 slot, exactly 1 granted) | fixture |
| urlscan buckets independent; headers and 429 reconciled | `test_urlscan_actions…`, `test_urlscan_headers…`, `…test_button…quota_table` | fixture |
| Censys PAT format, one concurrent, 100-credit ceiling, paid operation blocked | `test_censys_*` | fixture |
| 401 / 403 / 402 / 429 / timeout / 5xx / no-match / disabled / expired authorization → distinct states, bounded retries, no false completion | `test_each_virustotal_answer…`, `test_a_rejected_key…`, `test_timeouts…`, `test_a_provider_the_operator_turned_off…`, `test_authorization_is_checked_again…` | fixture |
| EDGAR contact: validated, saved, read back, persists across restart, blocks when missing, sent as User-Agent, paced | `test_edgar_*`, web `quota.test.tsx`, e2e `settings: the SEC contact…` | fixture |
| VirusTotal public API blocked for business or client use until a licence is confirmed; re-checked at dispatch | `test_virustotal_public_api_is_blocked…` | fixture |
| Global cancel; cancelled work never runs and the investigation says so | `test_cancel_queued_work…` | fixture |
| Shodan never planned or contacted by default | `test_shodan_is_disabled_by_default…` | fixture |
| One-click dashboard shows why it is partial, what waits, when it resumes | `test_one_click_investigation_shows…`, web `Investigations waiting for limits` | fixture |
| Migration 0018 additive, keeps data, rolls back | `test_migration_0018_…` | real SQLite file |
| No secret in ledger, state, queue, usage view | `test_the_ledger_and_state_tables…`, `test_usage_view…`, `test_queue_and_ledger…` | — |
| No call path bypasses the dispatcher | `test_no_code_path…`, `test_the_only_modules…`, `test_every_context…` | — |

### What was **not** verified live

Nothing in this build contacted VirusTotal, urlscan.io, Censys, Brave, the SEC or Shodan. These are therefore **fixture-only**: the exact JSON shape of the Censys Platform host response (the parser tolerates the documented `result`/`resource` wrapper
but was not checked against a real response); the Brave `X-RateLimit-*` header values (format taken from Brave's documentation); the urlscan.io `/api/v1/quotas` payload shape (parsed defensively; unknown fields are ignored); VirusTotal's `QuotaExceededError` body;
the first-of-the-month Censys credit reset (assumed, not documented); and whether each provider counts a timed-out request (treated as spent). Use **Test** on a provider once to turn "assumed" into "seen".

### Remaining gaps

- Censys and Shodan are reachable only from Advanced searches on an IP; the one-click planner offers VirusTotal and urlscan.io for owned domains, not Censys, because it has no source of IPs it may use as inputs.
- An outside user of the same account can exhaust a quota Fusion cannot see; the provider's 429 then defers the work.
- The ledger is guarded by one in-process lock: run one backend per data directory (the app already does).

## Migration and backup

Migration `0018_provider_quota_ledger` is additive: two new tables (`provider_ledger`, `provider_state`) and seven defaulted columns on `jobs`. The app keeps `osintcc.pre-0017.bak` automatically before upgrading.

1. Back up the data directory first (copy it, or use the encrypted backup). **Do not touch the live database until the copy has been opened successfully.**
2. Rehearse: copy the backup to a scratch folder and start the new build with `OSINTCC_DATA_DIR` pointing at it. Cases, evidence and stored key references must all be there. Provider usage will show empty counters (history starts now).
3. Rollback: stop the app, restore the copy (or run `alembic downgrade 0017`, which drops only the new tables and columns; queued provider work is then no longer deferred but stays in `jobs`).
4. Stored keys are untouched: they stay in the operating system's credential store.
