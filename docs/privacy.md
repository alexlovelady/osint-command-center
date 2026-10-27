# Privacy and data handling

What the application stores, where it can go, and what it does not do. Written from the code and tests, not from intentions.

## Network behaviour

- **No telemetry, analytics, crash reporting, update pings or "phone home".** The only outbound requests are the ones in a plan you
  previewed and confirmed (and workflow/schedule steps you explicitly enabled), the optional map tiles you opt into, the AI endpoint
  you configure, the update check you press, and the downloads you confirm on the Setup page. Tests assert zero HTTP calls for
  previews, offline mode, unconfigured updates and a Setup plan. **Packet capture:** on Linux (container, so every packet is the
  app's) the packaged shell idling for 60 s plus a scripted pass through the no-network API paths produced no DNS, TCP or UDP
  packets at all (only kernel ARP/IPv6 neighbour chatter in the first two seconds); the Windows `pktmon` capture is in `docs/progress.md`. **Windows caveat:** the UI is rendered by Microsoft's WebView2 runtime, which on every observed
  launch opened two TLS connections to Microsoft by itself — the real `pktmon` capture shows the server name `substrate.office.com` (Microsoft 365)
  (the app's shell and backend opened none). Browser switches did not stop it; see `docs/progress.md` for how to block it with a firewall rule or use the Linux build. Third-party CLIs are run with their own phone-home disabled where they have one (Maigret's
  automatic database update is switched off).
- Offline mode denies every network adapter at plan time and again at run time.
- Every request an adapter makes goes through the SSRF-safe client, so a target cannot steer the app into your own network.
- Active probing (a TCP connect check) is not in the default registry; it needs `OSINTCC_ENABLE_ACTIVE=1` **and** an unexpired
  scope authorization covering the exact target **and** per-run confirmation.

## What is stored (in `OSINTCC_DATA_DIR`)

| Item | Where | At rest |
|---|---|---|
| Evidence (responses, imports, captures, HUMINT reports) | `vault/` content-addressed files | **AES-256-GCM**, key in the OS credential store; each object's tag is bound to its SHA-256 (swapping files is detected). Objects written before encryption was enabled stay plaintext until you run *Encrypt the N older objects* |
| Cases, findings, entities, claims, notes, audit log, settings, full-text index | `osintcc.sqlite` | **SQLCipher 4 (AES-256, per-page HMAC)**, key = HKDF subkey of the master key in the OS credential store. A plaintext database from an older version is migrated on first start (verified table-by-table); the plaintext original is kept as `osintcc.sqlite.plaintext.bak` until you remove it (Settings → Encryption & backup, which overwrites then deletes it). If the key is unavailable the app **refuses to start** rather than open or recreate the database |
| Secrets (API keys, vault key) | OS credential store; if none exists, API keys only: AES-256-GCM-sealed rows in the encrypted database | Never in files, audit metadata or artifacts; never returned by the API (only "set / not set") |
| Backups | `backups/*.zip.enc` | AES-256-GCM with your passphrase (scrypt-derived key). The database snapshot and vault objects are plaintext *inside* the encrypted container on purpose, so a backup restores on a machine with a different master key (the restored database is re-encrypted on first start). An explicitly "unencrypted" backup is possible and labelled |
| Reports | `exports/*.enc` | **AES-256-GCM** with the vault key (tag bound to the report id); the plaintext file is removed. Downloads decrypt for the authenticated caller. What you download or copy out is plaintext, so treat it accordingly. With encryption explicitly off, reports are ordinary files |
| Tools and models installed by Setup | `tools/` and the Ollama model store | Public binaries, not secret. Each download is SHA-256-pinned; Python tools live in their own virtual environments |

The local case search does **not** hide RESTRICTED rows (they are your own case's data); the MCP search and AI retrieval do hide them unless you opt in.

## Start-up egress self-check

Every launch, for 90 s (`OSINTCC_EGRESS_WINDOW_S`; off with `OSINTCC_EGRESS_SELFCHECK=0`), the backend samples the OS connection table for its own process
tree (desktop shell, backend, and the browser-engine processes the shell starts) every 2 s and records any non-loopback connection. The verdict
(`clean` / `engine_only` / `offending` / `unavailable`) is shown on the Overview page, served at `GET /api/v1/system/egress-check` and written to the
audit log as `selfcheck.egress`. Connections that appear after you start an action (search, download, job) are listed separately as user-confirmed
activity and never fail the check. It is a connection-level sampler, not a packet capture: it needs no administrator rights but can miss a
connection that opens and closes between two samples. On the development machine the real Windows desktop reported `engine_only` (WebView2's
connection to Microsoft; 25 samples, 0 from our code), matching the packet capture.

## Sensitive categories

- **Sensitivity labels** (`PUBLIC`, `INTERNAL`, `RESTRICTED`, `SECRET`) travel with evidence and observations. Positions, GPS tracks,
  private captures and HUMINT material default to `RESTRICTED`. Reports, search, MCP and AI withhold restricted items by default and
  round exported coordinates to ~1 km unless you tick the sensitive-export box.
- **HUMINT** stores aliases only (no real-name fields exist), requires a consent record, never computes a trust score, supports
  withdrawal with deletion of content, claims and index rows, and lists items due for retention without deleting them.
- **People**: no facial recognition, no automatic identity merging, no scraping behind logins, no use of leaked credentials.
  Username matches are leads. Monitoring an individual needs a recorded purpose and acknowledgement.
- **Hardware**: receive-only; no decoding of encrypted or private communications; GPS/NMEA positions are restricted; ADS-B/AIS
  identifiers are reported as received and never resolved to an owner.

## AI

Off by default; the app is fully functional without it. A local model receives only case-scoped retrieved snippets. A cloud model
additionally needs (1) the case to allow cloud use, (2) a preview of the exact payload, destination and an estimate, and (3) your
approval of a one-time token bound to that payload. Restricted material is never sent to the cloud when the case forbids it. Each
transfer is logged. Model output is never evidence: citations to evidence the model was not given are rejected and shown as rejected.

## AI Copilot and Tutor

The Copilot is a panel on every page (General, Investigation, Tutor). Its conversations are stored in the encrypted database, per user and per
investigation, and are deleted with the case (or with *Delete conversation*). It uses your **local model by default**; with a local model nothing
leaves the machine (only loopback is contacted). A cloud model is used only when you pick it, the case allows it, and you approve the **exact
payload** shown to you for that one message; restricted evidence is never included in a cloud payload. What the assistant sees for a case: stored
findings, notes, evidence titles and observations that match your question (restricted items withheld unless you tick the local-only box), tool
status, and the documentation. Keys are never given to it. It cannot approve its own proposals; running a search, saving a note or requirement,
generating a report or running a workflow happens only when you press *Approve and run*, and each approval is audited.

## Automations

Automations store workflows, immutable versions, approvals, run records (inputs digests, outputs, errors), snapshots of datasets used for change detection, and notifications, all in the encrypted database and removed with their case. They contact only the sources a workflow lists, after a scope check at run time. Notifications are local (in-app/desktop) unless you approved a webhook destination by name; a webhook receives a short summary, never evidence content. The AI builder uses your local model by default; a cloud profile receives nothing unless you opted that profile in, and then only your goal text and the list of available tools. Suggestions are off by default; when on they read only searches and reports you ran in this application.

## Deleting data

Case purge shows what will go and needs confirmation; it deletes that case's rows, vault objects and index entries and records an
audit event. Deleting a plugin never deletes evidence it produced. Backups are separate files you manage.

## Export and sharing

Nothing leaves the machine except by an action of yours (report download, backup file, copied text). The MCP server serves only the
cases you name when you start it, to the local client that launched it.

## Active verification (AIV) and exposure intelligence (DARKINT)

**AIV** is off by default. When an administrator switches it on, the only outbound requests are the ones in a plan a person read and approved once, against hosts, ports and checks named by a live asset authorization. Each request is re-checked immediately before it is made: authorization still live, scope unchanged, DNS answer public and the same address the connection uses. Stored evidence keeps header names and values but redacts cookie values. Asset authorizations, plans, approvals, runs and observations live in the encrypted database and are part of encrypted backups. A report or a PHANTOM handoff file is written only when a person asks; the handoff carries confirmed observations only, never raw responses, cookies or secrets, and launches nothing.

**DARKINT** never obtains, stores, displays or exports plaintext passwords, password hashes, session tokens, identity or payment numbers, or leaked records: the tables have no column for them, request models reject unknown fields, and every title, note and imported row passes a redactor before it is indexed. Events hold a masked title, data **categories**, the provider's own reference, dates and a keyed token of the identifier (not the identifier). Identifiers are sent to a provider only after a preview you confirm, only for a subject whose consent covers exposure checks for that identifier and provider, and each lookup is audited without the identifier's value. The Pwned Passwords check hashes in your browser and relays five characters; nothing about it is stored. Uploaded import files are not kept. Nothing is sent to a cloud model or webhook except counts and generic text. Deleting a subject (purge) removes its events, reviews, checks and monitors; earlier encrypted backups still contain them until you delete those backups. Provider terms differ (Have I Been Pwned requires attribution; Ransomware.live's free interface is labelled personal use only): read them in `GET /darkint/sources` before enabling a provider.

## Associated emails and the cross-INT plan

An address is stored as a **candidate** only when a stored source shows it; the passage around it is redacted for secrets and for other people's addresses before storage, and viewers see addresses masked and no passages. Nothing is guessed or tried. A candidate is not an input: it is never sent to a breach provider and no research runs from it. Only an address a person **confirmed** (with the owner's attestation or independent corroboration, recorded as such) can be added as an input, and then only inside what the authorization covers: a client consent that names its identifiers does not cover a newly found address until the owner extends it. A rejected address is never researched again. The plan runs passive, authorized steps only, within depth and budget limits; exposure checks and active verification keep their own previews and approvals. A cloud model receives counts and generic text only.

## One-click investigation

- An investigation starts only with a recorded authorization. Without one it stays a draft and nothing is contacted.
- Before it starts, the plan lists which providers would receive which input (host names included). Pressing Investigate approves exactly the providers left ticked; everything else is shown as needing approval. The investigation record stores that approval list and every step it took (`investigation_runs`, `investigation_events`).
- The investigation never researches from a found handle, address or link until a person confirms it and chooses Use as input. A mailbox provider's domain, or a domain implied by an email address, is never researched.
- Phone numbers, dates of birth, addresses and identity references stay masked in every API response, event, report and model prompt; phone numbers are not searched at all.
- Nothing is sent to a cloud model. Local AI is optional and does not receive restricted values.

## Provider usage ledger

Fusion keeps a local ledger of the requests it sends to metered providers (provider, action, host name, time, HTTP status, whether the provider counted it) in the encrypted database, so limits survive a restart. It contains no credentials and no searched identifiers.
A credential is represented only by a truncated one-way fingerprint. The SEC EDGAR contact is configuration (the name and email you typed for the SEC's User-Agent), not a secret, and is stored unmasked in settings. Nothing in the ledger leaves the machine.
