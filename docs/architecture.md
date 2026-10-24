# Architecture

Local-first workstation. One user, one machine, nothing listening beyond loopback. This file describes what is built; the
spec (`../OSINT_Master_Spec.md`) describes the intent. Where they differ, `docs/decision-log.md` says why.

```
┌──────────────────────────── desktop shell (Tauri v2, Rust) ───────────────────────────┐
│ empty capability set · strict CSP · kill-on-close job object (Windows)                │
│   starts ─► backend sidecar ─ stdout:  OSINTCC_READY port=<ephemeral> token=<random>  │
│   WebView ◄─ backend_info command (port, token); exit = authenticated /system/shutdown│
└───────────────┬───────────────────────────────────────────────────────────────────────┘
                │ HTTP on 127.0.0.1 + Authorization: Bearer <per-launch token>
┌───────────────▼────────────────────────  backend (Python, FastAPI)  ──────────────────┐
│ middleware: bearer auth · origin allow-list · security headers · error envelope       │
│ api/v1/*  routes (case-scoped membership checks; admin gate on global operations)     │
│                                                                                       │
│  policy ──► search/plan ──► jobs/runner ──► adapters (drafts only) ──► persist_result │
│   targets·ssrf·engine         ▲   │            http · cli · local · active ·plugins   │
│   (plan time AND run time)    │   └─ workflows/scheduler (data-only DAGs)             │
│                                                                                       │
│  ingest/*  import-only parsers ─► observations + entities + relationships (drafts)    │
│  graph/fusion · graph/correlate   claims · hypotheses · contradictions · cross-links  │
│  ai/*  (off by default)   mcp_server (stdio, read-only)   hardware/* (receive-only)   │
│  reporting/build  HTML · Markdown · JSON · PDF   backup (passphrase-encrypted)        │
│  telemetry/audit  hash-chained audit log                                              │
└───────────────┬───────────────────────────────┬───────────────────────────────────────┘
                │ SQLAlchemy 2 + Alembic        │ content-addressed vault (AES-256-GCM)
     SQLCipher SQLite (WAL, FTS5)          <data dir>/vault/<sha256 prefix>/<sha256>
```

## Rules that shape everything

1. **Adapters return drafts; the core persists.** An adapter (built-in, CLI, plugin) never touches the database or the vault.
   `jobs.runner.persist_result` stores the raw response as hashed evidence, then findings, then relationships, each with
   provenance. Nothing without evidence becomes a finding.
2. **Policy is checked twice.** At plan time (what would run, why it is allowed) and again at execution time, so a scope
   change, offline switch, revoked authorization or closed case stops queued work. Active adapters need an unexpired,
   unrevoked scope authorization covering the exact target.
3. **One HTTP path.** Adapters receive `SafeHttp`: every hop is resolved and validated (no loopback/private/link-local/metadata
   ranges), the connection is pinned to the validated IP, redirects are capped, bodies are size-capped.
4. **Suggestion ≠ decision.** Graph merges, cross-discipline correlations, AI output, workflow alerts and update checks are
   proposals. An analyst action creates the durable record, and it is reversible and audited.
5. **Confidence is a label with a published rule**, derived from independent source groups, never a probability.
6. **Case scoping.** Entities are namespaced per case. Cross-case linking does not exist; AI retrieval, MCP tools and search
   are filtered by case membership in the query itself.
7. **Fail closed on secrets and keys.** Encryption is `required` by default: one master key (OS credential store) protects the vault, the SQLCipher
   database and the reports; without it the app refuses to start rather than open, recreate or write plaintext. Secrets live in the OS credential store.

## Modules (backend/osintcc)

| Module | Responsibility |
|---|---|
| `main.py` | app factory, `AppState`, middleware, lifespan recovery (jobs, scheduler, plugins, hardware sessions), headless `run()` |
| `server.py` | entry point; `mcp` subcommand; `--run-script` (packaged plugin runner) |
| `config` | `Settings` (data dir, offline, vault mode, test seams) |
| `db` | models, `UTCDateTime`, Alembic helpers and migrations `0001`–`0009`; `encrypt.py` (SQLCipher key derivation, one-way plaintext→encrypted migration, plaintext snapshots for backups) |
| `policy` | strict target parsers, SSRF guard, policy engine |
| `adapters` | `IntelAdapter` contract, registry, `http/`, `cli/`, `local/`, `active/` |
| `jobs` | durable queue, retries/backoff, persistence of adapter results |
| `search` | plan building and previews |
| `ingest` | importers (`.eml`, SigMF, sensor CSV, JPEG EXIF, GeoTIFF, PCAP, STIX, SBOM, firmware, EDGAR submissions, sanctions CSV, chain CSV, telemetry CSV, CCSDS, pulse CSV, ADS-B, AIS, NMEA, PDF, DOCX, SpiderFoot) |
| `graph` | fusion (claims/confidence/contradictions/gaps), cross-discipline correlation, unified timeline |
| `workflows` | data-only DAG validation, wave execution, snapshot diffs, scheduler |
| `ai` | provider-neutral clients (Ollama, OpenAI-compatible), case-scoped retrieval, citation verification, cloud consent tokens |
| `mcp_server.py` | stdio JSON-RPC server; read tools; write tools that wait for out-of-band approval |
| `hardware` | receive-only driver protocol; simulated and replay drivers; capture sessions |
| `plugins` | manifest validation, tree-hash review, out-of-process runner, quarantine |
| `evidence` | vault, AES-256-GCM cipher with AAD bound to the content hash |
| `setup` | first-run Setup: pinned `catalog.json`, hash-locked requirements, hardened downloader/extractor, tool + model installer, `installed.json` (which adapters read) |
| `reporting` | report collection and renderers; `store.py` encrypts reports at rest |
| `backup.py` | verified backup container (passphrase-encrypted), restore into a new directory only |
| `telemetry/audit.py` | append-only hash-chained audit events |

## Frontend (apps/web)

React 18 + TanStack Query. Plain CSS tokens with light/dark themes. The API token is read from the URL fragment once, scrubbed
from the address bar, and kept in `sessionStorage`. Case tabs: Search, Plans, Findings, Graph (Cytoscape), Timeline, Map
(Leaflet; OpenStreetMap tiles only when the user opts in), Evidence, Imports, Analysis, Cross-links, Workflows, Humint, AI,
Hardware, Notes, Reports. HTML from the server (notes) is already sanitized by an allow-list; there is no other
`dangerouslySetInnerHTML`.

## Processes and ports

| Process | Port | Notes |
|---|---|---|
| backend (dev) | 127.0.0.1:8791 | `scripts/dev.ps1` |
| backend (packaged) | 127.0.0.1:ephemeral | token printed only to the shell's pipe |
| web dev server | 127.0.0.1:5173 | proxies `/api` to the backend |
| E2E backend / web | 8792 / 5174 | `scripts/e2e_server.py`, mocked network |

The PyInstaller single-file backend runs as two OS processes (bootloader + interpreter); both exit on shutdown.
