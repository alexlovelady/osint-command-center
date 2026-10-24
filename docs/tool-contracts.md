# Tool, parser, plugin and protocol contracts

Everything that extends the application meets one of these contracts. All of them are **data in, drafts out**: none may write
to the database, the vault or the network directly.

## 1. Collection adapter (`backend/osintcc/adapters/base.py`)

```python
class IntelAdapter(Protocol):
    manifest: AdapterManifest
    async def health(self) -> dict            # {"status": "healthy"|"degraded"|"not_installed"|"unavailable", "version"?, "detail"?}
    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult
```

`AdapterManifest` declares: `id`, `name`, `version`, `supported_target_types`, `operation_class`
(`passive` | `public_site_query` | `active` | `local_only`), `needs_network`, `api_key_name`, `rate_limit_per_minute`,
`timeout_seconds`, `license`, `terms_url`, `endpoints` (shown in the preview *before* anything runs), `install_hint`,
`default_selected` (False = listed but only runs when chosen).

`AdapterResult` carries `status` (`success` | `partial` | `error` | `skipped` | `rate_limited`), `error_code`, `retryable`,
`retry_after_seconds`, `artifacts` (raw bytes + source URL + HTTP status → become hashed evidence), `findings`
(`subject`, `predicate`, `value`, `confidence`, `confidence_reason`, optional `source_published_at`), `relationships`, `warnings`.

Obligations:

- Network only through `ctx.http` (`SafeHttp`). DNS only through `ctx.dns_query`. Secrets only through `ctx.secret(name)`; a missing
  key returns `skipped/requires_key` **without making a request**; a key must never appear in an artifact URL, finding or log.
- A missing binary is `skipped/not_installed`, never a crash and never a green status.
- Parse failures keep the raw output as evidence and return `error/parse_error` (the adapter is reported degraded).
- Confidence must be justified in `confidence_reason`. Third-party assertions are `low`/`medium`; `high` needs an authoritative source.
- CLI adapters use fixed argv templates (`run_argv`): the target is one argv element, never a shell string, with timeout,
  output cap and a minimal environment.

Shipped adapters and their classes: see `docs/integration-matrix.md`.

## 2. Importer / parser (`backend/osintcc/ingest`)

`PARSERS[kind](data: bytes) -> ParsedIngest`, plus a detector appended to `DETECTORS` (`(lowercase_filename, head_bytes) -> kind | None`).
A parser must: validate before returning (raise `IngestError` for malformed input; nothing is stored then), never execute, render,
unpack-and-run or fetch anything the file references, set `access_class` (`PUBLIC` | `OWNED_AUTHORIZED` | `CONSENTED` |
`IMPORTED` | `SIMULATION`), `mime`, `sensitivity`, and describe values the file merely *claims* as claims. `ParsedIngest` holds
`observations` (discipline, kind, data, optional `observed_at`), `entities`, `relationships` (reasons required), `warnings`,
and optional `layers` for the map. Persistence (`ingest/service.py`) hashes the original bytes into the vault, deduplicates
re-imports, and writes the custody event.

## 3. Plugin protocol v1 (`sdk/osintcc_plugin_sdk.py`, example in `plugins/examples/example-robots`)

A plugin is a directory with `plugin.json` and an entrypoint. The host runs it **twice per target in a separate process**
(minimal environment, scratch cwd, CPU/memory/process limits on POSIX, timeout and output cap everywhere):

```
entrypoint --phase plan   < {"protocol":1,"phase":"plan","target":{...}}                 -> {"requests":[{"url":"https://..."}]}
entrypoint --phase parse  < {"protocol":1,"phase":"parse","target":{...},"responses":[…]} -> {status, artifacts, findings, relationships, warnings}
```

The plugin never touches the network: the host fetches only URLs on domains the manifest declared (`{target}` expands to the
target), at most `max_requests`, with SSRF protection and rate limits, and hands responses back (base64). Output is schema-validated;
fabricated provenance URLs are stripped, verification-only labels are refused, and three invalid outputs quarantine the plugin.
Install is disabled until an admin accepts the exact **tree hash**; any change after review disables it again. Required manifest
fields are enforced by `plugins/manager.py` (`test_manifest_rejections`). In a packaged build the host launches
`osintcc-backend --run-script <entrypoint>` because there is no separate Python; plugins there are limited to the standard-library
modules bundled in the sidecar.

## 4. Workflow definition (`configs/workflow-templates`, `backend/osintcc/workflows`)

JSON only — no code, URLs or unknown fields are accepted:

```json
{"schema_version": 1, "id": "…", "name": "…",
 "nodes": [{"id": "rdap", "adapter": "rdap", "input": "target", "depends_on": []},
           {"id": "changes", "task": "diff", "input": "target", "depends_on": ["archive"]}],
 "policy": {"active_allowed": false, "max_concurrency": 3, "max_depth": 4}}
```

Nodes run in dependency waves, at most `max_concurrency` at once. Adapters are re-checked by policy at run time. Schedules are
created **disabled**, enabling needs explicit confirmation, slots are idempotent, repeated failures back off then disable the
schedule with an alert, and monitoring an individual needs a recorded purpose and acknowledgement.

## 5. Hardware driver (`backend/osintcc/hardware`)

```python
class Driver(Protocol):
    def discover(self) -> list[Discovered]
    def capabilities(self, dev) -> dict
    def health(self) -> dict
    def start_capture(self, dev, scope) -> Handle
    def stop_capture(self, handle) -> CaptureResult      # bytes + filename + parser kind
    def import_capture(self, data: bytes, filename: str) -> CaptureResult
    def disconnect(self, dev) -> None
    def simulate(self, seed: int = 0, **kw) -> CaptureResult
```

Receive-only by construction: there is no transmit, jam, spoof or write method. Every driver works with no hardware
(`simulate`/`import_capture`). Real receivers need an ownership assessment and a law-and-purpose acknowledgement per session,
sessions have a duration limit and a visible stop, and a removed USB device keeps the partial capture. Captured bytes go through
the same importers as files.

## 6. MCP server (`python -m osintcc.server mcp` / `osintcc-backend mcp`)

stdio JSON-RPC. `--cases a,b` is the only scope (default none). Read tools: `list_cases`, `get_case_summary`,
`search_case_evidence`, `get_entity`, `get_graph_neighbors`, `list_tools`, `preview_investigation`, `get_job_status`,
`get_report`. Restricted material is omitted unless the server was started with `--allow-restricted`. Write tools — `start_search`,
`create_note`, `create_case`, `run_workflow` — do nothing until a person approves the exact arguments through the HTTP API; an
approval is single-use, bound to the argument hash, and the approved action still passes the policy gate.

## 7. Setup catalog (`backend/osintcc/setup/catalog.json`)

Every installable component is an entry with `kind` (`archive` | `pypi` | `pysrc` | `ollama`), a `version`, a per-platform block (`url`, `sha256`, `size`,
`format`, `main`, optional `members`/`strip`/`whole`/`rename` for archives, or a `requirements` file of `--hash` pins for Python tools) and optional
`needs`/`unsupported`. A new component is added by editing `scripts/build_catalog.py` (which takes the hash from the publisher and re-verifies it by
downloading) and regenerating. The downloader accepts only https URLs on the publisher hosts in `installer.ALLOWED_HOSTS`, at most six redirects, a size
cap, and deletes any file whose SHA-256 differs. A CLI adapter finds an installed tool through `installed.json` before looking at `PATH`.

## 8. Update manifest (`POST /api/v1/updates/check`)

`{"payload": "<json text>", "signature": "<base64 Ed25519 over the payload bytes>"}` with payload
`{version, released, notes, url, sha256}`. The public key and manifest URL are configured out of band
(`OSINTCC_UPDATE_KEY`, `OSINTCC_UPDATE_URL`). The check is user-initiated, admin-only, refused in offline mode, and never downloads
or installs anything.
