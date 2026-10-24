# Troubleshooting

Start with `uv run python -m osintcc.doctor` (or `osintcc.doctor --json`) and `GET /api/v1/health/ready`.

| Symptom | Likely cause | What to do |
|---|---|---|
| Window says *backend failed* / blank after start | Dev build cannot find Python (`.venv` missing), or the packaged `osintcc-backend.exe` is not next to `osintcc-desktop.exe` | Packaged: keep both files together. Dev: `uv sync --locked`, or set `OSINTCC_PYTHON` |
| `401 unauthorized` on every call | Wrong/old token. The token changes every launch | Reopen from the launcher; in the browser use the `#token=` URL the dev script prints |
| `403` with an origin message | Page served from an origin not on the allow-list (anything but 127.0.0.1/localhost:5173 and the Tauri origins) | Use the documented URL; do not widen the allow-list |
| `404` on a case you made | You are a different user than the case's owner (non-members get 404 to hide existence) | Use the same launcher/user |
| Evidence import fails with *vault encryption required* / run says vault key unavailable | OS credential store locked or missing (headless Linux without Secret Service) | Unlock the keyring; or set `OSINTCC_VAULT_KEY` (base64 of 32 random bytes) from your own secret store; or knowingly `OSINTCC_VAULT_ENCRYPTION=off`. The app will not silently write plaintext |
| App will not start: "database encryption is required but no key is available" / "encrypted with a different key" | The master key is not reachable (credential store locked, headless Linux without Secret Service, new profile) | Unlock the credential store, or on a server set `OSINTCC_VAULT_KEY` (base64 of 32 bytes), or restore a backup into a new directory. The data directory is never modified when the key is wrong |
| Setup: *SHA-256 mismatch* | The download differs from the pinned value (corrupt, or the publisher re-issued the file) | Nothing was installed. Retry; if it persists, do not bypass it: check the publisher and regenerate the catalog (`scripts/build_catalog.py`) |
| Setup: *not an allowed https publisher host* | A redirect went outside GitHub/SourceForge | Refused on purpose |
| Setup: Python tools fail | `uv` could not download CPython/wheels (offline, proxy) | Check the network; tools live in `<data dir>/tools/venvs/<tool>`; delete that folder and its entry in `tools/installed.json` to retry |
| Amass finds nothing | v5 passive mode returns little without data-source API keys and can take minutes | Configure Amass's own `config.yaml`; an empty result is "nothing found", not proof of absence |
| Evidence unreadable after reinstall / new Windows profile | The vault key lived in the old profile's credential store | Restore from an encrypted backup (it carries its own passphrase). Without the key and without a backup, encrypted objects cannot be recovered — by design |
| Source shows `not_installed` | Optional CLI not on `PATH` | Install it yourself (hint is in Tool Manager) and reopen the preview |
| Source shows `requires_key` / `requires_config` | No API key stored (`POST /secrets/<name>`), or EDGAR contact not set | Add it in Settings; no request is made until then |
| Run is `partial` | One source failed or timed out (crt.sh returns 502 at times) | Read the per-source details; re-run just that source — evidence deduplicates by hash |
| `rate_limited` | Provider asked to slow down | The job is rescheduled using `Retry-After`; do not loop manually |
| Nothing network-bound runs | Offline mode is on, or the case is archived (archived cases are read-only) | Settings → Offline off; unarchive the case |
| `409 integrity_failure` on download | The stored object no longer matches its hash (disk damage or tampering) | Restore that object from a verified backup; the audit log has the event |
| Report preview shows items *withheld* | They are RESTRICTED/SECRET (e.g. positions, HUMINT) | Intentional. *Include RESTRICTED material* in Reports exports them (exact coordinates too) |
| Cross-links is empty | Items with locations are RESTRICTED by default and excluded; or nothing from two disciplines falls in the window | Tick *include RESTRICTED observations*; widen the slider |
| AI tab says *AI is off* | Default | Settings → AI → add a profile (local first). Cloud also needs the case's permission and a one-time preview approval |
| MCP client sees no cases | Server was started without `--cases` | Restart it with the ids it may read |
| Plugin shows *tampered* | Files changed after review | Review again and re-enable with the new hash (or reinstall) |
| Plugin fails only in the packaged build | The packaged sidecar has no separate Python; it can import only bundled standard-library modules | Use the standard library, or run from source |
| `address already in use` on 8791 | A previous dev backend (or another program) holds the port | `OSINTCC_PORT=<n>`; the packaged app uses an ephemeral port |
| Overview says "OUTSIDE CONNECTIONS DETECTED while idle" | A process of the app's own tree held a non-loopback connection during the first 90 s without any action of yours | Open the audit log entry `selfcheck.egress` for the process and address; this should never happen, so treat it as a bug report. `engine_only` is the known WebView2 behaviour on Windows |
| Update check: `network_error` / `policy_denied` / `bad_signature` | Server unreachable; address is link-local/metadata; the manifest was not signed by the key built into this app (or was altered) | Check the address and that the server is running; republish with the same key. A bad signature is never bypassed |
| Update download: `hash_mismatch` / `too_large` | The file on the server changed after signing, or is larger than signed | Nothing is kept; republish |
| Windows SmartScreen warning | The build is not code-signed | Expected; verify the SHA-256 from `SHA256SUMS.txt` |
| `playwright` can't launch a browser | Needs Microsoft Edge installed (it uses the system Edge, no download) | Install Edge or point `channel` at another installed Chromium browser |
| Linux: shell won't build | Needs WebKitGTK and the Tauri Linux prerequisites | Not verified in this project; the backend and tests do run on Linux |

## Reading the audit log

Every denial, approval, import, correlation decision, update check and AI transfer is an audit event. Verify the chain with
`GET /api/v1/system/doctor` (`audit_chain.ok`). The chain detects edits and deletions of single events; it is **not** proof against
someone who can rewrite the whole database file.

## Collecting a bug report

`doctor --json`, the failing request's `request_id` (every error body has one), and the relevant `audit` entries. Do not attach
evidence, tokens or the data directory; the API token and keys must never be pasted into a report.
