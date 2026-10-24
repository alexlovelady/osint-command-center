# Operator runbook

For the person running the application. Windows paths shown; Linux differs only in the data directory
(`${XDG_DATA_HOME:-~/.local/share}/osintcc`). Override anywhere with `OSINTCC_DATA_DIR`.

## 1. Install / start

**Portable build (unsigned, Windows x64):** unzip `OSINT-Command-Center-<version>-win32-amd64.zip`, check `SHA256SUMS.txt`, run
`osintcc-desktop.exe`. Windows SmartScreen will warn because the file is not code-signed — that is expected until a signing
certificate is bought. Keep `osintcc-backend.exe` next to it. Needs the Microsoft WebView2 runtime (present on current Windows 11).

**From source:** `uv sync --locked`, `pnpm --dir apps/web install --frozen-lockfile`, then `./scripts/dev.ps1` and open the URL it
prints (`http://127.0.0.1:5173/#token=…`), or build the shell (`docs/packaging.md`).

Run `uv run python -m osintcc.doctor` first: it lists what is present, missing or broken. Missing optional tools are normal.

## 2. First run checklist

0. **Setup page.** The app opens on *Setup*. Review the tool list and the exact sources, tick the confirmation, press *Install selected*. This installs
   Subfinder, Amass, ExifTool, Sherlock and Maigret (theHarvester on Linux) and, optionally, a local uncensored model sized for your RAM through Ollama
   (Windows installs Ollama silently for your user if it is missing; on Linux install it yourself first). Skip it with *Finish setup*; you can return any
   time. CLI equivalent: `osintcc-backend setup status`, `setup install all --yes`, `setup model --yes`.
1. **Master key.** The first start creates an encryption key in the OS credential store (Windows Credential Manager / Secret Service).
   If the credential store is unavailable the app refuses to store evidence instead of writing plaintext. Settings → *Encryption & backup* shows
   the mode. Set `OSINTCC_VAULT_ENCRYPTION=off` only knowingly (tests do).
2. **Create a case with a purpose.** The purpose is shown on the case, written into reports, and required for people cases.
3. **Offline mode** (Settings) blocks every network adapter if you want a no-egress session.
4. **SEC EDGAR contact** (Settings) is required before the EDGAR adapter will run (the SEC requires an identifying User-Agent).
5. **AI is off.** Leave it off unless you configure a profile (Settings → AI). Cloud profiles additionally need per-case permission.

## 3. Everyday flow

Search → type a target → **Preview** (nothing is sent) → tick sources → confirm → watch the run → Findings / Graph / Timeline.
For repeatable work use **Plans** (preview, save, approve; policy is re-checked at approval) or **Workflows**. Findings can be promoted
to **claims** in Analysis, where only you can mark them verified. **Cross-links** suggests coincidences between disciplines; accept
or reject each, and revoke later if you change your mind. **Reports** → preview what is included/withheld, then generate.

## 4. Backups (do this before upgrading)

Settings → *Encryption & backup* → *Create encrypted backup* needs a passphrase (8+ characters; the button says UNENCRYPTED if you leave it empty). **There is no recovery for a lost passphrase.** Verify, then preview a
restore; restoring always writes into a **new** directory under `data/restores/<name>`. To switch, close the app and start it with
`OSINTCC_DATA_DIR` pointing there. See `docs/recovery.md`.

## 4b. API keys

Setup (and Settings) has a labelled spot for each key: VirusTotal, urlscan, Shodan, Censys (`API_ID:API_SECRET`), OpenCorporates, plus your SEC EDGAR contact string. They are
stored in the OS credential store (or, on a machine without one, sealed in the encrypted database), shown only as "set / not set", and can be replaced or removed. Nothing is
hard-coded or shipped. A source without a key stays unavailable and makes no request.

## 5. Updating

The app never updates itself. Publish a build with `scripts/update_tool.py publish` and serve the folder (`update_tool.py serve`, any web server, or a NAS). In Settings → Updates enter the
manifest address, *Check for updates* (signature verified against the key built into the app), then *Download and verify* (SHA-256 checked against the signed manifest). Run the saved file yourself. Installing an update never touches the data directory; schema migrations run on next start and keep a
`osintcc.pre-<rev>.bak` copy.

## 6. Optional tools

Subfinder, Sherlock, Maigret, amass, theHarvester, ExifTool and Ollama are discovered on `PATH`; the Tool Manager shows version and
health. Install them yourself after reviewing the project; the app never downloads or installs a tool. They run as separate
processes with a fixed command line and a timeout.

## 7. Plugins

Install (admin) → the plugin stays **disabled** → read its manifest, permissions and tree hash → Enable by confirming the exact hash.
A changed file disables it again. Uninstall removes files, never evidence.

## 8. MCP (an AI client reading your cases)

Start it per session with the cases it may see: `osintcc-backend mcp --cases <id>[,<id>]` (or `python -m osintcc.server mcp …`).
It is read-only; anything that would change data appears under Settings → *MCP approvals* and waits for you. Restricted material is
hidden unless you started it with `--allow-restricted`.

## 8b. The AI Copilot and tutor

Open it with the **Copilot** button (top bar or bottom right). **General** answers OSINT and how-the-app-works questions; **Investigation** (inside a
case) answers from that case's stored evidence with citations and offers *Recommend next steps*; **Tutor** teaches step by step and can highlight
the real controls (*Start walkthrough*). The model badge shows which model is answering; with no model (AI off, Ollama not running, model not
installed) it says so and still answers from the built-in documentation and your stored data. Anything it proposes (a search, a note, a report, a
workflow run) appears as a card; nothing happens until you press **Approve and run**. To switch models use the picker in the panel or Settings -> AI;
to make one the default for everyone use `PUT /api/v1/copilot/settings`. Conversations are kept per investigation and survive restarts.

## 9. Hardware

Nothing is required. Simulated and replay devices always work. A real receiver needs an ownership assessment and an acknowledgement
that you will follow local radio law; capture is receive-only, time-limited, and has a stop button. Real-driver code has **not** been
run against physical hardware in this build.

## 10. Shutting down and cleanup

Close the window: the shell asks the backend to stop (database checkpointed, jobs requeued on next start). If the app was killed,
the next start recovers interrupted jobs, capture sessions and workflow runs and marks them `interrupted`. Case purge shows a
preview and needs confirmation; it removes the case's evidence, never other cases'.

## 11. Verify an install end to end (no network)

On Windows the UI engine is Microsoft's WebView2, which contacts Microsoft by itself (see `docs/progress.md`); `uv run python scripts/egress_check.py --no-capture` shows exactly which process opens which connection.

```
uv run python scripts/sidecar_smoke.py      # frozen backend: handshake, migrations, imports, PDF, MCP, plugin runner, shutdown
cd apps/web && pnpm e2e                     # browser journeys + accessibility, mocked network, uses system Edge
```
