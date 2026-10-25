# OSINT Command Center

Local-first, evidence-grounded workstation for lawful, authorized public-source and multi-INT analysis. The specification it was built from
(`OSINT_Master_Spec.md`) is kept next to this folder, outside the repository.

**Status (2026-10-24):** the backend, web UI, desktop shell (Windows and Linux), importers, fusion, workflows, local-AI/MCP/plugin/hardware
layers, a first-run Setup wizard (tools + local model), an encrypted database, vault, reports and backups, and portable Windows and Linux builds
all exist and have passing automated tests. Some things are **unverified or not built** — real hardware, a real MCP client, a signed installer
and a clean-machine install — and are listed in [`docs/progress.md`](docs/progress.md), [`docs/integration-matrix.md`](docs/integration-matrix.md)
and [`docs/packaging.md`](docs/packaging.md). Read those before trusting a feature.

**Target Profile (addendum TP-1.0):** a people case opens on a consent-gated, evidence-grounded profile with a review queue, bounded research plans, an image workbench, exposure and remediation tracking and citation-checked reports. Guide and honest limits: [`docs/profile-guide.md`](docs/profile-guide.md); acceptance evidence: [`docs/profile-test-results.md`](docs/profile-test-results.md).

## Run (Windows or Linux; no WSL, Docker, hardware or cloud needed)

```bash
uv sync --locked
pnpm --dir apps/web install --frozen-lockfile
uv run python -m osintcc.doctor           # truthful prerequisite report
uv run pytest -q                          # backend tests (offline)
pnpm --dir apps/web test                  # UI unit tests
```

Development servers (fixed dev ports; packaged builds use an ephemeral port + random token):

```powershell
./scripts/dev.ps1        # backend :8791 + web :5173, prints the URL with the dev token
```

Open `http://127.0.0.1:5173/#token=dev-token-local-only`: create a case → Search → Preview → confirm.

Desktop window from source (needs Rust + MSVC Build Tools; uses the repo `.venv`):

```powershell
pnpm --dir apps/web build
cargo run --manifest-path apps/desktop/src-tauri/Cargo.toml
```

Windows installer (NSIS, per-user, unsigned): see `docs/packaging.md`. Updates: `scripts/update_tool.py` + Settings → Updates. Portable builds (unsigned): Windows via `scripts/build_sidecar.py`, `tauri build --no-bundle`, `scripts/release.py`; Linux via `docker/linux-build` — see
[`docs/packaging.md`](docs/packaging.md). Headless Linux without a Secret Service needs `OSINTCC_VAULT_KEY` (base64 of 32 random bytes).

**First run:** the app opens on **Setup** (also `python -m osintcc.setup status|install all --yes|model --yes`, or `osintcc-backend setup …` in a packaged build). It
shows the exact download URLs, installs Subfinder, Amass, ExifTool, Sherlock, Maigret (and theHarvester on Linux) into `<data dir>/tools` from SHA-256-pinned
artifacts, and pulls a local uncensored model sized for the machine's RAM (default `huihui_ai/qwen3-abliterated:8b`, 5 GB, CPU-only) through Ollama.

Opt-in live check (real public sources, low volume, reserved domain): `uv run python scripts/live_smoke.py example.com`.

## What it does
- Cases with purpose/scope; strict target parsers; preview-then-confirm collection plans; policy checked at plan time and at run time.
- Sources: RDAP, DNS, crt.sh, Wayback, Subfinder, Sherlock/Maigret output formats and ExifTool (verified against the real services/tools); SEC EDGAR,
  Overpass, VirusTotal, urlscan, Shodan, Censys, OpenCorporates, GDELT (mock-tested); Amass and theHarvester (installed and started, output parsing only partly verified).
- Import-only analysis across disciplines: email, SigMF/pulse/telemetry/CCSDS, EXIF/GeoTIFF/PNG, PCAP/STIX, SBOM/firmware, EDGAR/sanctions/chain CSV,
  ADS-B/AIS/NMEA, PDF/DOCX, SpiderFoot — each stored inert, parsed offline, with its access class and caveats.
- AES-256-GCM evidence vault, SQLCipher database, encrypted reports, provenance on every finding, claims with independence-based confidence labels, contradictions,
  hypotheses, requirements, reversible merges, **cross-discipline correlation suggestions** and a unified timeline.
- Workflows and an off-by-default scheduler; optional local/cloud AI (off by default, cited answers only) with an in-app **Copilot & Tutor** (modes, per-case history, next-step recommendations, approval-gated actions, guided walkthroughs; see `docs/copilot.md`); read-only MCP server; sandboxed plugins;
  receive-only hardware layer with simulated devices.
- Reports (executive / technical / evidence pack / multi-INT; HTML, Markdown, JSON, PDF) with a preview of what is included and withheld;
  passphrase-encrypted backups; tamper-evident audit chain; case purge with preview.

## What it deliberately does not do
No interception, no credential use, no CAPTCHA or rate-limit evasion, no facial recognition, no automatic identity merging, no scraping behind logins,
no telemetry, no automatic updates; no data leaves the machine except requests you confirmed.

## Verify
```bash
uv run ruff check backend tests scripts && uv run mypy && uv run pytest -q
pnpm --dir apps/web typecheck && pnpm --dir apps/web lint && pnpm --dir apps/web test && pnpm --dir apps/web e2e
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml
uv run python scripts/sidecar_smoke.py       # after building the sidecar
```

## Known limitations (read before trusting it)
Releases are unsigned and there is no installer (portable zip / tarball). On Windows the WebView2 UI engine contacts Microsoft 365 (`substrate.office.com`) by itself; our code opens no outside connections (see progress.md).
A lost master key or backup passphrase is unrecoverable by design. Real SDR/GPS hardware and a real MCP client were never exercised; the Linux
desktop shell was run under a virtual display in a container, not on a physical desktop.
See `SECURITY.md`, `docs/threat-model.md`, `docs/privacy.md`, `docs/decision-log.md`.

## Documentation
[architecture](docs/architecture.md) · [API](docs/api.md) / [examples](docs/api-examples.md) · [data model](docs/data-model.md) ·
[tool contracts](docs/tool-contracts.md) · [operator runbook](docs/operator-runbook.md) · [troubleshooting](docs/troubleshooting.md) ·
[recovery](docs/recovery.md) · [privacy](docs/privacy.md) · [threat model](docs/threat-model.md) · [integration matrix](docs/integration-matrix.md) ·
[capabilities](docs/discipline-capabilities.md) · [sources & licences](docs/source-licenses.md) · [licence audit](docs/license-audit.md) ·
[benchmarks](docs/benchmarks.md) · [packaging](docs/packaging.md) · [install matrix](docs/install-matrix.md) · [decision log](docs/decision-log.md) ·
[progress](docs/progress.md)
