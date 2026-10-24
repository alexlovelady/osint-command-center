# Integration matrix — what has actually been exercised

Honest status per integration. **Live** = run against the real service/tool on this machine. **Mocked** = behaviour proven against
recorded/synthetic responses or a fake binary, never against the real thing. **Absent** = not installed here, adapter reports
`not_installed`. Nothing here is "working" unless the Evidence column says it ran.

## Collection adapters

| Adapter | Kind | Needs | Evidence |
|---|---|---|---|
| `rdap`, `dns`, `crtsh`, `wayback` | built-in HTTP/DNS | nothing | **Live** (`scripts/live_smoke.py example.com`: 30 findings; crt.sh sometimes 502 → run `partial`, by design) + mocked tests |
| `sec_edgar` | HTTP | contact string setting | **Mocked** only (synthetic submissions JSON). Never called live |
| `overpass` (OpenStreetMap) | HTTP | nothing | **Mocked** only |
| `virustotal`, `urlscan`, `shodan` | HTTP, read-only lookups | API key (urlscan: optional) | **Mocked** only; a missing key makes no request (tested) |
| `censys`, `opencorporates`, `gdelt` | HTTP | `censys`/`opencorporates` keys; GDELT none | **Mocked** only (this release). Response shapes follow provider docs and were not checked against live responses |
| `lookalike` | local | nothing | Local, deterministic, tested |
| `subfinder` | external CLI | Setup installs it | **Live**: real v2.17.0 run on example.com returned 25 517 names; the adapter now caps at 2000 and says so |
| `sherlock`, `maigret` | external CLI | Setup installs them | **Output format verified** against the real tools (one known public account on one/few sites); never run across their full site lists |
| `sherlock`, `maigret` (full default runs) | external CLI | Setup installs them | **Live**: `octocat` → 102 and 147 candidates, parsers match the tools' own counts |
| `amass` | external CLI | Setup installs it | v5.1.1 **starts and accepts the flags**; a passive run for example.com produced no output within its time limit, so name parsing is **unverified**. The run exposed an orphaned-helper-process bug (fixed, with a regression test) |
| `theharvester` | external CLI | Linux only | v4.11.1 installs and starts on Linux (container); see `docs/progress.md` for the real run |
| `tcp_connect` | active | `OSINTCC_ENABLE_ACTIVE=1` + scope authorization | Local loopback tests only; not in the default registry |
| `plugin:*` | out-of-process plugins | admin review | Example plugin with host-mediated fetch, mocked network |

## Importers (offline, deterministic, tested on synthetic fixtures)

`.eml`, SigMF, sensor CSV, JPEG EXIF, GeoTIFF, PCAP/pcapng, STIX 2.1, CycloneDX/SPDX, firmware (static), EDGAR submissions JSON,
sanctions CSV, chain CSV, telemetry CSV, CCSDS, pulse CSV, ADS-B, AIS, NMEA, PDF, DOCX, SpiderFoot JSON export.
Not tested against real-world samples: formats were built from public specifications and synthetic generators; expect odd
real files to be rejected with a clear error rather than half-parsed.

## Platform and runtime

| Item | Status |
|---|---|
| Windows 11 x64 backend, tests | **Live**: suite passes |
| Linux backend, tests (Ubuntu 22.04 container, Python 3.12) | **Live**: 430 tests, ruff and mypy pass |
| macOS | Not tested |
| Python 3.12 / 3.13 / 3.14 | **Live**: full suite passes on all three (Windows); 3.12 also in the Linux container |
| Tauri shell on Windows (dev + release build, portable folder) | **Live**: builds, starts the bundled backend, closes cleanly |
| Tauri shell on Linux | **Built and run** in an Ubuntu 22.04 container under Xvfb (renders, starts the bundled backend, SIGKILL leaves no backend). Not run on a physical Linux desktop |
| Tauri shell on macOS | Not built |
| PyInstaller sidecar (Windows and Linux) | **Live**: `scripts/sidecar_smoke.py` 28/28 on each (plain and encrypted passes, MCP, plugin runner, setup subcommand) |
| NSIS/MSI installer, code signing | **Not built** (see `docs/packaging.md`) |
| Clean-VM install test | **Not possible here** (Windows 11 Home has no Hyper-V/Sandbox) — unverified |
| Browser E2E + axe (Edge, mocked network) | **Live**: `pnpm e2e` |
| Windows installer (NSIS) | **Built and install/launch/close/uninstall tested** on this machine; not on a clean PC |
| Update server (signed manifest + verified download) | **Live** on loopback with the real installer; not over a LAN/internet host |
| GitHub Actions | **Ran**: all jobs green except the desktop job (fixed afterwards; re-run pending) |
| Packet capture of app launch | **Linux: done** (container, nothing from the app). **Windows: connection attribution done** (nothing from our code; WebView2 talks to Microsoft); real `pktmon` capture done: the only app-tree traffic is WebView2 → `substrate.office.com` |
| Screen readers (NVDA/Narrator) | Not tested; only automated axe checks |

## AI, MCP, hardware

| Integration | Status |
|---|---|
| Ollama (local) + `huihui_ai/qwen3-abliterated:8b` | **Live**: `scripts/ai_live_check.py` through the app's retrieval → prompt → model → citation check answered with a verified citation in 17 s (CPU-only 5.9 tok/s). llama.cpp: mocked |
| OpenAI-compatible cloud | **Mocked**. Never sent a real request; consent/preview/token gate tested |
| MCP server | Protocol and gates tested with a scripted JSON-RPC client; the frozen binary answers `initialize`. **Not tested with a real MCP client** (Claude Desktop, etc.) |
| RTL-SDR / other receivers | Driver reports `not_installed`; gated; **never touched real hardware**. Simulated and replay drivers are tested |
| GPS/NMEA, ADS-B, AIS | File/log import only; no live receivers |

## Frontend libraries

| Library | Use | Status |
|---|---|---|
| Cytoscape | graph | Rendered in the E2E run |
| Leaflet + OSM tiles | map | Code and unit tests; tiles are opt-in and **were not fetched** in any test |
| TanStack Query, React | all views | Unit tests + E2E |

Re-verify anything marked Live after upgrading a dependency, and update this file when something moves from Mocked/Absent to Live.
