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

## AIV and DARKINT (addendum v1.1)

Full evidence tables: `docs/aiv-darkint-status.md`. None of the rows below was exercised against a third-party service.

| Integration | Kind | Needs | Evidence |
|---|---|---|---|
| Built-in HTTP metadata, TLS posture, TCP connect | AIV, in-process | an asset authorization and an approved plan | **Fixture-tested** against real local lab sockets and TLS handshakes |
| Nmap (connect scan only) | AIV, external CLI | installed by you (`apt install nmap`) | Flags checked against 7.98; real XML is the parser fixture; end to end through a stand-in program; real-binary test skips when absent |
| Naabu | AIV, external CLI | installed by you | Flags checked against 2.6.1; real JSONL fixture |
| Nuclei (reviewed templates only) | AIV, external CLI | installed by you; a reviewed template | Flags checked against engine 3.11.1; real JSONL fixture; no live scan of a lab target |
| dnstwist (permutations, offline) | local CLI adapter | installed by you | Flags and output verified against 20240812 |
| ProjectDiscovery httpx | detected only | – | Reported as healthy / wrong program / absent; **not used** for checks |
| ZAP passive import, sslscan | – | – | **Not implemented** / not used |
| Have I Been Pwned (account, domain) | DARKINT, HTTP | your paid key; terms accepted by an administrator | **Fixture-tested**, not live-verified |
| Pwned Passwords range | DARKINT, HTTP relay | nothing | **Fixture-tested** (existing TP5 feature) |
| Ransomware.live v2 | DARKINT, HTTP | terms accepted (provider labels the free API personal use only) | **Fixture-tested**, not live-verified |
| Intelligence X | DARKINT | commercial licence | **Not implemented**; manual intake only |
| MISP | DARKINT | an export file | File import **fixture-tested**; live connector **not implemented** |
| Manual intake, CSV / JSON import | DARKINT | – | **Fixture-tested** |

## Associated email discovery

| Source | Kind | Needs | Evidence |
|---|---|---|---|
| `github_public` | HTTP (public API, anonymous) | a username input; explicit confirmation each run | **Fixture-tested**, not live-verified. Commit author fields are self-declared; 60 requests per hour anonymously |
| `page_contacts` | HTTP (one public page) | a page URL input (confirmed profile or business contact page) | **Fixture-tested**, not live-verified |
| Existing case evidence (findings from theHarvester and the two sources above, imported records that also name the subject) | local | nothing | **Fixture-tested** |
| Search engines, social graphs, people-search sites | – | – | **Not implemented**: no permitted automation interface was verified |
| Breach providers | DARKINT | confirmed address added as an input; provider enabled | exposure of confirmed inputs only (see the DARKINT rows) |
