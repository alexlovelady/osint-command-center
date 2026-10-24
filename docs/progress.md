# Progress log

Last updated 2026-10-24 (UTC). Host: Windows 11 Home 10.0.26200 (Intel Core Ultra 9 285, 31 GB RAM, RTX 5070 Ti present but not used for the model test),
Python 3.14.6 (also 3.12.14, 3.13.15), Node 24.16.0, pnpm 11.18.0, uv 0.12.19, rustc 1.99.1, Docker 29.6.1. Every number below was produced by running
the command shown on this machine; anything not run is listed under *Not verified*.

## Verification evidence

| Check | Result |
|---|---|
| `uv run pytest -q`, Windows, Python 3.14 | **460 passed, 0 failed, 0 warnings** (offline) |
| Same suite on Python **3.12.14** and **3.13.15** (Windows) | **460 passed** on each; `mypy` clean |
| Same suite on Linux (Ubuntu 22.04 container, Python 3.12.15) | **459 passed, 1 skipped** (the real-ExifTool test: not installed in that container); `ruff` and `mypy` clean |
| Backend coverage (`--cov=osintcc`) | **89%** overall (9772 statements). db/encrypt 95%, reporting/store 86%, ingest/exiftool 91%, vault 95%, policy 82–97%. Lowest: `setup/installer.py` 67% (the real download/extract/venv paths are exercised by real installs, not unit tests), `server.py` 0% (covered by the frozen smoke test) |
| `ruff check backend tests scripts`, `mypy` (96 files) | clean / `no issues found` |
| Web: `tsc`, `eslint`, `vitest`, `vite build` | clean · **22 tests** · build OK |
| Browser E2E (`pnpm e2e`, Playwright 1.60 + system Edge, mocked network) | **7 passed**, including axe WCAG 2.0/2.1 A+AA with no serious/critical violations on every page (now incl. Setup) and all 16 case tabs, light and dark |
| `cargo test` (shell) | 2 passed on Windows and in the Linux container |
| Frozen backend, `scripts/sidecar_smoke.py` | **32/32 on Windows and 32/32 on Linux** (includes the start-up egress self-check and the built-in update key): each run does a plain pass and an **encrypted** pass (database file is ciphertext, report stored as `.enc` yet downloadable, MCP `initialize`, plugin runner, keyring backend, graceful exit) plus the `setup status` subcommand |
| Linux desktop shell (container, Xvfb) | Built (4 MB) and **run**: the real window renders the first-run Setup page (`docs/evidence/linux-egress/shell.png`), starts the bundled backend, and `kill -9` of the shell left **0** backend processes |
| **Real local model** (`scripts/ai_live_check.py`) | `huihui_ai/qwen3-abliterated:8b` (5.0 GB) answered through the app's retrieval → prompt → model → citation-verification pipeline: grounded answer with a verified evidence id, in **17 s**; CPU-only generation **5.9 tokens/s** |
| **Real tool installs** (Setup code, Windows) | Subfinder 2.17.0, Amass 5.1.1, ExifTool 13.59, Sherlock 0.16.2, Maigret 0.6.6 installed under `%APPDATA%\osintcc\tools`; every download matched the publisher's SHA-256 and each reports its version |
| **Real tool installs** (Linux container, frozen binary) | same five installed with uv-managed Python 3.12 and hash-locked wheels; theHarvester 4.11.1 installed from source and **ran** (real adapter run on example.com parsed 2 hostnames) |
| Real tool runs | Subfinder (25 517 names for example.com → now capped at 2000), Sherlock and Maigret output formats match the parsers, ExifTool enriched a real JPEG import. **Amass 5.1.1 returned nothing in 5.5 minutes**, so its name parsing is unverified |
| Live passive smoke (`scripts/live_smoke.py example.com`, earlier today) | rdap ✔ dns ✔ crt.sh ✔ wayback ✔ — 30 findings |
| Dependency advisories | `pip-audit` (40 production packages): none · `pnpm audit`: none · `cargo audit`: no vulnerabilities, 2 Linux-only transitive warnings (`proc-macro-error` unmaintained, `glib` unsound) |
| Licence inventory | 40 Python + 9 web + 415 Rust packages, all permissive (2 `r-efi` crates offer MIT/Apache among options). SBOMs in `docs/supply-chain/` |
| Secret scan (`scripts/secret_scan.py --dist`) | 269 files + shipped binaries: 0 findings |
| Benchmarks | `docs/benchmarks.md`: **no measurable overhead from SQLCipher/encrypted vault** at 3000 rows |
| Generated docs | `scripts/gen_docs.py --check` current; `tests/integration/test_api_examples.py` replays the API examples |

## This round (installer, keys, updates, tool runs, capture, CI)

| Item | Result |
|---|---|
| **Windows installer** (NSIS, per-user, unsigned) | Built (58 MB). Silent install to a test folder, launch (bundled backend started, DB created), clean close, silent uninstall: all worked. Not tested on a clean PC |
| **API-key spot in Setup** | Keys (VirusTotal, urlscan, Shodan, Censys, OpenCorporates) + EDGAR contact entered in Setup/Settings; stored in the OS credential store or, with none, sealed in the encrypted DB; never returned or logged. 4 backend + 1 UI test |
| **Update server** | `scripts/update_tool.py` (keygen/publish/serve/verify), signed per-platform manifests, verified download, Settings → Updates UI. Real flow with the packaged backend + the real installer: check → verified signature → 58 MB download → hash matched. A bug found by this run: the public key had not been bundled into the frozen app (the smoke test now catches it). Private key is at `%APPDATA%\osintcc-release\update-signing.key` (back it up) |
| **Sherlock, real full run** (`octocat`, default flags) | success, **102 profile candidates in 30 s**; the count equals the tool's own "Search completed with 102 results" |
| **Maigret, real full run** (`octocat`) | success, **147 candidates in 19 s**; one is a site's front page ("Discord: https://discord.com"): a false positive the tool itself reports, kept as a low-confidence lead |
| **Amass 5.1.1, real run** (iana.org) | The adapter now does `enum` + `subs -names` and returns success with 0 names and an explicit warning. Amass v5 stores results in its own database and its passive mode finds nothing without API-keyed data sources (all are commented out in its default config); enabling the keyless ones I could find still produced nothing and `-timeout` was not honoured. **Real names were never obtained, so name parsing is verified only with fixtures** |
| **pktmon parser** | Windows pktmon writes Wi-Fi (802.11) frames under the Ethernet link type, which hid every TCP flow. `net.py` now reads 802.11 data frames: the same capture went from 16 UDP flows to **251 flows incl. TLS server names** (`substrate.office.com` among them; the two flows from `10.5.1.226:61136/61137` match the ports `netstat` attributed to WebView2). 2 new tests |
| **CI on GitHub** | First runs: backend (Windows+Linux × Python 3.12/3.13/3.14) green, web incl. E2E green, supply-chain green, Linux container build + egress green; **desktop `cargo test` failed** (the shell embeds the built UI and CI had not built it) → fixed; actions now pinned to commit SHAs |
| **WebView2 firewall script** | `scripts/windows/block-webview2-egress.ps1` (`-Mode Substrate` default / `All`, `-WhatIf`, `-Remove`, admin required). Dry-run tested; **not applied** to this machine. Caveat in its header: every WebView2 app shares `msedgewebview2.exe`, so any rule also affects them |

## Network egress ("packet capture")

| Platform | Method | Result |
|---|---|---|
| **Linux** (container, so every packet on the interface belongs to the app) | `tcpdump -i any` for the whole run: real shell under Xvfb idle 60 s, then the bundled backend driven through case creation, search/plan **preview**, setup status/plan, update check, tools, doctor, offline mode and an offline search | 214 packets, all loopback except 11 kernel ARP / IPv6 neighbour-discovery frames in the first two seconds, before the app started. **No DNS, TCP or UDP from the app.** The offline search was refused (409) without a request. Evidence: `docs/evidence/linux-egress/` |
| **Windows**, connection attribution (`scripts/egress_check.py --no-capture`) | `netstat -ano` polled every 0.5 s for the whole process tree (shell, bundled backend, and the WebView2 processes it spawns) for 75 s idle + the same API pass | **Our code (shell + backend): 0 non-loopback connections.** The **WebView2 engine** (Microsoft's `msedgewebview2.exe`, which renders the UI) opened **2 TLS connections to Microsoft-owned addresses (52.96.x.x / 40.104.x.x:443)** shortly after launch, every run. Extra Chromium switches (`--disable-background-networking`, `--disable-component-update`, `--disable-sync`, …) and a black-hole proxy did **not** stop them, so they are made by the browser process itself, not by the page or our code |
| **Windows**, real packet capture (`pktmon`, all adapters, 4 min 10 s, you accepted the UAC prompts) | app idle 75 s + the same API pass | 18 606 packets machine-wide. Our code: still 0 connections. The only connections from the app's process tree were the WebView2 engine's to **`substrate.office.com`** (Microsoft 365's Substrate service; 91 packets, 56 KB, within the first ~15 s after launch; the name was read from the TLS handshake bytes). Everything else in the capture was other programs/virtual adapters (SSDP, mDNS, NetBIOS broadcasts). Note: the script's own summary could not list the TCP flows (pktmon's frames are not plain Ethernet for the pcap parser), so the finding above came from a byte-level scan of the capture; a parser fix is open |

Consequence you should know about: on Windows the UI is hosted by Microsoft's WebView2 runtime, and that runtime talks to Microsoft on its own. If
that is unacceptable, block `msedgewebview2.exe` for the app's WebView folder (`%LOCALAPPDATA%\local.osintcc.desktop\EBWebView`) in Windows Firewall,
or use the Linux build (WebKitGTK) where the capture shows nothing.

### Start-up self-check (added after the capture)

The capture became a built-in test: `selfcheck/egress.py` runs automatically at launch (90 s window), writes an audit event and shows the verdict on the
Overview page. Verified: 7 backend tests (verdict logic, user-activity exemption, a real socket to a non-loopback address is attributed to this
process, endpoint + audit event, opt-out), 3 UI tests, frozen-build smoke on Windows (clean), and the **real Windows desktop app** reported `engine_only`
(25 samples, 0 connections from our code, 1 from WebView2). Limits: sampling every 2 s (short connections can be missed), connection-level only.

## Phase gates (spec §15, §21, §23.10)

| Phase | Status |
|---|---|
| 0 — doctor, install matrix, decision log, threat model, source licences | **PASS** |
| 1 — shell + API + migrations + cases + parsers + sources + job queue + evidence + search + Tool Manager | **PASS** on Windows and Linux |
| 2 — graph, provenance, merge review, notes, timeline, FTS, reports, purge, claims/hypotheses/fusion, plans | **PASS** |
| 3 / 3B / 3C — multi-INT importers and adapters, map, EDGAR, Overpass, PCAP/STIX, GeoTIFF/EXIF | **PASS for parsing and mocked services**; real-world file corpora and live EDGAR/Overpass **not tested** |
| 4 / 4B — workflows + scheduler, local AI, MCP, HUMINT, FININT/TECHINT/FISINT/ELINT | **PASS**; the local AI now has a real-model run; MCP only with a scripted client |
| 5 / 5B — encrypted vault, **database** and **reports**, backups, plugin SDK, hardware layer, cross-discipline correlation, briefing, update check, audits, packaging, **first-run Setup** | **PARTIAL**: all built and tested **except** a signed installer, a clean-machine install test, real hardware and a real update server |

## Spec §22 delivery checklist

- [x] System doctor detects missing dependencies
- [~] Launches and shuts down cleanly — Windows portable build and Linux (container) verified; no installed package, no physical Linux desktop
- [~] No default cloud/tracking/outbound requests — **our code: yes** (Linux packet capture; Windows connection attribution); **WebView2 on Windows talks to Microsoft by itself** (see above); Windows packet capture pending your UAC approval
- [x] Case create/read/update/archive and run history
- [x] Target parser + explicit permission preview (also Plans)
- [x] Three+ truly working passive domain sources (four, live-verified today) plus Subfinder
- [x] Tool Manager truthful install, version and key state; **Setup installs the optional tools**
- [x] Evidence metadata, provenance, hashes, original references
- [x] Safe local import and backup/restore verified (encrypted container; restore under a different master key re-encrypts the database)
- [x] Graph with source-linked edges and reversible identity review
- [~] Map with attribution and precision limits — implemented, axe-checked; OSM tiles are opt-in and never fetched in tests
- [x] Timeline distinguishes observed / published / captured / ingested time
- [~] Corporate (EDGAR/OpenCorporates mocked) and document (EML/PDF/DOCX + ExifTool) workflows
- [x] HTML/PDF/Markdown/JSON reports (encrypted at rest), preview before write
- [x] Scheduler durable, bounded, opt-in
- [x] Local AI grounded and disabled gracefully — **real model run**; AI off until enabled (Setup can enable it)
- [~] MCP least privilege and confirmation gate — scripted client only
- [x] Injection, SSRF, XSS, traversal, tamper, authz, **download-integrity, process-tree** tests pass
- [x] Dependency licences audited
- [ ] **Windows clean-VM packaging/install test — not performed** (Windows Home: no Hyper-V/Sandbox)
- [x] Docs with reproducible commands (README index)
- [x] This file

## Not verified / not built (read this)

1. **WebView2's connection to `substrate.office.com`** (Microsoft 365) on Windows is not stopped by any browser switch I tried (background-networking/sync/component-update off, a black-hole proxy, and blocking all non-local name resolution all left it unchanged). It is made by Microsoft's runtime, not our code. Remedies: a Windows Firewall rule for `msedgewebview2.exe` under `%LOCALAPPDATA%\local.osintcc.desktop\EBWebView`, or use the Linux build.
2. **Code signing.** The Windows installer, zip and Linux tarball are unsigned (you chose that); SmartScreen will warn.
3. **Clean-machine installs** (either OS). The Linux shell has only run in a container under a virtual display.
4. **Amass 5.1.1** found no names without API-keyed data sources, so its name parsing was exercised only with fixtures.
5. **Services tested only with mocks**: EDGAR, Overpass, VirusTotal, urlscan, Shodan, Censys, OpenCorporates, GDELT (no keys supplied).
6. **Real MCP client** never connected. **Real hardware** never attached (you confirmed this is expected). Ollama's own Windows installer path was not exercised (Ollama was already installed).
7. **Keyring on a desktop Linux session** (Secret Service) was not exercised; Linux checks used `OSINTCC_VAULT_KEY`. A headless Linux box without it will refuse to start by design.
8. **Update flow** was tested against a local server only (loopback), never over a LAN/internet host; there is exactly one signing key.
9. **CI** (`.github/workflows/ci.yml`): the repository was pushed (private, `github.com/alexlovelady/osint-command-center`) after everything else was verified, so the workflow's first GitHub run had not been seen when this was written; its Python 3.12–3.14 × Windows/Linux matrix and Linux container job are untested there.
10. **Screen readers**, low-spec hardware performance and UI frame rates were not tested. The model is slow on weak CPUs (5.9 tok/s here).
11. The model is a community "abliterated" Qwen3 fine-tune, not a vendor release; its outputs are never treated as evidence and the app's own controls are the safety boundary.
12. macOS not attempted.

## Bugs found by running it (each fixed with a regression test unless noted)

Earlier sessions: UI token-in-hash routing; naive-datetime/UTC shift; loopback URL accepted by the preview; `-`-prefixed usernames; Windows pipe leak
after a timeout kill; preview preselecting a missing tool; truncated PNG crash; DNS double-count; cloud preflight contacted the provider; MCP
`create_case` approval scoping; PCAP first-timestamp regression; orphaned backend after abrupt shell kill (Windows job object); axe colour contrast
(light accent); frozen-build relative import; secret-scanner header pattern; 26 dev-tool advisories; Playwright vs Edge launch.

This session:
1. **Timed-out CLI tools left helper processes running** (found when Amass's helper survived a kill) → whole process tree is killed (Windows `taskkill /T`, POSIX process group); test spawns a grandchild and checks it dies.
2. **Maigret downloaded its site database at run time** and would recurse into discovered identities → `--no-autoupdate --no-recursion --no-extracting`; CLI tools now run in a scratch directory (a tool had written stray folders into the project).
3. Subfinder returned **25 517 hostnames** for example.com and would have flooded a case → capped at 2000 with a warning.
4. Amass v5 refused to start without `APPDATA`/`LOCALAPPDATA` (the runner strips the environment) → per-adapter allow-listed variables and a working directory.
5. The backup snapshot used SQLite's backup API, which cannot copy an encrypted database to a plaintext one → `sqlcipher_export` snapshot (and a test that restores under a different key).
6. The Linux-only MCP stdio test inherited an environment with no key source → test sets it explicitly; the app's fail-closed behaviour (refuse to start without a key) is now tested.
7. A Setup redirect from GitHub to `codeload.github.com` was (correctly) refused by the allow-list, which exposed that theHarvester's source tarball needs that host → added, with a test of the exact allow-list.
8. theHarvester has no `--version`, so health reported "degraded" → probes `--help`.
9. `egress_check.py` mis-parsed its own flag as a path, and the Windows checksum file overwrote the Linux entry → fixed.

## Next actions (if you continue)

1. Decide about WebView2's `substrate.office.com` traffic (the firewall script, or a bundled fixed-version runtime so a firewall rule can be app-specific).
2. Test the installer and the Linux tarball on a clean PC and a stock Ubuntu desktop.
3. Enter real API keys in Setup and run the keyed services once; connect a real MCP client later.
4. Back up the update-signing private key.
