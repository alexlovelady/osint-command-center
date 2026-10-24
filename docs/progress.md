# Progress log

Last updated 2026-10-24 (UTC). Host: Windows 11 Home 10.0.26200 (Intel Core Ultra 9 285, 31 GB RAM, RTX 5070 Ti present but not used for the model test),
Python 3.14.6 (also 3.12.14, 3.13.15), Node 24.16.0, pnpm 11.18.0, uv 0.12.19, rustc 1.99.1, Docker 29.6.1. Every number below was produced by running
the command shown on this machine; anything not run is listed under *Not verified*.

## Verification evidence

| Check | Result |
|---|---|
| `uv run pytest -q`, Windows, Python 3.14 | **433 passed, 0 failed, 0 warnings** (offline) |
| Same suite on Python **3.12.14** and **3.13.15** (Windows) | **433 passed** on each; `mypy` clean on each |
| Same suite on Linux (Ubuntu 22.04 container, Python 3.12.15) | **432 passed, 1 skipped** (the real-ExifTool test: not installed in that container); `ruff` and `mypy` clean |
| Backend coverage (`--cov=osintcc`) | **89%** overall (9772 statements). db/encrypt 95%, reporting/store 86%, ingest/exiftool 91%, vault 95%, policy 82–97%. Lowest: `setup/installer.py` 67% (the real download/extract/venv paths are exercised by real installs, not unit tests), `server.py` 0% (covered by the frozen smoke test) |
| `ruff check backend tests scripts`, `mypy` (96 files) | clean / `no issues found` |
| Web: `tsc`, `eslint`, `vitest`, `vite build` | clean · **16 tests** · build OK |
| Browser E2E (`pnpm e2e`, Playwright 1.60 + system Edge, mocked network) | **7 passed**, including axe WCAG 2.0/2.1 A+AA with no serious/critical violations on every page (now incl. Setup) and all 16 case tabs, light and dark |
| `cargo test` (shell) | 2 passed on Windows and in the Linux container |
| Frozen backend, `scripts/sidecar_smoke.py` | **28/28 on Windows and 28/28 on Linux**: each run does a plain pass and an **encrypted** pass (database file is ciphertext, report stored as `.enc` yet downloadable, MCP `initialize`, plugin runner, keyring backend, graceful exit) plus the `setup status` subcommand |
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

## Network egress ("packet capture")

| Platform | Method | Result |
|---|---|---|
| **Linux** (container, so every packet on the interface belongs to the app) | `tcpdump -i any` for the whole run: real shell under Xvfb idle 60 s, then the bundled backend driven through case creation, search/plan **preview**, setup status/plan, update check, tools, doctor, offline mode and an offline search | 214 packets, all loopback except 11 kernel ARP / IPv6 neighbour-discovery frames in the first two seconds, before the app started. **No DNS, TCP or UDP from the app.** The offline search was refused (409) without a request. Evidence: `docs/evidence/linux-egress/` |
| **Windows**, connection attribution (`scripts/egress_check.py --no-capture`) | `netstat -ano` polled every 0.5 s for the whole process tree (shell, bundled backend, and the WebView2 processes it spawns) for 75 s idle + the same API pass | **Our code (shell + backend): 0 non-loopback connections.** The **WebView2 engine** (Microsoft's `msedgewebview2.exe`, which renders the UI) opened **2 TLS connections to Microsoft-owned addresses (52.96.x.x / 40.104.x.x:443)** shortly after launch, every run. Extra Chromium switches (`--disable-background-networking`, `--disable-component-update`, `--disable-sync`, …) and a black-hole proxy did **not** stop them, so they are made by the browser process itself, not by the page or our code |
| **Windows**, real packet capture (`pktmon`) | needs administrator rights: the script requests UAC twice | **Not done**: the UAC prompt was cancelled both times (nobody at the keyboard, or declined). Run `uv run python scripts/egress_check.py` yourself and accept the two prompts; it will identify the destinations |

Consequence you should know about: on Windows the UI is hosted by Microsoft's WebView2 runtime, and that runtime talks to Microsoft on its own. If
that is unacceptable, block `msedgewebview2.exe` for the app's WebView folder (`%LOCALAPPDATA%\local.osintcc.desktop\EBWebView`) in Windows Firewall,
or use the Linux build (WebKitGTK) where the capture shows nothing.

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

1. **Windows packet capture** and identification of WebView2's Microsoft destinations — needs your UAC approval (see above).
2. **Installer and code signing.** Portable zip (Windows) and tarball (Linux) only; unsigned. NSIS/MSI would need a toolchain download that was not approved.
3. **Clean-machine installs** (either OS). The Linux shell has only run in a container under a virtual display.
4. **Amass 5.1.1** produced no output within 5.5 minutes for example.com; its parsing of real names is unverified. Sherlock/Maigret were checked on one well-known public account, not across their full site lists.
5. **Services tested only with mocks**: EDGAR, Overpass, VirusTotal, urlscan, Shodan, Censys, OpenCorporates, GDELT (no keys supplied).
6. **Real MCP client** never connected. **Real hardware** never attached (you confirmed this is expected). Ollama's own Windows installer path was not exercised (Ollama was already installed).
7. **Keyring on a desktop Linux session** (Secret Service) was not exercised; Linux checks used `OSINTCC_VAULT_KEY`. A headless Linux box without it will refuse to start by design.
8. **Update flow**: signed-manifest check only; no server, key or installer.
9. **CI** (`.github/workflows/ci.yml`) had never run when this was written; Python 3.12–3.14 × Windows/Linux matrix and the Linux container job are untested there.
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

1. Run `uv run python scripts/egress_check.py` and accept the two UAC prompts; decide what to do about WebView2's Microsoft traffic.
2. Decide on an installer (NSIS download) and a signing certificate; test the portable builds on a clean Windows PC and a stock Ubuntu desktop.
3. Give the keyed services real API keys and run them once; connect a real MCP client.
4. Let `ci.yml` run and pin its actions to commit SHAs.
