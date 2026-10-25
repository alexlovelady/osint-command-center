# Install matrix (verified on this host, 2026-10-24, Windows 11 Home 10.0.26200)

Run `uv run python -m osintcc.doctor` for the live version of the first table.

| Component | Needed for | Detected | Status |
|---|---|---|---|
| Python | backend | 3.14.6 (also tested: 3.12.14 and 3.13.15 via uv; 3.12.15 in the Linux container) | **verified** on 3.12, 3.13, 3.14 (full suite + mypy) |
| uv | env/locking | 0.12.19 | **verified** |
| Node / pnpm | web UI, tests, E2E | 24.16.0 / 11.18.0 | **verified** |
| WebView2 | Tauri on Windows | 155.0.4283.62 | present |
| Microsoft Edge | Playwright E2E (`channel: msedge`) | installed system browser | **verified** (7 E2E tests run in it) |
| Rust (`rustc`, `cargo`) | Tauri shell | 1.99.1 (rustup, `stable-x86_64-pc-windows-msvc`) | **installed 2026-10-23 with owner approval** |
| MSVC Build Tools | Rust linker | 17.14.42 (VCTools) | **installed 2026-10-23 with owner approval** (needed elevation) |
| Tauri | desktop shell | crates 2.12.5 (`Cargo.lock`), `@tauri-apps/cli` 2.1.0 | **verified**: `cargo test`, release build (`--no-bundle`), launch |
| PyInstaller | frozen backend | 6.22.3 (dev dependency) | **verified**: `scripts/build_sidecar.py` + `sidecar_smoke.py` 12/12 |
| Playwright / axe | E2E and accessibility | 1.60.0 / @axe-core/playwright 4.10.1 (dev) | **verified** |
| cargo-audit | Rust advisories | 0.22.2 (`cargo install --locked`) | **verified** run; advisory DB fetched from GitHub |
| pip-audit | Python advisories | 2.10.1 (`uv tool run`) | **verified** run |
| Git | VCS | 2.54.0 | present; **`C:\OSINT` is not a repository** |
| WSL2 Ubuntu | earlier Linux verification | stopped distro, no sudo | used for `scripts/linux-test.sh`; superseded by the container build |
| Docker | Linux build, GUI and packet-capture tests | 29.6.1 (Ubuntu 22.04 image `osintcc-linux-build`) | **used**: `docker/linux-build` (see `docs/packaging.md`) |
| Ollama + `huihui_ai/qwen3-abliterated:8b` | local AI | Ollama 0.30.7 (0.40.10 available); model pulled with `ollama pull` (5.0 GB) | **verified**: a grounded, cited answer through the app's own pipeline in 17 s; CPU-only 5.9 tokens/s |
| Subfinder 2.17.0, Amass 5.1.1, ExifTool 13.59, Sherlock 0.16.2, Maigret 0.6.6 | optional tools | **installed by the new Setup code** into `%APPDATA%\osintcc\tools` (Windows) and in a Linux container; theHarvester 4.11.1 on Linux only | **verified**: hashes matched the publishers' checksums; each reports its version |
| NSIS / WiX | installer | not downloaded | **not built** (needs approval to download; see `docs/packaging.md`) |
| Hyper-V / Windows Sandbox | clean-VM test | unavailable on Windows Home | **clean-machine install test not possible here** |

## Dependency inventory

- Python runtime (locked in `uv.lock`): fastapi, uvicorn, pydantic, sqlalchemy, alembic, httpx, dnspython, idna, keyring, reportlab, markdown-it-py,
  nh3, pyyaml, numpy, cryptography. Dev: pytest, pytest-asyncio, pytest-cov, ruff, mypy, pyinstaller.
- Web (locked in `pnpm-lock.yaml`): react 18.3.1, @tanstack/react-query 5.59.0, cytoscape 3.30.2, leaflet 1.9.4. Dev: vite 6.4.5, vitest 4.1.12,
  typescript, eslint 9.39, typescript-eslint 8.72, Playwright 1.60.0, axe-core/playwright 4.10.1, @tauri-apps/cli 2.1.0.
- Rust: 415 crates in the release build graph (`Cargo.lock`).
- Full licence inventory: `docs/license-audit.md`. SBOMs (CycloneDX): `docs/supply-chain/`.

Nothing was installed system-wide except what is marked "with owner approval". Everything else is project-local
(`.venv`, `node_modules`, `target`, `dist`) or user-level tools (`cargo-audit` in `~/.cargo/bin`, uv/pip-audit tool caches).
`apps/web/pnpm-workspace.yaml` allows only the `esbuild` post-install script that `pnpm` blocks by default (D-013).

## Optional AIV tools (not installed by this application)

Nothing below is downloaded by Setup. Install with your OS package manager, then open Verification > Status: each tool is identity-checked and version-checked, and a program that is the wrong one or an unreviewed version is reported and not run.

| Tool | Kali / Debian | Verified flags | Used for |
|---|---|---|---|
| Nmap | `sudo apt install nmap` | 7.98 | connect-scan port and service check |
| Naabu | `sudo apt install naabu` where packaged, otherwise the upstream release page | 2.6.1 | fast port check (off by default) |
| Nuclei | `sudo apt install nuclei` where packaged, otherwise the upstream release page | engine 3.11.1 | reviewed read-only templates only |
| dnstwist | `sudo apt install dnstwist` or `pipx install dnstwist` | 20240812 | look-alike domain permutations (offline) |
| ProjectDiscovery httpx | `sudo apt install httpx-toolkit` (the Python client also installs a command named `httpx`) | 1.12.0 | detected, not used |

The built-in HTTP, TLS and TCP checks need none of them. Licences differ (Nmap uses the Nmap Public Source License; the ProjectDiscovery tools are MIT; dnstwist is Apache-2.0): read them before redistributing any binary.
