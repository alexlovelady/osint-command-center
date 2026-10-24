# Packaging and release

What exists, how it was verified, and what is deliberately not done.

## What is built

| Artefact | Command | Result on the development machine |
|---|---|---|
| Web UI | `pnpm --dir apps/web build` | `apps/web/dist` (≈590 kB JS, not code-split) |
| Backend sidecar | `uv run python scripts/build_sidecar.py` | `dist/sidecar/osintcc-backend.exe`, single file, ≈54 MB (PyInstaller 6, Python 3.14); also copied as `osintcc-backend-x86_64-pc-windows-msvc.exe` (Tauri `externalBin` naming) |
| Desktop shell | `cd apps/desktop && ../web/node_modules/.bin/tauri build --no-bundle` | `src-tauri/target/release/osintcc-desktop.exe`, ≈3.3 MB, Tauri 2.12 |
| **Windows installer** | copy `dist/sidecar/osintcc-backend-x86_64-pc-windows-msvc.exe` to `apps/desktop/src-tauri/binaries/`, then `cd apps/desktop && ../web/node_modules/.bin/tauri build --bundles nsis` | `bundle/nsis/OSINT Command Center_0.1.0_x64-setup.exe`, 58 MB, per-user (no admin), unsigned; `release.py` copies it to `dist/release/` with its SHA-256 |
| Portable release | `uv run python scripts/release.py` | `dist/release/OSINT-Command-Center-<version>-win32-amd64/` + `.zip` + `SHA256SUMS.txt` (shell + sidecar + README + SECURITY) |

The shell prefers `osintcc-backend.exe` next to itself and falls back to the repository `.venv` for development.

## Verification performed

- `uv run python scripts/sidecar_smoke.py` against the frozen exe: stdout handshake (1.9 s from launch), health/migrations from the
  bundled migration files, ingest of JPEG/DOCX/PDF/PCAP, a multi-INT **PDF** report (reportlab in the bundle), MCP `initialize`,
  the plugin script runner, `keyring` backend import (Windows Credential Manager backend), and graceful shutdown with exit code 0 — 12/12 checks.
- The portable folder was launched by running `osintcc-desktop.exe` directly: the bundled backend started (two processes: PyInstaller
  bootloader + interpreter), created its database in a temporary `OSINTCC_DATA_DIR`, and closing the window ended both.

## Linux build (container)

`docker build -t osintcc-linux-build docker/linux-build`, then
`docker run --rm -v <repo>:/src:ro -v <repo>/dist/linux:/out osintcc-linux-build bash /src/docker/linux-build/build.sh` runs, inside Ubuntu 22.04
(glibc 2.35, pinned uv, rustup): `uv sync --locked`, ruff, mypy, the full pytest suite (Python 3.12), the PyInstaller sidecar (70 MB), `cargo test`, the release
shell (4 MB) and `sidecar_smoke.py` (28/28). `scripts/release.py --linux` makes the `.tar.gz` with checksums. `docker/linux-build/egress.sh`
(run with `--cap-add NET_RAW --cap-add NET_ADMIN`) starts the real shell under Xvfb, drives the backend, captures every packet with `tcpdump`,
checks that SIGKILL of the shell leaves no backend process, and saves a screenshot.

## Installer test (this machine)

`OSINT Command Center_0.1.0_x64-setup.exe /S /D=C:\OSINT\install-test` installed silently without admin rights (app, bundled backend, uninstaller). The installed
`osintcc-desktop.exe` started the bundled backend from the install folder, created its database, closed cleanly with 0 backend processes left, and
`uninstall.exe /S` removed the folder. Building it made Tauri's bundler download NSIS 3 and `nsis_tauri_utils.dll` from github.com/tauri-apps (it validates their hashes).
Not tested: a machine without the WebView2 runtime (the installer is set to download Microsoft's bootstrapper then), an upgrade over an existing install, and any other
Windows version.

## Updates

`scripts/update_tool.py` is the publisher: `keygen` (once; the private key lives in `%APPDATA%\osintcc-release\update-signing.key`, never in the repo; the matching public key is
`backend/osintcc/setup/update_key.pub` and is built into the app), `publish --version X --base-url URL FILE…` (signs a manifest with each file's SHA-256), `serve` (a plain
static file server) and `verify`. In the app: Settings → Updates → address of `manifest.json` → *Check* → *Download and verify*. The app never installs anything; it saves
the verified file under `<data dir>/updates/` and tells you to run it. Tested end to end with the real installer through the packaged backend (check → signed hash → 58 MB download → hash
matches). Back up before running an update. **Back up the private key**: if it is lost, already-installed apps cannot be sent updates they will accept (they must be reinstalled with a new key).

## Not done, and why

- **MSI and Linux packages (.deb/.AppImage).** Only the NSIS installer exists; Linux ships as a tarball.
- **Code signing.** No certificate. Binaries are unsigned: expect SmartScreen warnings. Do not tell users to disable it; give them the
  SHA-256 and sign when a certificate exists.
- **Clean-machine test.** Windows 11 Home has no Hyper-V or Windows Sandbox here, and no VM was available. The portable build has only
  been run on the machine that built it (which has Python, Rust and Node installed). Treat "runs on a clean Windows install" as
  **unverified**; the likely failure is a missing WebView2 runtime on very old systems.
- **macOS package.** Not attempted.
- **Linux package** is built and checked in a container (below) but has **not** been installed on a physical Linux desktop or a minimal distro; it
  needs `libwebkit2gtk-4.1` and GTK 3 at runtime, and a Secret Service (or `OSINTCC_VAULT_KEY`) for the master key.
- **Auto-update.** Only a signed-manifest *check* exists (`POST /api/v1/updates/check`); no update server or key exists, and nothing is ever
  installed automatically.
- **Reproducible builds.** Not attempted; PyInstaller output embeds timestamps.

## Known packaging caveats

- Plugins in the packaged app run through `osintcc-backend --run-script` and can import only the standard-library modules the sidecar bundles.
- The sidecar is a PyInstaller *onefile* build: it unpacks to a temp directory on each start, which costs start-up time and can be flagged
  by some antivirus products. A one-directory build avoids both at the cost of shipping a folder.
- `scripts/release.py` writes `LICENSES-THIRD-PARTY.txt` as a pointer to `docs/license-audit.md`, not a full notices file; assemble a real
  notices bundle before commercial redistribution.

## Release checklist

1. `uv run pytest`, `ruff`, `mypy`, `pnpm lint/typecheck/test/build`, `cargo test`, `pnpm e2e` all green.
2. `pip-audit`, `pnpm audit`, `cargo audit`, `scripts/secret_scan.py --dist`, `scripts/license_audit.py` reviewed.
3. Build sidecar → shell → `sidecar_smoke.py` → `release.py`.
4. Publish `SHA256SUMS.txt` alongside the zip; sign when possible.
