#!/usr/bin/env bash
# Runs INSIDE the container: copy the source, run the full Linux verification, build the web UI, the frozen backend and the desktop shell.
# Every stage logs in full to /out/logs/<stage>.log (and to the console); any failure stops the build with a nonzero exit code and says which stage.
set -Eeuo pipefail
mkdir -p /work /out/logs
STAGE="start"
trap 'rc=$?; echo; echo "!!! BUILD FAILED in stage: ${STAGE} (exit ${rc}). Full log: /out/logs/${STAGE// /_}.log" >&2; exit $rc' ERR

# stage <name> <command...>: run with the whole output teed to a log file; pipefail keeps the command's own exit code.
stage() { STAGE="$1"; shift; echo; echo "=== $STAGE"; "$@" 2>&1 | tee "/out/logs/${STAGE// /_}.log"; }

cd /src
tar --exclude=./.venv --exclude='./.venv-*' --exclude=./apps/web/node_modules --exclude=./apps/web/dist --exclude=./apps/desktop/src-tauri/target --exclude=./dist \
    --exclude=./build --exclude=./data --exclude=./apps/web/test-results --exclude='__pycache__' --exclude=.mypy_cache --exclude=.ruff_cache \
    --exclude=.pytest_cache --exclude=./apps/desktop/src-tauri/gen --exclude=./apps/desktop/src-tauri/binaries -cf - . | tar -xf - -C /work
cd /work
find /work -name '*.py' -exec chmod 644 {} +   # bind mounts from Windows show every file as executable
export UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/work/.venv CI=true
echo "=== tools: node $(node --version), pnpm $(pnpm --version), $(rustc --version), $(uv --version)"

# ---- Python: unchanged verification stages
stage "python sync"        uv sync --locked --python 3.12
stage "ruff"               uv run ruff check backend tests scripts
stage "mypy"               uv run mypy
OSINTCC_RETRY_SCALE=0.001 stage "pytest" uv run pytest -q
stage "sidecar pyinstaller" uv run python scripts/build_sidecar.py

# ---- Web UI: the Tauri shell embeds apps/web/dist (frontendDist), so it must exist BEFORE cargo test or the release build
stage "web install"        pnpm --dir apps/web install --frozen-lockfile
stage "web build"          pnpm --dir apps/web build
test -f apps/web/dist/index.html || { echo "apps/web/dist/index.html is missing after the web build" >&2; false; }

# ---- Desktop shell: externalBin must be the REAL frozen backend (never a placeholder)
STAGE="sidecar copy"
SIDECAR=/work/dist/sidecar/osintcc-backend-x86_64-unknown-linux-gnu
test -s "$SIDECAR" || { echo "frozen backend missing or empty: $SIDECAR" >&2; false; }
[ "$(stat -c %s "$SIDECAR")" -gt 10000000 ] || { echo "frozen backend is suspiciously small: $(stat -c %s "$SIDECAR") bytes" >&2; false; }
file "$SIDECAR" | grep -q "ELF 64-bit" || { echo "frozen backend is not a Linux ELF executable" >&2; false; }
mkdir -p apps/desktop/src-tauri/binaries
cp "$SIDECAR" apps/desktop/src-tauri/binaries/osintcc-backend-x86_64-unknown-linux-gnu
chmod +x apps/desktop/src-tauri/binaries/osintcc-backend-x86_64-unknown-linux-gnu
cd apps/desktop/src-tauri
stage "cargo test"         cargo test --locked
stage "cargo release build" cargo build --release --locked --features tauri/custom-protocol
cd /work

stage "frozen backend smoke" uv run python scripts/sidecar_smoke.py

# ---- export the two real executables
STAGE="export"
mkdir -p /out/linux
cp dist/sidecar/osintcc-backend apps/desktop/src-tauri/target/release/osintcc-desktop /out/linux/
chmod +x /out/linux/*
for f in /out/linux/osintcc-backend /out/linux/osintcc-desktop; do
  file "$f" | grep -q "ELF 64-bit" || { echo "$f is not a Linux executable" >&2; false; }
  [ "$(stat -c %s "$f")" -gt 1000000 ] || { echo "$f is suspiciously small" >&2; false; }
done
( cd /out/linux && sha256sum osintcc-backend osintcc-desktop | tee SHA256SUMS.txt )
echo; echo "=== BUILD OK: $(ls -la /out/linux | tail -3 | tr '\n' ' ')"
