#!/usr/bin/env bash
# Runs INSIDE the container: copy the source, run the full Linux verification, build the sidecar and desktop shell.
set -euo pipefail
mkdir -p /work /out
cd /src
tar --exclude=./.venv --exclude='./.venv-*' --exclude=./apps/web/node_modules --exclude=./apps/desktop/src-tauri/target --exclude=./dist \
    --exclude=./build --exclude=./data --exclude=./apps/web/test-results --exclude='__pycache__' --exclude=.mypy_cache --exclude=.ruff_cache \
    --exclude=.pytest_cache --exclude=./apps/desktop/src-tauri/gen -cf - . | tar -xf - -C /work
cd /work
find /work -name '*.py' -exec chmod 644 {} +   # bind mounts from Windows show every file as executable
export UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/work/.venv
echo "=== python $(uv run --python 3.12 python --version 2>&1)"
uv sync --locked --python 3.12
echo "=== ruff / mypy / pytest";
uv run ruff check backend tests scripts
uv run mypy
OSINTCC_RETRY_SCALE=0.001 uv run pytest -q 2>&1 | tail -5
echo "=== sidecar (PyInstaller)"
uv run python scripts/build_sidecar.py 2>&1 | tail -2
echo "=== desktop shell (cargo test + release build)"
cd apps/desktop/src-tauri
mkdir -p binaries && cp /work/dist/sidecar/osintcc-backend-x86_64-unknown-linux-gnu binaries/   # tauri.conf lists it as externalBin
cargo test 2>&1 | grep "test result"
cargo build --release --features tauri/custom-protocol 2>&1 | tail -2
cd /work
echo "=== frozen backend smoke"
uv run python scripts/sidecar_smoke.py 2>&1 | tail -40
mkdir -p /out/linux
cp dist/sidecar/osintcc-backend apps/desktop/src-tauri/target/release/osintcc-desktop /out/linux/
chmod +x /out/linux/*
echo "=== built: $(ls -la /out/linux | tail -2 | tr '\n' ' ')"
