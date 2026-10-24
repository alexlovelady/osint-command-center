#!/usr/bin/env bash
# Verifies the backend on Linux without sudo: user-level uv (hash-checked), managed Python, locked deps, full pytest.
# Usage: scripts/linux-test.sh [UV_VERSION]      (copy the repo somewhere on the Linux filesystem first for speed)
set -euo pipefail
UV_VERSION="${1:-0.12.19}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$HOME/.local/bin" "$HOME/.cache/osintcc-uv"
if ! command -v uv >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/uv" ]; then
  cd "$HOME/.cache/osintcc-uv"
  base="https://github.com/astral-sh/uv/releases/download/${UV_VERSION}"
  curl -fsSL -o uv.tgz "${base}/uv-x86_64-unknown-linux-gnu.tar.gz"
  curl -fsSL -o uv.sha "${base}/uv-x86_64-unknown-linux-gnu.tar.gz.sha256"
  expected="$(cut -d' ' -f1 uv.sha)"
  actual="$(sha256sum uv.tgz | cut -d' ' -f1)"
  if [ "$expected" != "$actual" ]; then echo "uv download hash mismatch; refusing to install" >&2; exit 1; fi
  echo "uv hash verified: $actual"
  tar -xzf uv.tgz --strip-components=1 -C "$HOME/.local/bin"
fi
export PATH="$HOME/.local/bin:$PATH"
cd "$ROOT"
uv --version
uv sync --locked
uv run python -m osintcc.doctor || true
uv run ruff check backend tests scripts
uv run mypy
OSINTCC_RETRY_SCALE=0.001 uv run pytest -q "$@"
