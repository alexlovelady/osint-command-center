# Prints present/missing/version for every prerequisite. Read-only: installs nothing, changes nothing.
param([switch]$Json)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  Write-Host "uv is missing. Install it from https://docs.astral.sh/uv/getting-started/installation/ then re-run." -ForegroundColor Yellow
  exit 2
}
if ($Json) { uv run python -m osintcc.doctor --json } else { uv run python -m osintcc.doctor }
exit $LASTEXITCODE
