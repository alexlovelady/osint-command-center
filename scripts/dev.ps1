# Starts the loopback backend (fixed DEV port 8791) and the web UI. Development only.
# Packaged builds use an ephemeral port and a random per-launch token instead.
param([string]$Token = 'dev-token-local-only')
Set-Location (Split-Path $PSScriptRoot -Parent)
$env:OSINTCC_SESSION_TOKEN = $Token
$backend = Start-Process uv -ArgumentList 'run','python','-m','osintcc.server','--dev-port' -PassThru -NoNewWindow
try {
  Write-Host "Open http://127.0.0.1:5173/#token=$Token"
  pnpm --dir apps/web run dev
} finally {
  if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id }
}
