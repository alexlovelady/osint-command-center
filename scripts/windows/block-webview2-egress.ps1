<#
.SYNOPSIS
  Blocks the WebView2 engine (the browser component that draws OSINT Command Center's window on Windows) from reaching Microsoft 365.

.DESCRIPTION
  The real packet capture (docs/progress.md) shows the engine opening TLS connections to substrate.office.com (Microsoft 365) shortly after launch,
  with nothing of ours involved. Windows Firewall cannot scope a rule to one application's WebView2 instance: every app that uses WebView2 shares
  the same msedgewebview2.exe. So this rule affects ALL WebView2 apps on the machine for the address ranges it covers.

  Modes
    Substrate (default)  outbound TCP/443 from msedgewebview2.exe to the Microsoft 365 / Exchange Online ranges seen in the capture
                         (52.96.0.0/14, 40.104.0.0/15) plus the current addresses of substrate.office.com. Narrow, but it will break WebView2-based
                         Outlook/Teams-style content that needs those ranges.
    All                  block ALL outbound traffic from msedgewebview2.exe (requires -IUnderstandThisAffectsOtherApps). Loopback is not filtered
                         by Windows Firewall, so OSINT Command Center keeps working; its optional OpenStreetMap tiles and any other WebView2 app do not.

  Needs an elevated PowerShell. Reversible: run with -Remove. Supports -WhatIf to show the rule without creating it.

.EXAMPLE
  ./block-webview2-egress.ps1 -WhatIf
  ./block-webview2-egress.ps1
  ./block-webview2-egress.ps1 -Mode All -IUnderstandThisAffectsOtherApps
  ./block-webview2-egress.ps1 -Remove
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [ValidateSet("Substrate", "All")] [string]$Mode = "Substrate",
  [switch]$IUnderstandThisAffectsOtherApps,
  [switch]$Remove
)
$ErrorActionPreference = "Stop"
$ruleName = "OSINT Command Center - block WebView2 egress ($Mode)"
$prefix = "OSINT Command Center - block WebView2 egress"

function Test-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not $WhatIfPreference -and -not (Test-Admin)) { throw "Run this from an elevated (Administrator) PowerShell, or add -WhatIf to preview." }

if ($Remove) {
  $existing = @(Get-NetFirewallRule -DisplayName "$prefix*" -ErrorAction SilentlyContinue)
  if ($existing.Count -eq 0) { Write-Host "No OSINT Command Center WebView2 rules found."; return }
  foreach ($r in $existing) { if ($PSCmdlet.ShouldProcess($r.DisplayName, "Remove firewall rule")) { Remove-NetFirewallRule -Name $r.Name; Write-Host "Removed: $($r.DisplayName)" } }
  return
}

$roots = @("${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application", "$env:ProgramFiles\Microsoft\EdgeWebView\Application") | Where-Object { Test-Path $_ }
$exes = @($roots | ForEach-Object { Get-ChildItem $_ -Directory | ForEach-Object { Join-Path $_.FullName "msedgewebview2.exe" } } | Where-Object { Test-Path $_ })
if ($exes.Count -eq 0) { throw "msedgewebview2.exe was not found: the WebView2 runtime is not installed in the standard location." }

if ($Mode -eq "All" -and -not $IUnderstandThisAffectsOtherApps) { throw "-Mode All blocks every WebView2 app on this machine; add -IUnderstandThisAffectsOtherApps to proceed." }

$remote = @()
if ($Mode -eq "Substrate") {
  $remote = @("52.96.0.0/14", "40.104.0.0/15")
  foreach ($h in "substrate.office.com") {
    try { $remote += (Resolve-DnsName $h -Type A -ErrorAction Stop | Where-Object Type -eq "A" | ForEach-Object { $_.IPAddress }) } catch { Write-Warning "could not resolve $h" }
  }
  $remote = @($remote | Select-Object -Unique)
}

Write-Host "Rule: $ruleName"
Write-Host "Programs: $($exes -join '; ')"
Write-Host ("Remote: " + $(if ($Mode -eq "All") { "any address (all outbound traffic from these programs)" } else { $remote -join ", " }))
Write-Host "Note: a new WebView2 runtime version installs to a new folder; re-run this script after WebView2 updates."

foreach ($exe in $exes) {
  $name = "$ruleName - $([IO.Path]::GetFileName([IO.Path]::GetDirectoryName($exe)))"
  if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) { Write-Host "Already present: $name"; continue }
  if ($PSCmdlet.ShouldProcess($name, "Create outbound block rule")) {
    $args = @{ DisplayName = $name; Direction = "Outbound"; Action = "Block"; Program = $exe; Profile = "Any"; Description = "Created by OSINT Command Center scripts/windows/block-webview2-egress.ps1. Remove with -Remove." }
    if ($Mode -eq "Substrate") { $args.RemoteAddress = $remote; $args.Protocol = "TCP"; $args.RemotePort = 443 }
    New-NetFirewallRule @args | Out-Null
    Write-Host "Created: $name"
  }
}
