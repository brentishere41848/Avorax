param(
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\uninstall_report.json")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null
try {
  & (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") -RequireAdmin -ReportPath (Join-Path (Split-Path $ReportPath) "setup_report.json")
  sc.exe stop PasusProcessGuard 2>$null | Out-Host
  sc.exe delete PasusProcessGuard 2>$null | Out-Host
  [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    uninstalled = $true
    quarantine_deleted = $false
    errors = @()
  } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
} catch {
  [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    uninstalled = $false
    quarantine_deleted = $false
    errors = @($_.Exception.Message)
  } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  throw
}
