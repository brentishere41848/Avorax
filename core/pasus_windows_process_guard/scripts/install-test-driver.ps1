param(
  [string]$InfPath = $(Join-Path $PSScriptRoot "..\driver\PasusProcessGuard.inf"),
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\install_report.json")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null
try {
  & (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") -RequireAdmin -ReportPath (Join-Path (Split-Path $ReportPath) "setup_report.json")
  $testSigning = (& bcdedit /enum | Select-String -Pattern "testsigning\s+Yes" -Quiet)
  if (-not $testSigning) { throw "Windows TESTSIGNING is not enabled. Pasus will not enable it automatically." }
  pnputil /add-driver $InfPath /install
  if ($LASTEXITCODE -ne 0) { throw "pnputil failed to install PasusProcessGuard." }
  sc.exe start PasusProcessGuard | Out-Host
  [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    installed = $true
    running = $true
    monitor_only = $true
    errors = @()
  } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
} catch {
  [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    installed = $false
    running = $false
    monitor_only = $true
    errors = @($_.Exception.Message)
  } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  throw
}
