param(
  [string]$InfPath = $(Join-Path $PSScriptRoot "..\driver\ZentorAvFilter.inf"),
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\install_report.json")
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null
try {
  & (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") -RequireAdmin -ReportPath (Join-Path (Split-Path $ReportPath) "setup_report.json")
  $testSigning = (& bcdedit /enum | Select-String -Pattern "testsigning\s+Yes" -Quiet)
  if (-not $testSigning) {
    throw "Windows TESTSIGNING is not enabled. Avorax will not enable it automatically. Read enable-test-signing-warning.md and enable it manually only in a development VM."
  }
  if (-not (Test-Path -LiteralPath $InfPath)) { throw "Driver INF not found: $InfPath" }
  pnputil /add-driver $InfPath /install
  if ($LASTEXITCODE -ne 0) { throw "pnputil failed to install ZentorAvFilter." }
  fltmc load ZentorAvFilter
  if ($LASTEXITCODE -ne 0) { throw "fltmc failed to load ZentorAvFilter." }
  $loaded = (fltmc filters | Select-String -Pattern "ZentorAvFilter" -Quiet)
  [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    installed = $true
    running = $loaded
    test_signed = $true
    production_signed = $false
    communication_port_ok = $false
    errors = @()
  } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
} catch {
  [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    installed = $false
    running = $false
    errors = @($_.Exception.Message)
  } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  throw
}
