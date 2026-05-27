param(
  [string]$InfPath = $(Join-Path $PSScriptRoot "..\driver\PasusAvFilter.inf")
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Administrator rights are required to install the Pasus test driver."
}

$testSigning = (& bcdedit /enum | Select-String -Pattern "testsigning\s+Yes" -Quiet)
if (-not $testSigning) {
  throw "Windows TESTSIGNING is not enabled. Pasus will not enable it automatically. Read enable-test-signing-warning.md and enable it manually only in a development VM."
}

if (-not (Test-Path -LiteralPath $InfPath)) {
  throw "Driver INF not found: $InfPath"
}

pnputil /add-driver $InfPath /install
if ($LASTEXITCODE -ne 0) {
  throw "pnputil failed to install PasusAvFilter."
}

fltmc load PasusAvFilter
if ($LASTEXITCODE -ne 0) {
  throw "fltmc failed to load PasusAvFilter."
}

fltmc filters | Select-String -Pattern "PasusAvFilter" | Out-Host
Write-Host "PasusAvFilter test driver installed and loaded."
