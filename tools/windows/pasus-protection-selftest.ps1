param(
  [switch]$BuildDriver,
  [switch]$InstallDriver,
  [switch]$ProcessGuard,
  [string]$ReportPath = $(Join-Path (Resolve-Path ".") "dist\windows-driver-validation\selftest_report.json")
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path "."
$miniScripts = Join-Path $root "core\pasus_windows_minifilter\scripts"
$processScripts = Join-Path $root "core\pasus_windows_process_guard\scripts"

if ($BuildDriver) {
  & (Join-Path $miniScripts "build-driver.ps1")
  if ($ProcessGuard) {
    & (Join-Path $processScripts "build-driver.ps1")
  }
}

if ($InstallDriver) {
  & (Join-Path $miniScripts "install-test-driver.ps1")
  if ($ProcessGuard) {
    & (Join-Path $processScripts "install-test-driver.ps1")
  }
}

Push-Location (Join-Path $root "core\pasus_guard_service")
try {
  cargo build --release
  if ($LASTEXITCODE -ne 0) { throw "Guard Service release build failed." }
} finally {
  Pop-Location
}

& (Join-Path $miniScripts "run-driver-self-test.ps1") -ReportPath $ReportPath
Write-Host "Pasus protection self-test report: $ReportPath"
