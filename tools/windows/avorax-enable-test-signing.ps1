#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Write-Warning "This enables Windows TESTSIGNING for Avorax development driver validation. Use only on a development VM or test machine. Production Avorax drivers must be Microsoft-signed."
$bcd = (bcdedit.exe /enum) 2>$null | Out-String
if ($bcd -match "(?im)^\s*testsigning\s+Yes\s*$") {
  Write-Host "Windows TESTSIGNING is already enabled. If ZentorAvFilter is installed, run avorax-install-driver.ps1 or reboot if it was just changed."
  exit 0
}

bcdedit.exe /set testsigning on | Out-Host
if ($LASTEXITCODE -ne 0) {
  throw "bcdedit failed to enable TESTSIGNING. Exit code: $LASTEXITCODE"
}

Write-Host "Windows TESTSIGNING has been enabled. Reboot is required before the test-signed Avorax minifilter can load."
Write-Host "After reboot, rerun: C:\Program Files\Avorax\tools\windows\avorax-install-driver.ps1"
