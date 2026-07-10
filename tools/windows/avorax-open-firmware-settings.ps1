#Requires -RunAsAdministrator
param(
  [switch]$ConfirmFirmwareReboot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot "avorax-system32-tools.ps1")

Write-Warning "This will reboot Windows into UEFI firmware settings. Use it to disable Secure Boot on a development/test machine so Windows TESTSIGNING can be enabled for the test-signed Avorax minifilter. Save your work before continuing."
Write-Warning "Production Avorax drivers require Microsoft signing instead of disabling Secure Boot."
if (-not $ConfirmFirmwareReboot) {
  throw "Refusing to reboot into UEFI firmware settings without -ConfirmFirmwareReboot."
}

$secureBoot = $null
try {
  $secureBoot = Confirm-SecureBootUEFI
  Write-Host "Secure Boot enabled: $secureBoot"
} catch {
  Write-Warning "Could not query Secure Boot state: $(Get-AvoraxBoundedDiagnostic $_.Exception.Message)"
}

Write-Host "Rebooting into UEFI firmware settings in 30 seconds. Press Ctrl+C now to cancel."
$shutdown = Get-AvoraxSystem32Tool "shutdown.exe"
$shutdownDiagnostic = Invoke-AvoraxCommandDiagnostic $shutdown @("/r", "/fw", "/t", "30", "/c", "Avorax development driver remediation: rebooting to UEFI firmware settings so Secure Boot can be disabled for TESTSIGNING.") "shutdown /r /fw" 4096
if ($shutdownDiagnostic.output) {
  Write-Host $shutdownDiagnostic.output
}
if ($shutdownDiagnostic.exit_code -ne 0) {
  throw "shutdown /r /fw failed with exit code $($shutdownDiagnostic.exit_code): $($shutdownDiagnostic.output)"
}
