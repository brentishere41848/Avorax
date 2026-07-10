#Requires -RunAsAdministrator
param(
  [switch]$ConfirmTestSigningChange,
  [string]$InstallRoot
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "avorax-system32-tools.ps1")

function Get-BoundedDiagnostic([object]$Value, [int]$MaxLength = 4096) {
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return "" }
  $text = $text.Trim()
  if ($text.Length -le $MaxLength) { return $text }
  return $text.Substring(0, $MaxLength) + "...<truncated>"
}

function Test-LocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Resolve-InstalledDriverHelperPath([AllowNull()][string]$Path) {
  $root = $Path
  if ([string]::IsNullOrWhiteSpace($root)) {
    foreach ($name in @('ProgramFiles', 'ProgramW6432', 'PROGRAMFILES')) {
      $value = [Environment]::GetEnvironmentVariable($name)
      if ([string]::IsNullOrWhiteSpace($value)) { continue }
      $candidateRoot = $value.Trim()
      if (Test-LocalWindowsPath $candidateRoot) {
        $root = Join-Path $candidateRoot 'Avorax'
        break
      }
    }
  }
  if ([string]::IsNullOrWhiteSpace($root)) { return $null }
  if (-not (Test-LocalWindowsPath $root)) { return $null }
  Join-Path ([System.IO.Path]::GetFullPath($root)) 'tools\windows\avorax-install-driver.ps1'
}

Write-Warning "This enables Windows TESTSIGNING for Avorax development driver validation. Use only on a development VM or test machine. Production Avorax drivers must be Microsoft-signed."
$bcdedit = Get-AvoraxSystem32Tool 'bcdedit.exe'
$bcdeditDiagnostic = Invoke-AvoraxCommandDiagnostic $bcdedit @("/enum") "bcdedit /enum" 32768
$bcd = $bcdeditDiagnostic.output
if ($bcdeditDiagnostic.exit_code -ne 0) {
  throw (Get-BoundedDiagnostic "Unable to inspect TESTSIGNING state before changing it; bcdedit /enum failed with exit code $($bcdeditDiagnostic.exit_code)`: $bcd")
}
if ($bcd -match "(?im)^\s*testsigning\s+Yes\s*$") {
  Write-Host "Windows TESTSIGNING is already enabled. If ZentorAvFilter is installed, run avorax-install-driver.ps1 or reboot if it was just changed."
  exit 0
}

if (-not $ConfirmTestSigningChange) {
  throw "Refusing to enable Windows TESTSIGNING without -ConfirmTestSigningChange. Use only on a development VM or test machine."
}

$setDiagnostic = Invoke-AvoraxCommandDiagnostic $bcdedit @("/set", "testsigning", "on") "bcdedit /set testsigning on" 4096
$setText = $setDiagnostic.output
if ($setDiagnostic.exit_code -ne 0) {
  throw (Get-BoundedDiagnostic "bcdedit failed to enable TESTSIGNING. Exit code: $($setDiagnostic.exit_code). Output: $setText")
}
if ($setText) {
  Write-Host $setText
}

Write-Host "Windows TESTSIGNING has been enabled. Reboot is required before the test-signed Avorax minifilter can load."
$driverHelperPath = Resolve-InstalledDriverHelperPath $InstallRoot
if ($driverHelperPath) {
  Write-Host "After reboot, rerun: $driverHelperPath"
} else {
  Write-Host "After reboot, rerun avorax-install-driver.ps1 from the validated Avorax install tools directory."
}
