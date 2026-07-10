param(
  [string]$RepoRoot = $(Resolve-Path "."),
  [string]$CargoPath = $env:CARGO
)

$ErrorActionPreference = "Stop"
$errors = @()
$maxGateDiagnosticChars = 4096

function Get-BoundedGateDiagnostic {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  if ($text.Length -le $maxGateDiagnosticChars) { return $text }
  return $text.Substring(0, $maxGateDiagnosticChars) + "...[truncated]"
}

function Add-GateError([string]$Message) {
  $bounded = Get-BoundedGateDiagnostic $Message
  $script:errors += $bounded
  Write-Error $bounded -ErrorAction Continue
}

function Invoke-GateCommand([string]$Tool, [string[]]$Arguments, [string]$DisplayName, [string]$WorkingDirectory) {
  if (-not $Tool) {
    Add-GateError "$DisplayName could not run because its executable was unavailable."
    return
  }
  $diagnostic = Invoke-AvoraxGateCommandDiagnostic $Tool $Arguments $DisplayName 32768 $WorkingDirectory
  if ($diagnostic.exit_code -ne 0) {
    Add-GateError "$DisplayName failed with exit code $($diagnostic.exit_code): $($diagnostic.output)"
  }
}

. (Join-Path $PSScriptRoot "avorax-security-gate-tools.ps1")
$repo = Get-AvoraxGateDirectory ([System.IO.Path]::GetFullPath((Resolve-Path $RepoRoot).Path)) "Repository root"
$cargo = $null
try {
  $cargo = Get-AvoraxRequiredTool $CargoPath "Cargo executable"
} catch {
  Add-GateError $_.Exception.Message
}

$fixtureRoot = Join-Path $repo "tests\fixtures\benign"
try {
  $fixtureRoot = Get-AvoraxGateDirectory $fixtureRoot "Benign fixture corpus"
} catch {
  Add-GateError $_.Exception.Message
}

$required = @(
  "normal-installer-like.txt",
  "cli-tool-like.txt",
  "consumer-launcher-like.txt",
  "vpn-installer-like.txt",
  "signed-looking-metadata.json",
  "unsigned-dev-tool-fixture.txt",
  "safe-admin-script.ps1",
  "archive-benign-executable-name.txt"
)

foreach ($name in $required) {
  try {
    Get-AvoraxGateFile (Join-Path $fixtureRoot $name) "Benign fixture $name" | Out-Null
  } catch {
    Add-GateError $_.Exception.Message
  }
}

if ($cargo) {
  try {
    $localCoreCrate = Get-AvoraxGateDirectory (Join-Path $repo "core\zentor_local_core") "local-core crate"
    Invoke-GateCommand $cargo @("test", "normal_exe_is_not_confirmed_threat") "normal_exe_is_not_confirmed_threat" $localCoreCrate
    Invoke-GateCommand $cargo @("test", "avorax_installer_exe_is_suppressed") "Avorax installer EXE false-positive suppression" $localCoreCrate
    Invoke-GateCommand $cargo @("test", "avorax_msi_is_suppressed") "Avorax MSI false-positive suppression" $localCoreCrate
    Invoke-GateCommand $cargo @("test", "setup_exe_in_downloads_is_not_probable_or_confirmed") "setup.exe weak-signal false-positive suppression" $localCoreCrate
    Invoke-GateCommand $cargo @("test", "zentor_internal_files_are_never_flagged_by_heuristics") "Avorax internal file false-positive suppression" $localCoreCrate
    Invoke-GateCommand $cargo @("test", "lockdown_blocks_unknown_unsigned_executable_without_malware_label") "Lockdown unknown-app label" $localCoreCrate
    Invoke-GateCommand $cargo @("test", "balanced_allows_unknown_benign_executable_with_monitoring") "Balanced unknown benign executable policy" $localCoreCrate
  } catch {
    Add-GateError $_.Exception.Message
  }
}

if ($cargo) {
  try {
    $nativeEngineCrate = Get-AvoraxGateDirectory (Join-Path $repo "core\zentor_native_engine") "native-engine crate"
    Invoke-GateCommand $cargo @("test", "normal_exe_in_downloads_is_not_malware") "Native normal EXE false-positive suppression" $nativeEngineCrate
    Invoke-GateCommand $cargo @("test", "avorax_installer_exe_is_likely_clean_not_quarantine_eligible") "Native Avorax installer trust" $nativeEngineCrate
    Invoke-GateCommand $cargo @("test", "avorax_msi_is_likely_clean_not_quarantine_eligible") "Native Avorax MSI trust" $nativeEngineCrate
  } catch {
    Add-GateError $_.Exception.Message
  }
}

if ($cargo) {
  try {
    $guardCrate = Get-AvoraxGateDirectory (Join-Path $repo "core\zentor_guard_service") "guard-service crate"
    Invoke-GateCommand $cargo @("test", "driver_request_unknown_lockdown_blocks_without_malware_label") "Guard unknown-app label" $guardCrate
    Invoke-GateCommand $cargo @("test", "driver_request_unknown_balanced_allows_and_monitors") "Guard balanced unknown app" $guardCrate
  } catch {
    Add-GateError $_.Exception.Message
  }
}

if ($errors.Count -gt 0) {
  throw "Avorax false-positive gate failed with $($errors.Count) error(s)."
}

Write-Host "Avorax false-positive gate passed."
