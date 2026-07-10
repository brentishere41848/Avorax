param(
  [string]$RepoRoot = $(Resolve-Path "."),
  [string]$CargoPath = $env:CARGO,
  [string]$PythonPath = $env:AVORAX_PYTHON,
  [int]$KnownGoodCacheTargetMs = 50,
  [int]$KnownBadCacheTargetMs = 100,
  [int]$UnknownLockdownTargetMs = 750
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

function Require-TargetMilliseconds([int]$Value, [string]$Name) {
  if ($Value -lt 1 -or $Value -gt 60000) {
    Add-GateError "$Name must be between 1 and 60000 milliseconds."
    return $false
  }
  return $true
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

. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")
$repo = Get-AvoraxGateDirectory ([System.IO.Path]::GetFullPath((Resolve-Path $RepoRoot).Path)) "Repository root"
$cargo = $null
$python = $null

[void](Require-TargetMilliseconds $KnownGoodCacheTargetMs "KnownGoodCacheTargetMs")
[void](Require-TargetMilliseconds $KnownBadCacheTargetMs "KnownBadCacheTargetMs")
[void](Require-TargetMilliseconds $UnknownLockdownTargetMs "UnknownLockdownTargetMs")

try {
  $cargo = Get-AvoraxRequiredTool $CargoPath "Cargo executable"
} catch {
  Add-GateError $_.Exception.Message
}
try {
  $python = Get-AvoraxRequiredTool $PythonPath "Python executable"
} catch {
  Add-GateError $_.Exception.Message
}

if ($cargo) {
  try {
    $guardCrate = Get-AvoraxGateDirectory (Join-Path $repo "core\zentor_guard_service") "guard-service crate"
    Invoke-GateCommand $cargo @("test", "driver_request_known_good_allows_in_lockdown") "Known-good cache decision test" $guardCrate
    Invoke-GateCommand $cargo @("test", "driver_request_known_bad_blocks") "Known-bad cache decision test" $guardCrate
    Invoke-GateCommand $cargo @("test", "driver_request_unknown_lockdown_blocks_without_malware_label") "Unknown Lockdown decision test" $guardCrate
  } catch {
    Add-GateError $_.Exception.Message
  }
}

try {
  $benchmarkScript = Get-AvoraxGateFile (Join-Path $repo "tools\perf\avorax-benchmark.py") "Safe performance benchmark harness"
  if ($python -and $cargo) {
    Invoke-GateCommand $python @($benchmarkScript, "--repo-root", $repo, "--cargo-path", $cargo, "--file-count", "64", "--file-size", "4096") "Safe performance benchmark harness" $repo
  }
} catch {
  Add-GateError $_.Exception.Message
}

$report = [ordered]@{
  known_good_cache_target_ms = $KnownGoodCacheTargetMs
  known_bad_cache_target_ms = $KnownBadCacheTargetMs
  unknown_lockdown_target_ms = $UnknownLockdownTargetMs
  measured_by = "unit decision path; WDK VM should run driver latency tests"
  status = if ($errors.Count -eq 0) { "pass" } else { "fail" }
}

$out = Join-Path $repo "dist\performance\performance_gate_report.json"
Write-AvoraxGateJsonFileAtomic $out $report 4 "performance report"

if ($errors.Count -gt 0) {
  throw "Avorax performance gate failed with $($errors.Count) error(s)."
}

Write-Host "Avorax performance gate passed. Report: $out"
