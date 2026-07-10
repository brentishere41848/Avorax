param(
  [string]$RepoRoot = $(Resolve-Path "."),
  [string]$SelfTestReport = $(Join-Path (Resolve-Path ".") "dist\windows-driver-validation\selftest_report.json"),
  [string]$CargoPath = $env:CARGO,
  [switch]$DriverFeatureEnabled
)

$ErrorActionPreference = "Stop"
$errors = @()
$maxDiagnosticChars = 4096
$maxJsonBytes = 1048576

function Add-GateError([string]$Message) {
  $bounded = Get-BoundedDiagnostic $Message
  $script:errors += $bounded
  Write-Error $bounded -ErrorAction Continue
}

function Get-BoundedDiagnostic {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  if ($text.Length -le $maxDiagnosticChars) { return $text }
  return $text.Substring(0, $maxDiagnosticChars) + "...[truncated]"
}

function Add-MissingTestsObjectError {
  Add-GateError "Protection self-test report is missing a tests object."
}

function Require-BooleanTrueTest([object]$Tests, [string]$Name, [string]$FailureMessage) {
  $property = $Tests.PSObject.Properties[$Name]
  if ($null -eq $property) {
    Add-GateError "Protection self-test report is missing tests.$Name."
    return
  }
  if (-not ($property.Value -is [bool])) {
    $type = if ($null -eq $property.Value) { "null" } else { $property.Value.GetType().Name }
    Add-GateError "Protection self-test report tests.$Name must be JSON boolean true, got $type."
    return
  }
  if (-not $property.Value) {
    Add-GateError $FailureMessage
  }
}

function Read-JsonFile([string]$Path, [string]$Description) {
  try {
    $json = Read-AvoraxGateTextFileBounded ([System.IO.Path]::GetFullPath($Path)) $maxJsonBytes $Description
    return ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    $message = Get-BoundedDiagnostic $_.Exception.Message
    if ($message.StartsWith("$Description exceeds ")) {
      Add-GateError $message
    } else {
      Add-GateError "$Description is not valid bounded JSON: $message"
    }
    return $null
  }
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

try {
  $report = Read-JsonFile $SelfTestReport "Protection self-test report"
  if ($report) {
    $testsProperty = $report.PSObject.Properties["tests"]
    if ($null -eq $testsProperty -or $null -eq $testsProperty.Value -or -not ($testsProperty.Value -is [pscustomobject])) {
      Add-MissingTestsObjectError
    } else {
      $tests = $testsProperty.Value
      Require-BooleanTrueTest $tests "eicar_scan_blocked" "EICAR scanner/verdict test did not block."
      Require-BooleanTrueTest $tests "unknown_unsigned_lockdown_policy_blocked" "Lockdown policy did not block unknown unsigned test executable."
      Require-BooleanTrueTest $tests "unknown_unsigned_allowed_after_hash_approval" "Exact-hash approval did not allow the unknown test executable."
      Require-BooleanTrueTest $tests "known_good_executable_allowed" "Known-good executable was not allowed."
      Require-BooleanTrueTest $tests "normal_exe_blocked_only_as_unknown" "Normal executable was mislabeled or not handled as unknown in Lockdown."
      if ($DriverFeatureEnabled) {
        Require-BooleanTrueTest $tests "unknown_unsigned_lockdown_blocked_before_launch" "Driver-enabled Lockdown did not verify before-launch unknown-app blocking."
      }
    }
  }
} catch {
  Add-GateError (Get-BoundedDiagnostic $_.Exception.Message)
}

if ($cargo) {
  try {
    $guardCrate = Get-AvoraxGateDirectory (Join-Path $repo "core\zentor_guard_service") "guard-service crate"
    Invoke-GateCommand $cargo @("test", "driver_request_known_bad_blocks") "Known-bad Guard block test" $guardCrate
    Invoke-GateCommand $cargo @("test", "driver_request_safe_eicar_blocks") "EICAR Guard block test" $guardCrate
  } catch {
    Add-GateError $_.Exception.Message
  }
}

if ($errors.Count -gt 0) {
  throw "Avorax protection gate failed with $($errors.Count) error(s)."
}

Write-Host "Avorax protection gate passed."
