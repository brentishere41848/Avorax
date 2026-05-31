param(
  [string]$RepoRoot = $(Resolve-Path "."),
  [string]$SelfTestReport = $(Join-Path (Resolve-Path ".") "dist\windows-driver-validation\selftest_report.json"),
  [switch]$DriverFeatureEnabled
)

$ErrorActionPreference = "Stop"
$errors = @()

function Add-GateError([string]$Message) {
  $script:errors += $Message
  Write-Error $Message -ErrorAction Continue
}

if (-not (Test-Path -LiteralPath $SelfTestReport)) {
  Add-GateError "Protection self-test report is missing: $SelfTestReport"
} else {
  $report = Get-Content -Raw -LiteralPath $SelfTestReport | ConvertFrom-Json
  if (-not $report.tests.eicar_scan_blocked) {
    Add-GateError "EICAR scanner/verdict test did not block."
  }
  if (-not $report.tests.unknown_unsigned_lockdown_policy_blocked) {
    Add-GateError "Lockdown policy did not block unknown unsigned test executable."
  }
  if (-not $report.tests.unknown_unsigned_allowed_after_hash_approval) {
    Add-GateError "Exact-hash approval did not allow the unknown test executable."
  }
  if (-not $report.tests.known_good_executable_allowed) {
    Add-GateError "Known-good executable was not allowed."
  }
  if (-not $report.tests.normal_exe_blocked_only_as_unknown) {
    Add-GateError "Normal executable was mislabeled or not handled as unknown in Lockdown."
  }
  if ($DriverFeatureEnabled -and -not $report.tests.unknown_unsigned_lockdown_blocked_before_launch) {
    Add-GateError "Driver-enabled Lockdown did not verify before-launch unknown-app blocking."
  }
}

Push-Location (Join-Path $RepoRoot "core\zentor_guard_service")
try {
  cargo test driver_request_known_bad_blocks
  if ($LASTEXITCODE -ne 0) { Add-GateError "Known-bad Guard block test failed." }
  cargo test driver_request_safe_eicar_blocks
  if ($LASTEXITCODE -ne 0) { Add-GateError "EICAR Guard block test failed." }
} finally {
  Pop-Location
}

if ($errors.Count -gt 0) {
  throw "Avorax protection gate failed with $($errors.Count) error(s)."
}

Write-Host "Avorax protection gate passed."
