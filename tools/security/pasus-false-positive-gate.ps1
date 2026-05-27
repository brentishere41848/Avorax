param(
  [string]$RepoRoot = $(Resolve-Path ".")
)

$ErrorActionPreference = "Stop"
$errors = @()

function Add-GateError([string]$Message) {
  $script:errors += $Message
  Write-Error $Message -ErrorAction Continue
}

$fixtureRoot = Join-Path $RepoRoot "tests\fixtures\benign"
if (-not (Test-Path -LiteralPath $fixtureRoot)) {
  Add-GateError "Benign fixture corpus is missing: $fixtureRoot"
}

$required = @(
  "normal-installer-like.txt",
  "cli-tool-like.txt",
  "game-launcher-like.txt",
  "vpn-installer-like.txt",
  "signed-looking-metadata.json",
  "unsigned-dev-tool-fixture.txt",
  "safe-admin-script.ps1",
  "archive-benign-executable-name.txt"
)

foreach ($name in $required) {
  if (-not (Test-Path -LiteralPath (Join-Path $fixtureRoot $name))) {
    Add-GateError "Missing benign fixture: $name"
  }
}

Push-Location (Join-Path $RepoRoot "core\pasus_local_core")
try {
  cargo test normal_exe_is_not_confirmed_threat
  if ($LASTEXITCODE -ne 0) { Add-GateError "normal_exe_is_not_confirmed_threat failed." }
  cargo test lockdown_blocks_unknown_unsigned_executable_without_malware_label
  if ($LASTEXITCODE -ne 0) { Add-GateError "Lockdown unknown-app label test failed." }
  cargo test balanced_allows_unknown_benign_executable_with_monitoring
  if ($LASTEXITCODE -ne 0) { Add-GateError "Balanced unknown benign executable policy failed." }
} finally {
  Pop-Location
}

Push-Location (Join-Path $RepoRoot "core\pasus_guard_service")
try {
  cargo test driver_request_unknown_lockdown_blocks_without_malware_label
  if ($LASTEXITCODE -ne 0) { Add-GateError "Guard unknown-app label test failed." }
  cargo test driver_request_unknown_balanced_allows_and_monitors
  if ($LASTEXITCODE -ne 0) { Add-GateError "Guard balanced unknown app test failed." }
} finally {
  Pop-Location
}

if ($errors.Count -gt 0) {
  throw "Pasus false-positive gate failed with $($errors.Count) error(s)."
}

Write-Host "Pasus false-positive gate passed."
