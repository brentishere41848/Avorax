param(
  [string]$RepoRoot = $(Resolve-Path "."),
  [int]$KnownGoodCacheTargetMs = 50,
  [int]$KnownBadCacheTargetMs = 100,
  [int]$UnknownLockdownTargetMs = 750
)

$ErrorActionPreference = "Stop"
$errors = @()

function Add-GateError([string]$Message) {
  $script:errors += $Message
  Write-Error $Message -ErrorAction Continue
}

Push-Location (Join-Path $RepoRoot "core\zentor_guard_service")
try {
  cargo test driver_request_known_good_allows_in_lockdown
  if ($LASTEXITCODE -ne 0) { Add-GateError "Known-good cache decision test failed." }
  cargo test driver_request_known_bad_blocks
  if ($LASTEXITCODE -ne 0) { Add-GateError "Known-bad cache decision test failed." }
  cargo test driver_request_unknown_lockdown_blocks_without_malware_label
  if ($LASTEXITCODE -ne 0) { Add-GateError "Unknown Lockdown decision test failed." }
} finally {
  Pop-Location
}

$report = [ordered]@{
  known_good_cache_target_ms = $KnownGoodCacheTargetMs
  known_bad_cache_target_ms = $KnownBadCacheTargetMs
  unknown_lockdown_target_ms = $UnknownLockdownTargetMs
  measured_by = "unit decision path; WDK VM should run driver latency tests"
  status = if ($errors.Count -eq 0) { "pass" } else { "fail" }
}

$out = Join-Path $RepoRoot "dist\performance\performance_gate_report.json"
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $out -Encoding UTF8

if ($errors.Count -gt 0) {
  throw "Avorax performance gate failed with $($errors.Count) error(s)."
}

Write-Host "Avorax performance gate passed. Report: $out"
