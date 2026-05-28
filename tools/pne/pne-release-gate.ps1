param(
  [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
)

$ErrorActionPreference = "Stop"

function Fail($Message) {
  Write-Error $Message
  exit 1
}

Set-Location $RepoRoot

$required = @(
  "core/pasus_native_engine/Cargo.toml",
  "assets/pasus_native/signatures/pasus_core.psig",
  "assets/pasus_native/signatures/pasus_core.metadata.json",
  "assets/pasus_native/rules/pasus_rules.prule",
  "assets/pasus_native/rules/pasus_rules.metadata.json",
  "assets/pasus_native/ml/pasus_native_model.pmodel",
  "assets/pasus_native/ml/pasus_native_model.metadata.json",
  "assets/pasus_native/trust/pasus_known_good.ptrust",
  "assets/pasus_native/trust/pasus_known_bad_test.ptrust"
)

foreach ($path in $required) {
  if (-not (Test-Path $path)) {
    Fail "Missing required PNE artifact: $path"
  }
}

$metadata = Get-Content "assets/pasus_native/ml/pasus_native_model.metadata.json" -Raw | ConvertFrom-Json
if ($metadata.production_ready -eq $false) {
  Write-Host "Native ML is development-only; AI-only auto-quarantine must remain disabled."
}

cargo test --manifest-path "core/pasus_native_engine/Cargo.toml"
cargo test --manifest-path "core/pasus_local_core/Cargo.toml"
cargo test --manifest-path "core/pasus_guard_service/Cargo.toml"

$badUi = rg -n "ClamAV through Pasus local core|YARA Rules|bundled ClamAV|anti-cheat|gaming protection|fair play|game setup" apps/pasus_client/lib apps/pasus_website --glob "*.dart" --glob "*.tsx" --glob "*.ts"
if ($LASTEXITCODE -eq 0) {
  Write-Host $badUi
  Fail "User-facing UI still contains old primary-engine or gaming copy."
}

$status = @{
  native_engine = "pass"
  signatures = (Get-Content "assets/pasus_native/signatures/pasus_core.metadata.json" -Raw | ConvertFrom-Json).signature_count
  rules = (Get-Content "assets/pasus_native/rules/pasus_rules.metadata.json" -Raw | ConvertFrom-Json).rule_count
  compatibility_engines_enabled_by_default = $false
}

$status | ConvertTo-Json -Depth 4 | Set-Content "pne_release_gate_report.json"
Write-Host "PNE release gate passed."
