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
  "core/zentor_native_engine/Cargo.toml",
  "assets/zentor_native/signatures/zentor_core.zsig",
  "assets/zentor_native/signatures/zentor_core.metadata.json",
  "assets/zentor_native/rules/zentor_rules.zrule",
  "assets/zentor_native/rules/zentor_rules.metadata.json",
  "assets/zentor_native/ml/zentor_native_model.zmodel",
  "assets/zentor_native/ml/zentor_native_model.metadata.json",
  "assets/zentor_native/trust/zentor_known_good.ztrust",
  "assets/zentor_native/trust/zentor_known_bad_test.ztrust"
)

foreach ($path in $required) {
  if (-not (Test-Path $path)) {
    Fail "Missing required ZNE artifact: $path"
  }
}

$metadata = Get-Content "assets/zentor_native/ml/zentor_native_model.metadata.json" -Raw | ConvertFrom-Json
if ($metadata.production_ready -eq $false) {
  Write-Host "Native ML is development-only; AI-only auto-quarantine must remain disabled."
}

$signatureMetadata = Get-Content "assets/zentor_native/signatures/zentor_core.metadata.json" -Raw | ConvertFrom-Json
if (-not $signatureMetadata.pack_sha256) {
  Fail "Native signature metadata is missing pack_sha256."
}
if ($signatureMetadata.signature_count -lt 1) {
  Fail "Native signature pack must contain at least one compiled signature."
}

cargo build --manifest-path "core/zentor_native_engine/Cargo.toml" --bin zentor-signature-compiler
cargo test --manifest-path "core/zentor_native_engine/Cargo.toml"
cargo test --manifest-path "core/zentor_local_core/Cargo.toml"
cargo test --manifest-path "core/zentor_guard_service/Cargo.toml"

$oldBrand = "Pa" + "sus"
$oldBrandUpper = "PA" + "SUS"
$oldBrandLower = "pa" + "sus"
$oldAntiCheat = "anti" + "-cheat"
$oldFairPlay = "fair" + " play"
$oldGamingProtection = "gaming" + " protection"
$oldGameSetup = "game" + " setup"
$oldPlayerSession = "player" + " session"
$oldMatchTelemetry = "match" + " telemetry"
$badPattern = "ClamAV through Avorax local core|YARA Rules|bundled ClamAV|$oldBrand|$oldBrandUpper|$oldBrandLower|$oldAntiCheat|$oldFairPlay|$oldGamingProtection|$oldGameSetup|$oldPlayerSession|$oldMatchTelemetry"
$badUi = rg -n $badPattern apps/zentor_client/lib --glob "*.dart" --glob "*.tsx" --glob "*.ts"
if ($LASTEXITCODE -eq 0) {
  Write-Host $badUi
  Fail "User-facing UI still contains old primary-engine or gaming copy."
}

$status = @{
  native_engine = "pass"
  signatures = $signatureMetadata.signature_count
  signature_pack_sha256 = $signatureMetadata.pack_sha256
  rules = (Get-Content "assets/zentor_native/rules/zentor_rules.metadata.json" -Raw | ConvertFrom-Json).rule_count
  compatibility_engines_enabled_by_default = $false
}

$status | ConvertTo-Json -Depth 4 | Set-Content "zne_release_gate_report.json"
Write-Host "ZNE release gate passed."
