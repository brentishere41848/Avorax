param(
  [string]$SelfTestReport = $(Join-Path (Resolve-Path ".") "dist\windows-driver-validation\selftest_report.json"),
  [switch]$DriverFeatureEnabled,
  [switch]$AiFeatureEnabled = $true
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path "."
$errors = @()

function Add-Error([string]$Message) {
  $script:errors += $Message
  Write-Error $Message -ErrorAction Continue
}

try {
  & (Join-Path $root "tools\branding\branding-check.ps1") -Root $root
} catch {
  Add-Error "Branding check failed: $($_.Exception.Message)"
}

if (-not (Test-Path -LiteralPath $SelfTestReport)) {
  Add-Error "selftest_report.json is missing: $SelfTestReport"
} else {
  $report = Get-Content -Raw -LiteralPath $SelfTestReport | ConvertFrom-Json
  if ($report.overall_result -ne "pass" -and $DriverFeatureEnabled) {
    Add-Error "Driver feature is enabled but protection self-test did not pass."
  }
  if ($DriverFeatureEnabled -and -not $report.driver.communication_port_ok) {
    Add-Error "Driver feature is enabled but driver communication port is not OK."
  }
}

$metadataPath = Join-Path $root "assets\models\zentor_static_malware_model.metadata.json"
$modelPath = Join-Path $root "assets\models\zentor_static_malware_model.onnx"
if ($AiFeatureEnabled) {
  if (-not (Test-Path -LiteralPath $modelPath)) { Add-Error "AI model file is missing: $modelPath" }
  if (-not (Test-Path -LiteralPath $metadataPath)) { Add-Error "AI metadata file is missing: $metadataPath" }
  if (Test-Path -LiteralPath $metadataPath) {
    $metadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
    if (-not $metadata.production_ready) {
      Write-Warning "AI model is development-only; release must not enable AI-only auto-quarantine."
    }
  }
}

$dist = Join-Path $root "dist"
if (Test-Path -LiteralPath $dist) {
  $badArtifacts = Get-ChildItem -LiteralPath $dist -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "\.(msi|exe)$" -and $_.Name -notlike "Zentor-AntiVirus-*-x64*" }
  foreach ($artifact in $badArtifacts) {
    Add-Error "Installer artifact is not Zentor-AntiVirus named: $($artifact.Name)"
  }
}

Push-Location (Join-Path $root "core\zentor_guard_service")
try {
  cargo test
  if ($LASTEXITCODE -ne 0) { Add-Error "Guard Service tests failed." }
} finally {
  Pop-Location
}

Push-Location (Join-Path $root "core\zentor_local_core")
try {
  cargo test
  if ($LASTEXITCODE -ne 0) { Add-Error "Local core tests failed." }
} finally {
  Pop-Location
}

Push-Location (Join-Path $root "apps\zentor_client")
try {
  flutter test
  if ($LASTEXITCODE -ne 0) { Add-Error "Flutter tests failed." }
} finally {
  Pop-Location
}

& (Join-Path $root "tools\security\zentor-false-positive-gate.ps1") -RepoRoot $root
if ($LASTEXITCODE -ne 0) { Add-Error "False-positive gate failed." }

$protectionArgs = @{
  RepoRoot = $root
  SelfTestReport = $SelfTestReport
}
if ($DriverFeatureEnabled) {
  & (Join-Path $root "tools\security\zentor-protection-gate.ps1") @protectionArgs -DriverFeatureEnabled
} else {
  & (Join-Path $root "tools\security\zentor-protection-gate.ps1") @protectionArgs
}
if ($LASTEXITCODE -ne 0) { Add-Error "Protection gate failed." }

& (Join-Path $root "tools\perf\zentor-performance-gate.ps1") -RepoRoot $root
if ($LASTEXITCODE -ne 0) { Add-Error "Performance gate failed." }

if ($errors.Count -gt 0) {
  throw "Zentor release gate failed with $($errors.Count) error(s)."
}

Write-Host "Zentor release gate passed."
