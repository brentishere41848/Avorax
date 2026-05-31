param(
  [string]$InstallPath = "C:\Program Files\Avorax",
  [string]$ProgramDataPath = "C:\ProgramData\Avorax",
  [switch]$RequireGuardRunning
)

$ErrorActionPreference = "Stop"
$errors = @()

function Add-CheckError([string]$Message) {
  $script:errors += $Message
  Write-Error $Message -ErrorAction Continue
}

function Require-Path([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) {
    Add-CheckError "$Description is missing: $Path"
    return $false
  }
  return $true
}

Write-Host "Avorax installed smoke test"
Write-Host "InstallPath: $InstallPath"
Write-Host "ProgramDataPath: $ProgramDataPath"

Require-Path $InstallPath "Install directory" | Out-Null
Require-Path (Join-Path $InstallPath "Avorax.exe") "Avorax app executable" | Out-Null
Require-Path (Join-Path $InstallPath "avorax_core_service.exe") "Avorax Core Service executable" | Out-Null
Require-Path (Join-Path $InstallPath "avorax_guard_service.exe") "Avorax Guard Service executable" | Out-Null
Require-Path (Join-Path $InstallPath "avorax_update_service.exe") "Avorax Update Service executable" | Out-Null
Require-Path (Join-Path $InstallPath "engine") "Avorax Native Engine directory" | Out-Null
Require-Path (Join-Path $InstallPath "engine\config\engine.default.json") "Engine default config" | Out-Null
Require-Path (Join-Path $InstallPath "engine\ml\avorax_native_model.amodel") "Native ML model" | Out-Null
Require-Path (Join-Path $InstallPath "engine\ml\avorax_native_model.metadata.json") "Native ML metadata" | Out-Null
Require-Path (Join-Path $InstallPath "engine\trust\avorax_known_good.atrust") "Known-good trust pack" | Out-Null
Require-Path (Join-Path $InstallPath "engine\trust\avorax_known_bad_test.atrust") "Known-bad test trust pack" | Out-Null
Require-Path (Join-Path $InstallPath "engine\trust\avorax_release_manifest.json") "Avorax release manifest" | Out-Null

$signatures = Get-ChildItem -LiteralPath (Join-Path $InstallPath "engine\signatures") -Filter "*.asig" -File -ErrorAction SilentlyContinue
$rules = Get-ChildItem -LiteralPath (Join-Path $InstallPath "engine\rules") -Filter "*.arule" -File -ErrorAction SilentlyContinue
if (($signatures | Measure-Object).Count -le 0) {
  Add-CheckError "No installed Avorax signature packs were found under engine\signatures."
}
if (($rules | Measure-Object).Count -le 0) {
  Add-CheckError "No installed Avorax rule packs were found under engine\rules."
}

foreach ($dir in @("config", "logs", "events", "Quarantine", "scans", "cache", "reports", "migration")) {
  Require-Path (Join-Path $ProgramDataPath $dir) "ProgramData $dir directory" | Out-Null
}
foreach ($dir in @("updates", "updates\staging", "updates\rollback", "updates\logs")) {
  Require-Path (Join-Path $ProgramDataPath $dir) "ProgramData $dir directory" | Out-Null
}
Require-Path (Join-Path $ProgramDataPath "reports\install_report.json") "Install report" | Out-Null

$coreService = Get-Service -Name "avorax_core_service" -ErrorAction SilentlyContinue
if (-not $coreService) {
  Add-CheckError "Avorax Core Service is not installed."
} elseif ($coreService.Status -ne "Running") {
  Add-CheckError "Avorax Core Service is installed but not running. Status: $($coreService.Status)"
}

$guardService = Get-Service -Name "avorax_guard_service" -ErrorAction SilentlyContinue
if (-not $guardService) {
  Add-CheckError "Avorax Guard Service is not installed."
} elseif ($RequireGuardRunning -and $guardService.Status -ne "Running") {
  Add-CheckError "Avorax Guard Service is installed but not running. Status: $($guardService.Status)"
}

$updateService = Get-Service -Name "avorax_update_service" -ErrorAction SilentlyContinue
if (-not $updateService) {
  Add-CheckError "Avorax Update Service is not installed."
}

$coreExe = Join-Path $InstallPath "avorax_core_service.exe"
if (Test-Path -LiteralPath $coreExe) {
  $payload = '{"command":"health"}'
  $output = $payload | & $coreExe
  if ($LASTEXITCODE -ne 0 -or -not ($output -join "`n").Contains('"ok":true')) {
    Add-CheckError "Avorax Core Service health command failed."
  }
}

if ($errors.Count -gt 0) {
  throw "Avorax installed smoke test failed with $($errors.Count) error(s)."
}

Write-Host "Avorax installed smoke test passed."
