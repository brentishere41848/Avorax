param(
  [string]$StagePath = $(Join-Path (Resolve-Path ".") "dist\windows-msi\stage")
)

$ErrorActionPreference = "Stop"
$errors = @()

function Add-CheckError([string]$Message) {
  $script:errors += $Message
  Write-Error $Message -ErrorAction Continue
}

function Require-Path([string]$RelativePath, [string]$Description) {
  $path = Join-Path $StagePath $RelativePath
  if (-not (Test-Path -LiteralPath $path)) {
    Add-CheckError "$Description is missing from installer stage: $RelativePath"
  }
}

Write-Host "Avorax installer stage test"
Write-Host "StagePath: $StagePath"

if (-not (Test-Path -LiteralPath $StagePath)) {
  throw "Installer stage was not found: $StagePath"
}

foreach ($required in @(
  @("Avorax.exe", "Avorax app executable"),
  @("avorax_core_service.exe", "Avorax Core Service executable"),
  @("avorax_guard_service.exe", "Avorax Guard Service executable"),
  @("avorax_update_service.exe", "Avorax Update Service executable"),
  @("engine\config\engine.default.json", "engine default config"),
  @("engine\signatures\avorax_core.asig", "core signature pack"),
  @("engine\rules\avorax_core.arule", "core rule pack"),
  @("engine\ml\avorax_native_model.amodel", "native ML model"),
  @("engine\ml\avorax_native_model.metadata.json", "native ML metadata"),
  @("engine\ml\zentor_native_model.zmodel", "native ML source model"),
  @("engine\ml\zentor_native_model.metadata.json", "native ML source metadata"),
  @("engine\trust\avorax_known_good.atrust", "known-good trust pack"),
  @("engine\trust\avorax_known_bad_test.atrust", "known-bad test trust pack"),
  @("engine\trust\avorax_release_manifest.json", "release self-trust manifest"),
  @("docs\limitations.md", "limitations documentation"),
  @("docs\safe-malware-testing.md", "safe malware testing documentation"),
  @("docs\real-time-protection.md", "real-time protection documentation"),
  @("tools\windows\avorax-installed-smoke-test.ps1", "installed smoke test"),
  @("tools\update\avorax-build-update-package.ps1", "update package builder"),
  @("install-manifest.json", "install manifest")
)) {
  Require-Path $required[0] $required[1]
}

$signatureCount = (Get-ChildItem -LiteralPath (Join-Path $StagePath "engine\signatures") -Filter "*.asig" -File -ErrorAction SilentlyContinue | Measure-Object).Count
$ruleCount = (Get-ChildItem -LiteralPath (Join-Path $StagePath "engine\rules") -Filter "*.arule" -File -ErrorAction SilentlyContinue | Measure-Object).Count
if ($signatureCount -le 0) { Add-CheckError "Installer stage contains no Avorax .asig signature packs." }
if ($ruleCount -le 0) { Add-CheckError "Installer stage contains no Avorax .arule rule packs." }

$manifestPath = Join-Path $StagePath "engine\trust\avorax_release_manifest.json"
if (Test-Path -LiteralPath $manifestPath) {
  $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
  $manifestPaths = @($manifest.files | ForEach-Object { $_.path })
  foreach ($trusted in @(
    "Avorax.exe",
    "avorax_core_service.exe",
    "avorax_guard_service.exe",
    "engine\signatures\avorax_core.asig",
    "engine\rules\avorax_core.arule",
    "engine\ml\avorax_native_model.amodel"
  )) {
    if ($manifestPaths -notcontains $trusted) {
      Add-CheckError "Release self-trust manifest does not include: $trusted"
    }
  }
}

$installerOutputs = Get-ChildItem -LiteralPath (Split-Path (Split-Path $StagePath)) -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -in @(".msi", ".exe") }
$legacyProjectPattern = ("Zen" + "tor") + "|" + ("Pa" + "sus")
foreach ($artifact in $installerOutputs) {
  if ($artifact.Name -notlike "Avorax-AntiVirus-*-x64*" -or $artifact.Name -match $legacyProjectPattern) {
    Add-CheckError "Installer artifact has invalid product naming: $($artifact.Name)"
  }
}

$wxsFiles = Get-ChildItem -LiteralPath (Split-Path $StagePath) -Filter "*.wxs" -File -ErrorAction SilentlyContinue
$unrelatedDomainPattern = $legacyProjectPattern + "|" + ("anti" + "-cheat") + "|" + ("gam" + "ing")
foreach ($wxs in $wxsFiles) {
  $content = Get-Content -Raw -LiteralPath $wxs.FullName
  $productFacingContent = ($content -split "`r?`n" | Where-Object {
    $_ -match "<Package " -or
    $_ -match "<Bundle " -or
    $_ -match "<Shortcut " -or
    $_ -match "<ServiceInstall " -or
    $_ -match "<bal:WixStandardBootstrapperApplication "
  }) -join "`n"
  $visibleProductCopy = $productFacingContent -replace '\sId="[^"]+"', ''
  if ($visibleProductCopy -match $unrelatedDomainPattern) {
    Add-CheckError "Installer WiX source contains forbidden product copy: $($wxs.Name)"
  }
  if ($wxs.Name -ne "Avorax.wxs") {
    if ($wxs.Name -eq "Avorax.Bundle.wxs") {
      $hasVisibleBootstrapper = $content -match "<bal:WixStandardBootstrapperApplication[\s\S]+Theme=`"hyperlinkLicense`""
      $hasVisibleMsiPackage = $content -match "<MsiPackage[^>]+Visible=`"yes`""
      if (-not $hasVisibleBootstrapper -or -not $hasVisibleMsiPackage) {
        Add-CheckError "EXE bootstrapper does not surface visible install UI/progress for proof during install."
      }
    }
    continue
  }
  if ($content -notmatch "<ui:WixUI[^>]+Id=`"WixUI_Minimal`"") {
    Add-CheckError "MSI WiX source does not include a visible installer UI."
  }
  if ($content -notmatch "<WixVariable[^>]+Id=`"WixUILicenseRtf`"") {
    Add-CheckError "MSI WiX source does not include the installer license/proof page asset."
  }
  foreach ($serviceName in @("avorax_core_service", "avorax_guard_service")) {
    $serviceControlPattern = "<ServiceControl[^>]+Name=`"$serviceName`"[^>]+Start=`"both`""
    if ($content -notmatch $serviceControlPattern) {
      Add-CheckError "Installer WiX source does not start $serviceName during install and repair."
    }
  }
  if ($content -notmatch "Name=`"avorax_update_service`"") {
    Add-CheckError "Installer WiX source does not register Avorax Update Service."
  }
  foreach ($updateDir in @("AvoraxData_updates_staging", "AvoraxData_updates_rollback", "AvoraxData_updates_logs")) {
    if ($content -notmatch $updateDir) {
      Add-CheckError "Installer WiX source is missing update directory $updateDir."
    }
  }
}

if ($errors.Count -gt 0) {
  throw "Avorax installer stage test failed with $($errors.Count) error(s)."
}

Write-Host "Avorax installer stage test passed."
