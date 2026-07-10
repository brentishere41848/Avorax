param(
  [string]$StagePath = $(Join-Path (Resolve-Path ".") "dist\windows-msi\stage")
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")
$errors = @()
$maxDiagnosticChars = 4096
$maxJsonBytes = 1048576

function Get-BoundedDiagnostic {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  if ($text.Length -le $maxDiagnosticChars) { return $text }
  return $text.Substring(0, $maxDiagnosticChars) + "...[truncated]"
}

function Add-CheckError([string]$Message) {
  $bounded = Get-BoundedDiagnostic $Message
  $script:errors += $bounded
  Write-Error $bounded -ErrorAction Continue
}

function Test-LocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Test-NoReparsePath([string]$Path, [string]$Description) {
  if (-not (Test-LocalWindowsPath $Path)) {
    Add-CheckError "$Description must be on a local Windows drive path: $Path"
    return $false
  }
  $current = [System.IO.Path]::GetFullPath($Path)
  while ($true) {
    if (Test-Path -LiteralPath $current) {
      try {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      } catch {
        Add-CheckError "$Description path component is uninspectable: $current"
        return $false
      }
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Add-CheckError "$Description must not traverse a reparse point: $current"
        return $false
      }
    }
    $parent = [System.IO.Directory]::GetParent($current)
    if ($null -eq $parent) { break }
    if ($parent.FullName -eq $current) { break }
    $current = $parent.FullName
  }
  return $true
}

function Require-Item([string]$Path, [string]$Description, [string]$Kind) {
  if (-not (Test-NoReparsePath $Path $Description)) {
    return $null
  }
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  } catch {
    Add-CheckError "$Description is missing or uninspectable: $Path"
    return $null
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Add-CheckError "$Description must not be a reparse point: $Path"
    return $null
  }
  if ($Kind -eq "file" -and -not ($item -is [System.IO.FileInfo])) {
    Add-CheckError "$Description is not a regular file: $Path"
    return $null
  }
  if ($Kind -eq "directory" -and -not ($item -is [System.IO.DirectoryInfo])) {
    Add-CheckError "$Description is not a directory: $Path"
    return $null
  }
  return $item.FullName
}

function Require-File([string]$Path, [string]$Description) {
  Require-Item $Path $Description "file"
}

function Require-Directory([string]$Path, [string]$Description) {
  Require-Item $Path $Description "directory"
}

function Assert-RepoChildPath([string]$Path, [string]$Base, [string]$Description) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    Add-CheckError "$Description must resolve to a child path inside the Avorax repository root, not the repository root itself."
    return $false
  }
  $basePrefix = $baseFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Add-CheckError "$Description must resolve inside the Avorax repository root: $pathFull"
    return $false
  }
  return $true
}

function Require-StageFile([string]$RelativePath, [string]$Description) {
  Require-File (Join-Path $StagePath $RelativePath) $Description | Out-Null
}

function Get-RegularChildFiles([string]$Path, [string]$Filter = "*") {
  $directory = Require-Directory $Path "directory for $Filter"
  if (-not $directory) { return @() }
  try {
    @(Get-ChildItem -LiteralPath $directory -Filter $Filter -File -ErrorAction Stop |
      Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 })
  } catch {
    Add-CheckError "Could not enumerate $Filter files in $directory`: $(Get-BoundedDiagnostic $_.Exception.Message)"
    @()
  }
}

function Get-JsonPropertyValue([object]$Object, [string]$Name, [string]$Description) {
  if ($null -eq $Object) {
    Add-CheckError "$Description object is missing."
    return $null
  }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property) {
    Add-CheckError "$Description.$Name is missing."
    return $null
  }
  return $property.Value
}

function Read-JsonFile([string]$Path, [string]$Description) {
  $file = Require-File $Path $Description
  if (-not $file) { return $null }
  try {
    $json = Read-AvoraxGateTextFileBounded $file $maxJsonBytes $Description
    return ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    $message = Get-BoundedDiagnostic $_.Exception.Message
    if ($message.StartsWith("$Description exceeds ")) {
      Add-CheckError $message
    } else {
      Add-CheckError "$Description is not valid bounded JSON: $message"
    }
    return $null
  }
}

function Test-SafeManifestRelativePath([object]$Value) {
  if (-not ($Value -is [string]) -or [string]::IsNullOrWhiteSpace($Value)) {
    return $false
  }
  $normalized = $Value -replace '/', '\'
  if ([System.IO.Path]::IsPathRooted($normalized)) { return $false }
  if ($normalized.StartsWith('\') -or $normalized.EndsWith('\') -or $normalized.Contains('\\')) { return $false }
  if ($normalized -match '(^|\\)\.\.(\\|$)') { return $false }
  if ($normalized -match '(^|\\)\.(\\|$)') { return $false }
  if ($normalized -match '[\x00-\x1F]') { return $false }
  return $true
}

function Test-Sha256Hex([object]$Value) {
  return ($Value -is [string] -and $Value -match '^[A-Fa-f0-9]{64}$')
}

function Test-NonNegativeJsonInteger([object]$Value) {
  if ($Value -is [bool]) { return $false }
  if (-not ($Value -is [int] -or $Value -is [long])) { return $false }
  return ([int64]$Value -ge 0)
}

Write-Host "Avorax installer stage test"
Write-Host "StagePath: $StagePath"

$repoRoot = Require-Directory ([System.IO.Path]::GetFullPath((Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path)) "Avorax repository root"
if (-not $repoRoot) { throw "Avorax repository root was not found or safe to inspect." }
if (-not (Test-NoReparsePath $StagePath "Installer stage")) {
  throw "Installer stage was not safe to inspect: $StagePath"
}
$stagePathFull = [System.IO.Path]::GetFullPath($StagePath)
if (-not (Assert-RepoChildPath $stagePathFull $repoRoot "Installer stage")) {
  throw "Installer stage path was not safe to inspect: $StagePath"
}
$stageRoot = Require-Directory $StagePath "Installer stage"
if (-not $stageRoot) { throw "Installer stage was not found or safe to inspect: $StagePath" }
$StagePath = $stageRoot

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
  @("tools\windows\avorax-core-health-probe.ps1", "structured installed core health probe"),
  @("tools\windows\avorax-installed-core-lifecycle-probe.ps1", "structured installed core lifecycle probe"),
  @("tools\windows\avorax-local-scan.ps1", "installed lifecycle local scan wrapper"),
  @("tools\windows\avorax-quarantine.ps1", "installed lifecycle quarantine wrapper"),
  @("tools\security\avorax-security-gate-tools.ps1", "installed lifecycle security gate helpers"),
  @("tools\update\avorax-build-update-package.ps1", "update package builder"),
  @("tools\update\avorax-dev-sign-manifest.py", "development update manifest signer"),
  @("install-manifest.json", "install manifest")
)) {
  Require-StageFile $required[0] $required[1]
}

$signatureCount = (Get-RegularChildFiles (Join-Path $StagePath "engine\signatures") "*.asig" | Measure-Object).Count
$ruleCount = (Get-RegularChildFiles (Join-Path $StagePath "engine\rules") "*.arule" | Measure-Object).Count
if ($signatureCount -le 0) { Add-CheckError "Installer stage contains no Avorax .asig signature packs." }
if ($ruleCount -le 0) { Add-CheckError "Installer stage contains no Avorax .arule rule packs." }

$manifestPath = Join-Path $StagePath "engine\trust\avorax_release_manifest.json"
$manifest = Read-JsonFile $manifestPath "release self-trust manifest"
if ($manifest) {
  $product = Get-JsonPropertyValue $manifest "product" "release self-trust manifest"
  if ($product -ne "Avorax Anti-Virus") {
    Add-CheckError "Release self-trust manifest product is invalid."
  }
  $version = Get-JsonPropertyValue $manifest "version" "release self-trust manifest"
  if (-not ($version -is [string]) -or [string]::IsNullOrWhiteSpace($version)) {
    Add-CheckError "Release self-trust manifest version must be a non-empty JSON string."
  }
  $files = Get-JsonPropertyValue $manifest "files" "release self-trust manifest"
  $manifestPaths = @()
  $seenManifestPaths = @{}
  if ($null -eq $files -or -not ($files -is [array])) {
    Add-CheckError "Release self-trust manifest files must be a JSON array."
  } else {
    $index = 0
    foreach ($entry in $files) {
      $description = "release self-trust manifest files[$index]"
      if ($null -eq $entry -or -not ($entry -is [pscustomobject])) {
        Add-CheckError "$description must be a JSON object."
        $index += 1
        continue
      }
      $normalizedPath = $null
      $path = Get-JsonPropertyValue $entry "path" $description
      if (-not (Test-SafeManifestRelativePath $path)) {
        Add-CheckError "$description.path must be a safe relative path."
      } else {
        $normalizedPath = ($path -replace '/', '\')
        $manifestPaths += $normalizedPath
        $key = $normalizedPath.ToLowerInvariant()
        if ($seenManifestPaths.ContainsKey($key)) {
          Add-CheckError "Release self-trust manifest contains duplicate path: $normalizedPath"
        } else {
          $seenManifestPaths[$key] = $true
        }
      }
      $sha256 = Get-JsonPropertyValue $entry "sha256" $description
      $sha256Valid = Test-Sha256Hex $sha256
      if (-not $sha256Valid) {
        Add-CheckError "$description.sha256 must be a 64-character SHA-256 hex string."
      }
      $bytes = Get-JsonPropertyValue $entry "bytes" $description
      $bytesValid = Test-NonNegativeJsonInteger $bytes
      if (-not $bytesValid) {
        Add-CheckError "$description.bytes must be a non-negative JSON integer."
      }
      if ($normalizedPath) {
        $stagedFile = Require-File (Join-Path $StagePath $normalizedPath) "$description staged file"
        if ($stagedFile) {
          $stagedItem = Get-Item -LiteralPath $stagedFile -Force -ErrorAction Stop
          if ($sha256Valid) {
            $actualSha256 = (Get-FileHash -LiteralPath $stagedFile -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualSha256 -ne $sha256.ToLowerInvariant()) {
              Add-CheckError "$description.sha256 does not match staged file hash for $normalizedPath."
            }
          }
          if ($bytesValid -and $stagedItem.Length -ne [int64]$bytes) {
            Add-CheckError "$description.bytes does not match staged file length for $normalizedPath."
          }
        }
      }
      $index += 1
    }
  }
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

$installerOutputs = Get-RegularChildFiles (Split-Path (Split-Path $StagePath)) |
  Where-Object { $_.Extension -in @(".msi", ".exe") }
$legacyProjectPattern = ("Zen" + "tor") + "|" + ("Pa" + "sus")
foreach ($artifact in $installerOutputs) {
  if ($artifact.Name -notlike "Avorax-AntiVirus-*-x64*" -or $artifact.Name -match $legacyProjectPattern) {
    Add-CheckError "Installer artifact has invalid product naming: $($artifact.Name)"
  }
}

$wxsFiles = Get-RegularChildFiles (Split-Path $StagePath) "*.wxs"
$unrelatedDomainPattern = $legacyProjectPattern + "|" + ("anti" + "-cheat") + "|" + ("gam" + "ing")
foreach ($wxs in $wxsFiles) {
  $content = Read-AvoraxGateTextFileBounded $wxs.FullName $maxJsonBytes "installer WiX source"
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
    $serviceControlPattern = "<ServiceControl[^>]+Name=`"$serviceName`""
    if ($content -notmatch $serviceControlPattern) {
      Add-CheckError "Installer WiX source does not manage $serviceName during uninstall/repair."
    }
    $startDuringRepairPattern = "<ServiceControl[^>]+Name=`"$serviceName`"[^>]+Start=`"both`""
    if ($content -match $startDuringRepairPattern) {
      Add-CheckError "Installer WiX source starts $serviceName during repair/uninstall as well as install; use Start=install only so repairs do not revive stale services."
    }
    $startDuringInstallPattern = "<ServiceControl[^>]+Name=`"$serviceName`"[^>]+Start=`"install`""
    if ($content -notmatch $startDuringInstallPattern) {
      Add-CheckError "Installer WiX source must start $serviceName after install so protection services are not left stopped."
    }
  }
  $coreServiceOnLocalCorePattern = '<File[^>]+Source="[^"]*zentor_local_core\.exe"[^>]*>\s*<ServiceInstall[^>]+Name="avorax_core_service"'
  if ($content -notmatch $coreServiceOnLocalCorePattern) {
    Add-CheckError "Avorax Core Service must be registered from zentor_local_core.exe so the service path always targets the canonical installed local-core binary."
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
