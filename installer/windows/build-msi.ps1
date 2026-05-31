param(
  [string]$Version = "0.1.0",
  [string]$Configuration = "Release",
  [switch]$SkipFlutterBuild,
  [switch]$RequireLocalCore,
  [switch]$AllowIncompletePayload,
  [switch]$SkipClamAV,
  [switch]$IncludeClamAVCompatibility,
  [switch]$AllowDevelopmentModel
)

$ErrorActionPreference = "Stop"

function Require-Command([string]$Name, [string]$Hint) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "$Name was not found. $Hint"
  }
}

function Invoke-Checked([scriptblock]$Command, [string]$FailureMessage) {
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "$FailureMessage Exit code: $LASTEXITCODE"
  }
}

function Copy-Tree([string]$Source, [string]$Destination) {
  if (Test-Path $Destination) {
    Remove-Item -LiteralPath $Destination -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  Copy-Item -Path (Join-Path $Source "*") -Destination $Destination -Recurse -Force
}

function Copy-RequiredTree([string]$Source, [string]$Destination, [string]$Name) {
  if (-not (Test-Path $Source)) {
    throw "$Name source was not found: $Source"
  }
  Copy-Tree $Source $Destination
}

function Copy-RequiredFile([string]$Source, [string]$Destination, [string]$Name) {
  if (-not (Test-Path $Source)) {
    throw "$Name file was not found: $Source"
  }
  New-Item -ItemType Directory -Force -Path (Split-Path $Destination) | Out-Null
  Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Assert-StagePath([string]$RelativePath, [string]$Description) {
  $path = Join-Path $stageDir $RelativePath
  if (-not (Test-Path $path)) {
    throw "Installer payload is incomplete. Missing $Description at $RelativePath"
  }
}

function Copy-RequiredAlias([string]$Source, [string]$Destination, [string]$Name) {
  if (-not (Test-Path $Source)) {
    throw "$Name source was not found: $Source"
  }
  New-Item -ItemType Directory -Force -Path (Split-Path $Destination) | Out-Null
  Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Ensure-ClamAVPackage([string]$ZipPath, [string]$Url, [string]$ExpectedSha256) {
  if (Test-Path $ZipPath) {
    $existingHash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash
    if ($existingHash -ne $ExpectedSha256) {
      throw "Cached ClamAV package hash mismatch. Expected $ExpectedSha256 but found $existingHash at $ZipPath"
    }
    return
  }

  New-Item -ItemType Directory -Force -Path (Split-Path $ZipPath) | Out-Null
  Write-Host "Downloading ClamAV runtime: $Url"
  Invoke-WebRequest -Uri $Url -OutFile $ZipPath
  $downloadedHash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash
  if ($downloadedHash -ne $ExpectedSha256) {
    throw "Downloaded ClamAV package hash mismatch. Expected $ExpectedSha256 but found $downloadedHash"
  }
}

function Copy-ClamAVRuntime([string]$ZipPath, [string]$ExtractDir, [string]$Destination) {
  if (Test-Path $ExtractDir) {
    Remove-Item -LiteralPath $ExtractDir -Recurse -Force
  }
  if (Test-Path $Destination) {
    Remove-Item -LiteralPath $Destination -Recurse -Force
  }

  New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  Expand-Archive -LiteralPath $ZipPath -DestinationPath $ExtractDir -Force

  $sourceRoot = $ExtractDir
  $candidateRoots = Get-ChildItem -LiteralPath $ExtractDir -Directory
  foreach ($candidateRoot in $candidateRoots) {
    if (Test-Path (Join-Path $candidateRoot.FullName "clamscan.exe")) {
      $sourceRoot = $candidateRoot.FullName
      break
    }
  }

  $runtimeExtensions = @(".exe", ".dll", ".txt", ".md")
  Get-ChildItem -LiteralPath $sourceRoot -File |
    Where-Object { $runtimeExtensions -contains $_.Extension.ToLowerInvariant() } |
    ForEach-Object {
      Copy-Item -LiteralPath $_.FullName -Destination $Destination -Force
    }

  foreach ($directoryName in @("certs", "conf_examples", "COPYING")) {
    $sourceDirectory = Join-Path $sourceRoot $directoryName
    if (Test-Path $sourceDirectory) {
      Copy-Tree $sourceDirectory (Join-Path $Destination $directoryName)
    }
  }

  if (-not (Test-Path (Join-Path $Destination "clamscan.exe"))) {
    throw "ClamAV runtime was expanded, but clamscan.exe was not found."
  }
}

function To-WixId([string]$Value) {
  $id = [regex]::Replace($Value, "[^A-Za-z0-9_]", "_")
  if ($id -match "^[0-9]") {
    $id = "I_$id"
  }
  if ($id.Length -gt 60) {
    $hash = [System.BitConverter]::ToString(
      [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value))
    ).Replace("-", "").Substring(0, 10)
    $id = $id.Substring(0, 45) + "_" + $hash
  }
  return $id
}

function XmlEscape([string]$Value) {
  return [System.Security.SecurityElement]::Escape($Value)
}

function Get-RelativePath([string]$Base, [string]$Path) {
  $baseFull = [IO.Path]::GetFullPath($Base).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $pathFull = [IO.Path]::GetFullPath($Path)
  if ($pathFull.TrimEnd('\', '/').Equals($baseFull.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    return "."
  }
  if ($pathFull.StartsWith($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    return $pathFull.Substring($baseFull.Length)
  }
  return $pathFull
}

function Get-FlutterBuildNumber([string]$Version) {
  $buildNumber = [regex]::Replace($Version, "[^0-9]", "")
  if ([string]::IsNullOrWhiteSpace($buildNumber)) {
    return "1"
  }
  return $buildNumber
}

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$clientDir = Join-Path $root "apps\zentor_client"
$releaseDir = Join-Path $clientDir "build\windows\x64\runner\$Configuration"
$workspaceTargetDir = Join-Path $root "target\release"
$localCoreExe = Join-Path $root "core\zentor_local_core\target\x86_64-pc-windows-msvc\release\zentor_local_core.exe"
$localCoreExeGnu = Join-Path $root "core\zentor_local_core\target\x86_64-pc-windows-gnu\release\zentor_local_core.exe"
$localCoreExeDefault = Join-Path $root "core\zentor_local_core\target\release\zentor_local_core.exe"
$localCoreExeWorkspace = Join-Path $workspaceTargetDir "zentor_local_core.exe"
$guardServiceExeDefault = Join-Path $root "core\zentor_guard_service\target\release\zentor_guard_service.exe"
$guardServiceExeWorkspace = Join-Path $workspaceTargetDir "zentor_guard_service.exe"
$updateServiceExeDefault = Join-Path $root "core\avorax_update_service\target\release\avorax_update_service.exe"
$updateServiceExeWorkspace = Join-Path $workspaceTargetDir "avorax_update_service.exe"
$distRoot = Join-Path $root "dist"
$stageDir = Join-Path $distRoot "windows-msi\stage"
$wxsPath = Join-Path $distRoot "windows-msi\Avorax.wxs"
$bundleWxsPath = Join-Path $distRoot "windows-msi\Avorax.Bundle.wxs"
$msiPath = Join-Path $distRoot "Avorax-AntiVirus-$Version-x64.msi"
$exeInstallerPath = Join-Path $distRoot "Avorax-AntiVirus-$Version-x64-setup.exe"
$clamAvVersion = "1.5.2"
$clamAvUrl = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$clamAvVersion/clamav-$clamAvVersion.win.x64.zip"
$clamAvSha256 = "6F868ED7A7E5A15ACED82C53A4FA9F3F42FA9D7F7DE14A606BA8DB0756518EED"
$clamAvZipPath = Join-Path $PSScriptRoot "cache\clamav-$clamAvVersion.win.x64.zip"
$clamAvExtractDir = Join-Path $distRoot "windows-msi\clamav-extract"
$modelSourceDir = Join-Path $root "assets\models"
$nativeSourceDir = Join-Path $root "assets\zentor_native"
$yaraSourceDir = Join-Path $root "assets\yara"
$testAssetsSourceDir = Join-Path $root "assets\test"
$trustAssetsSourceDir = Join-Path $root "assets\trust"
$threatAssetsSourceDir = Join-Path $root "assets\threats"
$driverToolsSourceDir = Join-Path $root "core\zentor_windows_minifilter"
$processGuardToolsSourceDir = Join-Path $root "core\zentor_windows_process_guard"
$windowsToolsSourceDir = Join-Path $root "tools\windows"
$securityToolsSourceDir = Join-Path $root "tools\security"
$perfToolsSourceDir = Join-Path $root "tools\perf"
$brandingToolsSourceDir = Join-Path $root "tools\branding"
$zneToolsSourceDir = Join-Path $root "tools\zne"
$intelToolsSourceDir = Join-Path $root "tools\zentor_intel"
$simulatorsSourceDir = Join-Path $root "tools\simulators"
$updateToolsSourceDir = Join-Path $root "tools\update"
$docsSourceDir = Join-Path $root "docs"
$modelFile = Join-Path $modelSourceDir "zentor_static_malware_model.onnx"
$modelMetadataFile = Join-Path $modelSourceDir "zentor_static_malware_model.metadata.json"

Require-Command "dotnet" "Install the .NET SDK."

if (-not $SkipFlutterBuild) {
  $flutter = "flutter"
  if (Test-Path "C:\Users\Brent\develop\flutter\bin\flutter.bat") {
    $flutter = "C:\Users\Brent\develop\flutter\bin\flutter.bat"
  }
  Push-Location $clientDir
  try {
    $buildNumber = Get-FlutterBuildNumber $Version
    Invoke-Checked { & $flutter build windows --release --build-name $Version --build-number $buildNumber "--dart-define=AVORAX_APP_VERSION=$Version" "--dart-define=ZENTOR_APP_VERSION=$Version" "--dart-define=AVORAX_UPDATE_FEED_URL=https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json" "--dart-define=AVORAX_UPDATE_CHANNEL=dev" "--dart-define=AVORAX_UPDATES_REPO_OWNER=brentishere41848" "--dart-define=AVORAX_UPDATES_REPO_NAME=Avorax" } "Flutter Windows release build failed."
  } finally {
    Pop-Location
  }
}

if (-not (Test-Path (Join-Path $releaseDir "Avorax.exe"))) {
  throw "Flutter release output was not found at $releaseDir"
}

if (-not (Test-Path $localCoreExe) -and -not (Test-Path $localCoreExeDefault) -and -not (Test-Path $localCoreExeGnu) -and -not (Test-Path $localCoreExeWorkspace)) {
  $cargo = Get-Command "cargo" -ErrorAction SilentlyContinue
  if (-not $cargo -and (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe")) {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    $cargo = Get-Command "cargo" -ErrorAction SilentlyContinue
  }
  if ($cargo) {
    Push-Location (Join-Path $root "core\zentor_local_core")
    try {
      Invoke-Checked { cargo build --release } "zentor_local_core release build failed."
    } finally {
      Pop-Location
    }
  }
}

if (-not (Test-Path $guardServiceExeDefault)) {
  $cargo = Get-Command "cargo" -ErrorAction SilentlyContinue
  if (-not $cargo -and (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe")) {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    $cargo = Get-Command "cargo" -ErrorAction SilentlyContinue
  }
  if ($cargo) {
    Push-Location (Join-Path $root "core\zentor_guard_service")
    try {
      Invoke-Checked { cargo build --release } "zentor_guard_service release build failed."
    } finally {
      Pop-Location
    }
  }
}

if (-not (Test-Path $updateServiceExeDefault) -and -not (Test-Path $updateServiceExeWorkspace)) {
  $cargo = Get-Command "cargo" -ErrorAction SilentlyContinue
  if (-not $cargo -and (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe")) {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    $cargo = Get-Command "cargo" -ErrorAction SilentlyContinue
  }
  if ($cargo) {
    Push-Location (Join-Path $root "core\avorax_update_service")
    try {
      Invoke-Checked { cargo build --release } "avorax_update_service release build failed."
    } finally {
      Pop-Location
    }
  }
}

New-Item -ItemType Directory -Force -Path (Split-Path $wxsPath) | Out-Null
Copy-Tree $releaseDir $stageDir

if (-not (Test-Path $modelFile) -or -not (Test-Path $modelMetadataFile)) {
  throw "Avorax AI model assets are required: $modelFile and $modelMetadataFile"
}
$modelMetadata = Get-Content -Raw -LiteralPath $modelMetadataFile | ConvertFrom-Json
if (-not $modelMetadata.production_ready -and -not $AllowDevelopmentModel) {
  throw "The packaged AI model is marked production_ready=false. Provide a validated production model or pass -AllowDevelopmentModel for an explicitly non-production build."
}
$stageModelDir = Join-Path $stageDir "assets\models"
$releaseModelDir = Join-Path $releaseDir "assets\models"
Copy-RequiredTree $modelSourceDir $stageModelDir "AI model assets"
Copy-RequiredTree $modelSourceDir $releaseModelDir "AI model assets"

if (-not (Test-Path (Join-Path $nativeSourceDir "signatures\zentor_core.zsig")) -or -not (Test-Path (Join-Path $nativeSourceDir "rules\zentor_rules.zrule")) -or -not (Test-Path (Join-Path $nativeSourceDir "ml\zentor_native_model.zmodel"))) {
  throw "Avorax Native Engine assets are required under $nativeSourceDir"
}
$stageNativeDir = Join-Path $stageDir "assets\zentor_native"
$releaseNativeDir = Join-Path $releaseDir "assets\zentor_native"
Copy-RequiredTree $nativeSourceDir $stageNativeDir "Avorax Native Engine assets"
Copy-RequiredTree $nativeSourceDir $releaseNativeDir "Avorax Native Engine assets"

$stageEngineDir = Join-Path $stageDir "engine"
$releaseEngineDir = Join-Path $releaseDir "engine"
Copy-RequiredTree $nativeSourceDir $stageEngineDir "installed Avorax Native Engine assets"
Copy-RequiredTree $nativeSourceDir $releaseEngineDir "installed Avorax Native Engine assets"
New-Item -ItemType Directory -Force -Path (Join-Path $stageEngineDir "config") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $releaseEngineDir "config") | Out-Null
$engineDefaultConfig = @{
  product = "Avorax Anti-Virus"
  engine = "Avorax Native Engine"
  installed_layout_version = 1
  compatibility_engines_enabled = $false
} | ConvertTo-Json -Depth 4
Set-Content -LiteralPath (Join-Path $stageEngineDir "config\engine.default.json") -Value $engineDefaultConfig -Encoding UTF8
Set-Content -LiteralPath (Join-Path $releaseEngineDir "config\engine.default.json") -Value $engineDefaultConfig -Encoding UTF8
Copy-RequiredAlias (Join-Path $nativeSourceDir "signatures\zentor_core.zsig") (Join-Path $stageEngineDir "signatures\avorax_core.asig") "core native signature alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "signatures\zentor_core.zsig") (Join-Path $releaseEngineDir "signatures\avorax_core.asig") "core native signature alias"
foreach ($signatureAlias in @(
  @("zentor_realworld_hashes.zsig", "avorax_realworld_hashes.asig"),
  @("zentor_script_threats.zsig", "avorax_script_threats.asig"),
  @("zentor_ransomware_indicators.zsig", "avorax_ransomware_indicators.asig"),
  @("zentor_infostealer_indicators.zsig", "avorax_infostealer_indicators.asig"),
  @("zentor_miner_pup_indicators.zsig", "avorax_miner_pup_indicators.asig")
)) {
  $source = Join-Path $nativeSourceDir "signatures\$($signatureAlias[0])"
  if (Test-Path $source) {
    Copy-RequiredAlias $source (Join-Path $stageEngineDir "signatures\$($signatureAlias[1])") "native signature alias"
    Copy-RequiredAlias $source (Join-Path $releaseEngineDir "signatures\$($signatureAlias[1])") "native signature alias"
  }
}
Copy-RequiredAlias (Join-Path $nativeSourceDir "rules\zentor_rules.zrule") (Join-Path $stageEngineDir "rules\avorax_core.arule") "core native rule alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "rules\zentor_rules.zrule") (Join-Path $releaseEngineDir "rules\avorax_core.arule") "core native rule alias"
foreach ($ruleAlias in @(
  @("zentor_script_threats.zrule", "avorax_script_threats.arule"),
  @("zentor_ransomware.zrule", "avorax_ransomware.arule"),
  @("zentor_infostealers.zrule", "avorax_infostealers.arule"),
  @("zentor_persistence.zrule", "avorax_persistence.arule"),
  @("zentor_miners_pup.zrule", "avorax_miners_pup.arule")
)) {
  $source = Join-Path $nativeSourceDir "rules\$($ruleAlias[0])"
  if (Test-Path $source) {
    Copy-RequiredAlias $source (Join-Path $stageEngineDir "rules\$($ruleAlias[1])") "native rule alias"
    Copy-RequiredAlias $source (Join-Path $releaseEngineDir "rules\$($ruleAlias[1])") "native rule alias"
  }
}
Copy-RequiredAlias (Join-Path $nativeSourceDir "ml\zentor_native_model.zmodel") (Join-Path $stageEngineDir "ml\avorax_native_model.amodel") "native ML model alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "ml\zentor_native_model.zmodel") (Join-Path $releaseEngineDir "ml\avorax_native_model.amodel") "native ML model alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "ml\zentor_native_model.metadata.json") (Join-Path $stageEngineDir "ml\avorax_native_model.metadata.json") "native ML metadata alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "ml\zentor_native_model.metadata.json") (Join-Path $releaseEngineDir "ml\avorax_native_model.metadata.json") "native ML metadata alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "trust\zentor_known_good.ztrust") (Join-Path $stageEngineDir "trust\avorax_known_good.atrust") "known-good trust alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "trust\zentor_known_good.ztrust") (Join-Path $releaseEngineDir "trust\avorax_known_good.atrust") "known-good trust alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "trust\zentor_known_bad_test.ztrust") (Join-Path $stageEngineDir "trust\avorax_known_bad_test.atrust") "known-bad test trust alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "trust\zentor_known_bad_test.ztrust") (Join-Path $releaseEngineDir "trust\avorax_known_bad_test.atrust") "known-bad test trust alias"

if (Test-Path (Join-Path $yaraSourceDir "zentor_core_rules.yar")) {
  $stageYaraDir = Join-Path $stageDir "assets\yara"
  $releaseYaraDir = Join-Path $releaseDir "assets\yara"
  Copy-Tree $yaraSourceDir $stageYaraDir
  Copy-Tree $yaraSourceDir $releaseYaraDir
}

if (-not (Test-Path (Join-Path $testAssetsSourceDir "known_bad_test_hashes.json"))) {
  throw "Known-bad test hash asset is required: $(Join-Path $testAssetsSourceDir "known_bad_test_hashes.json")"
}
$stageTestDir = Join-Path $stageDir "assets\test"
$releaseTestDir = Join-Path $releaseDir "assets\test"
Copy-RequiredTree $testAssetsSourceDir $stageTestDir "safe test assets"
Copy-RequiredTree $testAssetsSourceDir $releaseTestDir "safe test assets"

$stageTrustDir = Join-Path $stageDir "assets\trust"
$releaseTrustDir = Join-Path $releaseDir "assets\trust"
Copy-RequiredTree $trustAssetsSourceDir $stageTrustDir "trust assets"
Copy-RequiredTree $trustAssetsSourceDir $releaseTrustDir "trust assets"

$stageThreatsDir = Join-Path $stageDir "assets\threats"
$releaseThreatsDir = Join-Path $releaseDir "assets\threats"
Copy-RequiredTree $threatAssetsSourceDir $stageThreatsDir "known-bad test threat assets"
Copy-RequiredTree $threatAssetsSourceDir $releaseThreatsDir "known-bad test threat assets"

foreach ($requiredDriverFile in @(
  "driver\ZentorAvFilter.vcxproj",
  "driver\ZentorAvFilter.inf",
  "driver\Driver.c",
  "driver\Communication.c",
  "driver\Filter.c",
  "scripts\build-driver.ps1",
  "scripts\install-test-driver.ps1",
  "scripts\uninstall-test-driver.ps1"
)) {
  $driverFilePath = Join-Path $driverToolsSourceDir $requiredDriverFile
  if (-not (Test-Path $driverFilePath)) {
    throw "Avorax Windows driver development file is missing: $driverFilePath"
  }
}
$stageDriverToolsDir = Join-Path $stageDir "driver-tools\zentor_windows_minifilter"
Copy-RequiredTree $driverToolsSourceDir $stageDriverToolsDir "Windows minifilter driver tools"
$stageProcessGuardToolsDir = Join-Path $stageDir "driver-tools\zentor_windows_process_guard"
Copy-RequiredTree $processGuardToolsSourceDir $stageProcessGuardToolsDir "Windows process guard driver tools"

$stageToolsDir = Join-Path $stageDir "tools"
Copy-RequiredTree $windowsToolsSourceDir (Join-Path $stageToolsDir "windows") "Windows validation tools"
Copy-RequiredTree $securityToolsSourceDir (Join-Path $stageToolsDir "security") "security release gates"
Copy-RequiredTree $perfToolsSourceDir (Join-Path $stageToolsDir "perf") "performance release gate"
Copy-RequiredTree $brandingToolsSourceDir (Join-Path $stageToolsDir "branding") "branding release gate"
Copy-RequiredTree $zneToolsSourceDir (Join-Path $stageToolsDir "zne") "ZNE self-test tools"
Copy-RequiredTree $intelToolsSourceDir (Join-Path $stageToolsDir "zentor_intel") "safe threat-intel tools"
Copy-RequiredTree $simulatorsSourceDir (Join-Path $stageToolsDir "simulators") "safe simulator tools"
Copy-RequiredTree $updateToolsSourceDir (Join-Path $stageToolsDir "update") "update package tools"

$coreSource = $null
if (Test-Path $localCoreExe) {
  $coreSource = $localCoreExe
} elseif (Test-Path $localCoreExeDefault) {
  $coreSource = $localCoreExeDefault
} elseif (Test-Path $localCoreExeGnu) {
  $coreSource = $localCoreExeGnu
} elseif (Test-Path $localCoreExeWorkspace) {
  $coreSource = $localCoreExeWorkspace
}

if ($coreSource) {
  Copy-Item -LiteralPath $coreSource -Destination (Join-Path $stageDir "avorax_core_service.exe") -Force
  Copy-Item -LiteralPath $coreSource -Destination (Join-Path $releaseDir "avorax_core_service.exe") -Force
  Copy-Item -LiteralPath $coreSource -Destination (Join-Path $stageDir "zentor_local_core.exe") -Force
  Copy-Item -LiteralPath $coreSource -Destination (Join-Path $releaseDir "zentor_local_core.exe") -Force
} elseif ($RequireLocalCore -or -not $AllowIncompletePayload) {
  throw "zentor_local_core.exe was not found. Avorax installers must include the local core and Avorax Native Engine runtime. Build it for Windows first or pass -AllowIncompletePayload only for local packaging diagnostics."
} else {
  Write-Warning "zentor_local_core.exe was not found. This diagnostic package will install the app, but local malware scanning will show Engine Unavailable until the core is deployed."
}

if (Test-Path $guardServiceExeDefault) {
  Copy-Item -LiteralPath $guardServiceExeDefault -Destination (Join-Path $stageDir "avorax_guard_service.exe") -Force
  Copy-Item -LiteralPath $guardServiceExeDefault -Destination (Join-Path $releaseDir "avorax_guard_service.exe") -Force
  Copy-Item -LiteralPath $guardServiceExeDefault -Destination (Join-Path $stageDir "zentor_guard_service.exe") -Force
  Copy-Item -LiteralPath $guardServiceExeDefault -Destination (Join-Path $releaseDir "zentor_guard_service.exe") -Force
} elseif (Test-Path $guardServiceExeWorkspace) {
  Copy-Item -LiteralPath $guardServiceExeWorkspace -Destination (Join-Path $stageDir "avorax_guard_service.exe") -Force
  Copy-Item -LiteralPath $guardServiceExeWorkspace -Destination (Join-Path $releaseDir "avorax_guard_service.exe") -Force
  Copy-Item -LiteralPath $guardServiceExeWorkspace -Destination (Join-Path $stageDir "zentor_guard_service.exe") -Force
  Copy-Item -LiteralPath $guardServiceExeWorkspace -Destination (Join-Path $releaseDir "zentor_guard_service.exe") -Force
} elseif (-not $AllowIncompletePayload) {
  throw "zentor_guard_service.exe was not found. Avorax installers must include and register the Guard Service. Build it for Windows first or pass -AllowIncompletePayload only for local packaging diagnostics."
} else {
  Write-Warning "zentor_guard_service.exe was not found. This diagnostic package will not include the real-time Guard helper."
}

if (Test-Path $updateServiceExeDefault) {
  Copy-Item -LiteralPath $updateServiceExeDefault -Destination (Join-Path $stageDir "avorax_update_service.exe") -Force
  Copy-Item -LiteralPath $updateServiceExeDefault -Destination (Join-Path $releaseDir "avorax_update_service.exe") -Force
} elseif (Test-Path $updateServiceExeWorkspace) {
  Copy-Item -LiteralPath $updateServiceExeWorkspace -Destination (Join-Path $stageDir "avorax_update_service.exe") -Force
  Copy-Item -LiteralPath $updateServiceExeWorkspace -Destination (Join-Path $releaseDir "avorax_update_service.exe") -Force
} elseif (-not $AllowIncompletePayload) {
  throw "avorax_update_service.exe was not found. Avorax installers must include and register the Update Service. Build it for Windows first or pass -AllowIncompletePayload only for local packaging diagnostics."
} else {
  Write-Warning "avorax_update_service.exe was not found. This diagnostic package cannot apply in-app .aup updates."
}

if ($IncludeClamAVCompatibility -and -not $SkipClamAV) {
  Ensure-ClamAVPackage $clamAvZipPath $clamAvUrl $clamAvSha256
  Copy-ClamAVRuntime $clamAvZipPath $clamAvExtractDir (Join-Path $stageDir "ClamAV")
  Copy-ClamAVRuntime $clamAvZipPath $clamAvExtractDir (Join-Path $releaseDir "ClamAV")
  Write-Host "Bundled optional ClamAV compatibility runtime $clamAvVersion in the MSI."
} else {
  Write-Host "Skipping ClamAV compatibility runtime. Avorax Native Engine is the primary scanner."
}

$runtimeDlls = @(
  "C:\Windows\System32\vcruntime140.dll",
  "C:\Windows\System32\vcruntime140_1.dll",
  "C:\Windows\System32\msvcp140.dll"
)
foreach ($dll in $runtimeDlls) {
  if (Test-Path $dll) {
    Copy-Item -LiteralPath $dll -Destination $stageDir -Force
  } else {
    Write-Warning "Visual C++ runtime file missing on this machine: $dll"
  }
}

$docsStage = Join-Path $stageDir "docs"
Copy-RequiredTree $docsSourceDir $docsStage "documentation"
Copy-RequiredFile (Join-Path $root "README.md") (Join-Path $docsStage "README.md") "README"

$manifest = [ordered]@{
  product = "Avorax Anti-Virus"
  version = $Version
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  includes = [ordered]@{
    flutter_client = Test-Path (Join-Path $stageDir "Avorax.exe")
    local_core = Test-Path (Join-Path $stageDir "avorax_core_service.exe")
    guard_service = Test-Path (Join-Path $stageDir "avorax_guard_service.exe")
    update_service = Test-Path (Join-Path $stageDir "avorax_update_service.exe")
    native_engine_assets = Test-Path (Join-Path $stageDir "engine")
    ai_model_assets = Test-Path (Join-Path $stageDir "assets\models")
    trust_assets = Test-Path (Join-Path $stageDir "assets\trust")
    known_bad_test_assets = Test-Path (Join-Path $stageDir "assets\threats")
    windows_driver_tools = Test-Path (Join-Path $stageDir "driver-tools")
    validation_tools = Test-Path (Join-Path $stageDir "tools\windows\zentor-protection-selftest.ps1")
    release_gates = Test-Path (Join-Path $stageDir "tools\windows\zentor-release-gate.ps1")
    safe_simulators = Test-Path (Join-Path $stageDir "tools\simulators")
    docs = Test-Path (Join-Path $stageDir "docs\windows-driver.md")
    clamav_compatibility = Test-Path (Join-Path $stageDir "ClamAV")
  }
  service_install = [ordered]@{
    core_service = "installed and started by MSI"
    guard_service = "installed and started by MSI"
    update_service = "installed by MSI as manual-demand updater"
  }
  driver_status = "driver source and validation scripts are packaged; driver is not silently installed or enabled"
}
$manifestPath = Join-Path $stageDir "install-manifest.json"
($manifest | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $releaseDir "install-manifest.json") -Force

$releaseManifestPath = Join-Path $stageEngineDir "trust\avorax_release_manifest.json"
$releaseFiles = Get-ChildItem -LiteralPath $stageDir -Recurse -File |
  Where-Object { $_.FullName -ne $releaseManifestPath } |
  Sort-Object FullName |
  ForEach-Object {
    [ordered]@{
      path = Get-RelativePath $stageDir $_.FullName
      sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      bytes = $_.Length
    }
  }
$releaseManifest = [ordered]@{
  product = "Avorax Anti-Virus"
  version = $Version
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  files = $releaseFiles
}
($releaseManifest | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $releaseManifestPath -Encoding UTF8
Copy-Item -LiteralPath $releaseManifestPath -Destination (Join-Path $releaseEngineDir "trust\avorax_release_manifest.json") -Force

foreach ($requiredPayload in @(
  @("Avorax.exe", "Flutter desktop client"),
  @("avorax_core_service.exe", "Avorax Core Service"),
  @("avorax_guard_service.exe", "Avorax Guard Service"),
  @("avorax_update_service.exe", "Avorax Update Service"),
  @("zentor_local_core.exe", "local core scanner helper"),
  @("zentor_guard_service.exe", "Guard Service"),
  @("engine\config\engine.default.json", "installed engine config"),
  @("engine\signatures\avorax_core.asig", "installed native signature pack"),
  @("engine\rules\avorax_core.arule", "installed native rule pack"),
  @("engine\ml\avorax_native_model.amodel", "installed native ML model"),
  @("engine\ml\zentor_native_model.zmodel", "installed native ML source model"),
  @("engine\trust\avorax_known_good.atrust", "installed trust store"),
  @("engine\trust\avorax_release_manifest.json", "Avorax release self-trust manifest"),
  @("assets\zentor_native\signatures\zentor_core.zsig", "native signature pack"),
  @("assets\zentor_native\rules\zentor_rules.zrule", "native rule pack"),
  @("assets\zentor_native\ml\zentor_native_model.zmodel", "native ML model"),
  @("assets\models\zentor_static_malware_model.onnx", "AI compatibility model"),
  @("assets\test\known_bad_test_hashes.json", "safe known-bad test hashes"),
  @("assets\trust\zentor_known_good.db", "trust store"),
  @("assets\threats\zentor_known_bad_test_hashes.json", "known-bad test threat asset"),
  @("driver-tools\zentor_windows_minifilter\scripts\run-driver-self-test.ps1", "minifilter driver self-test"),
  @("driver-tools\zentor_windows_process_guard\scripts\run-process-guard-self-test.ps1", "process guard self-test"),
  @("tools\windows\zentor-protection-selftest.ps1", "protection self-test"),
  @("tools\windows\zentor-release-gate.ps1", "Windows release gate"),
  @("tools\windows\avorax-installed-smoke-test.ps1", "installed smoke test"),
  @("tools\windows\avorax-installer-stage-test.ps1", "installer stage test"),
  @("tools\security\zentor-false-positive-gate.ps1", "false-positive gate"),
  @("tools\perf\zentor-performance-gate.ps1", "performance gate"),
  @("tools\branding\branding-check.ps1", "branding gate"),
  @("tools\zne\zne-release-gate.ps1", "ZNE release gate"),
  @("tools\simulators", "safe simulators"),
  @("tools\zentor_intel", "safe threat-intel tools"),
  @("tools\update\avorax-build-update-package.ps1", "update package builder"),
  @("docs\README.md", "installed README"),
  @("docs\windows-driver.md", "driver documentation"),
  @("docs\safe-malware-testing.md", "safe malware testing documentation"),
  @("install-manifest.json", "installed payload manifest")
)) {
  Assert-StagePath $requiredPayload[0] $requiredPayload[1]
}

$files = Get-ChildItem -LiteralPath $stageDir -Recurse -File |
  Where-Object { $_.Extension -ne ".pdb" } |
  Sort-Object FullName

$directories = @{}
foreach ($file in $files) {
  $relativeDir = Get-RelativePath $stageDir $file.DirectoryName
  if ($relativeDir -eq ".") { continue }
  $parts = $relativeDir -split "[/\\]"
  $current = ""
  foreach ($part in $parts) {
    $current = if ($current) { Join-Path $current $part } else { $part }
    if (-not $directories.ContainsKey($current)) {
      $parent = [IO.Path]::GetDirectoryName($current)
      $directories[$current] = [ordered]@{
        Id = "DIR_" + (To-WixId $current)
        Name = $part
        Parent = if ($parent) { "DIR_" + (To-WixId $parent) } else { "INSTALLFOLDER" }
      }
    }
  }
}

$directoryXml = New-Object System.Text.StringBuilder
foreach ($dir in $directories.GetEnumerator() | Sort-Object { $_.Key.Split('\').Count }) {
  [void]$directoryXml.AppendLine("    <DirectoryRef Id=`"$($dir.Value.Parent)`">")
  [void]$directoryXml.AppendLine("      <Directory Id=`"$($dir.Value.Id)`" Name=`"$(XmlEscape $dir.Value.Name)`" />")
  [void]$directoryXml.AppendLine("    </DirectoryRef>")
}

$componentsXml = New-Object System.Text.StringBuilder
$componentRefsXml = New-Object System.Text.StringBuilder
$index = 0
foreach ($file in $files) {
  $index++
  $relativePath = Get-RelativePath $stageDir $file.FullName
  $relativeDir = [IO.Path]::GetDirectoryName($relativePath)
  $directoryId = if ([string]::IsNullOrEmpty($relativeDir)) { "INSTALLFOLDER" } else { "DIR_" + (To-WixId $relativeDir) }
  $componentId = "CMP_$index"
  $fileId = "FIL_$index"
  [void]$componentsXml.AppendLine("    <DirectoryRef Id=`"$directoryId`">")
  [void]$componentsXml.AppendLine("      <Component Id=`"$componentId`" Guid=`"*`">")
  [void]$componentsXml.AppendLine("        <File Id=`"$fileId`" Source=`"$(XmlEscape $file.FullName)`" KeyPath=`"yes`" />")
  if ($relativePath -eq "avorax_core_service.exe") {
    [void]$componentsXml.AppendLine("        <ServiceInstall Id=`"AvoraxCoreServiceInstall`" Type=`"ownProcess`" Vital=`"yes`" Name=`"avorax_core_service`" DisplayName=`"Avorax Core Service`" Description=`"Provides local scanning, native engine loading, quarantine, scan jobs, and local protection state for Avorax Anti-Virus.`" Start=`"auto`" Account=`"LocalSystem`" ErrorControl=`"normal`" Arguments=`"--service`" />")
    [void]$componentsXml.AppendLine("        <ServiceControl Id=`"AvoraxCoreServiceControl`" Name=`"avorax_core_service`" Start=`"both`" Stop=`"both`" Remove=`"uninstall`" Wait=`"yes`" />")
  }
  if ($relativePath -eq "avorax_guard_service.exe") {
    [void]$componentsXml.AppendLine("        <ServiceInstall Id=`"AvoraxGuardServiceInstall`" Type=`"ownProcess`" Vital=`"yes`" Name=`"avorax_guard_service`" DisplayName=`"Avorax Guard Service`" Description=`"Provides real-time protection, process monitoring, driver communication, and threat response for Avorax Anti-Virus.`" Start=`"auto`" Account=`"LocalSystem`" ErrorControl=`"normal`" Arguments=`"--service`" />")
    [void]$componentsXml.AppendLine("        <ServiceControl Id=`"AvoraxGuardServiceControl`" Name=`"avorax_guard_service`" Start=`"both`" Stop=`"both`" Remove=`"uninstall`" Wait=`"yes`" />")
  }
  if ($relativePath -eq "avorax_update_service.exe") {
    [void]$componentsXml.AppendLine("        <ServiceInstall Id=`"AvoraxUpdateServiceInstall`" Type=`"ownProcess`" Vital=`"yes`" Name=`"avorax_update_service`" DisplayName=`"Avorax Update Service`" Description=`"Applies verified Avorax updates, manages rollback, and updates Avorax components safely.`" Start=`"demand`" Account=`"LocalSystem`" ErrorControl=`"normal`" Arguments=`"--service`" />")
    [void]$componentsXml.AppendLine("        <ServiceControl Id=`"AvoraxUpdateServiceControl`" Name=`"avorax_update_service`" Stop=`"both`" Remove=`"uninstall`" Wait=`"yes`" />")
  }
  [void]$componentsXml.AppendLine("      </Component>")
  [void]$componentsXml.AppendLine("    </DirectoryRef>")
  [void]$componentRefsXml.AppendLine("      <ComponentRef Id=`"$componentId`" />")
}

$installReportSource = Join-Path $distRoot "windows-msi\install_report.template.json"
$installReport = [ordered]@{
  version = $Version
  install_path = "C:\Program Files\Avorax"
  app_installed = $true
  core_service_installed = $true
  core_service_running = $false
  guard_service_installed = $true
  guard_service_running = $false
  update_service_installed = $true
  update_service_running = $false
  native_engine_assets_present = $true
  signature_pack_count = (Get-ChildItem -LiteralPath (Join-Path $stageEngineDir "signatures") -File -Filter "*.asig").Count
  rule_pack_count = (Get-ChildItem -LiteralPath (Join-Path $stageEngineDir "rules") -File -Filter "*.arule").Count
  model_present = Test-Path (Join-Path $stageEngineDir "ml\avorax_native_model.amodel")
  trust_pack_present = Test-Path (Join-Path $stageEngineDir "trust\avorax_known_good.atrust")
  engine_self_test_result = "pending_post_install_validation"
  errors = @()
}
($installReport | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $installReportSource -Encoding UTF8

$programDataSubdirs = @("config", "logs", "events", "Quarantine", "scans", "cache", "reports", "migration", "updates")
$updateDataSubdirs = @("staging", "rollback", "logs")
$programDataXml = New-Object System.Text.StringBuilder
$programDataRefsXml = New-Object System.Text.StringBuilder
[void]$programDataXml.AppendLine("    <StandardDirectory Id=`"CommonAppDataFolder`">")
[void]$programDataXml.AppendLine("      <Directory Id=`"AvoraxProgramDataFolder`" Name=`"Avorax`">")
foreach ($dir in $programDataSubdirs) {
  if ($dir -eq "updates") {
    [void]$programDataXml.AppendLine("        <Directory Id=`"AvoraxData_updates`" Name=`"updates`">")
    [void]$programDataXml.AppendLine("          <Directory Id=`"AvoraxData_updates_staging`" Name=`"staging`" />")
    [void]$programDataXml.AppendLine("          <Directory Id=`"AvoraxData_updates_rollback`" Name=`"rollback`" />")
    [void]$programDataXml.AppendLine("          <Directory Id=`"AvoraxData_updates_logs`" Name=`"logs`" />")
    [void]$programDataXml.AppendLine("        </Directory>")
  } else {
    [void]$programDataXml.AppendLine("        <Directory Id=`"AvoraxData_$dir`" Name=`"$dir`" />")
  }
}
[void]$programDataXml.AppendLine("      </Directory>")
[void]$programDataXml.AppendLine("    </StandardDirectory>")
foreach ($dir in $programDataSubdirs) {
  $componentId = "AvoraxCreateData_$dir"
  [void]$programDataXml.AppendLine("    <DirectoryRef Id=`"AvoraxData_$dir`">")
  [void]$programDataXml.AppendLine("      <Component Id=`"$componentId`" Guid=`"*`">")
  [void]$programDataXml.AppendLine("        <CreateFolder />")
  if ($dir -eq "reports") {
    [void]$programDataXml.AppendLine("        <File Id=`"AvoraxInstallReportFile`" Source=`"$(XmlEscape $installReportSource)`" Name=`"install_report.json`" KeyPath=`"yes`" />")
  } else {
    [void]$programDataXml.AppendLine("        <RegistryValue Root=`"HKLM`" Key=`"Software\Avorax\ProgramData`" Name=`"$dir`" Type=`"integer`" Value=`"1`" KeyPath=`"yes`" />")
  }
  [void]$programDataXml.AppendLine("      </Component>")
  [void]$programDataXml.AppendLine("    </DirectoryRef>")
  [void]$programDataRefsXml.AppendLine("      <ComponentRef Id=`"$componentId`" />")
}
foreach ($dir in $updateDataSubdirs) {
  $componentId = "AvoraxCreateData_updates_$dir"
  [void]$programDataXml.AppendLine("    <DirectoryRef Id=`"AvoraxData_updates_$dir`">")
  [void]$programDataXml.AppendLine("      <Component Id=`"$componentId`" Guid=`"*`">")
  [void]$programDataXml.AppendLine("        <CreateFolder />")
  [void]$programDataXml.AppendLine("        <RegistryValue Root=`"HKLM`" Key=`"Software\Avorax\ProgramData\updates`" Name=`"$dir`" Type=`"integer`" Value=`"1`" KeyPath=`"yes`" />")
  [void]$programDataXml.AppendLine("      </Component>")
  [void]$programDataXml.AppendLine("    </DirectoryRef>")
  [void]$programDataRefsXml.AppendLine("      <ComponentRef Id=`"$componentId`" />")
}

$upgradeCode = "35E0D125-9699-4CFB-8E93-588D0E83F517"
$wxs = @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package
    Name="Avorax Anti-Virus"
    Manufacturer="Avorax Security"
    Version="$Version"
    UpgradeCode="$upgradeCode"
    Scope="perMachine">
    <MajorUpgrade DowngradeErrorMessage="A newer version of Avorax is already installed." />
    <MediaTemplate EmbedCab="yes" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="Avorax" />
    </StandardDirectory>
    <StandardDirectory Id="ProgramMenuFolder">
      <Directory Id="ApplicationProgramsFolder" Name="Avorax Anti-Virus" />
    </StandardDirectory>
$programDataXml

$directoryXml
$componentsXml
    <DirectoryRef Id="ApplicationProgramsFolder">
      <Component Id="StartMenuShortcut" Guid="*">
        <Shortcut Id="ZentorStartMenuShortcut" Name="Avorax Anti-Virus" Target="[INSTALLFOLDER]Avorax.exe" WorkingDirectory="INSTALLFOLDER" />
        <RemoveFolder Id="RemoveApplicationProgramsFolder" On="uninstall" />
        <RegistryValue Root="HKCU" Key="Software\Avorax\Client" Name="installed" Type="integer" Value="1" KeyPath="yes" />
      </Component>
    </DirectoryRef>

    <Feature Id="MainFeature" Title="Avorax Anti-Virus" Level="1">
$componentRefsXml
$programDataRefsXml
      <ComponentRef Id="StartMenuShortcut" />
    </Feature>
  </Package>
</Wix>
"@

Set-Content -LiteralPath $wxsPath -Value $wxs -Encoding UTF8

dotnet tool restore
if ($LASTEXITCODE -ne 0) {
  throw "WiX tool restore failed. Exit code: $LASTEXITCODE"
}
Invoke-Checked { dotnet wix build $wxsPath -arch x64 -o $msiPath } "MSI build failed."

if (-not (Test-Path $msiPath)) {
  throw "MSI build did not produce the expected package: $msiPath"
}

$bundleUpgradeCode = "9D6FE1FD-B9F4-4C80-9D03-CF7F453D00B9"
$bundleWxs = @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"
     xmlns:bal="http://wixtoolset.org/schemas/v4/wxs/bal">
  <Bundle
    Name="Avorax Anti-Virus"
    Manufacturer="Avorax Security"
    Version="$Version"
    UpgradeCode="$bundleUpgradeCode">
    <BootstrapperApplication>
      <bal:WixStandardBootstrapperApplication
        Theme="hyperlinkLicense"
        LicenseUrl="https://github.com/brentishere41848/Avorax/blob/main/docs/privacy.md"
        LaunchTarget="C:\Program Files\Avorax\Avorax.exe"
        LaunchWorkingFolder="C:\Program Files\Avorax" />
    </BootstrapperApplication>
    <Chain>
      <MsiPackage SourceFile="$(XmlEscape $msiPath)" Compressed="yes" />
    </Chain>
  </Bundle>
</Wix>
"@

Set-Content -LiteralPath $bundleWxsPath -Value $bundleWxs -Encoding UTF8
dotnet wix extension add WixToolset.BootstrapperApplications.wixext/6.0.2
if ($LASTEXITCODE -ne 0) {
  throw "WiX bootstrapper extension restore failed. Exit code: $LASTEXITCODE"
}
Invoke-Checked { dotnet wix build $bundleWxsPath -arch x64 -ext WixToolset.BootstrapperApplications.wixext -o $exeInstallerPath } "EXE installer build failed."

Write-Host "Created MSI: $msiPath"
Write-Host "Created EXE installer: $exeInstallerPath"
