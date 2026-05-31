param(
  [string]$Version = "0.1.0",
  [string]$Configuration = "Release",
  [switch]$SkipFlutterBuild,
  [switch]$RequireLocalCore,
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
$distRoot = Join-Path $root "dist"
$stageDir = Join-Path $distRoot "windows-msi\stage"
$wxsPath = Join-Path $distRoot "windows-msi\Zentor.wxs"
$bundleWxsPath = Join-Path $distRoot "windows-msi\Zentor.Bundle.wxs"
$msiPath = Join-Path $distRoot "Zentor-AntiVirus-$Version-x64.msi"
$exeInstallerPath = Join-Path $distRoot "Zentor-AntiVirus-$Version-x64-setup.exe"
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
    Invoke-Checked { & $flutter build windows --release --build-name $Version --build-number $buildNumber "--dart-define=ZENTOR_APP_VERSION=$Version" } "Flutter Windows release build failed."
  } finally {
    Pop-Location
  }
}

if (-not (Test-Path (Join-Path $releaseDir "Zentor.exe"))) {
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

New-Item -ItemType Directory -Force -Path (Split-Path $wxsPath) | Out-Null
Copy-Tree $releaseDir $stageDir

if (-not (Test-Path $modelFile) -or -not (Test-Path $modelMetadataFile)) {
  throw "Zentor AI model assets are required: $modelFile and $modelMetadataFile"
}
$modelMetadata = Get-Content -Raw -LiteralPath $modelMetadataFile | ConvertFrom-Json
if (-not $modelMetadata.production_ready -and -not $AllowDevelopmentModel) {
  throw "The packaged AI model is marked production_ready=false. Provide a validated production model or pass -AllowDevelopmentModel for an explicitly non-production build."
}
$stageModelDir = Join-Path $stageDir "assets\models"
$releaseModelDir = Join-Path $releaseDir "assets\models"
Copy-Tree $modelSourceDir $stageModelDir
Copy-Tree $modelSourceDir $releaseModelDir

if (-not (Test-Path (Join-Path $nativeSourceDir "signatures\zentor_core.zsig")) -or -not (Test-Path (Join-Path $nativeSourceDir "rules\zentor_rules.zrule")) -or -not (Test-Path (Join-Path $nativeSourceDir "ml\zentor_native_model.zmodel"))) {
  throw "Zentor Native Engine assets are required under $nativeSourceDir"
}
$stageNativeDir = Join-Path $stageDir "assets\zentor_native"
$releaseNativeDir = Join-Path $releaseDir "assets\zentor_native"
Copy-Tree $nativeSourceDir $stageNativeDir
Copy-Tree $nativeSourceDir $releaseNativeDir

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
Copy-Tree $testAssetsSourceDir $stageTestDir
Copy-Tree $testAssetsSourceDir $releaseTestDir

$stageTrustDir = Join-Path $stageDir "assets\trust"
$releaseTrustDir = Join-Path $releaseDir "assets\trust"
Copy-Tree $trustAssetsSourceDir $stageTrustDir
Copy-Tree $trustAssetsSourceDir $releaseTrustDir

$stageThreatsDir = Join-Path $stageDir "assets\threats"
$releaseThreatsDir = Join-Path $releaseDir "assets\threats"
Copy-Tree $threatAssetsSourceDir $stageThreatsDir
Copy-Tree $threatAssetsSourceDir $releaseThreatsDir

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
    throw "Zentor Windows driver development file is missing: $driverFilePath"
  }
}
$stageDriverToolsDir = Join-Path $stageDir "driver-tools\zentor_windows_minifilter"
Copy-Tree $driverToolsSourceDir $stageDriverToolsDir
$stageProcessGuardToolsDir = Join-Path $stageDir "driver-tools\zentor_windows_process_guard"
Copy-Tree $processGuardToolsSourceDir $stageProcessGuardToolsDir

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
  Copy-Item -LiteralPath $coreSource -Destination (Join-Path $stageDir "zentor_local_core.exe") -Force
  Copy-Item -LiteralPath $coreSource -Destination (Join-Path $releaseDir "zentor_local_core.exe") -Force
} elseif ($RequireLocalCore) {
  throw "zentor_local_core.exe was not found. Build it for Windows first or run without -RequireLocalCore."
} else {
  Write-Warning "zentor_local_core.exe was not found. The MSI will install the app, but local malware scanning will show Engine Unavailable until the core is deployed."
}

if (Test-Path $guardServiceExeDefault) {
  Copy-Item -LiteralPath $guardServiceExeDefault -Destination (Join-Path $stageDir "zentor_guard_service.exe") -Force
  Copy-Item -LiteralPath $guardServiceExeDefault -Destination (Join-Path $releaseDir "zentor_guard_service.exe") -Force
} elseif (Test-Path $guardServiceExeWorkspace) {
  Copy-Item -LiteralPath $guardServiceExeWorkspace -Destination (Join-Path $stageDir "zentor_guard_service.exe") -Force
  Copy-Item -LiteralPath $guardServiceExeWorkspace -Destination (Join-Path $releaseDir "zentor_guard_service.exe") -Force
} else {
  Write-Warning "zentor_guard_service.exe was not found. The MSI will not include the real-time Guard helper."
}

if ($IncludeClamAVCompatibility -and -not $SkipClamAV) {
  Ensure-ClamAVPackage $clamAvZipPath $clamAvUrl $clamAvSha256
  Copy-ClamAVRuntime $clamAvZipPath $clamAvExtractDir (Join-Path $stageDir "ClamAV")
  Copy-ClamAVRuntime $clamAvZipPath $clamAvExtractDir (Join-Path $releaseDir "ClamAV")
  Write-Host "Bundled optional ClamAV compatibility runtime $clamAvVersion in the MSI."
} else {
  Write-Host "Skipping ClamAV compatibility runtime. Zentor Native Engine is the primary scanner."
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
New-Item -ItemType Directory -Force -Path $docsStage | Out-Null
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\privacy.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\malware-protection.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\quarantine.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\windows-driver.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\real-time-protection.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\protection-self-test.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\testing-eicar.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\lockdown-mode.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\application-control.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\external-validation.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\lab-readiness.md") -Destination $docsStage -Force
Copy-Item -LiteralPath (Join-Path $root "docs\false-positives.md") -Destination $docsStage -Force

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
  if ($relativePath -eq "zentor_guard_service.exe") {
    [void]$componentsXml.AppendLine("        <ServiceInstall Id=`"ZentorGuardServiceInstall`" Type=`"ownProcess`" Vital=`"yes`" Name=`"zentor_guard_service`" DisplayName=`"Zentor Guard Service`" Description=`"User-visible Zentor post-launch real-time protection service.`" Start=`"auto`" Account=`"LocalSystem`" ErrorControl=`"normal`" Arguments=`"--service`" />")
    [void]$componentsXml.AppendLine("        <ServiceControl Id=`"ZentorGuardServiceControl`" Name=`"zentor_guard_service`" Start=`"install`" Stop=`"both`" Remove=`"uninstall`" Wait=`"yes`" />")
  }
  [void]$componentsXml.AppendLine("      </Component>")
  [void]$componentsXml.AppendLine("    </DirectoryRef>")
  [void]$componentRefsXml.AppendLine("      <ComponentRef Id=`"$componentId`" />")
}

$upgradeCode = "35E0D125-9699-4CFB-8E93-588D0E83F517"
$wxs = @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package
    Name="Zentor Anti-Virus"
    Manufacturer="Zentor Security"
    Version="$Version"
    UpgradeCode="$upgradeCode"
    Scope="perMachine">
    <MajorUpgrade DowngradeErrorMessage="A newer version of Zentor is already installed." />
    <MediaTemplate EmbedCab="yes" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="Zentor" />
    </StandardDirectory>
    <StandardDirectory Id="ProgramMenuFolder">
      <Directory Id="ApplicationProgramsFolder" Name="Zentor Anti-Virus" />
    </StandardDirectory>

$directoryXml
$componentsXml
    <DirectoryRef Id="ApplicationProgramsFolder">
      <Component Id="StartMenuShortcut" Guid="*">
        <Shortcut Id="ZentorStartMenuShortcut" Name="Zentor Anti-Virus" Target="[INSTALLFOLDER]Zentor.exe" WorkingDirectory="INSTALLFOLDER" />
        <RemoveFolder Id="RemoveApplicationProgramsFolder" On="uninstall" />
        <RegistryValue Root="HKCU" Key="Software\Zentor\Client" Name="installed" Type="integer" Value="1" KeyPath="yes" />
      </Component>
    </DirectoryRef>

    <Feature Id="MainFeature" Title="Zentor Anti-Virus" Level="1">
$componentRefsXml
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
    Name="Zentor Anti-Virus"
    Manufacturer="Zentor Security"
    Version="$Version"
    UpgradeCode="$bundleUpgradeCode">
    <BootstrapperApplication>
      <bal:WixStandardBootstrapperApplication
        Theme="hyperlinkLicense"
        LicenseUrl="https://github.com/brentishere41848/zentor_anti-virus/blob/main/docs/privacy.md" />
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
