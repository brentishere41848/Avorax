param(
  [string]$Version = "0.1.0",
  [string]$Configuration = "Release",
  [switch]$SkipFlutterBuild,
  [switch]$RequireLocalCore,
  [switch]$SkipClamAV,
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

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$clientDir = Join-Path $root "apps\pasus_client"
$releaseDir = Join-Path $clientDir "build\windows\x64\runner\$Configuration"
$localCoreExe = Join-Path $root "core\pasus_local_core\target\x86_64-pc-windows-msvc\release\pasus_local_core.exe"
$localCoreExeGnu = Join-Path $root "core\pasus_local_core\target\x86_64-pc-windows-gnu\release\pasus_local_core.exe"
$localCoreExeDefault = Join-Path $root "core\pasus_local_core\target\release\pasus_local_core.exe"
$guardServiceExeDefault = Join-Path $root "core\pasus_guard_service\target\release\pasus_guard_service.exe"
$distRoot = Join-Path $root "dist"
$stageDir = Join-Path $distRoot "windows-msi\stage"
$wxsPath = Join-Path $distRoot "windows-msi\Pasus.wxs"
$bundleWxsPath = Join-Path $distRoot "windows-msi\Pasus.Bundle.wxs"
$msiPath = Join-Path $distRoot "Pasus-$Version-x64.msi"
$exeInstallerPath = Join-Path $distRoot "Pasus-$Version-x64-setup.exe"
$clamAvVersion = "1.5.2"
$clamAvUrl = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$clamAvVersion/clamav-$clamAvVersion.win.x64.zip"
$clamAvSha256 = "6F868ED7A7E5A15ACED82C53A4FA9F3F42FA9D7F7DE14A606BA8DB0756518EED"
$clamAvZipPath = Join-Path $PSScriptRoot "cache\clamav-$clamAvVersion.win.x64.zip"
$clamAvExtractDir = Join-Path $distRoot "windows-msi\clamav-extract"
$modelSourceDir = Join-Path $root "assets\models"
$yaraSourceDir = Join-Path $root "assets\yara"
$testAssetsSourceDir = Join-Path $root "assets\test"
$trustAssetsSourceDir = Join-Path $root "assets\trust"
$threatAssetsSourceDir = Join-Path $root "assets\threats"
$driverToolsSourceDir = Join-Path $root "core\pasus_windows_minifilter"
$processGuardToolsSourceDir = Join-Path $root "core\pasus_windows_process_guard"
$modelFile = Join-Path $modelSourceDir "pasus_static_malware_model.onnx"
$modelMetadataFile = Join-Path $modelSourceDir "pasus_static_malware_model.metadata.json"

Require-Command "dotnet" "Install the .NET SDK."

if (-not $SkipFlutterBuild) {
  $flutter = "flutter"
  if (Test-Path "C:\Users\Brent\develop\flutter\bin\flutter.bat") {
    $flutter = "C:\Users\Brent\develop\flutter\bin\flutter.bat"
  }
  Push-Location $clientDir
  try {
    Invoke-Checked { & $flutter build windows --release } "Flutter Windows release build failed."
  } finally {
    Pop-Location
  }
}

if (-not (Test-Path (Join-Path $releaseDir "Pasus.exe"))) {
  throw "Flutter release output was not found at $releaseDir"
}

if (-not (Test-Path $localCoreExe) -and -not (Test-Path $localCoreExeDefault) -and -not (Test-Path $localCoreExeGnu)) {
  $cargo = Get-Command "cargo" -ErrorAction SilentlyContinue
  if (-not $cargo -and (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe")) {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    $cargo = Get-Command "cargo" -ErrorAction SilentlyContinue
  }
  if ($cargo) {
    Push-Location (Join-Path $root "core\pasus_local_core")
    try {
      Invoke-Checked { cargo build --release } "pasus_local_core release build failed."
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
    Push-Location (Join-Path $root "core\pasus_guard_service")
    try {
      Invoke-Checked { cargo build --release } "pasus_guard_service release build failed."
    } finally {
      Pop-Location
    }
  }
}

New-Item -ItemType Directory -Force -Path (Split-Path $wxsPath) | Out-Null
Copy-Tree $releaseDir $stageDir

if (-not (Test-Path $modelFile) -or -not (Test-Path $modelMetadataFile)) {
  throw "Pasus AI model assets are required: $modelFile and $modelMetadataFile"
}
$modelMetadata = Get-Content -Raw -LiteralPath $modelMetadataFile | ConvertFrom-Json
if (-not $modelMetadata.production_ready -and -not $AllowDevelopmentModel) {
  throw "The packaged AI model is marked production_ready=false. Provide a validated production model or pass -AllowDevelopmentModel for an explicitly non-production build."
}
$stageModelDir = Join-Path $stageDir "assets\models"
$releaseModelDir = Join-Path $releaseDir "assets\models"
Copy-Tree $modelSourceDir $stageModelDir
Copy-Tree $modelSourceDir $releaseModelDir

if (-not (Test-Path (Join-Path $yaraSourceDir "pasus_core_rules.yar"))) {
  throw "Pasus YARA rule pack is required: $(Join-Path $yaraSourceDir "pasus_core_rules.yar")"
}
$stageYaraDir = Join-Path $stageDir "assets\yara"
$releaseYaraDir = Join-Path $releaseDir "assets\yara"
Copy-Tree $yaraSourceDir $stageYaraDir
Copy-Tree $yaraSourceDir $releaseYaraDir

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
  "driver\PasusAvFilter.vcxproj",
  "driver\PasusAvFilter.inf",
  "driver\Driver.c",
  "driver\Communication.c",
  "driver\Filter.c",
  "scripts\build-driver.ps1",
  "scripts\install-test-driver.ps1",
  "scripts\uninstall-test-driver.ps1"
)) {
  $driverFilePath = Join-Path $driverToolsSourceDir $requiredDriverFile
  if (-not (Test-Path $driverFilePath)) {
    throw "Pasus Windows driver development file is missing: $driverFilePath"
  }
}
$stageDriverToolsDir = Join-Path $stageDir "driver-tools\pasus_windows_minifilter"
Copy-Tree $driverToolsSourceDir $stageDriverToolsDir
$stageProcessGuardToolsDir = Join-Path $stageDir "driver-tools\pasus_windows_process_guard"
Copy-Tree $processGuardToolsSourceDir $stageProcessGuardToolsDir

$coreSource = $null
if (Test-Path $localCoreExe) {
  $coreSource = $localCoreExe
} elseif (Test-Path $localCoreExeDefault) {
  $coreSource = $localCoreExeDefault
} elseif (Test-Path $localCoreExeGnu) {
  $coreSource = $localCoreExeGnu
}

if ($coreSource) {
  Copy-Item -LiteralPath $coreSource -Destination (Join-Path $stageDir "pasus_local_core.exe") -Force
  Copy-Item -LiteralPath $coreSource -Destination (Join-Path $releaseDir "pasus_local_core.exe") -Force
} elseif ($RequireLocalCore) {
  throw "pasus_local_core.exe was not found. Build it for Windows first or run without -RequireLocalCore."
} else {
  Write-Warning "pasus_local_core.exe was not found. The MSI will install the app, but local malware scanning will show Engine Unavailable until the core is deployed."
}

if (Test-Path $guardServiceExeDefault) {
  Copy-Item -LiteralPath $guardServiceExeDefault -Destination (Join-Path $stageDir "pasus_guard_service.exe") -Force
  Copy-Item -LiteralPath $guardServiceExeDefault -Destination (Join-Path $releaseDir "pasus_guard_service.exe") -Force
} else {
  Write-Warning "pasus_guard_service.exe was not found. The MSI will not include the real-time Guard helper."
}

if (-not $SkipClamAV) {
  Ensure-ClamAVPackage $clamAvZipPath $clamAvUrl $clamAvSha256
  Copy-ClamAVRuntime $clamAvZipPath $clamAvExtractDir (Join-Path $stageDir "ClamAV")
  Copy-ClamAVRuntime $clamAvZipPath $clamAvExtractDir (Join-Path $releaseDir "ClamAV")
  Write-Host "Bundled ClamAV $clamAvVersion runtime in the MSI."
} else {
  Write-Warning "Skipping bundled ClamAV. Signature scanning will require clamdscan/clamscan on PATH or PASUS_CLAMAV_CLAMSCAN."
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
  [void]$componentsXml.AppendLine("      </Component>")
  [void]$componentsXml.AppendLine("    </DirectoryRef>")
  [void]$componentRefsXml.AppendLine("      <ComponentRef Id=`"$componentId`" />")
}

$upgradeCode = "35E0D125-9699-4CFB-8E93-588D0E83F517"
$wxs = @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package
    Name="Pasus"
    Manufacturer="Pasus"
    Version="$Version"
    UpgradeCode="$upgradeCode"
    Scope="perMachine">
    <MajorUpgrade DowngradeErrorMessage="A newer version of Pasus is already installed." />
    <MediaTemplate EmbedCab="yes" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="Pasus" />
    </StandardDirectory>
    <StandardDirectory Id="ProgramMenuFolder">
      <Directory Id="ApplicationProgramsFolder" Name="Pasus" />
    </StandardDirectory>

$directoryXml
$componentsXml
    <DirectoryRef Id="ApplicationProgramsFolder">
      <Component Id="StartMenuShortcut" Guid="*">
        <Shortcut Id="PasusStartMenuShortcut" Name="Pasus" Target="[INSTALLFOLDER]Pasus.exe" WorkingDirectory="INSTALLFOLDER" />
        <RemoveFolder Id="RemoveApplicationProgramsFolder" On="uninstall" />
        <RegistryValue Root="HKCU" Key="Software\Pasus\Client" Name="installed" Type="integer" Value="1" KeyPath="yes" />
      </Component>
    </DirectoryRef>

    <Feature Id="MainFeature" Title="Pasus" Level="1">
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
    Name="Pasus"
    Manufacturer="Pasus"
    Version="$Version"
    UpgradeCode="$bundleUpgradeCode">
    <BootstrapperApplication>
      <bal:WixStandardBootstrapperApplication
        Theme="hyperlinkLicense"
        LicenseUrl="https://github.com/brentishere41848/pasus_anti-virus/blob/main/docs/privacy.md" />
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
