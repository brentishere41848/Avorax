param(
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Channel = "dev",
  [string]$PayloadRoot = "dist\windows-msi\stage",
  [string]$OutputDir = "dist\updates",
  [string]$SignerCommand = $env:AVORAX_UPDATE_SIGNER
)

$ErrorActionPreference = "Stop"
. (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path "tools\security\avorax-security-gate-tools.ps1")
$script:NormalUpdateEnginePayloadComponents = @("signatures", "rules", "ml", "trust")
$script:NormalUpdateEngineSourcePrunedChildren = @("config", "test_corpus", "threat_intel")
function Write-Utf8NoBom([string]$Path, [string]$Content) {
  $encoding = New-Object System.Text.UTF8Encoding($false)
  $target = [System.IO.Path]::GetFullPath($Path)
  [System.IO.File]::WriteAllText($target, $Content, $encoding)
}

function Assert-SafeToken([string]$Value, [string]$Name) {
  if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
    throw "$Name must be a non-empty token containing only letters, digits, dot, underscore, and dash."
  }
  if ($Value -eq "." -or $Value -eq ".." -or $Value.Contains("..")) {
    throw "$Name must not contain traversal segments."
  }
}

function Assert-RelativeRepoPath([string]$Path, [string]$Name) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Name must not be blank."
  }
  if ([System.IO.Path]::IsPathRooted($Path)) {
    throw "$Name must be relative to the Avorax repository root."
  }
  $parts = $Path -split '[\\/]+' | Where-Object { $_ -ne "" -and $_ -ne "." }
  if ($parts | Where-Object { $_ -eq ".." }) {
    throw "$Name must not contain traversal segments."
  }
}

function Get-RepoChildPath([string]$RelativePath, [string]$Name) {
  Assert-RelativeRepoPath $RelativePath $Name
  $full = [System.IO.Path]::GetFullPath((Join-Path $script:root $RelativePath))
  $rootWithSeparator = $script:root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  if ($full -eq $script:root) {
    throw "$Name must resolve to a child path inside the Avorax repository root, not the repository root itself."
  }
  if ($full -ne $script:root -and -not $full.StartsWith($rootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Name resolved outside the Avorax repository root: $full"
  }
  $full
}

function Test-LocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Assert-NoReparsePath([string]$Path, [string]$Description) {
  if (-not (Test-LocalWindowsPath $Path)) {
    throw "$Description must be on a local Windows drive path: $Path"
  }
  $current = [System.IO.Path]::GetFullPath($Path)
  while ($true) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not traverse a reparse point: $current"
      }
    }
    $parent = [System.IO.Directory]::GetParent($current)
    if ($null -eq $parent) { break }
    if ($parent.FullName -eq $current) { break }
    $current = $parent.FullName
  }
}

function Require-Item([string]$Path, [string]$Description, [string]$Kind) {
  Assert-NoReparsePath $Path $Description
  $target = [System.IO.Path]::GetFullPath($Path)
  $item = Get-Item -LiteralPath $target -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $target"
  }
  if ($Kind -eq "file" -and -not ($item -is [System.IO.FileInfo])) {
    throw "$Description is not a regular file: $target"
  }
  if ($Kind -eq "directory" -and -not ($item -is [System.IO.DirectoryInfo])) {
    throw "$Description is not a directory: $target"
  }
  $item.FullName
}

function Require-File([string]$Path, [string]$Description) {
  Require-Item $Path $Description "file"
}

function Require-Directory([string]$Path, [string]$Description) {
  Require-Item $Path $Description "directory"
}

function New-CheckedDirectory([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  $directory = [System.IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $directory)) {
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
  }
  Require-Directory $directory $Description
}

function Remove-ExistingRegularFile([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  $target = [System.IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $target)) { return }
  $file = Require-File $target $Description
  Remove-Item -LiteralPath $file -Force
}

function Write-Utf8NoBomAtomic([string]$Path, [string]$Content, [string]$Description) {
  $directory = New-CheckedDirectory (Split-Path $Path) "$Description directory"
  Assert-NoReparsePath $Path $Description
  $target = [System.IO.Path]::GetFullPath($Path)
  if (Test-Path -LiteralPath $target) {
    Require-File $target $Description | Out-Null
  }
  $tempPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".tmp")
  $backupPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".bak")
  Assert-NoReparsePath $tempPath "$Description temporary file path"
  Assert-NoReparsePath $backupPath "$Description backup file path"
  $tempTarget = [System.IO.Path]::GetFullPath($tempPath)
  $backupTarget = [System.IO.Path]::GetFullPath($backupPath)
  Remove-ExistingRegularFile $tempTarget "existing $Description temporary file"
  Remove-ExistingRegularFile $backupTarget "existing $Description backup file"
  try {
    Write-Utf8NoBom $tempTarget $Content
    $tempFile = Require-File $tempTarget "$Description temporary file"
    if (Test-Path -LiteralPath $target) {
      [System.IO.File]::Replace($tempFile, $target, $backupTarget)
    } else {
      [System.IO.File]::Move($tempFile, $target)
    }
  } finally {
    Remove-ExistingRegularFile $tempTarget "$Description temporary file"
    Remove-ExistingRegularFile $backupTarget "$Description backup file"
  }
}

function Remove-ExistingDirectory([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  $target = [System.IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $target)) { return }
  $directory = Require-Directory $target $Description
  Assert-NoReparseTree $directory $Description
  Remove-Item -LiteralPath $directory -Recurse -Force
}

function Assert-NoReparseTree([string]$Path, [string]$Description) {
  $directory = Require-Directory $Path $Description
  Get-ChildItem -LiteralPath $directory -Recurse -Force -ErrorAction Stop | ForEach-Object {
    if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Description contains a reparse-point entry: $($_.FullName)"
    }
  }
}

function Test-RegularFile([string]$Path) {
  Assert-NoReparsePath $Path "component file"
  $target = [System.IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $target -ErrorAction Stop)) {
    return $false
  }
  Require-File $target "component file" | Out-Null
  return $true
}

function Test-RegularDirectory([string]$Path) {
  Assert-NoReparsePath $Path "component directory"
  $target = [System.IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $target -ErrorAction Stop)) {
    return $false
  }
  Require-Directory $target "component directory" | Out-Null
  return $true
}

function Get-RegularPayloadFiles([string]$Path) {
  if (-not (Test-RegularDirectory $Path)) {
    return @()
  }
  $directory = Require-Directory $Path "payload file enumeration directory"
  Assert-NoReparseTree $directory "payload file enumeration directory"
  return @(Get-ChildItem -LiteralPath $directory -Recurse -File -Force -ErrorAction Stop | Sort-Object FullName)
}

function Copy-NormalUpdateEnginePayload([string]$SourceEngine, [string]$DestinationEngine) {
  if (-not (Test-RegularDirectory $SourceEngine)) {
    return
  }
  $engineSourceRoot = Require-Directory $SourceEngine "payload engine directory"
  Assert-NoReparseTree $engineSourceRoot "payload engine directory"
  New-CheckedDirectory $DestinationEngine "payload engine directory" | Out-Null
  $copiedRuntimeComponent = $false

  foreach ($name in $script:NormalUpdateEnginePayloadComponents) {
    $source = Join-Path $engineSourceRoot $name
    if (Test-RegularDirectory $source) {
      Assert-NoReparseTree $source "payload engine $name directory"
      $sourceDirectory = Require-Directory $source "payload engine $name directory"
      $componentFiles = @(Get-RegularPayloadFiles $sourceDirectory)
      if ($componentFiles.Count -eq 0) {
        throw "Normal .aup update package engine component 'engine\$name' contains no runtime files."
      }
      $destinationDirectory = Join-Path $DestinationEngine $name
      Assert-NoReparsePath $destinationDirectory "payload engine $name destination directory"
      Assert-NoReparseTree $sourceDirectory "payload engine $name directory before recursive copy"
      Copy-Item -LiteralPath $sourceDirectory -Destination $destinationDirectory -Recurse -Force
      $copiedRuntimeComponent = $true
    }
  }

  $engineDirectory = Require-Directory $SourceEngine "payload engine directory before child policy enumeration"
  Assert-NoReparseTree $engineDirectory "payload engine directory before child policy enumeration"
  foreach ($child in (Get-ChildItem -LiteralPath $engineDirectory -Force -ErrorAction Stop)) {
    if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Payload engine child must not be a reparse point: $($child.FullName)"
    }
    if ($script:NormalUpdateEnginePayloadComponents -contains $child.Name) {
      if (-not ($child -is [System.IO.DirectoryInfo])) {
        throw "Normal .aup update package engine component 'engine\$($child.Name)' must be a directory."
      }
      continue
    }
    if ($script:NormalUpdateEngineSourcePrunedChildren -contains $child.Name) {
      if (-not ($child -is [System.IO.DirectoryInfo])) {
        throw "Normal .aup update package pruned engine source child 'engine\$($child.Name)' must be a directory."
      }
      Write-Host "Skipping installer-stage engine source path excluded from normal .aup updates: engine\$($child.Name)"
      continue
    }
    throw "Normal .aup update package must not include unsupported engine payload path 'engine\$($child.Name)'. Only engine\signatures, engine\rules, engine\ml, and engine\trust are supported by normal updates."
  }

  if (-not $copiedRuntimeComponent) {
    throw "Payload engine source contains no supported runtime engine subdirectories for a normal .aup update."
  }
}

function Copy-NormalUpdateDocsPayload([string]$SourceDocs, [string]$DestinationDocs) {
  if (-not (Test-RegularDirectory $SourceDocs)) {
    return
  }
  $docsSourceRoot = Require-Directory $SourceDocs "payload docs directory"
  Assert-NoReparseTree $docsSourceRoot "payload docs directory"
  $docsFiles = @(Get-RegularPayloadFiles $docsSourceRoot)
  if ($docsFiles.Count -eq 0) {
    throw "Payload docs source contains no Markdown files for a normal .aup update."
  }
  $docsDirectory = Require-Directory $docsSourceRoot "payload docs directory before Markdown staging"
  Assert-NoReparseTree $docsDirectory "payload docs directory before Markdown staging"
  foreach ($file in $docsFiles) {
    if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Payload docs file must not be a reparse point: $($file.FullName)"
    }
    if ($file.Extension.ToLowerInvariant() -ne ".md" -or $file.Name -eq ".md") {
      throw "Normal .aup update package docs payload must contain Markdown files only: $($file.FullName)"
    }
    $relative = $file.FullName.Substring($docsDirectory.Length).TrimStart("\", "/")
    $destination = Join-Path $DestinationDocs $relative
    New-CheckedDirectory (Split-Path $destination) "payload docs destination directory" | Out-Null
    $sourceFile = Require-File $file.FullName "docs payload Markdown file"
    Assert-NoReparsePath $destination "docs payload destination file"
    Copy-Item -LiteralPath $sourceFile -Destination $destination -Force
  }
}

function Split-SignerCommand([string]$CommandLine) {
  if ($CommandLine -match '[\x00-\x1F]') {
    throw "AVORAX_UPDATE_SIGNER must not contain control characters."
  }
  $tokens = New-Object System.Collections.Generic.List[string]
  $builder = New-Object System.Text.StringBuilder
  $inQuote = $false
  foreach ($char in $CommandLine.ToCharArray()) {
    if ($char -eq '"') {
      $inQuote = -not $inQuote
      continue
    }
    if ([char]::IsWhiteSpace($char) -and -not $inQuote) {
      if ($builder.Length -gt 0) {
        $tokens.Add($builder.ToString())
        $builder.Clear() | Out-Null
      }
      continue
    }
    $builder.Append($char) | Out-Null
  }
  if ($inQuote) {
    throw "AVORAX_UPDATE_SIGNER contains an unterminated quote."
  }
  if ($builder.Length -gt 0) {
    $tokens.Add($builder.ToString())
  }
  if (-not $tokens -or $tokens.Count -eq 0) {
    throw "AVORAX_UPDATE_SIGNER did not contain a signer command."
  }
  $tokens.ToArray()
}

$root = [System.IO.Path]::GetFullPath((Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path)
Assert-SafeToken $Version "Version"
Assert-SafeToken $Channel "Channel"
$payloadSource = Get-RepoChildPath $PayloadRoot "PayloadRoot"
Require-Directory $payloadSource "Payload root" | Out-Null
Assert-NoReparseTree $payloadSource "Payload root"
if ([string]::IsNullOrWhiteSpace($SignerCommand)) {
  throw "AVORAX_UPDATE_SIGNER is required. Refusing to create an unsigned .aup package."
}
$signer = @(Split-SignerCommand $SignerCommand)
$signerExe = $signer[0]
if (-not [System.IO.Path]::IsPathRooted($signerExe)) {
  throw "AVORAX_UPDATE_SIGNER must start with an absolute local signer path."
}
$signerExe = Require-File $signerExe "Update manifest signer"
$signerArgs = @()
if ($signer.Count -gt 1) {
  $signerArgs = $signer[1..($signer.Count - 1)]
}

$out = Get-RepoChildPath $OutputDir "OutputDir"
$packageId = "avorax-$Version-$Channel"
$publicKeyId = if ([string]::IsNullOrWhiteSpace($env:AVORAX_UPDATE_PUBLIC_KEY_ID)) { "avorax-dev-ed25519" } else { $env:AVORAX_UPDATE_PUBLIC_KEY_ID }
Assert-SafeToken $publicKeyId "AVORAX_UPDATE_PUBLIC_KEY_ID"
$work = Join-Path $out "work-$packageId"
$payload = Join-Path $work "payload"
New-CheckedDirectory $out "Output directory" | Out-Null
Remove-ExistingDirectory $work "update package work directory"
New-CheckedDirectory $payload "update package payload directory" | Out-Null
$payloadApp = Join-Path $payload "app"
$payloadServices = Join-Path $payload "services"
$payloadEngine = Join-Path $payload "engine"
$payloadDocs = Join-Path $payload "docs"
$payloadSourceTools = Join-Path $payloadSource "tools"
if (Test-RegularDirectory $payloadSourceTools) {
  throw "Normal .aup update package must not include tools payloads because in-app updates do not have an explicit tooling workflow. Ship tooling changes through MSI/EXE."
}
$payloadSourceMigrations = Join-Path $payloadSource "migrations"
if (Test-RegularDirectory $payloadSourceMigrations) {
  throw "Normal .aup update package must not include migration payloads because in-app updates do not have an explicit migration workflow. Ship migration changes through MSI/EXE or a dedicated migration workflow."
}
$payloadSourceDriver = Join-Path $payloadSource "driver"
if (Test-RegularDirectory $payloadSourceDriver) {
  throw "Normal .aup update package must not include driver payloads because in-app updates do not have an explicit driver workflow. Ship driver changes through MSI/EXE or a dedicated signed-driver workflow."
}
$payloadSourceDriverTools = Join-Path $payloadSource "driver-tools"
if (Test-RegularDirectory $payloadSourceDriverTools) {
  throw "Normal .aup update package must not include driver-tools payloads because in-app updates do not have an explicit driver tooling workflow. Ship driver tooling changes through MSI/EXE or a dedicated signed-driver workflow."
}
New-CheckedDirectory $payloadApp "payload app directory" | Out-Null
New-CheckedDirectory $payloadServices "payload services directory" | Out-Null
New-CheckedDirectory $payloadDocs "payload docs directory" | Out-Null

$serviceFiles = @("avorax_core_service.exe", "avorax_guard_service.exe")
$excludedAppFiles = @("avorax_core_service.exe", "avorax_guard_service.exe", "avorax_update_service.exe")
$payloadSourceServicesRoot = Require-Directory $payloadSource "Payload root before service payload staging"
Assert-NoReparseTree $payloadSourceServicesRoot "Payload root before service payload staging"
$payloadSourceUpdateService = Join-Path $payloadSourceServicesRoot "avorax_update_service.exe"
if (Test-Path -LiteralPath $payloadSourceUpdateService) {
  Assert-NoReparsePath $payloadSourceUpdateService "Update Service payload source"
  $updateServiceItem = Get-Item -LiteralPath ([System.IO.Path]::GetFullPath($payloadSourceUpdateService)) -Force -ErrorAction Stop
  if (($updateServiceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Update Service payload source must not be a reparse point: $($updateServiceItem.FullName)"
  }
  throw "Normal .aup update package must not include avorax_update_service.exe because the updater cannot overwrite itself while running. Ship Update Service changes through MSI/EXE."
}
Get-ChildItem -LiteralPath $payloadSourceServicesRoot -Directory -ErrorAction Stop | ForEach-Object {
  if ($excludedAppFiles -contains $_.Name) {
    if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Managed service or updater payload directory must not be a reparse point: $($_.FullName)"
    }
    throw "Normal .aup update package app payload directory must not be named managed service or updater executable '$($_.Name)'. Service binaries must be regular top-level payload files and updater self-updates require MSI/EXE."
  }
}
foreach ($name in $serviceFiles) {
  $source = Join-Path $payloadSourceServicesRoot $name
  if (Test-RegularFile $source) {
    $sourceFile = Require-File $source "service payload $name"
    $destinationFile = Join-Path $payloadServices $name
    Assert-NoReparsePath $destinationFile "service payload destination $name"
    Copy-Item -LiteralPath $sourceFile -Destination $destinationFile -Force
  }
}

$payloadSourceFilesRoot = Require-Directory $payloadSource "Payload root before top-level file staging"
Assert-NoReparseTree $payloadSourceFilesRoot "Payload root before top-level file staging"
Get-ChildItem -LiteralPath $payloadSourceFilesRoot -File -ErrorAction Stop | ForEach-Object {
  if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Payload source file must not be a reparse point: $($_.FullName)"
  }
  if ($excludedAppFiles -contains $_.Name) { return }
  $sourceFile = Require-File $_.FullName "app payload file $($_.Name)"
  $destinationFile = Join-Path $payloadApp $_.Name
  Assert-NoReparsePath $destinationFile "app payload destination file $($_.Name)"
  Copy-Item -LiteralPath $sourceFile -Destination $destinationFile -Force
}

$payloadSourceDirectoriesRoot = Require-Directory $payloadSource "Payload root before top-level directory staging"
Assert-NoReparseTree $payloadSourceDirectoriesRoot "Payload root before top-level directory staging"
Get-ChildItem -LiteralPath $payloadSourceDirectoriesRoot -Directory -ErrorAction Stop | ForEach-Object {
  if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Payload source directory must not be a reparse point: $($_.FullName)"
  }
  if ($excludedAppFiles -contains $_.Name) {
    throw "Normal .aup update package app payload directory must not be named managed service or updater executable '$($_.Name)'. Service binaries must be regular top-level payload files and updater self-updates require MSI/EXE."
  }
  if ($_.Name -in @("engine", "docs", "tools", "driver", "driver-tools")) { return }
  Assert-NoReparseTree $_.FullName "app payload directory $($_.Name)"
  $sourceDirectory = Require-Directory $_.FullName "app payload directory $($_.Name)"
  $destinationDirectory = Join-Path $payloadApp $_.Name
  Assert-NoReparsePath $destinationDirectory "app payload destination directory $($_.Name)"
  Assert-NoReparseTree $sourceDirectory "app payload directory $($_.Name) before recursive copy"
  Copy-Item -LiteralPath $sourceDirectory -Destination $destinationDirectory -Recurse -Force
}

$payloadSourceEngine = Join-Path $payloadSource "engine"
Copy-NormalUpdateEnginePayload $payloadSourceEngine $payloadEngine

$payloadSourceDocs = Join-Path $payloadSource "docs"
Copy-NormalUpdateDocsPayload $payloadSourceDocs $payloadDocs

if (-not (Test-RegularDirectory $payloadEngine)) {
  throw "Payload stage is missing engine assets; refusing to create an update package that would leave the engine unavailable."
}
if (Test-RegularFile (Join-Path $payloadServices "avorax_update_service.exe")) {
  throw "Normal .aup update package must not include avorax_update_service.exe because the updater cannot overwrite itself while running. Ship Update Service changes through MSI/EXE."
}

$hashes = [ordered]@{}
$payloadHashRoot = Require-Directory $payload "payload hash root"
$payloadFilesForHash = @(Get-RegularPayloadFiles $payloadHashRoot)
$payloadFilesForHash | ForEach-Object {
  if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Payload file must not be a reparse point before hashing: $($_.FullName)"
  }
  $payloadFile = Require-File $_.FullName "payload file before hashing"
  $relative = $_.FullName.Substring($payloadHashRoot.Length).TrimStart("\", "/").Replace("\", "/")
  if ($relative -match '(^|/)driver($|/)' -or $relative -match '(^|/)driver-tools($|/)') {
    throw "Normal .aup update package leaked driver payload path '$relative'. Driver packages must ship via MSI/EXE, not in-app updates."
  }
  if ($relative -match '(^|/)tools($|/)') {
    throw "Normal .aup update package leaked tools payload path '$relative'. Tooling changes must ship via MSI/EXE or an explicit tooling workflow, not in-app updates."
  }
  if ($relative -match '(^|/)migrations($|/)') {
    throw "Normal .aup update package leaked migration payload path '$relative'. Migration changes must ship via MSI/EXE or an explicit migration workflow, not in-app updates."
  }
  if ($relative -match '^app/(engine|docs|tools|driver|driver-tools|migrations)(/|$)') {
    throw "Normal .aup update package app payload leaked restricted install path '$relative'. Restricted install paths must use their explicit update workflow, not payload/app."
  }
  if ($relative -match '^app/(avorax_update_service\.exe|avorax_core_service\.exe|avorax_guard_service\.exe)$') {
    throw "Normal .aup update package app payload leaked managed service or updater executable '$relative'. Service binaries must use payload/services and updater self-updates require MSI/EXE."
  }
  if ($relative -match '^engine/([^/]+)(/|$)') {
    $engineComponent = $Matches[1]
    if ($script:NormalUpdateEnginePayloadComponents -notcontains $engineComponent) {
      throw "Normal .aup update package leaked unsupported engine payload path '$relative'. Only engine/signatures, engine/rules, engine/ml, and engine/trust are supported."
    }
    if ($relative -notmatch '^engine/(signatures|rules|ml|trust)/.+') {
      throw "Normal .aup update package engine payload file must be under an explicit runtime subdirectory: '$relative'."
    }
  }
  if ($relative -match '^docs/') {
    if ($relative -notmatch '^docs/.+\.md$' -or $relative -match '^docs/(\.md|.*/\.md)$') {
      throw "Normal .aup update package leaked unsupported docs payload path '$relative'. Documentation payloads must be Markdown files only."
    }
  }
  $hashes[$relative] = (Get-FileHash -LiteralPath $payloadFile -Algorithm SHA256).Hash.ToLowerInvariant()
}

$payloadAppRoot = Require-Directory $payloadApp "payload app component evidence root"
$appPayloadFiles = @(Get-RegularPayloadFiles $payloadAppRoot)
$payloadServicesRoot = Require-Directory $payloadServices "payload services component evidence root"
$coreServicePayloadFile = Join-Path $payloadServicesRoot "avorax_core_service.exe"
$guardServicePayloadFile = Join-Path $payloadServicesRoot "avorax_guard_service.exe"
$hasCoreServicePayloadFile = Test-RegularFile $coreServicePayloadFile
$hasGuardServicePayloadFile = Test-RegularFile $guardServicePayloadFile
$payloadEngineRoot = Require-Directory $payloadEngine "payload engine component evidence root"
$engineSignaturePayloadFiles = @(Get-RegularPayloadFiles (Join-Path $payloadEngineRoot "signatures"))
$engineRulePayloadFiles = @(Get-RegularPayloadFiles (Join-Path $payloadEngineRoot "rules"))
$engineMlPayloadFiles = @(Get-RegularPayloadFiles (Join-Path $payloadEngineRoot "ml"))
$engineTrustPayloadFiles = @(Get-RegularPayloadFiles (Join-Path $payloadEngineRoot "trust"))
$enginePayloadFileCount = $engineSignaturePayloadFiles.Count + $engineRulePayloadFiles.Count + $engineMlPayloadFiles.Count + $engineTrustPayloadFiles.Count
$payloadDocsRoot = Require-Directory $payloadDocs "payload docs component evidence root"
$docsPayloadFiles = @(Get-RegularPayloadFiles $payloadDocsRoot)
$publishedAt = (Get-Date).ToUniversalTime().ToString("o")

$manifest = [ordered]@{
  product = "Avorax Anti-Virus"
  package_format_version = 1
  version = $Version
  previous_min_version = "0.0.0"
  channel = $Channel
  release_date = $publishedAt
  package_id = $packageId
  components = [ordered]@{
    app = $appPayloadFiles.Count -gt 0
    core_service = $hasCoreServicePayloadFile
    guard_service = $hasGuardServicePayloadFile
    update_service = $false
    native_engine_assets = $enginePayloadFileCount -gt 0
    signatures = $engineSignaturePayloadFiles.Count -gt 0
    rules = $engineRulePayloadFiles.Count -gt 0
    ml_model = $engineMlPayloadFiles.Count -gt 0
    trust_packs = $engineTrustPayloadFiles.Count -gt 0
    docs = $docsPayloadFiles.Count -gt 0
    driver_tools = $false
  }
  requires_restart = $true
  requires_reboot = $false
  requires_admin = $true
  driver_update_included = $false
  migration_steps = @()
  rollback_supported = $true
  payload_hashes = $hashes
  package_sha256 = ""
  signature_algorithm = "ed25519"
  public_key_id = $publicKeyId
  release_notes_url = $null
}

$manifestPath = Join-Path $work "manifest.json"
$sigPath = Join-Path $work "manifest.sig"
Write-Utf8NoBomAtomic $manifestPath ($manifest | ConvertTo-Json -Depth 20) "update manifest"
Assert-NoReparsePath $sigPath "update manifest signature path"
$manifestFile = Require-File $manifestPath "update manifest"
$signatureTarget = [System.IO.Path]::GetFullPath($sigPath)
$signerCommandArgs = @($signerArgs) + @($manifestFile, $signatureTarget)
$signerDiagnostic = Invoke-AvoraxGateCommandDiagnostic $signerExe $signerCommandArgs "update manifest signer" 32768 $root
if ($signerDiagnostic.exit_code -ne 0 -or -not (Test-Path -LiteralPath $signatureTarget)) {
  throw "Update manifest signing failed. Exit code: $($signerDiagnostic.exit_code). Output: $($signerDiagnostic.output). No .aup package was produced."
}
$signatureFile = Require-File $signatureTarget "update manifest signature"

$packagePath = Join-Path $out "Avorax-AntiVirus-$Version.aup"
$tempZipPath = Join-Path $out ("." + (Split-Path $packagePath -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".zip.tmp")
$backupZipPath = Join-Path $out ("." + (Split-Path $packagePath -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".bak")
Assert-NoReparsePath $packagePath "update package path"
Assert-NoReparsePath $tempZipPath "temporary update package path"
Assert-NoReparsePath $backupZipPath "update package backup path"
$packageTarget = [System.IO.Path]::GetFullPath($packagePath)
$tempZipTarget = [System.IO.Path]::GetFullPath($tempZipPath)
$backupZipTarget = [System.IO.Path]::GetFullPath($backupZipPath)
if (Test-Path -LiteralPath $packageTarget) {
  Require-File $packageTarget "existing update package" | Out-Null
}
Remove-ExistingRegularFile $tempZipTarget "existing temporary update package"
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
try {
  $zipStream = [System.IO.File]::Open($tempZipTarget, [System.IO.FileMode]::CreateNew)
  try {
    $zip = [System.IO.Compression.ZipArchive]::new($zipStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
    try {
      $workArchiveRoot = Require-Directory $work "update package work directory before zipping"
      Assert-NoReparseTree $workArchiveRoot "update package work directory before zipping"
      Get-ChildItem -LiteralPath $workArchiveRoot -Recurse -File -Force -ErrorAction Stop | Sort-Object FullName | ForEach-Object {
        if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
          throw "Update package work file must not be a reparse point before zipping: $($_.FullName)"
        }
        $sourceFile = Require-File $_.FullName "update package work file"
        $entryName = $_.FullName.Substring($workArchiveRoot.Length).TrimStart("\", "/").Replace("\", "/")
        if ($entryName -ne "manifest.json" -and $entryName -ne "manifest.sig" -and -not $entryName.StartsWith("payload/", [System.StringComparison]::Ordinal)) {
          throw "Update package work file has unsupported archive entry path before zipping: $entryName"
        }
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
          $zip,
          $sourceFile,
          $entryName,
          [System.IO.Compression.CompressionLevel]::Optimal
        ) | Out-Null
      }
    } finally {
      $zip.Dispose()
    }
  } finally {
    $zipStream.Dispose()
  }
  $tempZipFile = Require-File $tempZipTarget "temporary update package"
  if (Test-Path -LiteralPath $packageTarget) {
    [System.IO.File]::Replace($tempZipFile, $packageTarget, $backupZipTarget)
  } else {
    [System.IO.File]::Move($tempZipFile, $packageTarget)
  }
} finally {
  Remove-ExistingRegularFile $tempZipTarget "temporary update package"
  Remove-ExistingRegularFile $backupZipTarget "update package backup file"
}
$packageFile = Require-File $packageTarget "update package"
$packageHash = (Get-FileHash -LiteralPath $packageFile -Algorithm SHA256).Hash.ToLowerInvariant()
$packageFileName = Split-Path $packageFile -Leaf

$feed = [ordered]@{
  product = "Avorax Anti-Virus"
  channel = $Channel
  latest_version = $Version
  minimum_supported_version = "0.0.0"
  packages = @(
    [ordered]@{
      version = $Version
      package_url = $packageFileName
      package_sha256 = $packageHash
      release_notes = "Avorax $Version update package."
      published_at = $publishedAt
      required = $false
      critical = $false
      rollback_supported = $true
    }
  )
}
$feedPath = Join-Path $out "update-feed.json"
Assert-NoReparsePath $feedPath "update feed path"
Write-Utf8NoBomAtomic $feedPath ($feed | ConvertTo-Json -Depth 10) "update feed"
$feedFile = Require-File $feedPath "update feed"
Write-Host "Created update package: $packageFile"
Write-Host "Created update feed: $feedFile"
