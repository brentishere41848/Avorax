param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$Category,
  [Parameter(Mandatory = $true)][string]$SourceMetadata,
  [Parameter(Mandatory = $true)][string]$HashFeed,
  [Parameter(Mandatory = $true)][string]$PythonPath,
  [string]$Channel = "dev",
  [string]$OutputDir = "dist\updates",
  [string]$SignerCommand = $env:AVORAX_UPDATE_SIGNER
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath((Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path)
. (Join-Path $root "tools\security\avorax-security-gate-tools.ps1")

function Assert-RelativeRepoPath([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Description must not be blank."
  }
  if ([System.IO.Path]::IsPathRooted($Path)) {
    throw "$Description must be relative to the Avorax repository root."
  }
  $parts = @($Path -split '[\\/]+' | Where-Object { $_ -ne "" -and $_ -ne "." })
  if ($parts | Where-Object { $_ -eq ".." }) {
    throw "$Description must not contain traversal segments."
  }
}

function Get-RepoChildPath([string]$RelativePath, [string]$Description) {
  Assert-RelativeRepoPath $RelativePath $Description
  $full = [System.IO.Path]::GetFullPath((Join-Path $script:root $RelativePath))
  $prefix = $script:root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  if ($full -eq $script:root -or -not $full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must resolve to a child path inside the Avorax repository root."
  }
  return $full
}

function Get-RepoRelativePath([string]$Path, [string]$Description) {
  $full = [System.IO.Path]::GetFullPath($Path)
  $prefix = $script:root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  if (-not $full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description resolved outside the Avorax repository root: $full"
  }
  return $full.Substring($prefix.Length)
}

function Assert-NoReparseTree([string]$Path, [string]$Description) {
  $directory = Get-AvoraxGateDirectory $Path $Description
  Get-ChildItem -LiteralPath $directory -Recurse -Force -ErrorAction Stop | ForEach-Object {
    if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Description contains a reparse-point entry: $($_.FullName)"
    }
  }
}

function Remove-CheckedTempTree([string]$Path, [string]$AllowedRoot) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $target = [System.IO.Path]::GetFullPath($Path)
  $allowed = [System.IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\', '/')
  $prefix = $allowed + [System.IO.Path]::DirectorySeparatorChar
  if (-not $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove hash-intel temporary data outside its checked root: $target"
  }
  $directory = Get-AvoraxGateDirectory $target "hash-intel temporary directory"
  Assert-NoReparseTree $directory "hash-intel temporary directory"
  Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction Stop
}

function Invoke-CheckedCommand(
  [string]$Tool,
  [string[]]$Arguments,
  [string]$Description
) {
  $result = Invoke-AvoraxGateCommandDiagnostic $Tool $Arguments $Description 32768 $script:root
  if ($result.exit_code -ne 0) {
    throw "$Description failed with exit code $($result.exit_code): $($result.output)"
  }
  if (-not [string]::IsNullOrWhiteSpace($result.stdout)) {
    Write-Host $result.stdout
  }
}

function Assert-SafePathToken([string]$Value, [string]$Description) {
  if (
    [string]::IsNullOrWhiteSpace($Value) -or
    $Value.Length -gt 64 -or
    $Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or
    $Value.Contains("..")
  ) {
    throw "$Description must be a 1-64 character path token using letters, digits, dot, underscore, or dash."
  }
}

Assert-SafePathToken $Version "Version"
Assert-SafePathToken $Channel "Channel"
if (-not [System.IO.Path]::IsPathRooted($PythonPath)) {
  throw "PythonPath must be an absolute local executable path."
}
$python = Get-AvoraxRequiredTool ([System.IO.Path]::GetFullPath($PythonPath)) "Python executable"
$sourcePath = Get-AvoraxGateFile (Get-RepoChildPath $SourceMetadata "SourceMetadata") "reviewed hash source metadata"
$hashFeedPath = Get-AvoraxGateFile (Get-RepoChildPath $HashFeed "HashFeed") "reviewed SHA-256 feed"
$outputPath = Get-RepoChildPath $OutputDir "OutputDir"
Assert-AvoraxNoReparsePath $outputPath "hash-intel update output directory"
if ([string]::IsNullOrWhiteSpace($SignerCommand)) {
  throw "AVORAX_UPDATE_SIGNER is required. Refusing to create an unsigned hash-intel update."
}

$packBuilder = Get-AvoraxGateFile (Join-Path $root "tools\zentor_intel\build_realworld_detection_pack.py") "hash-intel pack builder"
$updateBuilder = Get-AvoraxGateFile (Join-Path $root "tools\update\avorax-build-update-package.ps1") "signed update package builder"
$powershell = Get-AvoraxRequiredTool ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$tempParent = Get-RepoChildPath ".workflow\ultracode\avorax-hardening\tmp" "hash-intel temporary parent"
New-AvoraxGateDirectory $tempParent "hash-intel temporary parent" | Out-Null
$tempRoot = Join-Path $tempParent ("hash-intel-update-" + [System.Guid]::NewGuid().ToString("N"))
$builderWork = Join-Path $outputPath "work-avorax-$Version-$Channel"
$payloadRoot = Join-Path $tempRoot "payload"
$signatureDirectory = Join-Path $payloadRoot "engine\signatures"
$signaturePath = Join-Path $signatureDirectory "zentor_reviewed_known_bad.zsig"

try {
  New-AvoraxGateDirectory $tempRoot "hash-intel temporary root" | Out-Null
  New-AvoraxGateDirectory $payloadRoot "hash-intel payload root" | Out-Null
  New-AvoraxGateDirectory (Join-Path $payloadRoot "engine") "hash-intel engine root" | Out-Null
  New-AvoraxGateDirectory $signatureDirectory "hash-intel signature directory" | Out-Null

  Invoke-CheckedCommand $python @(
    $packBuilder,
    "--source", $sourcePath,
    "--hashes", $hashFeedPath,
    "--output", $signaturePath,
    "--category", $Category,
    "--version", $Version
  ) "reviewed SHA-256 pack build"

  $signatureFile = Get-AvoraxGateFile $signaturePath "reviewed SHA-256 signature pack"
  $payloadFiles = @(Get-ChildItem -LiteralPath $payloadRoot -Recurse -File -Force -ErrorAction Stop)
  if ($payloadFiles.Count -ne 1 -or $payloadFiles[0].FullName -ne $signatureFile) {
    throw "Hash-intel update staging must contain exactly one reviewed signature pack."
  }
  Assert-NoReparseTree $payloadRoot "hash-intel update payload"

  $payloadRelative = Get-RepoRelativePath $payloadRoot "hash-intel payload"
  Invoke-CheckedCommand $powershell @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $updateBuilder,
    "-Version", $Version,
    "-Channel", $Channel,
    "-PayloadRoot", $payloadRelative,
    "-OutputDir", $OutputDir,
    "-SignerCommand", $SignerCommand
  ) "signed hash-intel update package build"

  $packagePath = Get-AvoraxGateFile (Join-Path $outputPath "Avorax-AntiVirus-$Version.aup") "signed hash-intel update package"
  $feedPath = Get-AvoraxGateFile (Join-Path $outputPath "update-feed.json") "hash-intel update feed"
  Write-Host "Created signed hash-intel update package: $packagePath"
  Write-Host "Created hash-intel update feed: $feedPath"
} finally {
  try {
    Remove-CheckedTempTree $builderWork $outputPath
  } finally {
    Remove-CheckedTempTree $tempRoot $tempParent
  }
}
