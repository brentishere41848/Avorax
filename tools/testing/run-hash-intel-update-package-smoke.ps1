param(
  [string]$RepoRoot = "",
  [Parameter(Mandatory = $true)][string]$PythonPath,
  [string]$UpdateServicePath = "",
  [string]$SignerPath = "",
  [string]$KeygenPath = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
  Resolve-Path (Join-Path $PSScriptRoot "..\..")
} else {
  $RepoRoot
}
$repo = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $RepoRoot).Path)
. (Join-Path $repo "tools\security\avorax-security-gate-tools.ps1")

function Restore-EnvVar([string]$Name, [AllowNull()][object]$Value) {
  if ($null -eq $Value) {
    if (Test-Path -Path "Env:\$Name") {
      Remove-Item -Path "Env:\$Name" -ErrorAction Stop
    }
  } else {
    Set-Item -Path "Env:\$Name" -Value $Value -ErrorAction Stop
  }
}

function Resolve-ReleaseBinary([string]$ConfiguredPath, [string]$FileName) {
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $script:repo "target\release\$FileName"
  }
  $resolved = Get-AvoraxRequiredTool ([System.IO.Path]::GetFullPath($candidate)) "release $FileName"
  if ([System.IO.Path]::GetFileName($resolved) -ne $FileName) {
    throw "Hash-intel update smoke expects $FileName, got: $resolved"
  }
  return $resolved
}

function Invoke-SmokeCommand([string]$Tool, [string[]]$Arguments, [string]$Description) {
  $result = Invoke-AvoraxGateCommandDiagnostic $Tool $Arguments $Description 32768 $script:repo
  if ($result.exit_code -ne 0) {
    throw "$Description failed with exit code $($result.exit_code): $($result.output)"
  }
  return $result
}

function Assert-SmokeCommandFails(
  [string]$Tool,
  [string[]]$Arguments,
  [string]$Description,
  [string]$ExpectedDiagnostic
) {
  $result = Invoke-AvoraxGateCommandDiagnostic $Tool $Arguments $Description 32768 $script:repo
  if ($result.exit_code -eq 0) {
    throw "$Description unexpectedly succeeded."
  }
  if ($result.output -notlike "*$ExpectedDiagnostic*") {
    throw "$Description did not report its expected diagnostic: $($result.output)"
  }
}

function Get-RepoRelativePath([string]$Path) {
  $target = [System.IO.Path]::GetFullPath($Path)
  $prefix = $script:repo.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  if (-not $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Hash-intel smoke path escaped repository root: $target"
  }
  return $target.Substring($prefix.Length)
}

function Write-Utf8NoBomFile([string]$Path, [string]$Text) {
  [System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($Path),
    $Text,
    [System.Text.UTF8Encoding]::new($false)
  )
}

function Get-TextSha256([string]$Text) {
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    return ([System.BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
  } finally {
    $sha256.Dispose()
  }
}

function Assert-NoReparseTree([string]$Path, [string]$Description) {
  $directory = Get-AvoraxGateDirectory $Path $Description
  Get-ChildItem -LiteralPath $directory -Recurse -Force -ErrorAction Stop | ForEach-Object {
    if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Description contains a reparse-point entry: $($_.FullName)"
    }
  }
}

function Remove-SmokeTemp([string]$Path, [string]$AllowedParent) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $target = [System.IO.Path]::GetFullPath($Path)
  $parent = [System.IO.Path]::GetFullPath($AllowedParent).TrimEnd('\', '/')
  $prefix = $parent + [System.IO.Path]::DirectorySeparatorChar
  if (-not $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove hash-intel smoke data outside checked temporary parent: $target"
  }
  Assert-NoReparseTree $target "hash-intel smoke temporary tree"
  $directory = Get-AvoraxGateDirectory $target "hash-intel smoke temporary tree"
  Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction Stop
}

$python = Get-AvoraxRequiredTool ([System.IO.Path]::GetFullPath($PythonPath)) "Python executable"
$updateService = Resolve-ReleaseBinary $UpdateServicePath "avorax_update_service.exe"
$signer = Resolve-ReleaseBinary $SignerPath "avorax_sign_manifest.exe"
$keygen = Resolve-ReleaseBinary $KeygenPath "avorax_generate_update_key.exe"
$wrapper = Get-AvoraxGateFile (Join-Path $repo "tools\update\avorax-build-hash-intel-update.ps1") "hash-intel update wrapper"
$powershell = Get-AvoraxRequiredTool ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$tempParent = Join-Path $repo ".workflow\ultracode\avorax-hardening\tmp"
New-AvoraxGateDirectory $tempParent "hash-intel smoke temporary parent" | Out-Null
$tempRoot = Join-Path $tempParent ("hash-intel-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$inputRoot = Join-Path $tempRoot "input"
$outputRoot = Join-Path $tempRoot "output"
$dataRoot = Join-Path $tempRoot "data"
$version = "0.3.1"
$channel = "stable"
$publicKeyId = "avorax-hash-intel-smoke-ed25519"
$oldDataDir = [System.Environment]::GetEnvironmentVariable("AVORAX_DATA_DIR")
$oldPublicKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_HEX")
$oldPublicKeyId = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_ID")
$oldSigningKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX")
$oldDevUpdates = [System.Environment]::GetEnvironmentVariable("AVORAX_ALLOW_DEVELOPMENT_UPDATES")

try {
  New-AvoraxGateDirectory $tempRoot "hash-intel smoke temporary root" | Out-Null
  New-AvoraxGateDirectory $inputRoot "hash-intel smoke input root" | Out-Null
  New-AvoraxGateDirectory $outputRoot "hash-intel smoke output root" | Out-Null
  New-AvoraxGateDirectory $dataRoot "hash-intel smoke data root" | Out-Null

  $sourcePath = Join-Path $inputRoot "source.json"
  $hashPath = Join-Path $inputRoot "hashes.txt"
  $fixtureHash = Get-TextSha256 "benign reviewed hash-only update smoke fixture"
  Write-Utf8NoBomFile $sourcePath (@{
      source_name = "reviewed hash-only smoke fixture"
      source_url = "https://example.invalid/reviewed-hashes"
      source_type = "test_fixture"
      malware_family = "Fixture.Safe"
    } | ConvertTo-Json)
  Write-Utf8NoBomFile $hashPath ($fixtureHash + "`n")

  $sourceRelative = Get-RepoRelativePath $sourcePath
  $hashRelative = Get-RepoRelativePath $hashPath
  $outputRelative = Get-RepoRelativePath $outputRoot
  Assert-SmokeCommandFails $powershell @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $wrapper,
    "-Version", "../escape", "-Category", "trojan",
    "-SourceMetadata", $sourceRelative, "-HashFeed", $hashRelative,
    "-PythonPath", $python, "-OutputDir", $outputRelative,
    "-SignerCommand", "unused"
  ) "hash-intel traversal version rejection" "Version must be a 1-64 character path token"
  Assert-SmokeCommandFails $powershell @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $wrapper,
    "-Version", $version, "-Category", "trojan",
    "-SourceMetadata", $sourceRelative, "-HashFeed", $hashRelative,
    "-PythonPath", "python.exe", "-OutputDir", $outputRelative,
    "-SignerCommand", "unused"
  ) "hash-intel relative Python rejection" "PythonPath must be an absolute local executable path"

  $keyResult = Invoke-SmokeCommand $keygen @() "hash-intel smoke update key generation"
  $privateLine = @($keyResult.stdout -split "`r?`n" | Where-Object { $_ -like "private=*" })[0]
  $publicLine = @($keyResult.stdout -split "`r?`n" | Where-Object { $_ -like "public=*" })[0]
  if ([string]::IsNullOrWhiteSpace($privateLine) -or [string]::IsNullOrWhiteSpace($publicLine)) {
    throw "Hash-intel smoke key generator did not emit private/public markers."
  }
  $privateKey = $privateLine.Substring("private=".Length).Trim()
  $publicKey = $publicLine.Substring("public=".Length).Trim()
  if ($privateKey -notmatch '^[0-9a-f]{64}$' -or $publicKey -notmatch '^[0-9a-f]{64}$') {
    throw "Hash-intel smoke key generator emitted malformed Ed25519 key material."
  }

  Set-Item -Path Env:\AVORAX_DATA_DIR -Value $dataRoot -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_PUBLIC_KEY_HEX -Value $publicKey -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_PUBLIC_KEY_ID -Value $publicKeyId -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX -Value $privateKey -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_ALLOW_DEVELOPMENT_UPDATES -Value "false" -ErrorAction Stop

  $signerCommand = '"' + $signer + '"'
  Invoke-SmokeCommand $powershell @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $wrapper,
    "-Version", $version,
    "-Category", "trojan",
    "-SourceMetadata", $sourceRelative,
    "-HashFeed", $hashRelative,
    "-PythonPath", $python,
    "-Channel", $channel,
    "-OutputDir", $outputRelative,
    "-SignerCommand", $signerCommand
  ) "signed hash-intel update wrapper smoke"

  $builderWork = Join-Path $outputRoot "work-avorax-$version-$channel"
  if (Test-Path -LiteralPath $builderWork) {
    throw "Hash-intel update wrapper left its package-builder work directory behind."
  }
  $packagePath = Get-AvoraxGateFile (Join-Path $outputRoot "Avorax-AntiVirus-$version.aup") "hash-intel smoke package"
  Get-AvoraxGateFile (Join-Path $outputRoot "update-feed.json") "hash-intel smoke feed" | Out-Null
  $verifyResult = Invoke-SmokeCommand $updateService @("--verify", $packagePath, "0.3.0") "signed hash-intel update verification"
  $manifest = $verifyResult.stdout | ConvertFrom-Json -ErrorAction Stop

  if ($manifest.version -ne $version -or $manifest.channel -ne $channel) {
    throw "Hash-intel smoke manifest version/channel mismatch."
  }
  if ([bool]$manifest.components.app -or [bool]$manifest.components.core_service -or [bool]$manifest.components.guard_service) {
    throw "Hash-intel update unexpectedly contains app or service components."
  }
  if (-not [bool]$manifest.components.native_engine_assets -or -not [bool]$manifest.components.signatures) {
    throw "Hash-intel update did not declare its signature engine component."
  }
  if ([bool]$manifest.components.rules -or [bool]$manifest.components.ml_model -or [bool]$manifest.components.trust_packs -or [bool]$manifest.components.docs) {
    throw "Hash-intel update unexpectedly contains non-signature engine or docs components."
  }

  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [System.IO.Compression.ZipFile]::OpenRead($packagePath)
  try {
    $entryNames = @($archive.Entries | ForEach-Object FullName | Sort-Object)
    $expectedEntries = @(
      "manifest.json",
      "manifest.sig",
      "payload/engine/signatures/zentor_reviewed_known_bad.zsig"
    ) | Sort-Object
    if (@(Compare-Object $expectedEntries $entryNames).Count -ne 0) {
      throw "Hash-intel update archive entry set mismatch."
    }
    $packEntry = $archive.GetEntry("payload/engine/signatures/zentor_reviewed_known_bad.zsig")
    $reader = [System.IO.StreamReader]::new($packEntry.Open(), [System.Text.Encoding]::UTF8, $true, 4096, $false)
    try {
      $pack = $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop
    } finally {
      $reader.Dispose()
    }
    if ($pack.signatures.Count -ne 1 -or $pack.signatures[0].pattern -ne $fixtureHash) {
      throw "Hash-intel update pack did not retain the reviewed fixture SHA-256 exactly."
    }
  } finally {
    $archive.Dispose()
  }

  Write-Host "Avorax signed hash-intel update package smoke test passed."
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $oldDataDir
  Restore-EnvVar "AVORAX_UPDATE_PUBLIC_KEY_HEX" $oldPublicKey
  Restore-EnvVar "AVORAX_UPDATE_PUBLIC_KEY_ID" $oldPublicKeyId
  Restore-EnvVar "AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX" $oldSigningKey
  Restore-EnvVar "AVORAX_ALLOW_DEVELOPMENT_UPDATES" $oldDevUpdates
  Remove-SmokeTemp $tempRoot $tempParent
}
