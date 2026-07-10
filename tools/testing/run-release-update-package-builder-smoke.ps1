param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$UpdateServicePath = "",
  [string]$SignerPath = "",
  [string]$KeygenPath = "",
  [int]$TimeoutSeconds = 90
)

$ErrorActionPreference = "Stop"

function Get-BoundedText {
  param([AllowNull()][object]$Value, [int]$MaxChars = 4096)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  $text = $text -replace "[`0-\x1F\x7F]+", " "
  if ($text.Length -le $MaxChars) { return $text }
  return $text.Substring(0, [Math]::Max(0, $MaxChars - 3)) + "..."
}

function Restore-EnvVar {
  param(
    [string]$Name,
    [AllowNull()][object]$Value
  )
  if ($null -eq $Value) {
    if (Test-Path -Path "Env:\$Name") {
      Remove-Item -Path "Env:\$Name" -ErrorAction Stop
    }
  } else {
    Set-Item -Path "Env:\$Name" -Value $Value -ErrorAction Stop
  }
}

function Resolve-ReleaseBinary {
  param(
    [string]$Repo,
    [string]$ConfiguredPath,
    [string]$FileName
  )
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Repo "target\release\$FileName"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release update-service binary is missing: $candidate. Run cargo build --release --manifest-path core\avorax_update_service\Cargo.toml first."
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  if ([System.IO.Path]::GetFileName($resolved) -ne $FileName) {
    throw "Release update package builder smoke expects $FileName, got: $resolved"
  }
  return $resolved
}

function ConvertTo-CmdArgument {
  param([string]$Value)
  return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-ReleaseCommand {
  param(
    [string]$Binary,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [int]$Timeout
  )

  $process = $null
  try {
    $argumentText = ($Arguments | ForEach-Object { ConvertTo-CmdArgument $_ }) -join " "
    $commandText = ConvertTo-CmdArgument $Binary
    if ($argumentText.Length -gt 0) {
      $commandText = "$commandText $argumentText"
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "cmd.exe"
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.Arguments = "/d /s /c `"$commandText`""
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "release update package builder command timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release update package builder command timed out after ${Timeout}s."
    }

    return [pscustomobject]@{
      ExitCode = $process.ExitCode
      Stdout = $stdoutTask.Result
      Stderr = $stderrTask.Result
    }
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function Get-RepoRelativePath {
  param(
    [string]$Repo,
    [string]$Path
  )
  $root = [System.IO.Path]::GetFullPath($Repo).TrimEnd('\', '/')
  $target = [System.IO.Path]::GetFullPath($Path)
  $prefix = $root + [System.IO.Path]::DirectorySeparatorChar
  if (-not $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "update package builder smoke path must stay under the repository: $target"
  }
  return $target.Substring($prefix.Length)
}

function Get-FileSha256Hex {
  param([string]$Path)
  $stream = [System.IO.File]::OpenRead($Path)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
  } finally {
    $sha256.Dispose()
    $stream.Dispose()
  }
}

function Write-Utf8NoBomFile {
  param([string]$Path, [string]$Text)
  [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Read-UpdateCliStatus {
  param([string]$DataRoot)
  $statusPath = Join-Path $DataRoot "updates\logs\update_cli_status.json"
  if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
    throw "update CLI status log was not written: $statusPath"
  }
  return (Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json -ErrorAction Stop)
}

function Assert-PayloadHash {
  param(
    [object]$Manifest,
    [string]$RelativePath,
    [string]$ExpectedHash
  )
  $property = $Manifest.payload_hashes.PSObject.Properties[$RelativePath]
  if ($null -eq $property) {
    throw "verified builder manifest is missing payload hash for $RelativePath"
  }
  if ($property.Value -ne $ExpectedHash) {
    throw "verified builder manifest payload hash mismatch for ${RelativePath}: $($property.Value)"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$updateService = Resolve-ReleaseBinary $repo $UpdateServicePath "avorax_update_service.exe"
$signer = Resolve-ReleaseBinary $repo $SignerPath "avorax_sign_manifest.exe"
$keygen = Resolve-ReleaseBinary $repo $KeygenPath "avorax_generate_update_key.exe"
$builder = Join-Path $repo "tools\update\avorax-build-update-package.ps1"
if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) {
  throw "update package builder script is missing: $builder"
}

$publicKeyId = "avorax-release-builder-smoke-ed25519"
$version = "0.3.0"
$channel = "stable"
$tempRoot = Join-Path $repo (".workflow\ultracode\avorax-hardening\tmp\release-update-builder-" + [System.Guid]::NewGuid().ToString("N"))
$payloadRoot = Join-Path $tempRoot "payload"
$outputRoot = Join-Path $tempRoot "out"
$dataRoot = Join-Path $tempRoot "data"

$oldDataDir = [System.Environment]::GetEnvironmentVariable("AVORAX_DATA_DIR")
$oldPublicKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_HEX")
$oldPublicKeyId = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_ID")
$oldSigningKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX")
$oldSigner = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_SIGNER")
$oldDevUpdates = [System.Environment]::GetEnvironmentVariable("AVORAX_ALLOW_DEVELOPMENT_UPDATES")

try {
  New-Item -ItemType Directory -Path (Join-Path $payloadRoot "engine\signatures") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $payloadRoot "docs") -Force | Out-Null
  New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null

  $appFixture = Join-Path $payloadRoot "AvoraxBuilderSmoke.txt"
  $coreServiceFixture = Join-Path $payloadRoot "avorax_core_service.exe"
  $guardServiceFixture = Join-Path $payloadRoot "avorax_guard_service.exe"
  $signatureFixture = Join-Path $payloadRoot "engine\signatures\avorax_builder_smoke.asig"
  $docsFixture = Join-Path $payloadRoot "docs\builder-smoke.md"
  Write-Utf8NoBomFile $appFixture "benign Avorax update builder smoke app payload`n"
  Write-Utf8NoBomFile $coreServiceFixture "benign Avorax update builder smoke Core Service payload`n"
  Write-Utf8NoBomFile $guardServiceFixture "benign Avorax update builder smoke Guard Service payload`n"
  Write-Utf8NoBomFile $signatureFixture "{`"format`":`"avorax-builder-smoke-signature-fixture`",`"safe`":true}`n"
  Write-Utf8NoBomFile $docsFixture "# Avorax builder smoke`n`nBenign update package builder fixture.`n"

  $appHash = Get-FileSha256Hex $appFixture
  $coreServiceHash = Get-FileSha256Hex $coreServiceFixture
  $guardServiceHash = Get-FileSha256Hex $guardServiceFixture
  $signatureHash = Get-FileSha256Hex $signatureFixture
  $docsHash = Get-FileSha256Hex $docsFixture

  $keygenResult = Invoke-ReleaseCommand $keygen @() $repo $TimeoutSeconds
  if ($keygenResult.ExitCode -ne 0) {
    throw "release update key generator failed with $($keygenResult.ExitCode)"
  }
  $privateLine = ($keygenResult.Stdout -split "`r?`n" | Where-Object { $_ -like "private=*" } | Select-Object -First 1)
  $publicLine = ($keygenResult.Stdout -split "`r?`n" | Where-Object { $_ -like "public=*" } | Select-Object -First 1)
  if ([string]::IsNullOrWhiteSpace($privateLine) -or [string]::IsNullOrWhiteSpace($publicLine)) {
    throw "release update key generator did not emit the expected key material markers"
  }
  $privateKeyHex = $privateLine.Substring("private=".Length).Trim()
  $publicKeyHex = $publicLine.Substring("public=".Length).Trim()
  if ($privateKeyHex.Length -ne 64 -or $publicKeyHex.Length -ne 64) {
    throw "release update key generator emitted malformed key lengths"
  }

  Set-Item -Path Env:\AVORAX_DATA_DIR -Value $dataRoot -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_PUBLIC_KEY_HEX -Value $publicKeyHex -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_PUBLIC_KEY_ID -Value $publicKeyId -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX -Value $privateKeyHex -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_SIGNER -Value (ConvertTo-CmdArgument $signer) -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_ALLOW_DEVELOPMENT_UPDATES -Value "false" -ErrorAction Stop

  $payloadRelative = Get-RepoRelativePath $repo $payloadRoot
  $outputRelative = Get-RepoRelativePath $repo $outputRoot
  $builderResult = Invoke-ReleaseCommand "powershell.exe" @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $builder,
    "-Version",
    $version,
    "-Channel",
    $channel,
    "-PayloadRoot",
    $payloadRelative,
    "-OutputDir",
    $outputRelative
  ) $repo $TimeoutSeconds
  if ($builderResult.ExitCode -ne 0) {
    throw "release update package builder failed with $($builderResult.ExitCode): $(Get-BoundedText ($builderResult.Stdout + ' ' + $builderResult.Stderr))"
  }

  $packagePath = Join-Path $outputRoot "Avorax-AntiVirus-$version.aup"
  $feedPath = Join-Path $outputRoot "update-feed.json"
  if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
    throw "release update package builder did not create package: $packagePath"
  }
  if (-not (Test-Path -LiteralPath $feedPath -PathType Leaf)) {
    throw "release update package builder did not create feed: $feedPath"
  }

  $feed = Get-Content -LiteralPath $feedPath -Raw | ConvertFrom-Json -ErrorAction Stop
  $actualPackageHash = Get-FileSha256Hex $packagePath
  if ($feed.product -ne "Avorax Anti-Virus" -or $feed.channel -ne $channel -or $feed.latest_version -ne $version) {
    throw "builder feed product/channel/version mismatch"
  }
  if ($feed.packages.Count -ne 1) {
    throw "builder feed package count mismatch: $($feed.packages.Count)"
  }
  $feedPackage = $feed.packages[0]
  if ($feedPackage.package_url -ne "Avorax-AntiVirus-$version.aup") {
    throw "builder feed package_url mismatch: $($feedPackage.package_url)"
  }
  if ($feedPackage.package_sha256 -ne $actualPackageHash) {
    throw "builder feed package_sha256 mismatch"
  }

  $verifyResult = Invoke-ReleaseCommand $updateService @("--verify", $packagePath, "0.2.0") $repo $TimeoutSeconds
  if ($verifyResult.ExitCode -ne 0) {
    throw "release update-service failed to verify builder package: $(Get-BoundedText $verifyResult.Stderr)"
  }
  $verifiedManifest = $verifyResult.Stdout | ConvertFrom-Json -ErrorAction Stop
  if ($verifiedManifest.version -ne $version) {
    throw "verified builder manifest version mismatch: $($verifiedManifest.version)"
  }
  if ($verifiedManifest.channel -ne $channel) {
    throw "verified builder manifest channel mismatch: $($verifiedManifest.channel)"
  }
  if ($verifiedManifest.package_id -ne "avorax-$version-$channel") {
    throw "verified builder manifest package_id mismatch: $($verifiedManifest.package_id)"
  }
  if (-not [bool]$verifiedManifest.components.app) {
    throw "verified builder manifest did not declare app component"
  }
  if (-not [bool]$verifiedManifest.components.native_engine_assets -or -not [bool]$verifiedManifest.components.signatures) {
    throw "verified builder manifest did not declare signature engine component"
  }
  if (-not [bool]$verifiedManifest.components.docs) {
    throw "verified builder manifest did not declare docs component"
  }
  if (-not [bool]$verifiedManifest.components.core_service -or -not [bool]$verifiedManifest.components.guard_service) {
    throw "verified builder manifest did not declare service components"
  }
  if ([bool]$verifiedManifest.components.update_service -or [bool]$verifiedManifest.components.driver_tools -or [bool]$verifiedManifest.driver_update_included) {
    throw "verified builder manifest unexpectedly declares updater or driver-tool changes"
  }
  Assert-PayloadHash $verifiedManifest "app/AvoraxBuilderSmoke.txt" $appHash
  Assert-PayloadHash $verifiedManifest "services/avorax_core_service.exe" $coreServiceHash
  Assert-PayloadHash $verifiedManifest "services/avorax_guard_service.exe" $guardServiceHash
  Assert-PayloadHash $verifiedManifest "engine/signatures/avorax_builder_smoke.asig" $signatureHash
  Assert-PayloadHash $verifiedManifest "docs/builder-smoke.md" $docsHash

  $status = Read-UpdateCliStatus $dataRoot
  if (-not [bool]$status.ok -or $status.command -ne "--verify" -or $null -ne $status.error) {
    throw "builder package verification did not write successful update CLI status"
  }

  Write-Host "Avorax release update-package builder signed verify smoke test passed."
  Write-Host "Builder package: $packagePath"
  Write-Host "Builder feed: $feedPath"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $oldDataDir
  Restore-EnvVar "AVORAX_UPDATE_PUBLIC_KEY_HEX" $oldPublicKey
  Restore-EnvVar "AVORAX_UPDATE_PUBLIC_KEY_ID" $oldPublicKeyId
  Restore-EnvVar "AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX" $oldSigningKey
  Restore-EnvVar "AVORAX_UPDATE_SIGNER" $oldSigner
  Restore-EnvVar "AVORAX_ALLOW_DEVELOPMENT_UPDATES" $oldDevUpdates
  if (Test-Path -LiteralPath $tempRoot) {
    $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
    $repoPrefix = ([System.IO.Path]::GetFullPath($repo).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar)
    if (-not $resolvedTemp.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "refusing to remove update package builder smoke temp outside repo: $resolvedTemp"
    }
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction Stop
  }
}
