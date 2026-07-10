param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$UpdateServicePath = "",
  [string]$SignerPath = "",
  [string]$KeygenPath = "",
  [int]$TimeoutSeconds = 60
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
    throw "Release update-service smoke expects $FileName, got: $resolved"
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
    $commandText = (ConvertTo-CmdArgument $Binary)
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
        throw "release update-service command timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release update-service command timed out after ${Timeout}s."
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

function New-UpdateSmokeManifest {
  param(
    [string]$Version,
    [string]$PackageId,
    [string]$PublicKeyId,
    [string]$PayloadHash
  )

  return [ordered]@{
    product = "Avorax Anti-Virus"
    package_format_version = 1
    version = $Version
    previous_min_version = "0.1.0"
    channel = "stable"
    release_date = "2026-07-06T00:00:00Z"
    package_id = $PackageId
    components = [ordered]@{
      app = $true
      core_service = $false
      guard_service = $false
      update_service = $false
      native_engine_assets = $false
      signatures = $false
      rules = $false
      ml_model = $false
      trust_packs = $false
      docs = $false
      driver_tools = $false
    }
    requires_restart = $true
    requires_reboot = $false
    requires_admin = $true
    driver_update_included = $false
    migration_steps = @()
    rollback_supported = $true
    payload_hashes = [ordered]@{
      "app/AvoraxSmoke.txt" = $PayloadHash
    }
    package_sha256 = ""
    signature_algorithm = "ed25519"
    public_key_id = $PublicKeyId
    release_notes_url = $null
  }
}

function New-UpdatePackageZip {
  param(
    [string]$PackageRoot,
    [string]$PackagePath
  )

  if (Test-Path -LiteralPath $PackagePath) {
    throw "update smoke package already exists: $PackagePath"
  }
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::Open($PackagePath, [System.IO.Compression.ZipArchiveMode]::Create)
  try {
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $zip,
      (Join-Path $PackageRoot "manifest.json"),
      "manifest.json",
      [System.IO.Compression.CompressionLevel]::Optimal
    ) | Out-Null
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $zip,
      (Join-Path $PackageRoot "manifest.sig"),
      "manifest.sig",
      [System.IO.Compression.CompressionLevel]::Optimal
    ) | Out-Null
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $zip,
      (Join-Path $PackageRoot "payload\app\AvoraxSmoke.txt"),
      "payload/app/AvoraxSmoke.txt",
      [System.IO.Compression.CompressionLevel]::Optimal
    ) | Out-Null
  } finally {
    $zip.Dispose()
  }
}

function New-SignedUpdateSmokePackage {
  param(
    [string]$PackageRoot,
    [string]$PackagePath,
    [string]$Signer,
    [string]$Repo,
    [int]$Timeout,
    [string]$PackageId,
    [string]$Version,
    [string]$PayloadText,
    [string]$PublicKeyId,
    [switch]$TamperManifestAfterSign,
    [switch]$TamperPayloadAfterSign
  )

  New-Item -ItemType Directory -Path (Join-Path $PackageRoot "payload\app") -Force | Out-Null
  $payloadPath = Join-Path $PackageRoot "payload\app\AvoraxSmoke.txt"
  [System.IO.File]::WriteAllBytes($payloadPath, [System.Text.Encoding]::ASCII.GetBytes($PayloadText))
  $payloadHash = Get-FileSha256Hex $payloadPath

  $manifest = New-UpdateSmokeManifest $Version $PackageId $PublicKeyId $payloadHash
  $manifestPath = Join-Path $PackageRoot "manifest.json"
  Write-Utf8NoBomFile $manifestPath (($manifest | ConvertTo-Json -Depth 12) + "`n")

  $signaturePath = Join-Path $PackageRoot "manifest.sig"
  $signResult = Invoke-ReleaseCommand $Signer @($manifestPath, $signaturePath) $Repo $Timeout
  if ($signResult.ExitCode -ne 0) {
    throw "release update manifest signer failed with $($signResult.ExitCode): $(Get-BoundedText $signResult.Stderr)"
  }
  if (-not (Test-Path -LiteralPath $signaturePath -PathType Leaf)) {
    throw "release update manifest signer did not create manifest.sig"
  }

  if ($TamperManifestAfterSign) {
    $manifest.version = "0.2.1"
    Write-Utf8NoBomFile $manifestPath (($manifest | ConvertTo-Json -Depth 12) + "`n")
  }
  if ($TamperPayloadAfterSign) {
    [System.IO.File]::WriteAllBytes($payloadPath, [System.Text.Encoding]::ASCII.GetBytes("tampered benign update payload"))
  }

  New-UpdatePackageZip $PackageRoot $PackagePath
  return [pscustomobject]@{
    PayloadHash = $payloadHash
    PackagePath = $PackagePath
  }
}

function Read-UpdateCliStatus {
  param([string]$DataRoot)
  $statusPath = Join-Path $DataRoot "updates\logs\update_cli_status.json"
  if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
    throw "update CLI status log was not written: $statusPath"
  }
  return (Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json -ErrorAction Stop)
}

function Assert-StatusLog {
  param(
    [object]$Status,
    [bool]$ExpectedOk,
    [string]$ExpectedErrorText
  )
  if ([bool]$Status.ok -ne $ExpectedOk) {
    throw "update CLI status ok mismatch. Expected $ExpectedOk, got $($Status.ok)"
  }
  if ($Status.command -ne "--verify") {
    throw "update CLI status command mismatch: $($Status.command)"
  }
  if ($ExpectedOk) {
    if ($null -ne $Status.error) {
      throw "successful update CLI status unexpectedly included error: $($Status.error)"
    }
  } else {
    if ($null -eq $Status.error -or -not ([string]$Status.error).Contains($ExpectedErrorText)) {
      throw "failed update CLI status missing expected diagnostic '$ExpectedErrorText': $(Get-BoundedText $Status.error)"
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$updateService = Resolve-ReleaseBinary $repo $UpdateServicePath "avorax_update_service.exe"
$signer = Resolve-ReleaseBinary $repo $SignerPath "avorax_sign_manifest.exe"
$keygen = Resolve-ReleaseBinary $repo $KeygenPath "avorax_generate_update_key.exe"
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-update-service-verify-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$publicKeyId = "avorax-release-smoke-ed25519"

$oldDataDir = [System.Environment]::GetEnvironmentVariable("AVORAX_DATA_DIR")
$oldPublicKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_HEX")
$oldPublicKeyId = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_ID")
$oldSigningKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX")
$oldDevUpdates = [System.Environment]::GetEnvironmentVariable("AVORAX_ALLOW_DEVELOPMENT_UPDATES")

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null

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
  Set-Item -Path Env:\AVORAX_ALLOW_DEVELOPMENT_UPDATES -Value "false" -ErrorAction Stop

  $validPackage = New-SignedUpdateSmokePackage `
    (Join-Path $tempRoot "valid") `
    (Join-Path $tempRoot "valid.aup") `
    $signer `
    $repo `
    $TimeoutSeconds `
    "avorax-release-verify-smoke-valid" `
    "0.2.0" `
    "benign Avorax release update smoke payload" `
    $publicKeyId

  $validResult = Invoke-ReleaseCommand $updateService @("--verify", $validPackage.PackagePath, "0.1.0") $repo $TimeoutSeconds
  if ($validResult.ExitCode -ne 0) {
    throw "release update-service failed to verify valid signed package: $(Get-BoundedText $validResult.Stderr)"
  }
  $verifiedManifest = $validResult.Stdout | ConvertFrom-Json -ErrorAction Stop
  if ($verifiedManifest.version -ne "0.2.0") {
    throw "verified update manifest version mismatch: $($verifiedManifest.version)"
  }
  if ($verifiedManifest.package_id -ne "avorax-release-verify-smoke-valid") {
    throw "verified update manifest package_id mismatch: $($verifiedManifest.package_id)"
  }
  if ($verifiedManifest.channel -ne "stable") {
    throw "verified update manifest channel mismatch: $($verifiedManifest.channel)"
  }
  if (-not [bool]$verifiedManifest.components.app) {
    throw "verified update manifest did not preserve app component"
  }
  if ([bool]$verifiedManifest.components.update_service -or [bool]$verifiedManifest.driver_update_included) {
    throw "verified update manifest unexpectedly declares updater or driver changes"
  }
  $manifestPayloadHash = $verifiedManifest.payload_hashes.PSObject.Properties["app/AvoraxSmoke.txt"].Value
  if ($manifestPayloadHash -ne $validPackage.PayloadHash) {
    throw "verified update manifest payload hash mismatch"
  }
  Assert-StatusLog (Read-UpdateCliStatus $dataRoot) $true ""

  $tamperedManifestPackage = New-SignedUpdateSmokePackage `
    (Join-Path $tempRoot "tampered-manifest") `
    (Join-Path $tempRoot "tampered-manifest.aup") `
    $signer `
    $repo `
    $TimeoutSeconds `
    "avorax-release-verify-smoke-manifest-tamper" `
    "0.2.0" `
    "benign Avorax release update smoke payload" `
    $publicKeyId `
    -TamperManifestAfterSign
  $tamperedManifestResult = Invoke-ReleaseCommand $updateService @("--verify", $tamperedManifestPackage.PackagePath, "0.1.0") $repo $TimeoutSeconds
  if ($tamperedManifestResult.ExitCode -eq 0) {
    throw "release update-service accepted a manifest modified after signing"
  }
  if (-not $tamperedManifestResult.Stderr.Contains("manifest signature verification failed")) {
    throw "manifest-tamper diagnostic mismatch: $(Get-BoundedText $tamperedManifestResult.Stderr)"
  }
  Assert-StatusLog (Read-UpdateCliStatus $dataRoot) $false "manifest signature verification failed"

  $tamperedPayloadPackage = New-SignedUpdateSmokePackage `
    (Join-Path $tempRoot "tampered-payload") `
    (Join-Path $tempRoot "tampered-payload.aup") `
    $signer `
    $repo `
    $TimeoutSeconds `
    "avorax-release-verify-smoke-payload-tamper" `
    "0.2.0" `
    "benign Avorax release update smoke payload" `
    $publicKeyId `
    -TamperPayloadAfterSign
  $tamperedPayloadResult = Invoke-ReleaseCommand $updateService @("--verify", $tamperedPayloadPackage.PackagePath, "0.1.0") $repo $TimeoutSeconds
  if ($tamperedPayloadResult.ExitCode -eq 0) {
    throw "release update-service accepted a payload modified after signing"
  }
  if (-not $tamperedPayloadResult.Stderr.Contains("payload hash mismatch for payload/app/AvoraxSmoke.txt")) {
    throw "payload-tamper diagnostic mismatch: $(Get-BoundedText $tamperedPayloadResult.Stderr)"
  }
  Assert-StatusLog (Read-UpdateCliStatus $dataRoot) $false "payload hash mismatch for payload/app/AvoraxSmoke.txt"

  Write-Host "Avorax release update-service signed package verify/tamper smoke test passed."
  Write-Host "Verified valid signed package: $($validPackage.PackagePath)"
  Write-Host "Manifest tamper diagnostic: $(Get-BoundedText $tamperedManifestResult.Stderr)"
  Write-Host "Payload tamper diagnostic: $(Get-BoundedText $tamperedPayloadResult.Stderr)"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $oldDataDir
  Restore-EnvVar "AVORAX_UPDATE_PUBLIC_KEY_HEX" $oldPublicKey
  Restore-EnvVar "AVORAX_UPDATE_PUBLIC_KEY_ID" $oldPublicKeyId
  Restore-EnvVar "AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX" $oldSigningKey
  Restore-EnvVar "AVORAX_ALLOW_DEVELOPMENT_UPDATES" $oldDevUpdates
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
