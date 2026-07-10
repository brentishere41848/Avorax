param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$UpdateServicePath = "",
  [string]$SignerPath = "",
  [string]$KeygenPath = "",
  [string]$FakeScSourcePath = "",
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
    throw "Release update-service apply success fake-service smoke expects $FileName, got: $resolved"
  }
  return $resolved
}

function Resolve-FakeScSource {
  param([string]$ConfiguredPath)

  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = "C:\Program Files\Git\usr\bin\true.exe"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Fake service-control success executable is missing: $candidate"
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  $probe = [System.Diagnostics.Process]::Start($resolved, "stop avorax_guard_service")
  $probe.WaitForExit(5000) | Out-Null
  if (-not $probe.HasExited) {
    try { $probe.Kill($true) } catch {}
    throw "Fake service-control success executable did not exit promptly: $resolved"
  }
  if ($probe.ExitCode -ne 0) {
    throw "Fake service-control success executable must exit 0 with service-like arguments: $resolved"
  }
  return $resolved
}

function ConvertTo-ProcessArgument {
  param([string]$Value)
  return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-ReleaseCommand {
  param(
    [string]$Binary,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [int]$Timeout,
    [hashtable]$Environment = @{}
  )

  $process = $null
  try {
    $argumentText = ($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join " "

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Binary
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.Arguments = $argumentText
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($entry in $Environment.GetEnumerator()) {
      $startInfo.EnvironmentVariables[$entry.Key] = [string]$entry.Value
    }

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "release update-service apply success fake-service command timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release update-service apply success fake-service command timed out after ${Timeout}s."
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

function Add-PackageFile {
  param(
    [System.IO.Compression.ZipArchive]$Zip,
    [string]$PackageRoot,
    [string]$RelativePath
  )

  [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
    $Zip,
    (Join-Path $PackageRoot $RelativePath),
    ($RelativePath -replace "\\", "/"),
    [System.IO.Compression.CompressionLevel]::Optimal
  ) | Out-Null
}

function New-ApplySuccessManifest {
  param(
    [hashtable]$PayloadHashes,
    [string]$PublicKeyId
  )

  return [ordered]@{
    product = "Avorax Anti-Virus"
    package_format_version = 1
    version = "0.6.0"
    previous_min_version = "0.5.0"
    channel = "stable"
    release_date = "2026-07-07T00:00:00Z"
    package_id = "avorax-release-apply-success-fake-service-smoke"
    components = [ordered]@{
      app = $true
      core_service = $true
      guard_service = $true
      update_service = $false
      native_engine_assets = $true
      signatures = $true
      rules = $true
      ml_model = $true
      trust_packs = $true
      docs = $true
      driver_tools = $false
    }
    requires_restart = $true
    requires_reboot = $false
    requires_admin = $true
    driver_update_included = $false
    migration_steps = @()
    rollback_supported = $true
    payload_hashes = [ordered]@{
      "app/Avorax.exe" = $PayloadHashes["payload\app\Avorax.exe"]
      "services/avorax_core_service.exe" = $PayloadHashes["payload\services\avorax_core_service.exe"]
      "services/avorax_guard_service.exe" = $PayloadHashes["payload\services\avorax_guard_service.exe"]
      "engine/signatures/new.asig" = $PayloadHashes["payload\engine\signatures\new.asig"]
      "engine/rules/new.rule" = $PayloadHashes["payload\engine\rules\new.rule"]
      "engine/ml/new.model" = $PayloadHashes["payload\engine\ml\new.model"]
      "engine/trust/new.trust" = $PayloadHashes["payload\engine\trust\new.trust"]
      "docs/release.md" = $PayloadHashes["payload\docs\release.md"]
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
    throw "update apply success fake-service package already exists: $PackagePath"
  }
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::Open($PackagePath, [System.IO.Compression.ZipArchiveMode]::Create)
  try {
    Add-PackageFile $zip $PackageRoot "manifest.json"
    Add-PackageFile $zip $PackageRoot "manifest.sig"
    Add-PackageFile $zip $PackageRoot "payload\app\Avorax.exe"
    Add-PackageFile $zip $PackageRoot "payload\services\avorax_core_service.exe"
    Add-PackageFile $zip $PackageRoot "payload\services\avorax_guard_service.exe"
    Add-PackageFile $zip $PackageRoot "payload\engine\signatures\new.asig"
    Add-PackageFile $zip $PackageRoot "payload\engine\rules\new.rule"
    Add-PackageFile $zip $PackageRoot "payload\engine\ml\new.model"
    Add-PackageFile $zip $PackageRoot "payload\engine\trust\new.trust"
    Add-PackageFile $zip $PackageRoot "payload\docs\release.md"
  } finally {
    $zip.Dispose()
  }
}

function Read-JsonFile {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "expected JSON file was not written: $Path"
  }
  return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
}

function Assert-FileText {
  param([string]$Path, [string]$Expected)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "expected file is missing: $Path"
  }
  $actual = Get-Content -LiteralPath $Path -Raw
  if ($actual -ne $Expected) {
    throw "file content mismatch for $Path"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$updateService = Resolve-ReleaseBinary $repo $UpdateServicePath "avorax_update_service.exe"
$signer = Resolve-ReleaseBinary $repo $SignerPath "avorax_sign_manifest.exe"
$keygen = Resolve-ReleaseBinary $repo $KeygenPath "avorax_generate_update_key.exe"
$fakeScSource = Resolve-FakeScSource $FakeScSourcePath
$fakeScSourceDirectory = Split-Path -Parent $fakeScSource
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-update-service-apply-success-fake-service-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$installRoot = Join-Path $tempRoot "install"
$fakeWindowsRoot = Join-Path $tempRoot "fake-windows"
$packageRoot = Join-Path $tempRoot "package-root"
$packagePath = Join-Path $tempRoot "apply-success.aup"
$publicKeyId = "avorax-release-apply-success-fake-service-ed25519"
$packageId = "avorax-release-apply-success-fake-service-smoke"

$oldDataDir = [System.Environment]::GetEnvironmentVariable("AVORAX_DATA_DIR")
$oldPublicKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_HEX")
$oldPublicKeyId = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_ID")
$oldSigningKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX")
$oldDevUpdates = [System.Environment]::GetEnvironmentVariable("AVORAX_ALLOW_DEVELOPMENT_UPDATES")

try {
  New-Item -ItemType Directory -Path (Join-Path $packageRoot "payload\app") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $packageRoot "payload\services") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $packageRoot "payload\engine\signatures") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $packageRoot "payload\engine\rules") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $packageRoot "payload\engine\ml") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $packageRoot "payload\engine\trust") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $packageRoot "payload\docs") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $installRoot "engine\signatures") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $installRoot "engine\rules") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $installRoot "engine\ml") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $installRoot "engine\trust") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $installRoot "docs") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $fakeWindowsRoot "System32") -Force | Out-Null
  Copy-Item -LiteralPath $fakeScSource -Destination (Join-Path $fakeWindowsRoot "System32\sc.exe") -Force

  $oldApp = "old Avorax app fixture`n"
  $oldCore = "old Avorax core service fixture`n"
  $oldGuard = "old Avorax guard service fixture`n"
  $oldSignature = "old Avorax signature fixture`n"
  $oldRule = "old Avorax rule fixture`n"
  $oldModel = "old Avorax model fixture`n"
  $oldTrust = "old Avorax trust fixture`n"
  $oldDocs = "old Avorax docs fixture`n"
  Write-Utf8NoBomFile (Join-Path $installRoot "Avorax.exe") $oldApp
  Write-Utf8NoBomFile (Join-Path $installRoot "avorax_core_service.exe") $oldCore
  Write-Utf8NoBomFile (Join-Path $installRoot "avorax_guard_service.exe") $oldGuard
  Write-Utf8NoBomFile (Join-Path $installRoot "engine\signatures\old.asig") $oldSignature
  Write-Utf8NoBomFile (Join-Path $installRoot "engine\rules\old.rule") $oldRule
  Write-Utf8NoBomFile (Join-Path $installRoot "engine\ml\old.model") $oldModel
  Write-Utf8NoBomFile (Join-Path $installRoot "engine\trust\old.trust") $oldTrust
  Write-Utf8NoBomFile (Join-Path $installRoot "docs\old.md") $oldDocs

  $payloads = [ordered]@{
    "payload\app\Avorax.exe" = "new Avorax app fixture`n"
    "payload\services\avorax_core_service.exe" = "new Avorax core service fixture`n"
    "payload\services\avorax_guard_service.exe" = "new Avorax guard service fixture`n"
    "payload\engine\signatures\new.asig" = "new Avorax signature fixture`n"
    "payload\engine\rules\new.rule" = "new Avorax rule fixture`n"
    "payload\engine\ml\new.model" = "new Avorax model fixture`n"
    "payload\engine\trust\new.trust" = "new Avorax trust fixture`n"
    "payload\docs\release.md" = "# New Avorax release docs`n"
  }
  $payloadHashes = @{}
  foreach ($entry in $payloads.GetEnumerator()) {
    $path = Join-Path $packageRoot $entry.Key
    Write-Utf8NoBomFile $path $entry.Value
    $payloadHashes[$entry.Key] = Get-FileSha256Hex $path
  }

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

  Set-Item -Path Env:\AVORAX_DATA_DIR -Value $dataRoot -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_PUBLIC_KEY_HEX -Value $publicKeyHex -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_PUBLIC_KEY_ID -Value $publicKeyId -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX -Value $privateKeyHex -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_ALLOW_DEVELOPMENT_UPDATES -Value "false" -ErrorAction Stop

  $manifest = New-ApplySuccessManifest $payloadHashes $publicKeyId
  $manifestPath = Join-Path $packageRoot "manifest.json"
  $signaturePath = Join-Path $packageRoot "manifest.sig"
  Write-Utf8NoBomFile $manifestPath (($manifest | ConvertTo-Json -Depth 12) + "`n")

  $signResult = Invoke-ReleaseCommand $signer @($manifestPath, $signaturePath) $repo $TimeoutSeconds
  if ($signResult.ExitCode -ne 0) {
    throw "release update manifest signer failed with $($signResult.ExitCode): $(Get-BoundedText $signResult.Stderr)"
  }
  New-UpdatePackageZip $packageRoot $packagePath

  $fakePath = "$fakeScSourceDirectory" + [System.IO.Path]::PathSeparator + [System.Environment]::GetEnvironmentVariable("PATH")
  $applyResult = Invoke-ReleaseCommand `
    $updateService `
    @("--apply", $packagePath, $installRoot, "0.5.0") `
    $repo `
    $TimeoutSeconds `
    @{ SystemRoot = $fakeWindowsRoot; WINDIR = $fakeWindowsRoot; PATH = $fakePath }

  if ($applyResult.ExitCode -ne 0) {
    throw "release update-service apply success fake-service command failed with $($applyResult.ExitCode): $(Get-BoundedText $applyResult.Stderr)"
  }
  if ($applyResult.Stderr.Contains("Windows service-control tool")) {
    throw "apply success fake-service --apply reported a service-control diagnostic unexpectedly: $(Get-BoundedText $applyResult.Stderr)"
  }

  Assert-FileText (Join-Path $installRoot "Avorax.exe") $payloads["payload\app\Avorax.exe"]
  Assert-FileText (Join-Path $installRoot "avorax_core_service.exe") $payloads["payload\services\avorax_core_service.exe"]
  Assert-FileText (Join-Path $installRoot "avorax_guard_service.exe") $payloads["payload\services\avorax_guard_service.exe"]
  Assert-FileText (Join-Path $installRoot "engine\signatures\new.asig") $payloads["payload\engine\signatures\new.asig"]
  Assert-FileText (Join-Path $installRoot "engine\rules\new.rule") $payloads["payload\engine\rules\new.rule"]
  Assert-FileText (Join-Path $installRoot "engine\ml\new.model") $payloads["payload\engine\ml\new.model"]
  Assert-FileText (Join-Path $installRoot "engine\trust\new.trust") $payloads["payload\engine\trust\new.trust"]
  Assert-FileText (Join-Path $installRoot "docs\release.md") $payloads["payload\docs\release.md"]

  $rollbackRoot = Join-Path $dataRoot "updates\rollback\0.5.0"
  Assert-FileText (Join-Path $rollbackRoot "Avorax.exe") $oldApp
  Assert-FileText (Join-Path $rollbackRoot "avorax_core_service.exe") $oldCore
  Assert-FileText (Join-Path $rollbackRoot "avorax_guard_service.exe") $oldGuard
  Assert-FileText (Join-Path $rollbackRoot "engine\signatures\old.asig") $oldSignature
  Assert-FileText (Join-Path $rollbackRoot "engine\rules\old.rule") $oldRule
  Assert-FileText (Join-Path $rollbackRoot "engine\ml\old.model") $oldModel
  Assert-FileText (Join-Path $rollbackRoot "engine\trust\old.trust") $oldTrust

  $stagingRoot = Join-Path $dataRoot "updates\staging"
  if ((Test-Path -LiteralPath $stagingRoot) -and @(Get-ChildItem -LiteralPath $stagingRoot -Force -Recurse -ErrorAction Stop).Count -ne 0) {
    throw "apply success fake-service --apply left files under the update staging root"
  }

  $updateReport = Read-JsonFile (Join-Path $dataRoot "updates\logs\update_report.json")
  if ([bool]$updateReport.ok -ne $true -or [bool]$updateReport.applied -ne $true) {
    throw "apply success fake-service update_report.json did not record successful application"
  }
  if ($updateReport.package_id -ne $packageId -or $updateReport.version -ne "0.6.0") {
    throw "apply success fake-service update_report.json package identity mismatch"
  }
  if ($null -eq $updateReport.rollback -or -not ([string]$updateReport.rollback).Contains("0.5.0")) {
    throw "apply success fake-service update_report.json missing rollback snapshot evidence"
  }
  if ([bool]$updateReport.staging_cleanup_ok -ne $true -or $null -ne $updateReport.staging_cleanup_error) {
    throw "apply success fake-service update_report.json did not record successful staging cleanup"
  }

  $status = Read-JsonFile (Join-Path $dataRoot "updates\logs\update_cli_status.json")
  if ([bool]$status.ok -ne $true -or $status.command -ne "--apply") {
    throw "apply success fake-service --apply CLI status mismatch"
  }

  Write-Host "Avorax release update-service apply success fake-service smoke test passed."
  Write-Host "Fake service-control executable: $fakeScSource"
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
