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
    throw "Release update-service apply stop-failure smoke expects $FileName, got: $resolved"
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
        throw "release update-service apply stop-failure command timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release update-service apply stop-failure command timed out after ${Timeout}s."
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

function New-ApplyStopFailureManifest {
  param(
    [string]$PayloadHash,
    [string]$PublicKeyId
  )

  return [ordered]@{
    product = "Avorax Anti-Virus"
    package_format_version = 1
    version = "0.6.0"
    previous_min_version = "0.5.0"
    channel = "stable"
    release_date = "2026-07-06T00:00:00Z"
    package_id = "avorax-release-apply-stop-failure-smoke"
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
      "app/AvoraxStopFailureSmoke.txt" = $PayloadHash
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
    throw "update apply stop-failure package already exists: $PackagePath"
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
      (Join-Path $PackageRoot "payload\app\AvoraxStopFailureSmoke.txt"),
      "payload/app/AvoraxStopFailureSmoke.txt",
      [System.IO.Compression.CompressionLevel]::Optimal
    ) | Out-Null
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
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-update-service-apply-stop-failure-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$installRoot = Join-Path $tempRoot "install"
$fakeWindowsRoot = Join-Path $tempRoot "fake-windows"
$packageRoot = Join-Path $tempRoot "package-root"
$packagePath = Join-Path $tempRoot "stop-failure.aup"
$publicKeyId = "avorax-release-apply-stop-failure-ed25519"
$packageId = "avorax-release-apply-stop-failure-smoke"

$oldDataDir = [System.Environment]::GetEnvironmentVariable("AVORAX_DATA_DIR")
$oldPublicKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_HEX")
$oldPublicKeyId = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_ID")
$oldSigningKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX")
$oldDevUpdates = [System.Environment]::GetEnvironmentVariable("AVORAX_ALLOW_DEVELOPMENT_UPDATES")

try {
  New-Item -ItemType Directory -Path (Join-Path $packageRoot "payload\app") -Force | Out-Null
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $installRoot "engine\signatures") -Force | Out-Null
  New-Item -ItemType Directory -Path $fakeWindowsRoot -Force | Out-Null

  $oldApp = "old Avorax app fixture`n"
  $oldCore = "old Avorax core service fixture`n"
  $oldGuard = "old Avorax guard service fixture`n"
  $oldSignature = "old Avorax signature fixture`n"
  Write-Utf8NoBomFile (Join-Path $installRoot "Avorax.exe") $oldApp
  Write-Utf8NoBomFile (Join-Path $installRoot "avorax_core_service.exe") $oldCore
  Write-Utf8NoBomFile (Join-Path $installRoot "avorax_guard_service.exe") $oldGuard
  Write-Utf8NoBomFile (Join-Path $installRoot "engine\signatures\old.asig") $oldSignature

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

  $payloadPath = Join-Path $packageRoot "payload\app\AvoraxStopFailureSmoke.txt"
  Write-Utf8NoBomFile $payloadPath "new benign Avorax update apply stop-failure payload`n"
  $payloadHash = Get-FileSha256Hex $payloadPath
  $manifest = New-ApplyStopFailureManifest $payloadHash $publicKeyId
  $manifestPath = Join-Path $packageRoot "manifest.json"
  $signaturePath = Join-Path $packageRoot "manifest.sig"
  Write-Utf8NoBomFile $manifestPath (($manifest | ConvertTo-Json -Depth 12) + "`n")

  $signResult = Invoke-ReleaseCommand $signer @($manifestPath, $signaturePath) $repo $TimeoutSeconds
  if ($signResult.ExitCode -ne 0) {
    throw "release update manifest signer failed with $($signResult.ExitCode): $(Get-BoundedText $signResult.Stderr)"
  }
  New-UpdatePackageZip $packageRoot $packagePath

  $applyResult = Invoke-ReleaseCommand `
    $updateService `
    @("--apply", $packagePath, $installRoot, "0.5.0") `
    $repo `
    $TimeoutSeconds `
    @{ SystemRoot = $fakeWindowsRoot; WINDIR = $fakeWindowsRoot }

  if ($applyResult.ExitCode -eq 0) {
    throw "release update-service applied package even though service stop was forced to fail"
  }
  if (-not $applyResult.Stderr.Contains("update apply aborted because services did not stop")) {
    throw "release update-service stop-failure diagnostic mismatch: $(Get-BoundedText $applyResult.Stderr)"
  }
  if (-not $applyResult.Stderr.Contains("Windows service-control tool")) {
    throw "release update-service stop-failure diagnostic did not prove service-control preflight failure: $(Get-BoundedText $applyResult.Stderr)"
  }
  if (-not $applyResult.Stderr.Contains($fakeWindowsRoot)) {
    throw "release update-service stop-failure diagnostic did not use the fake Windows root"
  }

  $stagingRoot = Join-Path $dataRoot "updates\staging"
  $packageStaging = Join-Path $stagingRoot $packageId
  if (Test-Path -LiteralPath $packageStaging) {
    throw "stop-failure --apply left the package staging directory behind"
  }
  if ((Test-Path -LiteralPath $stagingRoot) -and @(Get-ChildItem -LiteralPath $stagingRoot -Force -Recurse -ErrorAction Stop).Count -ne 0) {
    throw "stop-failure --apply left files under the update staging root"
  }

  $rollbackRoot = Join-Path $dataRoot "updates\rollback\0.5.0"
  Assert-FileText (Join-Path $rollbackRoot "Avorax.exe") $oldApp
  Assert-FileText (Join-Path $rollbackRoot "avorax_core_service.exe") $oldCore
  Assert-FileText (Join-Path $rollbackRoot "avorax_guard_service.exe") $oldGuard
  Assert-FileText (Join-Path $rollbackRoot "engine\signatures\old.asig") $oldSignature

  Assert-FileText (Join-Path $installRoot "Avorax.exe") $oldApp
  Assert-FileText (Join-Path $installRoot "avorax_core_service.exe") $oldCore
  Assert-FileText (Join-Path $installRoot "avorax_guard_service.exe") $oldGuard
  Assert-FileText (Join-Path $installRoot "engine\signatures\old.asig") $oldSignature
  if (Test-Path -LiteralPath (Join-Path $installRoot "AvoraxStopFailureSmoke.txt")) {
    throw "stop-failure --apply copied app payload after service stop failure"
  }

  $updateReport = Read-JsonFile (Join-Path $dataRoot "updates\logs\update_report.json")
  if ([bool]$updateReport.ok -ne $false -or [bool]$updateReport.applied -ne $false) {
    throw "stop-failure update_report.json did not record failed non-application"
  }
  if ($updateReport.package_id -ne $packageId -or $updateReport.version -ne "0.6.0") {
    throw "stop-failure update_report.json package identity mismatch"
  }
  if ([bool]$updateReport.restart_after_stop_failure_ok -ne $false) {
    throw "stop-failure update_report.json should record failed restart after forced stop failure"
  }
  if ([bool]$updateReport.staging_cleanup_ok -ne $true -or $null -ne $updateReport.staging_cleanup_error) {
    throw "stop-failure update_report.json did not record successful staging cleanup"
  }
  if ($null -eq $updateReport.stop_error -or -not ([string]$updateReport.stop_error).Contains("Windows service-control tool")) {
    throw "stop-failure update_report.json missing service-control diagnostic"
  }
  if ($null -eq $updateReport.restart_after_stop_failure_error -or -not ([string]$updateReport.restart_after_stop_failure_error).Contains("Windows service-control tool")) {
    throw "stop-failure update_report.json missing restart diagnostic"
  }

  $status = Read-JsonFile (Join-Path $dataRoot "updates\logs\update_cli_status.json")
  if ([bool]$status.ok -ne $false -or $status.command -ne "--apply") {
    throw "stop-failure --apply CLI status mismatch"
  }
  if ($null -eq $status.error -or -not ([string]$status.error).Contains("update apply aborted because services did not stop")) {
    throw "stop-failure --apply CLI status missing stop-failure diagnostic"
  }

  Write-Host "Avorax release update-service apply stop-failure rollback/staging smoke test passed."
  Write-Host "Apply stop-failure diagnostic: $(Get-BoundedText $applyResult.Stderr)"
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
