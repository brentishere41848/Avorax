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
    throw "Release update-service apply tamper smoke expects $FileName, got: $resolved"
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
        throw "release update-service apply tamper command timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release update-service apply tamper command timed out after ${Timeout}s."
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

function New-ApplyTamperManifest {
  param(
    [string]$PayloadHash,
    [string]$PublicKeyId
  )

  return [ordered]@{
    product = "Avorax Anti-Virus"
    package_format_version = 1
    version = "0.5.0"
    previous_min_version = "0.4.0"
    channel = "stable"
    release_date = "2026-07-06T00:00:00Z"
    package_id = "avorax-release-apply-tamper-smoke"
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
      "app/AvoraxApplySmoke.txt" = $PayloadHash
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
    throw "update apply tamper package already exists: $PackagePath"
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
      (Join-Path $PackageRoot "payload\app\AvoraxApplySmoke.txt"),
      "payload/app/AvoraxApplySmoke.txt",
      [System.IO.Compression.CompressionLevel]::Optimal
    ) | Out-Null
  } finally {
    $zip.Dispose()
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

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$updateService = Resolve-ReleaseBinary $repo $UpdateServicePath "avorax_update_service.exe"
$signer = Resolve-ReleaseBinary $repo $SignerPath "avorax_sign_manifest.exe"
$keygen = Resolve-ReleaseBinary $repo $KeygenPath "avorax_generate_update_key.exe"
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-update-service-apply-tamper-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$installRoot = Join-Path $tempRoot "install"
$packageRoot = Join-Path $tempRoot "package-root"
$packagePath = Join-Path $tempRoot "tampered-apply.aup"
$publicKeyId = "avorax-release-apply-tamper-ed25519"

$oldDataDir = [System.Environment]::GetEnvironmentVariable("AVORAX_DATA_DIR")
$oldPublicKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_HEX")
$oldPublicKeyId = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_ID")
$oldSigningKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX")
$oldDevUpdates = [System.Environment]::GetEnvironmentVariable("AVORAX_ALLOW_DEVELOPMENT_UPDATES")

try {
  New-Item -ItemType Directory -Path (Join-Path $packageRoot "payload\app") -Force | Out-Null
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

  Set-Item -Path Env:\AVORAX_DATA_DIR -Value $dataRoot -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_PUBLIC_KEY_HEX -Value $publicKeyHex -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_PUBLIC_KEY_ID -Value $publicKeyId -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX -Value $privateKeyHex -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_ALLOW_DEVELOPMENT_UPDATES -Value "false" -ErrorAction Stop

  $payloadPath = Join-Path $packageRoot "payload\app\AvoraxApplySmoke.txt"
  Write-Utf8NoBomFile $payloadPath "benign Avorax update apply tamper payload`n"
  $payloadHash = Get-FileSha256Hex $payloadPath
  $manifest = New-ApplyTamperManifest $payloadHash $publicKeyId
  $manifestPath = Join-Path $packageRoot "manifest.json"
  $signaturePath = Join-Path $packageRoot "manifest.sig"
  Write-Utf8NoBomFile $manifestPath (($manifest | ConvertTo-Json -Depth 12) + "`n")

  $signResult = Invoke-ReleaseCommand $signer @($manifestPath, $signaturePath) $repo $TimeoutSeconds
  if ($signResult.ExitCode -ne 0) {
    throw "release update manifest signer failed with $($signResult.ExitCode): $(Get-BoundedText $signResult.Stderr)"
  }
  $manifest.version = "0.5.1"
  Write-Utf8NoBomFile $manifestPath (($manifest | ConvertTo-Json -Depth 12) + "`n")
  New-UpdatePackageZip $packageRoot $packagePath

  $applyResult = Invoke-ReleaseCommand $updateService @("--apply", $packagePath, $installRoot, "0.4.0") $repo $TimeoutSeconds
  if ($applyResult.ExitCode -eq 0) {
    throw "release update-service accepted tampered package during --apply"
  }
  if (-not $applyResult.Stderr.Contains("manifest signature verification failed")) {
    throw "release update-service --apply tamper diagnostic mismatch: $(Get-BoundedText $applyResult.Stderr)"
  }

  $stagingRoot = Join-Path $dataRoot "updates\staging"
  $rollbackRoot = Join-Path $dataRoot "updates\rollback"
  $updateReportPath = Join-Path $dataRoot "updates\logs\update_report.json"
  if (Test-Path -LiteralPath $stagingRoot) {
    throw "tampered --apply created update staging before package verification failed"
  }
  if (Test-Path -LiteralPath $rollbackRoot) {
    throw "tampered --apply created rollback data before package verification failed"
  }
  if (Test-Path -LiteralPath $updateReportPath -PathType Leaf) {
    throw "tampered --apply wrote update_report.json despite failing before activation"
  }
  if ((Test-Path -LiteralPath $installRoot) -and @(Get-ChildItem -LiteralPath $installRoot -Force -Recurse -ErrorAction Stop).Count -ne 0) {
    throw "tampered --apply wrote files into the temporary install directory"
  }

  $status = Read-UpdateCliStatus $dataRoot
  if ([bool]$status.ok -ne $false -or $status.command -ne "--apply") {
    throw "tampered --apply CLI status mismatch"
  }
  if ($null -eq $status.error -or -not ([string]$status.error).Contains("manifest signature verification failed")) {
    throw "tampered --apply CLI status missing signature diagnostic"
  }

  Write-Host "Avorax release update-service apply tamper fail-before-activation smoke test passed."
  Write-Host "Apply tamper diagnostic: $(Get-BoundedText $applyResult.Stderr)"
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
