param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [int]$TimeoutSeconds = 120
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

function Resolve-LocalCoreBinary {
  param(
    [string]$Repo,
    [string]$ConfiguredPath
  )
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Repo "target\release\zentor_local_core.exe"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release local-core binary is missing: $candidate. Run cargo build --release --manifest-path core\zentor_local_core\Cargo.toml first."
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  if ([System.IO.Path]::GetFileName($resolved) -ne "zentor_local_core.exe") {
    throw "Release local-core definition fail-safe smoke expects zentor_local_core.exe, got: $resolved"
  }
  return $resolved
}

function Invoke-LocalCoreBinaryJson {
  param(
    [hashtable]$Command,
    [string]$InputJsonPath,
    [string]$Repo,
    [string]$Binary,
    [int]$Timeout
  )

  $json = $Command | ConvertTo-Json -Compress
  [System.IO.File]::WriteAllText(
    $InputJsonPath,
    $json + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $process = $null
  try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "cmd.exe"
    $startInfo.WorkingDirectory = $Repo
    $startInfo.Arguments = "/d /c `"type `"$InputJsonPath`" | `"$Binary`"`""
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
        throw "release local-core timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core timed out after ${Timeout}s."
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
      throw "release local-core exited with $($process.ExitCode): $(Get-BoundedText $stderr)"
    }

    $jsonResponses = @()
    foreach ($line in ($stdout -split "`r?`n")) {
      $trimmed = $line.Trim()
      if ($trimmed.Length -eq 0) { continue }
      try {
        $body = $trimmed | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "release local-core emitted non-JSON stdout during definition fail-safe smoke: $(Get-BoundedText $trimmed)"
      }
      if ($body.type -eq "scan_progress" -or $body.type -eq "progress") {
        continue
      }
      $jsonResponses += $body
    }
    if ($jsonResponses.Count -eq 0) {
      throw "release local-core produced no JSON response. stderr: $(Get-BoundedText $stderr)"
    }
    return $jsonResponses[-1]
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function Write-TamperedReleaseSmokeSignaturePack {
  param(
    [string]$EngineRoot,
    [string]$FixtureSha256
  )

  $signaturesDir = Join-Path $EngineRoot "signatures"
  New-Item -ItemType Directory -Path $signaturesDir -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $EngineRoot "rules") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $EngineRoot "ml") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $EngineRoot "trust") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $EngineRoot "config") -Force | Out-Null

  $signature = [ordered]@{
    id = "ZNE-SAFE-RELEASE-FAILSAFE-001"
    name = "Tampered release smoke harmless known-bad hash fixture"
    version = "1"
    category = "testThreat"
    confidence = "confirmed"
    severity = "test"
    signature_type = "exact_hash"
    pattern = $FixtureSha256
    mask = $null
    offset = $null
    file_types = @("*")
    min_file_size = $null
    max_file_size = $null
    required_context = @()
    false_positive_notes = "Safe fixture hash only; this pack intentionally has a bad pack_sha256 for fail-safe validation."
    action_policy = "quarantine_if_policy_allows"
    created_at = "2026-07-06T00:00:00Z"
    updated_at = "2026-07-06T00:00:00Z"
  }
  $pack = [ordered]@{
    format = "zentor-signature-pack-v1"
    version = "1.0.0"
    compiler_version = $null
    created_at = $null
    pack_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
    signatures = @($signature)
  }
  [System.IO.File]::WriteAllText(
    (Join-Path $signaturesDir "avorax_core.asig"),
    ($pack | ConvertTo-Json -Depth 8) + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )
}

function Get-Sha256Hex {
  param([byte[]]$Bytes)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
  } finally {
    $sha256.Dispose()
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-definition-failsafe-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$fixture = Join-Path $tempRoot "safe-release-definition-failsafe.bin"
$inputJson = Join-Path $tempRoot "local-core-command.json"

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null
  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-known-bad-fixture")
  [System.IO.File]::WriteAllBytes($fixture, $fixtureBytes)
  Write-TamperedReleaseSmokeSignaturePack $engineRoot (Get-Sha256Hex $fixtureBytes)

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_ENGINE_DIR = $engineRoot

  $scan = Invoke-LocalCoreBinaryJson @{
    command = "scan_file"
    path = $fixture
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "custom"
  } $inputJson $repo $binary $TimeoutSeconds

  $errors = @($scan.scan_errors)
  if ($scan.status -ne "engineUnavailable") {
    throw "release local-core did not fail safe when signature pack verification failed: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($scan.files_scanned -ne 0 -or $scan.threats_found -ne 0 -or @($scan.threats).Count -ne 0) {
    throw "release local-core reported scan/threat results from an invalid signature pack: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($scan.skipped_files -lt 1) {
    throw "release local-core did not report the target as skipped after invalid signature pack verification: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if (-not ($errors | Where-Object { $_ -like "*signature pack hash mismatch*" })) {
    throw "release local-core did not expose the signature pack hash mismatch diagnostic: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    throw "release local-core removed the source fixture after invalid definition verification"
  }
  $payloads = @()
  if (Test-Path -LiteralPath $quarantineRoot) {
    $payloads = @(Get-ChildItem -LiteralPath $quarantineRoot -Recurse -File -ErrorAction Stop | Where-Object { $_.Name -like "*.avoraxq" })
  }
  if ($payloads.Count -ne 0) {
    throw "release local-core quarantined payloads after invalid definition verification: $($payloads[0].FullName)"
  }

  Write-Host "Avorax release local-core definition fail-safe smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Engine dir: $engineRoot"
  Write-Host "Status: $($scan.status)"
  Write-Host "Skipped files: $($scan.skipped_files)"
  Write-Host "Diagnostic: $($errors[0])"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "ZENTOR_LEGACY_DATA_DIR" $previousLegacyDataDir
  Restore-EnvVar "AVORAX_QUARANTINE_DIR" $previousQuarantineDir
  Restore-EnvVar "ZENTOR_ALLOWLIST_FILE" $previousAllowlistFile
  Restore-EnvVar "AVORAX_ENGINE_DIR" $previousEngineDir
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
