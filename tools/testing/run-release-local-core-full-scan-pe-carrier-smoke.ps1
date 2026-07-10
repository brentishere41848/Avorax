param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [int]$TimeoutSeconds = 180
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
    throw "Release local-core full-scan PE carrier smoke expects zentor_local_core.exe, got: $resolved"
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
        throw "release local-core full-scan PE carrier smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core full-scan PE carrier smoke timed out after ${Timeout}s."
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
        throw "release local-core emitted non-JSON stdout during full-scan PE carrier smoke: $(Get-BoundedText $trimmed)"
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

function Get-Sha256Hex {
  param([byte[]]$Bytes)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
  } finally {
    $sha256.Dispose()
  }
}

function Write-ReleasePeCarrierSignaturePack {
  param(
    [string]$EngineRoot,
    [string]$FixtureSha256
  )

  $signaturesDir = Join-Path $EngineRoot "signatures"
  $rulesDir = Join-Path $EngineRoot "rules"
  $mlDir = Join-Path $EngineRoot "ml"
  $trustDir = Join-Path $EngineRoot "trust"
  $configDir = Join-Path $EngineRoot "config"
  New-Item -ItemType Directory -Path $signaturesDir -Force | Out-Null
  New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
  New-Item -ItemType Directory -Path $mlDir -Force | Out-Null
  New-Item -ItemType Directory -Path $trustDir -Force | Out-Null
  New-Item -ItemType Directory -Path $configDir -Force | Out-Null

  $signature = [ordered]@{
    id = "ZNE-SAFE-RELEASE-FULLSCAN-PE-001"
    name = "Release full-scan PE carrier safe hash fixture"
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
    false_positive_notes = "Safe full-scan PE carrier hash fixture only; no malware binary is included or generated."
    action_policy = "quarantine_if_policy_allows"
    created_at = "2026-07-07T00:00:00Z"
    updated_at = "2026-07-07T00:00:00Z"
  }
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-07T00:00:00Z","false_positive_notes":"Safe full-scan PE carrier hash fixture only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-RELEASE-FULLSCAN-PE-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Release full-scan PE carrier safe hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-07T00:00:00Z","version":"1"}],"version":"1.0.0"}'
  $canonicalBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($canonicalJson)
  $packSha256 = Get-Sha256Hex $canonicalBytes
  $pack = [ordered]@{
    format = "zentor-signature-pack-v1"
    version = "1.0.0"
    compiler_version = $null
    created_at = $null
    pack_sha256 = $packSha256
    signatures = @($signature)
  }
  $packJson = $pack | ConvertTo-Json -Depth 8
  [System.IO.File]::WriteAllText(
    (Join-Path $signaturesDir "avorax_core.asig"),
    $packJson + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-fullscan-pe-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$scanRoot = Join-Path $tempRoot "scan-root"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$inputJson = Join-Path $tempRoot "local-core-command.json"

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $scanRoot -Force | Out-Null

  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("zentor-safe-release-fullscan-fixture")
  $carrierPaths = @(
    (Join-Path $scanRoot "safe-release-library.dll"),
    (Join-Path $scanRoot "safe-release-driver.sys"),
    (Join-Path $scanRoot "safe-release-screensaver.scr"),
    (Join-Path $scanRoot "safe-release-payload.bin")
  )
  foreach ($carrierPath in $carrierPaths) {
    [System.IO.File]::WriteAllBytes($carrierPath, $fixtureBytes)
  }
  $benignFile = Join-Path $scanRoot "benign-release-note.txt"
  [System.IO.File]::WriteAllText(
    $benignFile,
    "benign release full-scan smoke file`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  Write-ReleasePeCarrierSignaturePack $engineRoot (Get-Sha256Hex $fixtureBytes)

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_ENGINE_DIR = $engineRoot

  $scan = Invoke-LocalCoreBinaryJson @{
    command = "full_scan"
    paths = @($scanRoot)
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "full"
  } $inputJson $repo $binary $TimeoutSeconds

  if ($scan.status -ne "threatsFound") {
    throw "release local-core full_scan did not return a threat status: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $filesScanned = if ($null -ne $scan.files_scanned) { [int64]$scan.files_scanned } else { 0 }
  if ($filesScanned -lt 5) {
    throw "release local-core full_scan did not scan all carrier and benign files: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $quarantinedFiles = if ($null -ne $scan.quarantined_files) { [int64]$scan.quarantined_files } else { 0 }
  if ($quarantinedFiles -lt 4) {
    throw "release local-core full_scan did not quarantine all PE carrier fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }

  $carrierThreats = @()
  foreach ($carrierPath in $carrierPaths) {
    $fileName = Split-Path -Leaf $carrierPath
    $threat = @($scan.threats) | Where-Object {
      $_.file_name -eq $fileName -and
      $_.detection_type -eq "signature" -and
      ($_.confidence -eq "confirmed" -or $_.reason_summary -like "*signature*") -and
      $_.status -eq "quarantined" -and
      -not [string]::IsNullOrWhiteSpace([string]$_.quarantine_id) -and
      -not [string]::IsNullOrWhiteSpace([string]$_.quarantine_path) -and
      ([string]$_.quarantine_path).EndsWith(".avoraxq")
    } | Select-Object -First 1
    if ($null -eq $threat) {
      throw "release local-core full_scan did not report quarantined confirmed signature threat for ${fileName}: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
    }
    if (Test-Path -LiteralPath $carrierPath) {
      throw "release local-core full_scan left source PE carrier fixture in place after quarantine: $carrierPath"
    }
    if (-not (Test-Path -LiteralPath $threat.quarantine_path -PathType Leaf)) {
      throw "release local-core full_scan reported a missing quarantine payload: $($threat.quarantine_path)"
    }
    $carrierThreats += $threat
  }

  if (-not (Test-Path -LiteralPath $benignFile -PathType Leaf)) {
    throw "release local-core full_scan removed the benign non-matching fixture"
  }

  $list = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $inputJson $repo $binary $TimeoutSeconds
  if ($list.ok -ne $true) {
    throw "release local-core list_quarantine failed after full_scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }

  foreach ($threat in $carrierThreats) {
    $threatPath = [string]$threat.path
    $record = @($list.records) | Where-Object {
      $_.quarantine_id -eq $threat.quarantine_id -and
      ($_.original_path -eq $threatPath -or $_.original_path -eq $threat.path) -and
      $_.status -eq "quarantined" -and
      $_.action_taken -eq "quarantined" -and
      $_.quarantine_path -like "*.avoraxq"
    } | Select-Object -First 1
    if ($null -eq $record) {
      throw "release local-core full_scan quarantine record is missing for $($threat.file_name): $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
    }
    if (-not (Test-Path -LiteralPath $record.quarantine_path -PathType Leaf)) {
      throw "release local-core full_scan quarantine record payload is missing: $($record.quarantine_path)"
    }
  }

  Write-Host "Avorax release local-core full-scan PE carrier smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Engine dir: $engineRoot"
  Write-Host "Scan root: $scanRoot"
  Write-Host "Files scanned: $filesScanned"
  Write-Host "Threats: $(@($scan.threats).Count)"
  Write-Host "Quarantined files: $quarantinedFiles"
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
