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
    throw "Release local-core allowlist honored smoke expects zentor_local_core.exe, got: $resolved"
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
        throw "release local-core allowlist honored smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core allowlist honored smoke timed out after ${Timeout}s."
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
        throw "release local-core emitted non-JSON stdout during allowlist honored smoke: $(Get-BoundedText $trimmed)"
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

function Write-ReleaseAllowlistSignaturePack {
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
    id = "ZNE-SAFE-RELEASE-ALLOWLIST-HONORED-001"
    name = "Release allowlist honored harmless known-bad hash fixture"
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
    false_positive_notes = "Safe fixture hash only; no malware binary is included or generated."
    action_policy = "quarantine_if_policy_allows"
    created_at = "2026-07-07T00:00:00Z"
    updated_at = "2026-07-07T00:00:00Z"
  }
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-07T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-RELEASE-ALLOWLIST-HONORED-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Release allowlist honored harmless known-bad hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-07T00:00:00Z","version":"1"}],"version":"1.0.0"}'
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

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-allowlist-honored-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$fixture = Join-Path $tempRoot "safe-release-allowlisted.bin"
$inputJson = Join-Path $tempRoot "local-core-command.json"

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null
  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-known-bad-allowlisted-fixture")
  $expectedSha256 = Get-Sha256Hex $fixtureBytes
  $expectedStoredSha256 = "sha256:$expectedSha256"
  [System.IO.File]::WriteAllBytes($fixture, $fixtureBytes)
  $expectedContent = [System.IO.File]::ReadAllText($fixture, [System.Text.Encoding]::ASCII)
  [System.IO.File]::WriteAllText(
    $allowlistFile,
    "[]`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )
  Write-ReleaseAllowlistSignaturePack $engineRoot $expectedSha256

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_ENGINE_DIR = $engineRoot

  $entry = Invoke-LocalCoreBinaryJson @{
    command = "add_allowlist_entry"
    path = $fixture
  } $inputJson $repo $binary $TimeoutSeconds
  if ($entry.ok -ne $true -or [string]::IsNullOrWhiteSpace([string]$entry.entry.id)) {
    throw "release local-core could not add the allowlisted fixture entry: $(Get-BoundedText ($entry | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([string]$entry.entry.sha256 -ne $expectedStoredSha256) {
    throw "release local-core allowlist entry hash did not match the fixture hash: $(Get-BoundedText ($entry | ConvertTo-Json -Compress -Depth 8))"
  }

  $listBefore = Invoke-LocalCoreBinaryJson @{ command = "list_allowlist" } $inputJson $repo $binary $TimeoutSeconds
  $activeEntry = @($listBefore.entries) | Where-Object {
    $_.id -eq $entry.entry.id -and
    $_.active -eq $true -and
    $_.sha256 -eq $expectedStoredSha256
  } | Select-Object -First 1
  if ($listBefore.ok -ne $true -or $null -eq $activeEntry) {
    throw "release local-core did not persist the active allowlist entry before scan: $(Get-BoundedText ($listBefore | ConvertTo-Json -Compress -Depth 8))"
  }

  $scan = Invoke-LocalCoreBinaryJson @{
    command = "scan_file"
    path = $fixture
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "custom"
  } $inputJson $repo $binary $TimeoutSeconds

  $threats = @($scan.threats)
  $allowlistedThreat = $threats | Where-Object {
    $_.status -eq "allowlisted" -and
    $_.recommended_action -eq "allowlist" -and
    ($_.confidence -eq "confirmed" -or $_.reason_summary -like "*signature*" -or $_.reason_summary -like "*ZNE-SAFE-RELEASE-ALLOWLIST-HONORED-001*")
  } | Select-Object -First 1
  if ($scan.status -ne "threatsFound") {
    throw "release local-core scan did not surface the allowlisted confirmed fixture: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($scan.files_scanned -ne 1 -or $scan.threats_found -ne 1 -or $threats.Count -ne 1) {
    throw "release local-core allowlisted scan counters were unexpected: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($null -eq $allowlistedThreat) {
    throw "release local-core did not mark the confirmed fixture detection as allowlisted: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($scan.quarantined_files -ne 0) {
    throw "release local-core quarantined an allowlisted confirmed fixture: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($scan.scan_errors).Count -ne 0) {
    throw "release local-core reported scan errors during allowlist honored smoke: $(Get-BoundedText ($scan.scan_errors | ConvertTo-Json -Compress -Depth 8))"
  }
  if (-not [string]::IsNullOrWhiteSpace([string]$allowlistedThreat.quarantine_id) -or -not [string]::IsNullOrWhiteSpace([string]$allowlistedThreat.quarantine_path)) {
    throw "release local-core attached quarantine metadata to an allowlisted detection: $(Get-BoundedText ($allowlistedThreat | ConvertTo-Json -Compress -Depth 8))"
  }
  if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    throw "release local-core moved or removed the allowlisted confirmed fixture"
  }
  $actualContent = [System.IO.File]::ReadAllText($fixture, [System.Text.Encoding]::ASCII)
  if ($actualContent -ne $expectedContent) {
    throw "release local-core modified the allowlisted confirmed fixture content"
  }

  $listQuarantine = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $inputJson $repo $binary $TimeoutSeconds
  if ($listQuarantine.ok -ne $true) {
    throw "release local-core list_quarantine failed after allowlisted scan: $(Get-BoundedText ($listQuarantine | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($listQuarantine.records).Count -ne 0) {
    throw "release local-core created quarantine records for an allowlisted confirmed fixture: $(Get-BoundedText ($listQuarantine | ConvertTo-Json -Compress -Depth 8))"
  }
  if (Test-Path -LiteralPath $quarantineRoot) {
    $payload = Get-ChildItem -LiteralPath $quarantineRoot -Recurse -File -ErrorAction Stop |
      Where-Object { $_.Name -like "*.avoraxq" } |
      Select-Object -First 1
    if ($null -ne $payload) {
      throw "release local-core created a quarantine payload for an allowlisted confirmed fixture: $($payload.FullName)"
    }
  }

  Write-Host "Avorax release local-core allowlist honored smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Engine dir: $engineRoot"
  Write-Host "Allowlist id: $($entry.entry.id)"
  Write-Host "Fixture SHA-256: $expectedSha256"
  Write-Host "Threat status: $($allowlistedThreat.status)"
  Write-Host "Quarantined files: $($scan.quarantined_files)"
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
