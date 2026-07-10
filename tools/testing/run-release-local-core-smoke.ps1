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
    throw "Release local-core smoke expects zentor_local_core.exe, got: $resolved"
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
        throw "release local-core emitted non-JSON stdout during smoke test: $(Get-BoundedText $trimmed)"
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

function Write-ReleaseSmokeSignaturePack {
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
    id = "ZNE-SAFE-RELEASE-SMOKE-001"
    name = "Release smoke harmless known-bad hash fixture"
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
    created_at = "2026-07-06T00:00:00Z"
    updated_at = "2026-07-06T00:00:00Z"
  }
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-06T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-RELEASE-SMOKE-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Release smoke harmless known-bad hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-06T00:00:00Z","version":"1"}],"version":"1.0.0"}'
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

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$detectFixture = Join-Path $tempRoot "safe-release-detect.bin"
$quarantineFixture = Join-Path $tempRoot "safe-release-quarantine.bin"
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
  [System.IO.File]::WriteAllBytes($detectFixture, $fixtureBytes)
  [System.IO.File]::WriteAllBytes($quarantineFixture, $fixtureBytes)
  Write-ReleaseSmokeSignaturePack $engineRoot (Get-Sha256Hex $fixtureBytes)
  $expectedContent = [System.IO.File]::ReadAllText($quarantineFixture, [System.Text.Encoding]::ASCII)

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_ENGINE_DIR = $engineRoot

  $detect = Invoke-LocalCoreBinaryJson @{
    command = "scan_file"
    path = $detectFixture
    action_mode = "detectOnly"
    scan_kind = "custom"
  } $inputJson $repo $binary $TimeoutSeconds

  $detectThreats = @($detect.threats)
  $confirmedDetectThreat = $detectThreats | Where-Object {
    $_.confidence -eq "confirmed" -or $_.reason_summary -like "*signature*"
  } | Select-Object -First 1
  if ($detect.status -ne "threatsFound") {
    throw "release local-core detect-only scan did not return a threat status: $(Get-BoundedText ($detect | ConvertTo-Json -Compress))"
  }
  if ($null -eq $confirmedDetectThreat) {
    throw "release local-core detect-only scan did not include a confirmed simulator threat: $(Get-BoundedText ($detect | ConvertTo-Json -Compress))"
  }
  $detectQuarantinedFiles = if ($null -ne $detect.quarantined_files) { [int]$detect.quarantined_files } else { 0 }
  if ($detectQuarantinedFiles -ne 0) {
    throw "release local-core detect-only scan unexpectedly quarantined files: $(Get-BoundedText ($detect | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $detectFixture -PathType Leaf)) {
    throw "release local-core detect-only scan removed the simulator fixture"
  }

  $scan = Invoke-LocalCoreBinaryJson @{
    command = "scan_file"
    path = $quarantineFixture
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "custom"
  } $inputJson $repo $binary $TimeoutSeconds

  $threats = @($scan.threats)
  $quarantinedThreat = $threats | Where-Object {
    $_.status -eq "quarantined" -and
    ($_.confidence -eq "confirmed" -or $_.reason_summary -like "*signature*")
  } | Select-Object -First 1
  if ($scan.status -ne "threatsFound") {
    throw "release local-core quarantine scan did not return a threat status: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($null -eq $quarantinedThreat) {
    throw "release local-core quarantine scan did not quarantine a confirmed simulator threat: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ([string]::IsNullOrWhiteSpace([string]$quarantinedThreat.quarantine_id)) {
    throw "release local-core quarantine scan did not include quarantine_id: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ([string]::IsNullOrWhiteSpace([string]$quarantinedThreat.quarantine_path) -or -not ([string]$quarantinedThreat.quarantine_path).EndsWith(".avoraxq")) {
    throw "release local-core quarantine scan did not include a safe .avoraxq quarantine_path: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if (Test-Path -LiteralPath $quarantineFixture) {
    throw "release local-core quarantine scan left the source fixture in place after auto-quarantine"
  }

  $list = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $inputJson $repo $binary $TimeoutSeconds
  if ($list.ok -ne $true) {
    throw "release local-core list_quarantine failed: $(Get-BoundedText ($list | ConvertTo-Json -Compress))"
  }
  $record = @($list.records) | Where-Object {
    $_.quarantine_id -eq $quarantinedThreat.quarantine_id -and
    $_.original_path -eq $quarantineFixture -and
    $_.status -eq "quarantined" -and
    $_.action_taken -eq "quarantined" -and
    $_.quarantine_path -like "*.avoraxq"
  } | Select-Object -First 1
  if ($null -eq $record) {
    throw "release local-core did not list the quarantined simulator record: $(Get-BoundedText ($list | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $record.quarantine_path -PathType Leaf)) {
    throw "release local-core quarantine payload is missing: $($record.quarantine_path)"
  }

  $restore = Invoke-LocalCoreBinaryJson @{
    command = "restore_quarantine_item"
    quarantine_id = $record.quarantine_id
    confirmed = $true
  } $inputJson $repo $binary $TimeoutSeconds
  if ($restore.ok -ne $true -or $restore.record.status -ne "restored" -or $restore.record.action_taken -ne "restored") {
    throw "release local-core restore failed: $(Get-BoundedText ($restore | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $quarantineFixture -PathType Leaf)) {
    throw "release local-core did not restore the original fixture path"
  }
  $restoredContent = [System.IO.File]::ReadAllText($quarantineFixture, [System.Text.Encoding]::ASCII)
  if ($restoredContent -ne $expectedContent) {
    throw "release local-core restored content does not match the original simulator"
  }
  if (Test-Path -LiteralPath $record.quarantine_path) {
    throw "release local-core left the quarantined payload after restore"
  }

  Write-Host "Avorax release local-core safe hash fixture smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Engine dir: $engineRoot"
  Write-Host "Detect-only status: $($detect.status)"
  Write-Host "Detect-only threats: $($detectThreats.Count)"
  Write-Host "Quarantine status: $($scan.status)"
  Write-Host "Quarantine id: $($record.quarantine_id)"
  Write-Host "Restore status: $($restore.record.status)"
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
