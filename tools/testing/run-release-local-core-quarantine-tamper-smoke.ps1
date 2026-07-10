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
    throw "Release local-core quarantine tamper smoke expects zentor_local_core.exe, got: $resolved"
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
        throw "release local-core emitted non-JSON stdout during quarantine tamper smoke: $(Get-BoundedText $trimmed)"
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
    id = "ZNE-SAFE-RELEASE-QUARANTINE-TAMPER-001"
    name = "Release quarantine tamper harmless known-bad hash fixture"
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
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-06T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-RELEASE-QUARANTINE-TAMPER-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Release quarantine tamper harmless known-bad hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-06T00:00:00Z","version":"1"}],"version":"1.0.0"}'
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
  [System.IO.File]::WriteAllText(
    (Join-Path $signaturesDir "avorax_core.asig"),
    ($pack | ConvertTo-Json -Depth 8) + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )
}

function New-QuarantineTamperScenario {
  param([string]$Name)

  $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-quarantine-tamper-$Name-" + [System.Guid]::NewGuid().ToString("N"))
  $dataRoot = Join-Path $tempRoot "data"
  $legacyRoot = Join-Path $tempRoot "legacy-data"
  $quarantineRoot = Join-Path $tempRoot "quarantine"
  $engineRoot = Join-Path $tempRoot "engine"
  $allowlistFile = Join-Path $tempRoot "allowlist.json"
  $fixture = Join-Path $tempRoot "safe-release-quarantine-tamper-$Name.bin"
  $inputJson = Join-Path $tempRoot "local-core-command.json"

  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null
  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-known-bad-fixture")
  [System.IO.File]::WriteAllBytes($fixture, $fixtureBytes)
  Write-ReleaseSmokeSignaturePack $engineRoot (Get-Sha256Hex $fixtureBytes)

  return [ordered]@{
    Name = $Name
    TempRoot = $tempRoot
    DataRoot = $dataRoot
    LegacyRoot = $legacyRoot
    QuarantineRoot = $quarantineRoot
    EngineRoot = $engineRoot
    AllowlistFile = $allowlistFile
    Fixture = $fixture
    InputJson = $inputJson
  }
}

function Set-ScenarioEnvironment {
  param([object]$Scenario)

  $env:AVORAX_DATA_DIR = $Scenario.DataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $Scenario.LegacyRoot
  $env:AVORAX_QUARANTINE_DIR = $Scenario.QuarantineRoot
  $env:ZENTOR_ALLOWLIST_FILE = $Scenario.AllowlistFile
  $env:AVORAX_ENGINE_DIR = $Scenario.EngineRoot
}

function Invoke-QuarantineFixture {
  param(
    [object]$Scenario,
    [string]$Repo,
    [string]$Binary,
    [int]$Timeout
  )

  $scan = Invoke-LocalCoreBinaryJson @{
    command = "scan_file"
    path = $Scenario.Fixture
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "custom"
  } $Scenario.InputJson $Repo $Binary $Timeout

  $threats = @($scan.threats)
  $quarantinedThreat = $threats | Where-Object {
    $_.status -eq "quarantined" -and
    ($_.confidence -eq "confirmed" -or $_.reason_summary -like "*signature*")
  } | Select-Object -First 1
  if ($scan.status -ne "threatsFound") {
    throw "release local-core quarantine tamper setup did not find a threat for $($Scenario.Name): $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($scan.files_scanned -ne 1 -or $scan.threats_found -ne 1 -or $scan.quarantined_files -ne 1) {
    throw "release local-core quarantine tamper setup counters were unexpected for $($Scenario.Name): $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($null -eq $quarantinedThreat -or [string]::IsNullOrWhiteSpace([string]$quarantinedThreat.quarantine_id)) {
    throw "release local-core quarantine tamper setup did not return a quarantined confirmed threat for $($Scenario.Name): $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if (Test-Path -LiteralPath $Scenario.Fixture) {
    throw "release local-core quarantine tamper setup left the source fixture in place for $($Scenario.Name)"
  }

  $list = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $Scenario.InputJson $Repo $Binary $Timeout
  if ($list.ok -ne $true) {
    throw "release local-core list_quarantine failed during tamper setup for $($Scenario.Name): $(Get-BoundedText ($list | ConvertTo-Json -Compress))"
  }
  $record = @($list.records) | Where-Object {
    $_.quarantine_id -eq $quarantinedThreat.quarantine_id -and
    $_.status -eq "quarantined" -and
    $_.action_taken -eq "quarantined" -and
    $_.quarantine_path -like "*.avoraxq"
  } | Select-Object -First 1
  if ($null -eq $record) {
    throw "release local-core did not list the quarantined tamper fixture for $($Scenario.Name): $(Get-BoundedText ($list | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $record.quarantine_path -PathType Leaf)) {
    throw "release local-core quarantine tamper payload is missing for $($Scenario.Name): $($record.quarantine_path)"
  }

  return $record
}

function Assert-FailedAction {
  param(
    [object]$Response,
    [string]$ExpectedDiagnostic,
    [string]$Label
  )

  if ($Response.ok -ne $false) {
    throw "$Label unexpectedly succeeded: $(Get-BoundedText ($Response | ConvertTo-Json -Compress))"
  }
  if ([string]$Response.error -notlike "*$ExpectedDiagnostic*") {
    throw "$Label did not expose expected diagnostic '$ExpectedDiagnostic': $(Get-BoundedText ($Response | ConvertTo-Json -Compress))"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousEngineDir = $env:AVORAX_ENGINE_DIR
$tempRoots = New-Object System.Collections.Generic.List[string]

try {
  $metadataScenario = New-QuarantineTamperScenario "metadata-auth"
  $tempRoots.Add($metadataScenario.TempRoot) | Out-Null
  Set-ScenarioEnvironment $metadataScenario
  $metadataRecord = Invoke-QuarantineFixture $metadataScenario $repo $binary $TimeoutSeconds
  $metadataRecordPath = Join-Path $metadataScenario.QuarantineRoot "$($metadataRecord.quarantine_id).json"
  $metadataAuthPath = "$metadataRecordPath.auth"
  if (-not (Test-Path -LiteralPath $metadataRecordPath -PathType Leaf)) {
    throw "release local-core metadata tamper scenario did not write a quarantine metadata record"
  }
  if (-not (Test-Path -LiteralPath $metadataAuthPath -PathType Leaf)) {
    throw "release local-core metadata tamper scenario did not write a quarantine metadata auth sidecar"
  }
  $tamperedMetadata = Get-Content -LiteralPath $metadataRecordPath -Raw | ConvertFrom-Json
  $tamperedMetadata.engine = "tampered-engine"
  [System.IO.File]::WriteAllText(
    $metadataRecordPath,
    ($tamperedMetadata | ConvertTo-Json -Depth 8) + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $metadataList = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $metadataScenario.InputJson $repo $binary $TimeoutSeconds
  Assert-FailedAction $metadataList "quarantine metadata authentication failed" "tampered metadata list_quarantine"
  $metadataRestore = Invoke-LocalCoreBinaryJson @{
    command = "restore_quarantine_item"
    quarantine_id = $metadataRecord.quarantine_id
    confirmed = $true
  } $metadataScenario.InputJson $repo $binary $TimeoutSeconds
  Assert-FailedAction $metadataRestore "quarantine metadata authentication failed" "tampered metadata restore_quarantine_item"
  $metadataDelete = Invoke-LocalCoreBinaryJson @{
    command = "delete_quarantine_item"
    quarantine_id = $metadataRecord.quarantine_id
    confirmed = $true
  } $metadataScenario.InputJson $repo $binary $TimeoutSeconds
  Assert-FailedAction $metadataDelete "quarantine metadata authentication failed" "tampered metadata delete_quarantine_item"
  if (Test-Path -LiteralPath $metadataScenario.Fixture) {
    throw "tampered metadata restore unexpectedly recreated the source fixture"
  }
  if (-not (Test-Path -LiteralPath $metadataRecord.quarantine_path -PathType Leaf)) {
    throw "tampered metadata action unexpectedly removed the quarantined payload"
  }

  $payloadScenario = New-QuarantineTamperScenario "payload-hash"
  $tempRoots.Add($payloadScenario.TempRoot) | Out-Null
  Set-ScenarioEnvironment $payloadScenario
  $payloadRecord = Invoke-QuarantineFixture $payloadScenario $repo $binary $TimeoutSeconds
  [System.IO.File]::WriteAllText(
    $payloadRecord.quarantine_path,
    "tampered-known-bad-fixture",
    [System.Text.Encoding]::ASCII
  )

  $payloadList = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $payloadScenario.InputJson $repo $binary $TimeoutSeconds
  if ($payloadList.ok -ne $true) {
    throw "payload tamper list_quarantine should still list authenticated metadata: $(Get-BoundedText ($payloadList | ConvertTo-Json -Compress))"
  }
  $payloadRestore = Invoke-LocalCoreBinaryJson @{
    command = "restore_quarantine_item"
    quarantine_id = $payloadRecord.quarantine_id
    confirmed = $true
  } $payloadScenario.InputJson $repo $binary $TimeoutSeconds
  Assert-FailedAction $payloadRestore "quarantine payload hash mismatch" "tampered payload restore_quarantine_item"
  $payloadDelete = Invoke-LocalCoreBinaryJson @{
    command = "delete_quarantine_item"
    quarantine_id = $payloadRecord.quarantine_id
    confirmed = $true
  } $payloadScenario.InputJson $repo $binary $TimeoutSeconds
  Assert-FailedAction $payloadDelete "quarantine payload hash mismatch" "tampered payload delete_quarantine_item"
  if (Test-Path -LiteralPath $payloadScenario.Fixture) {
    throw "tampered payload restore unexpectedly recreated the source fixture"
  }
  if (-not (Test-Path -LiteralPath $payloadRecord.quarantine_path -PathType Leaf)) {
    throw "tampered payload action unexpectedly removed the quarantined payload"
  }

  Write-Host "Avorax release local-core quarantine tamper smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Metadata scenario diagnostic: $($metadataList.error)"
  Write-Host "Payload scenario restore diagnostic: $($payloadRestore.error)"
  Write-Host "Payload scenario delete diagnostic: $($payloadDelete.error)"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "ZENTOR_LEGACY_DATA_DIR" $previousLegacyDataDir
  Restore-EnvVar "AVORAX_QUARANTINE_DIR" $previousQuarantineDir
  Restore-EnvVar "ZENTOR_ALLOWLIST_FILE" $previousAllowlistFile
  Restore-EnvVar "AVORAX_ENGINE_DIR" $previousEngineDir
  foreach ($tempRoot in $tempRoots) {
    if (Test-Path -LiteralPath $tempRoot) {
      Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
    }
  }
}
