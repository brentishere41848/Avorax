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
    throw "Release local-core watch-poll scan smoke expects zentor_local_core.exe, got: $resolved"
  }
  return $resolved
}

function Invoke-LocalCoreBinaryJson {
  param(
    [hashtable]$Command,
    [string]$InputJsonPath,
    [string]$Repo,
    [string]$Binary,
    [int]$Timeout,
    [AllowNull()][scriptblock]$DuringRun = $null
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

    if ($null -ne $DuringRun) {
      & $DuringRun $process
    }

    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "release local-core watch-poll scan smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core watch-poll scan smoke timed out after ${Timeout}s."
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
        throw "release local-core emitted non-JSON stdout during watch-poll scan smoke: $(Get-BoundedText $trimmed)"
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

function Write-WatchPollSignaturePack {
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
    id = "ZNE-SAFE-RELEASE-WATCH-POLL-001"
    name = "Release watch-poll harmless known-bad hash fixture"
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
  $canonicalJson = '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1","signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat","confidence":"confirmed","created_at":"2026-07-07T00:00:00Z","false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.","file_types":["*"],"id":"ZNE-SAFE-RELEASE-WATCH-POLL-001","mask":null,"max_file_size":null,"min_file_size":null,"name":"Release watch-poll harmless known-bad hash fixture","offset":null,"pattern":"' + $FixtureSha256 + '","required_context":[],"severity":"test","signature_type":"exact_hash","updated_at":"2026-07-07T00:00:00Z","version":"1"}],"version":"1.0.0"}'
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

function Assert-ListContains {
  param(
    [object[]]$Values,
    [string]$Expected,
    [string]$Label
  )
  if (-not ($Values | Where-Object { $_ -eq $Expected })) {
    throw "$Label did not include '$Expected': $(Get-BoundedText ($Values | ConvertTo-Json -Compress -Depth 8))"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-watch-poll-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$watchRoot = Join-Path $tempRoot "watch-root"
$fixturePath = Join-Path $watchRoot "created-during-watch.bin"
$inputJson = Join-Path $tempRoot "local-core-command.json"

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $watchRoot -Force | Out-Null

  $fixtureBytes = [System.Text.Encoding]::ASCII.GetBytes("harmless-watch-poll-known-bad-fixture")
  Write-WatchPollSignaturePack $engineRoot (Get-Sha256Hex $fixtureBytes)

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_ENGINE_DIR = $engineRoot

  $watch = Invoke-LocalCoreBinaryJson -Command @{
    command = "watch_poll_scan"
    paths = @($watchRoot)
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "custom"
    duration_ms = 4000
    poll_interval_ms = 200
    max_events = 4
  } -InputJsonPath $inputJson -Repo $repo -Binary $binary -Timeout $TimeoutSeconds -DuringRun {
    param($Process)
    Start-Sleep -Milliseconds 650
    if ($Process.HasExited) {
      throw "release local-core watch-poll process exited before fixture creation."
    }
    [System.IO.File]::WriteAllBytes($fixturePath, $fixtureBytes)
  }

  if ($watch.ok -ne $true) {
    throw "release local-core watch_poll_scan failed: $(Get-BoundedText ($watch | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($watch.watcher.active -ne $true -or $watch.watcher.mode -ne "userModeBestEffort") {
    throw "watch_poll_scan did not report an active best-effort watcher plan: $(Get-BoundedText ($watch | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($watch.poll.active -ne $true -or $watch.poll.mode -ne "finiteUserModePolling") {
    throw "watch_poll_scan did not report finite user-mode polling: $(Get-BoundedText ($watch | ConvertTo-Json -Compress -Depth 8))"
  }
  foreach ($limitation in @(
      "finite-polling-session-only",
      "post-write-detection-only",
      "bounded-polling-limits",
      "no-persistent-service-monitor",
      "no-kernel-pre-execution-blocking"
    )) {
    Assert-ListContains @($watch.poll.limitations) $limitation "watch_poll_scan poll limitations"
  }

  if ([int]$watch.poll.eventsObserved -lt 1 -or [int]$watch.poll.filesScanned -lt 1) {
    throw "watch_poll_scan did not observe and scan the created fixture: $(Get-BoundedText ($watch | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([int]$watch.poll.threatsFound -lt 1 -or [int]$watch.poll.quarantinedFiles -lt 1) {
    throw "watch_poll_scan did not quarantine the confirmed safe exact-hash fixture: $(Get-BoundedText ($watch | ConvertTo-Json -Compress -Depth 8))"
  }
  $event = @($watch.poll.events) | Where-Object {
    $_.path -eq $fixturePath -and
    $_.scanStatus -eq "threatsFound" -and
    [int]$_.threatsFound -ge 1 -and
    [int]$_.quarantinedFiles -ge 1
  } | Select-Object -First 1
  if ($null -eq $event) {
    throw "watch_poll_scan event did not identify the created fixture threat/quarantine: $(Get-BoundedText ($watch | ConvertTo-Json -Compress -Depth 8))"
  }
  if (Test-Path -LiteralPath $fixturePath) {
    throw "watch_poll_scan left the confirmed fixture in the watched folder after quarantine."
  }

  $list = Invoke-LocalCoreBinaryJson -Command @{ command = "list_quarantine" } -InputJsonPath $inputJson -Repo $repo -Binary $binary -Timeout $TimeoutSeconds
  if ($list.ok -ne $true) {
    throw "release local-core list_quarantine failed after watch_poll_scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }
  $record = @($list.records) | Where-Object {
    $_.original_path -eq $fixturePath -and
    $_.status -eq "quarantined" -and
    $_.action_taken -eq "quarantined" -and
    $_.quarantine_path -like "*.avoraxq"
  } | Select-Object -First 1
  if ($null -eq $record) {
    throw "watch_poll_scan did not create a quarantine record for the created fixture: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }
  if (-not (Test-Path -LiteralPath $record.quarantine_path -PathType Leaf)) {
    throw "watch_poll_scan quarantine payload is missing: $($record.quarantine_path)"
  }

  Write-Host "Avorax release local-core watch-poll scan smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Watch root: $watchRoot"
  Write-Host "Poll mode: $($watch.poll.mode)"
  Write-Host "Poll events observed: $($watch.poll.eventsObserved)"
  Write-Host "Poll files scanned: $($watch.poll.filesScanned)"
  Write-Host "Poll threats found: $($watch.poll.threatsFound)"
  Write-Host "Poll quarantined files: $($watch.poll.quarantinedFiles)"
  Write-Host "Quarantine id: $($record.quarantine_id)"
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
