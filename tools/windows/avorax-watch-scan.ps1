param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string[]]$Path = @(),
  [switch]$AutoQuarantineConfirmed,
  [switch]$FailOnThreat,
  [string]$LocalCorePath = "",
  [string]$ReportPath = "",
  [string]$DataRoot = "",
  [string]$QuarantineRoot = "",
  [string]$AllowlistFile = "",
  [string]$EngineRoot = "",
  [ValidateRange(1, 10)]
  [int]$DurationSeconds = 8,
  [ValidateRange(50, 2000)]
  [int]$PollIntervalMilliseconds = 250,
  [ValidateRange(1, 32)]
  [int]$MaxEvents = 8,
  [int]$TimeoutSeconds = 30
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

function Assert-NotReparsePath {
  param([string]$PathValue, [string]$Description)
  $item = Get-Item -LiteralPath $PathValue -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $PathValue"
  }
}

function Resolve-RepoChildPath {
  param([string]$Repo, [string]$PathValue, [string]$Description)
  $rootFull = [System.IO.Path]::GetFullPath($Repo).TrimEnd('\', '/')
  $candidate = $PathValue
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $rootFull $candidate
  }
  $pathFull = [System.IO.Path]::GetFullPath($candidate)
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must be inside the repository: $pathFull"
  }
  if ($pathFull.TrimEnd('\', '/').Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must be a child file, not the repository root."
  }
  return $pathFull
}

function Resolve-LocalCoreBinary {
  param([string]$Repo, [string]$ConfiguredPath)
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Repo "target\release\zentor_local_core.exe"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release local-core binary is missing: $candidate. Run cargo build --release --manifest-path core\zentor_local_core\Cargo.toml first."
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  if ([System.IO.Path]::GetFileName($resolved) -ne "zentor_local_core.exe") {
    throw "Avorax watch scan expects zentor_local_core.exe, got: $resolved"
  }
  Assert-NotReparsePath $resolved "local-core binary"
  return $resolved
}

function Test-BroadWatchRoot {
  param([string]$PathValue)
  $full = [System.IO.Path]::GetFullPath($PathValue).TrimEnd('\', '/')
  $root = [System.IO.Path]::GetPathRoot($full).TrimEnd('\', '/')
  if ($full.Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
    return $true
  }
  $systemRoot = $env:SystemRoot
  if (-not [string]::IsNullOrWhiteSpace($systemRoot) -and
      $full.Equals([System.IO.Path]::GetFullPath($systemRoot).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    return $true
  }
  foreach ($value in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if (-not [string]::IsNullOrWhiteSpace($value) -and
        $full.Equals([System.IO.Path]::GetFullPath($value).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
      return $true
    }
  }
  return $false
}

function Resolve-WatchRoots {
  param([string[]]$RawPaths)
  if ($RawPaths.Count -lt 1) {
    throw "Avorax watch scan requires at least one explicit -Path directory."
  }
  if ($RawPaths.Count -gt 16) {
    throw "Avorax watch scan accepts at most 16 watch roots."
  }
  $resolved = @()
  foreach ($raw in $RawPaths) {
    if ([string]::IsNullOrWhiteSpace($raw)) {
      throw "Watch root path is empty."
    }
    if ($raw.Contains([char]0)) {
      throw "Watch root path contains a NUL byte."
    }
    if ($raw.Length -gt 4096) {
      throw "Watch root path exceeds 4096 characters."
    }
    if (-not (Test-Path -LiteralPath $raw -PathType Container)) {
      throw "Watch root is not an existing directory: $raw"
    }
    $full = (Resolve-Path -LiteralPath $raw).Path
    Assert-NotReparsePath $full "watch root"
    if (Test-BroadWatchRoot $full) {
      throw "Watch root is too broad for this finite user-mode wrapper: $full"
    }
    $resolved += $full
  }
  return @($resolved | Select-Object -Unique)
}

function Invoke-LocalCoreJson {
  param(
    [object]$Command,
    [string]$Repo,
    [string]$Binary,
    [int]$Timeout
  )

  $json = $Command | ConvertTo-Json -Compress
  $process = $null
  try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Binary
    $startInfo.WorkingDirectory = $Repo
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.WriteLine($json)
    $process.StandardInput.Close()

    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "Avorax watch scan timed out after ${Timeout}s and failed to stop local-core: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "Avorax watch scan timed out after ${Timeout}s."
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
      throw "local-core exited with $($process.ExitCode): $(Get-BoundedText $stderr)"
    }

    $responses = @()
    foreach ($line in ($stdout -split "`r?`n")) {
      $trimmed = $line.Trim()
      if ($trimmed.Length -eq 0) { continue }
      try {
        $body = $trimmed | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "local-core emitted non-JSON stdout during Avorax watch scan: $(Get-BoundedText $trimmed)"
      }
      if ($body.type -eq "scan_progress" -or $body.type -eq "progress") {
        continue
      }
      $responses += $body
    }
    if ($responses.Count -eq 0) {
      throw "local-core produced no JSON watch response. stderr: $(Get-BoundedText $stderr)"
    }
    $response = $responses[-1]
    if (($response.PSObject.Properties.Name -contains "ok") -and $response.ok -eq $false) {
      throw "local-core rejected Avorax watch scan command: $(Get-BoundedText $response.error)"
    }
    return [ordered]@{
      response = $response
      stderr = Get-BoundedText $stderr
    }
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function Write-JsonReportAtomic {
  param([string]$PathValue, [object]$Body)
  $directory = Split-Path -Parent $PathValue
  if (-not [string]::IsNullOrWhiteSpace($directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
  }
  $tempPath = Join-Path $directory (".tmp-" + [System.Guid]::NewGuid().ToString("N") + ".json")
  $backupPath = Join-Path $directory (".bak-" + [System.Guid]::NewGuid().ToString("N") + ".json")
  $json = $Body | ConvertTo-Json -Depth 100
  [System.IO.File]::WriteAllText($tempPath, $json + "`r`n", [System.Text.UTF8Encoding]::new($false))
  if (Test-Path -LiteralPath $PathValue -PathType Leaf) {
    [System.IO.File]::Replace($tempPath, $PathValue, $backupPath, $true)
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
      Remove-Item -LiteralPath $backupPath -Force
    }
  } else {
    [System.IO.File]::Move($tempPath, $PathValue)
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$roots = @(Resolve-WatchRoots $Path)

if ($TimeoutSeconds -lt ($DurationSeconds + 10)) {
  throw "TimeoutSeconds must be at least DurationSeconds + 10 for cleanup and report parsing."
}

$actionMode = "detectOnly"
if ($AutoQuarantineConfirmed) {
  $actionMode = "autoQuarantineConfirmedOnly"
}

$command = [ordered]@{
  command = "watch_poll_scan"
  paths = $roots
  action_mode = $actionMode
  scan_kind = "custom"
  duration_ms = [int64]($DurationSeconds * 1000)
  poll_interval_ms = [int64]$PollIntervalMilliseconds
  max_events = [int64]$MaxEvents
}

$reportFull = ""
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
  $reportFull = Resolve-RepoChildPath $repo $ReportPath "Avorax watch scan report"
}

$previousDataDir = $env:AVORAX_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  if (-not [string]::IsNullOrWhiteSpace($DataRoot)) {
    New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null
    $env:AVORAX_DATA_DIR = (Resolve-Path -LiteralPath $DataRoot).Path
  }
  if (-not [string]::IsNullOrWhiteSpace($QuarantineRoot)) {
    New-Item -ItemType Directory -Path $QuarantineRoot -Force | Out-Null
    $env:AVORAX_QUARANTINE_DIR = (Resolve-Path -LiteralPath $QuarantineRoot).Path
  }
  if (-not [string]::IsNullOrWhiteSpace($AllowlistFile)) {
    $allowlistDirectory = Split-Path -Parent $AllowlistFile
    if (-not [string]::IsNullOrWhiteSpace($allowlistDirectory)) {
      New-Item -ItemType Directory -Path $allowlistDirectory -Force | Out-Null
    }
    $env:ZENTOR_ALLOWLIST_FILE = [System.IO.Path]::GetFullPath($AllowlistFile)
  }
  if (-not [string]::IsNullOrWhiteSpace($EngineRoot)) {
    if (-not (Test-Path -LiteralPath $EngineRoot -PathType Container)) {
      throw "EngineRoot does not exist: $EngineRoot"
    }
    $env:AVORAX_ENGINE_DIR = (Resolve-Path -LiteralPath $EngineRoot).Path
  }

  $result = Invoke-LocalCoreJson $command $repo $binary $TimeoutSeconds
  $watch = $result.response
  $poll = $watch.poll
  $scanErrors = @($poll.scanErrors)
  $threatCount = if ($null -ne $poll.threatsFound) { [int64]$poll.threatsFound } else { 0 }
  $quarantineCount = if ($null -ne $poll.quarantinedFiles) { [int64]$poll.quarantinedFiles } else { 0 }

  $summary = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    tool = "avorax-watch-scan"
    repository = $repo
    local_core_path = $binary
    command = "watch_poll_scan"
    action_mode = $actionMode
    auto_quarantine_confirmed = [bool]$AutoQuarantineConfirmed
    watch_roots = $roots
    duration_seconds = $DurationSeconds
    poll_interval_ms = $PollIntervalMilliseconds
    max_events = $MaxEvents
    active = [bool]$poll.active
    mode = [string]$poll.mode
    limitations = @($poll.limitations)
    initial_files_observed = if ($null -ne $poll.initialFilesObserved) { [int64]$poll.initialFilesObserved } else { 0 }
    polls_completed = if ($null -ne $poll.pollsCompleted) { [int64]$poll.pollsCompleted } else { 0 }
    events_observed = if ($null -ne $poll.eventsObserved) { [int64]$poll.eventsObserved } else { 0 }
    files_scanned = if ($null -ne $poll.filesScanned) { [int64]$poll.filesScanned } else { 0 }
    threats_found = $threatCount
    quarantined_files = $quarantineCount
    scan_error_count = $scanErrors.Count
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      persistent_monitoring_claimed = $false
      pre_execution_blocking_claimed = $false
      kernel_driver_required = $false
      broad_default_watch_roots_allowed = $false
    }
    raw_watch_report = $watch
  }

  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-JsonReportAtomic $reportFull $summary
  }

  Write-Host "Avorax watch scan completed."
  Write-Host "Action mode: $actionMode"
  Write-Host "Mode: $($summary.mode)"
  Write-Host "Duration seconds: $DurationSeconds"
  Write-Host "Watch roots: $($roots.Count)"
  Write-Host "Events observed: $($summary.events_observed)"
  Write-Host "Files scanned: $($summary.files_scanned)"
  Write-Host "Threats found: $($summary.threats_found)"
  Write-Host "Quarantined files: $($summary.quarantined_files)"
  if ($summary.scan_error_count -gt 0) {
    Write-Host "Scan errors: $($summary.scan_error_count)"
  }
  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-Host "Report: $reportFull"
  }
  if ($FailOnThreat -and $threatCount -gt 0) {
    throw "Avorax watch scan found $threatCount threat(s)."
  }
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "AVORAX_QUARANTINE_DIR" $previousQuarantineDir
  Restore-EnvVar "ZENTOR_ALLOWLIST_FILE" $previousAllowlistFile
  Restore-EnvVar "AVORAX_ENGINE_DIR" $previousEngineDir
}
