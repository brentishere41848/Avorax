param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [ValidateSet("Quick", "Full", "File", "Folder")]
  [string]$ScanType = "Quick",
  [string[]]$Path = @(),
  [switch]$AutoQuarantineConfirmed,
  [switch]$FailOnThreat,
  [string]$LocalCorePath = "",
  [string]$ReportPath = "",
  [string]$DataRoot = "",
  [string]$QuarantineRoot = "",
  [string]$AllowlistFile = "",
  [string]$EngineRoot = "",
  [int]$TimeoutSeconds = 600
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
    throw "Avorax local scan expects zentor_local_core.exe, got: $resolved"
  }
  Assert-NotReparsePath $resolved "local-core binary"
  return $resolved
}

function Resolve-ScanTargets {
  param([string]$ScanTypeValue, [string[]]$RawPaths)
  if ($RawPaths.Count -gt 64) {
    throw "Avorax local scan accepts at most 64 target paths."
  }
  if (($ScanTypeValue -eq "File" -or $ScanTypeValue -eq "Folder") -and $RawPaths.Count -ne 1) {
    throw "$ScanTypeValue scan requires exactly one -Path value."
  }
  $resolved = @()
  foreach ($raw in $RawPaths) {
    if ([string]::IsNullOrWhiteSpace($raw)) {
      throw "Scan target path is empty."
    }
    if ($raw.Contains([char]0)) {
      throw "Scan target path contains a NUL byte."
    }
    if ($raw.Length -gt 4096) {
      throw "Scan target path exceeds 4096 characters."
    }
    if (-not (Test-Path -LiteralPath $raw)) {
      throw "Scan target does not exist: $raw"
    }
    $full = (Resolve-Path -LiteralPath $raw).Path
    Assert-NotReparsePath $full "scan target"
    if ($ScanTypeValue -eq "File" -and -not (Test-Path -LiteralPath $full -PathType Leaf)) {
      throw "File scan target is not a file: $full"
    }
    if ($ScanTypeValue -eq "Folder" -and -not (Test-Path -LiteralPath $full -PathType Container)) {
      throw "Folder scan target is not a directory: $full"
    }
    $resolved += $full
  }
  return $resolved
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
        throw "Avorax local scan timed out after ${Timeout}s and failed to stop local-core: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "Avorax local scan timed out after ${Timeout}s."
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
      throw "local-core exited with $($process.ExitCode): $(Get-BoundedText $stderr)"
    }

    $progressCount = 0
    $responses = @()
    foreach ($line in ($stdout -split "`r?`n")) {
      $trimmed = $line.Trim()
      if ($trimmed.Length -eq 0) { continue }
      try {
        $body = $trimmed | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "local-core emitted non-JSON stdout during Avorax local scan: $(Get-BoundedText $trimmed)"
      }
      if ($body.type -eq "scan_progress" -or $body.type -eq "progress") {
        $progressCount += 1
        continue
      }
      $responses += $body
    }
    if ($responses.Count -eq 0) {
      throw "local-core produced no JSON scan response. stderr: $(Get-BoundedText $stderr)"
    }
    $response = $responses[-1]
    if (($response.PSObject.Properties.Name -contains "ok") -and $response.ok -eq $false) {
      throw "local-core rejected Avorax local scan command: $(Get-BoundedText $response.error)"
    }
    return [ordered]@{
      response = $response
      progress_events = $progressCount
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
$targets = @(Resolve-ScanTargets $ScanType $Path)

if ($AutoQuarantineConfirmed -and $targets.Count -eq 0) {
  throw "Auto-quarantine from this wrapper requires explicit -Path targets. Re-run detect-only for default Quick/Full roots, or pass one or more explicit paths."
}

$actionMode = "detectOnly"
if ($AutoQuarantineConfirmed) {
  $actionMode = "autoQuarantineConfirmedOnly"
}

$commandName = "quick_scan_selected_paths"
$scanKind = "quick"
if ($ScanType -eq "Full") {
  $commandName = "full_scan"
  $scanKind = "full"
} elseif ($ScanType -eq "File") {
  $commandName = "scan_file"
  $scanKind = "custom"
} elseif ($ScanType -eq "Folder") {
  $commandName = "scan_folder"
  $scanKind = "custom"
}

$command = [ordered]@{
  command = $commandName
  action_mode = $actionMode
  scan_kind = $scanKind
}
if ($ScanType -eq "File" -or $ScanType -eq "Folder") {
  $command.path = $targets[0]
} elseif ($targets.Count -gt 0) {
  $command.paths = $targets
}

$reportFull = ""
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
  $reportFull = Resolve-RepoChildPath $repo $ReportPath "Avorax local scan report"
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
  $scan = $result.response
  $threatCount = if ($null -ne $scan.threats_found) { [int64]$scan.threats_found } else { @($scan.threats).Count }
  $quarantineCount = if ($null -ne $scan.quarantined_files) { [int64]$scan.quarantined_files } else { 0 }
  $scanErrors = @($scan.scan_errors)

  $summary = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    tool = "avorax-local-scan"
    repository = $repo
    local_core_path = $binary
    scan_type = $ScanType
    command = $commandName
    scan_kind = $scanKind
    action_mode = $actionMode
    auto_quarantine_confirmed = [bool]$AutoQuarantineConfirmed
    requested_paths = $targets
    progress_events = [int]$result.progress_events
    status = [string]$scan.status
    files_scanned = if ($null -ne $scan.files_scanned) { [int64]$scan.files_scanned } else { 0 }
    skipped_files = if ($null -ne $scan.skipped_files) { [int64]$scan.skipped_files } else { 0 }
    threats_found = $threatCount
    suspicious_found = if ($null -ne $scan.suspicious_found) { [int64]$scan.suspicious_found } else { 0 }
    quarantined_files = $quarantineCount
    scan_error_count = $scanErrors.Count
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      pre_execution_blocking_claimed = $false
      default_root_auto_quarantine_allowed = $false
    }
    raw_scan_report = $scan
  }

  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-JsonReportAtomic $reportFull $summary
  }

  Write-Host "Avorax local scan completed."
  Write-Host "Scan type: $ScanType"
  Write-Host "Action mode: $actionMode"
  Write-Host "Status: $($summary.status)"
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
    throw "Avorax local scan found $threatCount threat(s)."
  }
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "AVORAX_QUARANTINE_DIR" $previousQuarantineDir
  Restore-EnvVar "ZENTOR_ALLOWLIST_FILE" $previousAllowlistFile
  Restore-EnvVar "AVORAX_ENGINE_DIR" $previousEngineDir
}
