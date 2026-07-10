param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [switch]$RequireReady,
  [string]$LocalCorePath = "",
  [string]$ReportPath = "",
  [string]$EngineRoot = "",
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
    throw "Avorax status expects zentor_local_core.exe, got: $resolved"
  }
  Assert-NotReparsePath $resolved "local-core binary"
  return $resolved
}

function Resolve-OptionalEngineRoot {
  param([string]$PathValue)
  if ([string]::IsNullOrWhiteSpace($PathValue)) { return "" }
  if ($PathValue.Contains([char]0)) {
    throw "EngineRoot contains a NUL byte."
  }
  if ($PathValue.Length -gt 4096) {
    throw "EngineRoot exceeds 4096 characters."
  }
  if ($PathValue -replace '/', '\' -match '(^|\\)\.\.(\\|$)') {
    throw "EngineRoot must not contain parent traversal."
  }
  if (-not (Test-Path -LiteralPath $PathValue -PathType Container)) {
    throw "EngineRoot does not exist: $PathValue"
  }
  $resolved = (Resolve-Path -LiteralPath $PathValue).Path
  Assert-NotReparsePath $resolved "EngineRoot"
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
        throw "Avorax status timed out after ${Timeout}s and failed to stop local-core: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "Avorax status timed out after ${Timeout}s."
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
        throw "local-core emitted non-JSON stdout during Avorax status: $(Get-BoundedText $trimmed)"
      }
      if ($body.type -eq "scan_progress" -or $body.type -eq "progress") {
        continue
      }
      $responses += $body
    }
    if ($responses.Count -eq 0) {
      throw "local-core produced no JSON health response. stderr: $(Get-BoundedText $stderr)"
    }
    $response = $responses[-1]
    if (($response.PSObject.Properties.Name -contains "ok") -and $response.ok -eq $false) {
      throw "local-core rejected Avorax status command: $(Get-BoundedText $response.error)"
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

function Get-HealthState {
  param([object]$Health)
  $engineAvailable = [string]$Health.engine_status -eq "available" -and [string]$Health.native_engine_status -eq "ready"
  if (-not $engineAvailable) {
    return "unavailable"
  }
  if ($Health.native_self_test -eq $true -and [int64]$Health.native_signature_count -gt 0) {
    return "ready"
  }
  return "degraded"
}

function Get-HealthBlockers {
  param([object]$Health)
  $blockers = @()
  if ([string]$Health.engine_status -ne "available") {
    $blockers += "engine_status=$($Health.engine_status)"
  }
  if ([string]$Health.native_engine_status -ne "ready") {
    $blockers += "native_engine_status=$($Health.native_engine_status)"
  }
  if ($Health.native_self_test -ne $true) {
    $blockers += "native_self_test=false: $(Get-BoundedText $Health.native_self_test_error)"
  }
  if ([int64]$Health.native_signature_count -le 0) {
    $blockers += "native_signature_count=0"
  }
  return @($blockers)
}

function Assert-HealthShape {
  param([object]$Health)
  foreach ($field in @(
    "engine_status",
    "native_engine_status",
    "native_signature_count",
    "native_rule_count",
    "native_self_test",
    "core_service_status",
    "guard_status",
    "driver_status",
    "process_monitor_status",
    "behavior_monitor_status",
    "reputation_status",
    "ipc",
    "network_exposed",
    "install_path",
    "engine_directory"
  )) {
    if ($Health.PSObject.Properties.Name -notcontains $field) {
      throw "local-core health response is missing required field: $field"
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$engineRootFull = Resolve-OptionalEngineRoot $EngineRoot
$reportFull = ""
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
  $reportFull = Resolve-RepoChildPath $repo $ReportPath "Avorax status report"
}

$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  if (-not [string]::IsNullOrWhiteSpace($engineRootFull)) {
    $env:AVORAX_ENGINE_DIR = $engineRootFull
  }

  $result = Invoke-LocalCoreJson ([ordered]@{ command = "health" }) $repo $binary $TimeoutSeconds
  $health = $result.response
  Assert-HealthShape $health
  $healthState = Get-HealthState $health
  $blockers = @(Get-HealthBlockers $health)

  $summary = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    tool = "avorax-status"
    repository = $repo
    local_core_path = $binary
    command = "health"
    require_ready = [bool]$RequireReady
    health_state = $healthState
    ready = $healthState -eq "ready"
    blockers = $blockers
    engine_status = [string]$health.engine_status
    native_engine_status = [string]$health.native_engine_status
    native_signature_count = [int64]$health.native_signature_count
    native_rule_count = [int64]$health.native_rule_count
    native_self_test = [bool]$health.native_self_test
    native_self_test_error = Get-BoundedText $health.native_self_test_error
    core_service_status = [string]$health.core_service_status
    core_service_status_error = Get-BoundedText $health.core_service_status_error
    guard_status = [string]$health.guard_status
    guard_status_error = Get-BoundedText $health.guard_status_error
    driver_status = [string]$health.driver_status
    process_monitor_status = [string]$health.process_monitor_status
    process_monitor_capability = [string]$health.process_monitor_capability
    behavior_monitor_status = [string]$health.behavior_monitor_status
    reputation_status = [string]$health.reputation_status
    ipc = [string]$health.ipc
    network_exposed = [bool]$health.network_exposed
    install_path = [string]$health.install_path
    engine_directory = [string]$health.engine_directory
    requested_engine_root = $engineRootFull
    limitations = @(
      "Status is reported by local-core over stdio.",
      "Missing core/guard service or driver status means user-mode operation only.",
      "Pre-execution blocking is not claimed by this wrapper.",
      "Use -RequireReady to make degraded or unavailable health fail visibly."
    )
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      pre_execution_blocking_claimed = $false
      persistent_monitoring_claimed = $false
      kernel_driver_claimed = $false
      network_content_trusted = $false
    }
    raw_health = $health
  }

  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-JsonReportAtomic $reportFull $summary
  }

  Write-Host "Avorax status completed."
  Write-Host "Health state: $($summary.health_state)"
  Write-Host "Engine: $($summary.engine_status) / $($summary.native_engine_status)"
  Write-Host "Signatures: $($summary.native_signature_count)"
  Write-Host "Rules: $($summary.native_rule_count)"
  Write-Host "Native self-test: $($summary.native_self_test)"
  Write-Host "Core service: $($summary.core_service_status)"
  Write-Host "Guard: $($summary.guard_status)"
  Write-Host "Driver: $($summary.driver_status)"
  if ($blockers.Count -gt 0) {
    Write-Host "Blockers: $($blockers -join '; ')"
  }
  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-Host "Report: $reportFull"
  }
  if ($RequireReady -and $summary.ready -ne $true) {
    throw "Avorax status is not ready: $healthState; blockers: $($blockers -join '; ')"
  }
} finally {
  Restore-EnvVar "AVORAX_ENGINE_DIR" $previousEngineDir
}
