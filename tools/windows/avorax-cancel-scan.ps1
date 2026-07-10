param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [string]$ReportPath = "",
  [string]$DataRoot = "",
  [switch]$UseInstalledDataRoot,
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
    throw "Avorax cancel scan expects zentor_local_core.exe, got: $resolved"
  }
  Assert-NotReparsePath $resolved "local-core binary"
  return $resolved
}

function Resolve-IsolatedDataRoot {
  param([string]$PathValue)
  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    return ""
  }
  if ($PathValue.Contains([char]0)) {
    throw "DataRoot contains a NUL byte."
  }
  if ($PathValue.Length -gt 4096) {
    throw "DataRoot exceeds 4096 characters."
  }
  if ($PathValue -replace '/', '\' -match '(^|\\)\.\.(\\|$)') {
    throw "DataRoot must not contain parent traversal."
  }
  New-Item -ItemType Directory -Path $PathValue -Force | Out-Null
  $resolved = (Resolve-Path -LiteralPath $PathValue).Path
  Assert-NotReparsePath $resolved "DataRoot"
  return $resolved
}

function Test-PathUnderRoot {
  param([string]$PathValue, [string]$RootValue)
  $rootFull = [System.IO.Path]::GetFullPath($RootValue).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($PathValue)
  if ($pathFull.TrimEnd('\', '/').Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
    return $true
  }
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  return $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
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
        throw "Avorax cancel scan timed out after ${Timeout}s and failed to stop local-core: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "Avorax cancel scan timed out after ${Timeout}s."
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
        throw "local-core emitted non-JSON stdout during Avorax cancel scan: $(Get-BoundedText $trimmed)"
      }
      if ($body.type -eq "scan_progress" -or $body.type -eq "progress") {
        continue
      }
      $responses += $body
    }
    if ($responses.Count -eq 0) {
      throw "local-core produced no JSON cancel response. stderr: $(Get-BoundedText $stderr)"
    }
    $response = $responses[-1]
    if (($response.PSObject.Properties.Name -contains "ok") -and $response.ok -eq $false) {
      throw "local-core rejected Avorax cancel scan command: $(Get-BoundedText $response.error)"
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

if (-not [string]::IsNullOrWhiteSpace($DataRoot) -and $UseInstalledDataRoot) {
  throw "Avorax cancel scan accepts either -DataRoot or -UseInstalledDataRoot, not both."
}
if ([string]::IsNullOrWhiteSpace($DataRoot) -and -not $UseInstalledDataRoot) {
  throw "Avorax cancel scan requires -DataRoot for isolated proof or -UseInstalledDataRoot for an installed runtime."
}

$dataRootFull = Resolve-IsolatedDataRoot $DataRoot
$reportFull = ""
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
  $reportFull = Resolve-RepoChildPath $repo $ReportPath "Avorax cancel scan report"
}

$previousDataDir = $env:AVORAX_DATA_DIR

try {
  if (-not [string]::IsNullOrWhiteSpace($dataRootFull)) {
    $env:AVORAX_DATA_DIR = $dataRootFull
  }

  $command = [ordered]@{
    command = "cancel_scan"
  }
  $result = Invoke-LocalCoreJson $command $repo $binary $TimeoutSeconds
  $response = $result.response
  $tokenPath = [string]$response.cancel_token
  if ([string]::IsNullOrWhiteSpace($tokenPath)) {
    throw "local-core cancel response is missing cancel_token."
  }
  if ($tokenPath.Contains([char]0)) {
    throw "local-core cancel_token contains a NUL byte."
  }
  if ($tokenPath.Length -gt 4096) {
    throw "local-core cancel_token exceeds 4096 characters."
  }
  if (-not [System.IO.Path]::IsPathRooted($tokenPath)) {
    throw "local-core cancel_token must be absolute: $tokenPath"
  }

  $tokenFull = [System.IO.Path]::GetFullPath($tokenPath)
  if ([System.IO.Path]::GetFileName($tokenFull) -ne "cancel-active-scan") {
    throw "local-core cancel_token leaf must be cancel-active-scan: $tokenFull"
  }
  $tokenExists = Test-Path -LiteralPath $tokenFull -PathType Leaf
  if ($tokenExists) {
    Assert-NotReparsePath $tokenFull "cancel token"
  }

  $tokenUnderDataRoot = $false
  if (-not [string]::IsNullOrWhiteSpace($dataRootFull)) {
    $expectedToken = Join-Path (Join-Path $dataRootFull "runtime") "cancel-active-scan"
    if (-not $tokenFull.Equals([System.IO.Path]::GetFullPath($expectedToken), [StringComparison]::OrdinalIgnoreCase)) {
      throw "local-core cancel_token must stay inside DataRoot runtime: $tokenFull"
    }
    if (-not $tokenExists) {
      throw "local-core cancel_token was not written: $tokenFull"
    }
    $tokenUnderDataRoot = Test-PathUnderRoot $tokenFull $dataRootFull
  }

  $summary = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    tool = "avorax-cancel-scan"
    repository = $repo
    local_core_path = $binary
    command = "cancel_scan"
    data_root = $dataRootFull
    use_installed_data_root = [bool]$UseInstalledDataRoot
    cancel_requested = $true
    cancel_token_path = $tokenFull
    cancel_token_exists = [bool]$tokenExists
    token_under_data_root = [bool]$tokenUnderDataRoot
    ipc = "stdio"
    network_exposed = $false
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_component_installation = $false
      service_installation_attempted = $false
      process_kill_attempted = $false
      external_process_kill_attempted = $false
      child_process_timeout_cleanup_enabled = $true
      pre_execution_blocking_claimed = $false
      persistent_monitoring_claimed = $false
      installed_data_root_requested = [bool]$UseInstalledDataRoot
    }
    limitations = @(
      "cooperative-cancel-token-request-only",
      "running-scan-observation-covered-by-local-core-regressions",
      "no-installed-service-e2e-claim",
      "no-external-process-kill",
      "no-process-kill",
      "no-kernel-pre-execution-blocking"
    )
    raw_response = $response
    stderr = [string]$result.stderr
  }

  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-JsonReportAtomic $reportFull $summary
  }

  Write-Host "Avorax cancel scan requested."
  Write-Host "Cancel token: $tokenFull"
  if (-not [string]::IsNullOrWhiteSpace($dataRootFull)) {
    Write-Host "Data root: $dataRootFull"
  } else {
    Write-Host "Data root: installed runtime"
  }
  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-Host "Report: $reportFull"
  }
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
}
