param(
  [string]$GuardServicePath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "target\release\zentor_guard_service.exe"),
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\selftest_report.json")
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
. (Join-Path $RepoRoot "tools\windows\avorax-system32-tools.ps1")
$MaxSelfTestStdoutBytes = 1048576
$MaxSelfTestStderrBytes = 65536
$SelfTestTimeoutMilliseconds = 60000

function Assert-AvoraxRepoChildPath([string]$Path, [string]$Base, [string]$DisplayName) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$DisplayName must resolve to a child path inside the Avorax repository root, not the repository root itself."
  }
  Assert-AvoraxPathUnder $pathFull $Base $DisplayName
}

function Format-AvoraxBoundedOutput([object]$Value) {
  $text = ($Value | Out-String).Trim()
  if ($text.Length -le 8192) { return $text }
  return $text.Substring(0, 8192) + "...[truncated]"
}

function New-AvoraxBoundedStreamCapture([int]$MaxBytes, [string]$DisplayName) {
  [pscustomobject]@{
    bytes = [System.Collections.Generic.List[byte]]::new()
    max_bytes = $MaxBytes
    display_name = $DisplayName
    truncated = $false
  }
}

function Add-AvoraxBoundedStreamBytes([object]$Capture, [byte[]]$Buffer, [int]$Count) {
  if ($Count -le 0) { return }
  $remaining = [int]$Capture.max_bytes - $Capture.bytes.Count
  if ($remaining -gt 0) {
    $toKeep = [Math]::Min($Count, $remaining)
    for ($i = 0; $i -lt $toKeep; $i++) {
      [void]$Capture.bytes.Add($Buffer[$i])
    }
  }
  if ($Count -gt $remaining) {
    $Capture.truncated = $true
  }
}

function Get-AvoraxBoundedStreamText([object]$Capture) {
  $bytes = $Capture.bytes.ToArray()
  $text = [System.Text.Encoding]::UTF8.GetString($bytes)
  if ($Capture.truncated) {
    $text += [Environment]::NewLine + "...[truncated after $($Capture.max_bytes) bytes]"
  }
  return $text
}

function Read-AvoraxProcessStreamsWithLimit([System.Diagnostics.Process]$Process, [int]$TimeoutMilliseconds) {
  $stdout = New-AvoraxBoundedStreamCapture $MaxSelfTestStdoutBytes "Avorax Guard Service self-test stdout"
  $stderr = New-AvoraxBoundedStreamCapture $MaxSelfTestStderrBytes "Avorax Guard Service self-test stderr"
  $stdoutBuffer = New-Object byte[] 8192
  $stderrBuffer = New-Object byte[] 8192
  $stdoutDone = $false
  $stderrDone = $false
  $stdoutTask = $Process.StandardOutput.BaseStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
  $stderrTask = $Process.StandardError.BaseStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
  $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
  $timedOut = $false

  while ((-not $stdoutDone) -or (-not $stderrDone) -or (-not $Process.HasExited)) {
    $tasks = New-Object 'System.Collections.Generic.List[System.Threading.Tasks.Task]'
    if (-not $stdoutDone) { [void]$tasks.Add($stdoutTask) }
    if (-not $stderrDone) { [void]$tasks.Add($stderrTask) }

    $now = [DateTimeOffset]::UtcNow
    if ($now -ge $deadline) {
      $timedOut = $true
      if (-not $Process.HasExited) {
        $killError = $null
        try {
          $Process.Kill()
        } catch {
          $killError = $_.Exception.Message
        }
        if ($killError) {
          throw "Avorax Guard Service self-test timed out after $TimeoutMilliseconds milliseconds. Process kill failed: $(Format-AvoraxBoundedOutput $killError)"
        }
      }
    }

    if ($tasks.Count -eq 0) {
      if ($Process.HasExited) { break }
      Start-Sleep -Milliseconds 25
      continue
    }

    $remaining = [Math]::Max(1, [int]($deadline - $now).TotalMilliseconds)
    $waitMs = [Math]::Min(250, $remaining)
    $completedIndex = [System.Threading.Tasks.Task]::WaitAny($tasks.ToArray(), $waitMs)
    if ($completedIndex -lt 0) {
      if ($Process.HasExited -and $stdoutDone -and $stderrDone) { break }
      continue
    }

    $completed = $tasks[$completedIndex]
    if ([object]::ReferenceEquals($completed, $stdoutTask)) {
      $read = $stdoutTask.GetAwaiter().GetResult()
      if ($read -le 0) {
        $stdoutDone = $true
      } else {
        Add-AvoraxBoundedStreamBytes $stdout $stdoutBuffer $read
        $stdoutTask = $Process.StandardOutput.BaseStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
      }
      continue
    }

    if ([object]::ReferenceEquals($completed, $stderrTask)) {
      $read = $stderrTask.GetAwaiter().GetResult()
      if ($read -le 0) {
        $stderrDone = $true
      } else {
        Add-AvoraxBoundedStreamBytes $stderr $stderrBuffer $read
        $stderrTask = $Process.StandardError.BaseStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
      }
    }
  }

  [ordered]@{
    stdout = Get-AvoraxBoundedStreamText $stdout
    stderr = Get-AvoraxBoundedStreamText $stderr
    stdout_truncated = [bool]$stdout.truncated
    stderr_truncated = [bool]$stderr.truncated
    timed_out = $timedOut
  }
}

function Convert-AvoraxBoundedJsonText([string]$Text, [string]$DisplayName, [int]$MaxChars = 1048576) {
  if ([string]::IsNullOrWhiteSpace($Text)) {
    throw "$DisplayName is empty."
  }
  if ($Text.Length -gt $MaxChars) {
    throw "$DisplayName exceeds the JSON character limit of $MaxChars."
  }
  try {
    return ConvertFrom-Json -InputObject $Text -ErrorAction Stop
  } catch {
    throw "$DisplayName is not valid bounded JSON: $(Get-AvoraxBoundedDiagnostic $_.Exception.Message)"
  }
}

Assert-AvoraxNoReparsePath $ReportPath "minifilter self-test report"
Assert-AvoraxPathUnder $ReportPath $RepoRoot "minifilter self-test report"
Assert-AvoraxRepoChildPath $ReportPath $RepoRoot "minifilter self-test report"
$ReportDir = New-AvoraxRegularDirectory (Split-Path $ReportPath) "minifilter self-test report directory" $RepoRoot
$cmdFile = Join-Path $ReportDir "driver_self_test_command.json"

try {
  $guardService = Get-AvoraxRegularFile $GuardServicePath "Avorax Guard Service executable"
  Assert-AvoraxPathUnder $guardService $RepoRoot "Avorax Guard Service executable"

  $commandText = '{"command":"driver_self_test"}' + [Environment]::NewLine
  Write-AvoraxTextFileAtomic $cmdFile $commandText "minifilter self-test command" $RepoRoot
  [void](Get-AvoraxRegularFile $cmdFile "minifilter self-test command")
  Assert-AvoraxPathUnder $cmdFile $RepoRoot "minifilter self-test command"

  $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $guardService
  $startInfo.WorkingDirectory = Split-Path $guardService
  $startInfo.UseShellExecute = $false
  $startInfo.RedirectStandardInput = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.CreateNoWindow = $true
  $process = [System.Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  $exitCode = $null
  try {
    [void]$process.Start()
    $process.StandardInput.Write($commandText)
    $process.StandardInput.Close()
    $streams = Read-AvoraxProcessStreamsWithLimit $process $SelfTestTimeoutMilliseconds
    $raw = [string]$streams.stdout
    $stderrText = [string]$streams.stderr
    $exitCode = $process.ExitCode
  } finally {
    $process.Dispose()
  }
  if ($streams.timed_out) {
    throw "Avorax Guard Service self-test timed out after $SelfTestTimeoutMilliseconds milliseconds and the process was killed."
  }
  if ($streams.stdout_truncated) {
    throw "Avorax Guard Service self-test stdout exceeded $MaxSelfTestStdoutBytes bytes."
  }
  if ($streams.stderr_truncated) {
    throw "Avorax Guard Service self-test stderr exceeded $MaxSelfTestStderrBytes bytes."
  }
  if ($exitCode -ne 0) {
    throw "Avorax Guard Service self-test command failed. $(Format-AvoraxBoundedOutput ($raw + [Environment]::NewLine + $stderrText))"
  }
  if (-not $raw) {
    throw "Avorax Guard Service self-test produced no output."
  }
  $event = Convert-AvoraxBoundedJsonText $raw "Avorax Guard Service self-test event"
  if ($event.action -ne "driverSelfTest") {
    throw "Avorax Guard Service self-test returned unexpected action: $(Format-AvoraxBoundedOutput $event.action)"
  }
  if ($null -eq $event.message -or -not ($event.message -is [string])) {
    throw "Avorax Guard Service self-test event message must be a JSON string."
  }
  $report = Convert-AvoraxBoundedJsonText $event.message "Avorax Guard Service self-test report"
  Write-AvoraxJsonFileAtomic $ReportPath $report 12 "minifilter self-test report" $RepoRoot
  if ($report.overall_result -ne "pass") {
    Write-Host "Protection self-test failed. See $ReportPath"
    exit 1
  }
  Write-Host "Protection self-test passed: $ReportPath"
} catch {
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    overall_result = "fail"
    errors = @(Get-AvoraxBoundedDiagnostic $_.Exception.Message 4096)
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 12 "minifilter self-test report" $RepoRoot
  throw
}
