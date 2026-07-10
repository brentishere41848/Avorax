$securityGateTools = Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1"
$gateReaderAvailable = $true
try {
  Get-Command Read-AvoraxGateTextFileBounded -CommandType Function -ErrorAction Stop | Out-Null
} catch [System.Management.Automation.CommandNotFoundException] {
  $gateReaderAvailable = $false
}
if (-not $gateReaderAvailable) {
  . $securityGateTools
}

$script:AvoraxCoreHealthOutputByteLimit = 65536
$script:AvoraxCoreHealthTimeoutMs = 10000

function Test-AvoraxCoreHealthJsonInteger {
  param([AllowNull()][object]$Value)
  if ($Value -is [bool]) { return $false }
  return ($Value -is [int] -or $Value -is [long])
}

function ConvertFrom-AvoraxCoreHealthOutput {
  param(
    [AllowNull()][string]$Stdout,
    [AllowNull()][string]$Stderr,
    [int]$ExitCode
  )

  $stderrText = Get-AvoraxGateBoundedDiagnostic $Stderr
  if ($ExitCode -ne 0) {
    throw "Avorax Core Service health command exited with $ExitCode`: $stderrText"
  }

  $responses = @()
  foreach ($line in ([string]$Stdout -split "`r?`n")) {
    $trimmed = $line.Trim()
    if ($trimmed.Length -eq 0) { continue }
    try {
      $body = ConvertFrom-Json -InputObject $trimmed -ErrorAction Stop
    } catch {
      throw "Avorax Core Service health command emitted non-JSON stdout: $(Get-AvoraxGateBoundedDiagnostic $trimmed)"
    }
    if ($body.type -eq "scan_progress" -or $body.type -eq "progress") {
      continue
    }
    $responses += $body
  }

  if ($responses.Count -ne 1) {
    throw "Avorax Core Service health command expected exactly one JSON response, got $($responses.Count)."
  }

  $health = $responses[0]
  foreach ($field in @(
    "ok",
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
    if ($health.PSObject.Properties.Name -notcontains $field) {
      throw "Avorax Core Service health response is missing required field: $field"
    }
  }

  if (-not ($health.ok -is [bool])) {
    throw "Avorax Core Service health response ok must be a JSON boolean."
  }
  if ($health.ok -ne $true) {
    $errorText = Get-AvoraxGateBoundedDiagnostic $health.error
    throw "Avorax Core Service health response reported ok=false: $errorText"
  }
  if (-not ($health.native_self_test -is [bool])) {
    throw "Avorax Core Service health response native_self_test must be a JSON boolean."
  }
  if (-not (Test-AvoraxCoreHealthJsonInteger $health.native_signature_count) -or [int64]$health.native_signature_count -lt 0) {
    throw "Avorax Core Service health response native_signature_count must be a non-negative JSON integer."
  }
  if (-not (Test-AvoraxCoreHealthJsonInteger $health.native_rule_count) -or [int64]$health.native_rule_count -lt 0) {
    throw "Avorax Core Service health response native_rule_count must be a non-negative JSON integer."
  }
  foreach ($field in @(
    "engine_status",
    "native_engine_status",
    "core_service_status",
    "guard_status",
    "driver_status",
    "process_monitor_status",
    "behavior_monitor_status",
    "reputation_status",
    "install_path",
    "engine_directory"
  )) {
    $value = $health.PSObject.Properties[$field].Value
    if (-not ($value -is [string]) -or [string]::IsNullOrWhiteSpace($value)) {
      throw "Avorax Core Service health response $field must be a non-empty JSON string."
    }
  }
  if (-not ($health.ipc -is [string]) -or $health.ipc -ne "stdio") {
    throw "Avorax Core Service health response must report ipc=stdio."
  }
  if (-not ($health.network_exposed -is [bool]) -or $health.network_exposed -ne $false) {
    throw "Avorax Core Service health response must report network_exposed=false."
  }

  return [pscustomobject][ordered]@{
    health = $health
    stderr = $stderrText
    response_count = 1
  }
}

function Test-AvoraxCoreHealthOutputWithinLimit {
  param([string[]]$Paths)
  foreach ($path in $Paths) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { continue }
    $file = Get-AvoraxGateFile $path "Avorax Core Service health output"
    if ((Get-Item -LiteralPath $file -Force -ErrorAction Stop).Length -gt $script:AvoraxCoreHealthOutputByteLimit) {
      return $false
    }
  }
  return $true
}

function Stop-AvoraxCoreHealthProcess {
  param(
    [AllowNull()][System.Diagnostics.Process]$Process,
    [string]$Reason
  )
  if ($null -eq $Process -or $Process.HasExited) { return }
  try {
    $Process.Kill()
    if (-not $Process.WaitForExit(5000)) {
      throw "Avorax Core Service health command did not exit within 5000 ms after $Reason."
    }
  } catch {
    throw "Could not stop Avorax Core Service health command after $Reason`: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
}

function Invoke-AvoraxCoreHealthProbe {
  param(
    [string]$CoreExe,
    [string]$WorkingDirectory
  )

  $core = Get-AvoraxGateFile $CoreExe "Avorax Core Service executable"
  $working = Get-AvoraxGateDirectory $WorkingDirectory "Avorax Core Service working directory"
  $stdinPath = $null
  $stdoutPath = $null
  $stderrPath = $null
  $process = $null
  try {
    $stdinPath = New-AvoraxGateCommandTempFile "Avorax Core Service health stdin"
    $stdoutPath = New-AvoraxGateCommandTempFile "Avorax Core Service health stdout"
    $stderrPath = New-AvoraxGateCommandTempFile "Avorax Core Service health stderr"
    [System.IO.File]::WriteAllText(
      $stdinPath,
      "{`"command`":`"health`"}`r`n",
      [System.Text.UTF8Encoding]::new($false)
    )

    $process = Start-Process `
      -FilePath $core `
      -WorkingDirectory $working `
      -RedirectStandardInput $stdinPath `
      -RedirectStandardOutput $stdoutPath `
      -RedirectStandardError $stderrPath `
      -WindowStyle Hidden `
      -PassThru

    $deadline = [DateTime]::UtcNow.AddMilliseconds($script:AvoraxCoreHealthTimeoutMs)
    while (-not $process.HasExited) {
      Start-Sleep -Milliseconds 100
      if (-not (Test-AvoraxCoreHealthOutputWithinLimit @($stdoutPath, $stderrPath))) {
        Stop-AvoraxCoreHealthProcess $process "output limit"
        throw "Avorax Core Service health command exceeded the $script:AvoraxCoreHealthOutputByteLimit byte output limit."
      }
      if ([DateTime]::UtcNow -ge $deadline) {
        Stop-AvoraxCoreHealthProcess $process "timeout"
        throw "Avorax Core Service health command timed out after $script:AvoraxCoreHealthTimeoutMs ms."
      }
    }

    [void]$process.WaitForExit()
    $process.Refresh()
    if (-not (Test-AvoraxCoreHealthOutputWithinLimit @($stdoutPath, $stderrPath))) {
      throw "Avorax Core Service health command exceeded the $script:AvoraxCoreHealthOutputByteLimit byte output limit."
    }
    $stdout = Read-AvoraxGateTextFileBounded $stdoutPath $script:AvoraxCoreHealthOutputByteLimit "Avorax Core Service health stdout"
    $stderr = Read-AvoraxGateTextFileBounded $stderrPath $script:AvoraxCoreHealthOutputByteLimit "Avorax Core Service health stderr"
    return ConvertFrom-AvoraxCoreHealthOutput $stdout $stderr ([int]$process.ExitCode)
  } catch {
    Stop-AvoraxCoreHealthProcess $process "probe failure"
    throw "Avorax Core Service structured health probe failed: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  } finally {
    if ($null -ne $process) { $process.Dispose() }
    foreach ($temporary in @(
      @($stdinPath, "Avorax Core Service health stdin"),
      @($stdoutPath, "Avorax Core Service health stdout"),
      @($stderrPath, "Avorax Core Service health stderr")
    )) {
      if (-not [string]::IsNullOrWhiteSpace([string]$temporary[0])) {
        Remove-AvoraxGateCommandTempFile ([string]$temporary[0]) ([string]$temporary[1])
      }
    }
  }
}
