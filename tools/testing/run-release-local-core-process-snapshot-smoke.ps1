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
    throw "Release local-core process snapshot smoke expects zentor_local_core.exe, got: $resolved"
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

  $json = $Command | ConvertTo-Json -Compress -Depth 16
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
        throw "release local-core process snapshot smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core process snapshot smoke timed out after ${Timeout}s."
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
        throw "release local-core emitted non-JSON stdout during process snapshot smoke: $(Get-BoundedText $trimmed)"
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

function Invoke-LocalCoreBinaryFailure {
  param(
    [hashtable]$Command,
    [string]$InputJsonPath,
    [string]$Repo,
    [string]$Binary,
    [int]$Timeout
  )

  $json = $Command | ConvertTo-Json -Compress -Depth 16
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
        throw "release local-core malformed process snapshot smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core malformed process snapshot smoke timed out after ${Timeout}s."
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -eq 0) {
      throw "release local-core accepted malformed process snapshot input. stdout: $(Get-BoundedText $stdout)"
    }
    return [ordered]@{
      exit_code = $process.ExitCode
      stdout = $stdout
      stderr = $stderr
    }
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function New-ProcessObservation {
  param(
    [uint32]$ProcessId,
    [string]$ImagePath,
    [AllowNull()][string]$CommandLine,
    [AllowNull()][bool]$SignerTrusted = $null,
    [bool]$CommandLineTruncated = $false
  )
  $item = [ordered]@{
    pid = $ProcessId
    image_path = $ImagePath
  }
  if ($null -ne $CommandLine) {
    $item.command_line = $CommandLine
  }
  if ($CommandLineTruncated) {
    $item.command_line_truncated = $true
  }
  if ($null -ne $SignerTrusted) {
    $item.signer_trusted = $SignerTrusted
  }
  return $item
}

function Assert-FindingReason {
  param(
    [object]$Finding,
    [string]$Expected
  )
  if (-not (@($Finding.reasons) | Where-Object { $_ -like "*$Expected*" })) {
    throw "release local-core process snapshot finding did not include reason '$Expected': $(Get-BoundedText ($Finding | ConvertTo-Json -Compress -Depth 8))"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-process-snapshot-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$inputJson = Join-Path $tempRoot "local-core-command.json"

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot

  $observations = @(
    (New-ProcessObservation 42 "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "powershell.exe -WindowStyle Hidden -EncodedCommand benignfixture" $true),
    (New-ProcessObservation 43 "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" ("powershell.exe " + ("a" * 4352) + " -EncodedCommand benign-tail-fixture") $true),
    (New-ProcessObservation 44 "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "powershell.exe benign bounded head and tail fixture" $true $true),
    (New-ProcessObservation 45 "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" $null $true $true),
    (New-ProcessObservation 77 "C:\Users\Brent\AppData\Local\Temp\curl.exe" "curl.exe https://example.invalid/benign-fixture" $false),
    (New-ProcessObservation 78 "C:\Users\Brent\..\Temp\bad.exe" "bad.exe" $false)
  )
  for ($index = 0; $index -lt 260; $index++) {
    $observations += (New-ProcessObservation ([uint32](2000 + $index)) "C:\Windows\System32\benign-$index.exe" "benign-$index.exe --fixture" $true)
  }

  $snapshot = Invoke-LocalCoreBinaryJson -Command @{
    command = "evaluate_process_snapshot"
    process_observations = $observations
    process_monitor_policy = @{
      suspicious_threshold = 40
      allowed_image_paths = @()
    }
  } -InputJsonPath $inputJson -Repo $repo -Binary $binary -Timeout $TimeoutSeconds

  if ($snapshot.ok -ne $true) {
    throw "release local-core evaluate_process_snapshot failed: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($snapshot.status -ne "notActive") {
    throw "release local-core process snapshot smoke must not claim an active monitor loop: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($snapshot.capability -ne "userModeSnapshot") {
    throw "release local-core process snapshot smoke expected userModeSnapshot capability on Windows: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([string]$snapshot.status_reason -notlike "*snapshot-only*") {
    throw "release local-core process snapshot status reason did not explain snapshot-only limits: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([int]$snapshot.observed_processes -ne @($observations).Count) {
    throw "release local-core process snapshot did not report the bounded observation count: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([int]$snapshot.skipped_processes -lt 12) {
    throw "release local-core process snapshot did not report skipped malformed/over-limit observations: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($snapshot.findings).Count -ne 4) {
    throw "release local-core process snapshot expected exactly four suspicious findings: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 10))"
  }

  $scriptFinding = @($snapshot.findings) | Where-Object {
    $_.pid -eq 42 -and $_.verdict -eq "suspiciousProcess" -and [int]$_.score -ge 40
  } | Select-Object -First 1
  if ($null -eq $scriptFinding) {
    throw "release local-core process snapshot did not report the encoded script-host finding: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 10))"
  }
  Assert-FindingReason $scriptFinding "encoded or hidden"

  $tailFinding = @($snapshot.findings) | Where-Object {
    $_.pid -eq 43 -and $_.verdict -eq "suspiciousProcess" -and [int]$_.score -ge 40
  } | Select-Object -First 1
  if ($null -eq $tailFinding) {
    throw "release local-core process snapshot did not inspect the bounded command tail: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 10))"
  }
  Assert-FindingReason $tailFinding "encoded or hidden"
  Assert-FindingReason $tailFinding "truncated"

  $sourceTruncationFinding = @($snapshot.findings) | Where-Object {
    $_.pid -eq 44 -and $_.verdict -eq "suspiciousProcess" -and [int]$_.score -eq 40
  } | Select-Object -First 1
  if ($null -eq $sourceTruncationFinding) {
    throw "release local-core process snapshot did not review source-reported truncation: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 10))"
  }
  Assert-FindingReason $sourceTruncationFinding "omitted arguments require review"

  $downloadFinding = @($snapshot.findings) | Where-Object {
    $_.pid -eq 77 -and $_.verdict -eq "suspiciousProcess" -and [int]$_.score -ge 40
  } | Select-Object -First 1
  if ($null -eq $downloadFinding) {
    throw "release local-core process snapshot did not report the unsigned user-writable downloader finding: $(Get-BoundedText ($snapshot | ConvertTo-Json -Compress -Depth 10))"
  }
  Assert-FindingReason $downloadFinding "remote transfer"
  Assert-FindingReason $downloadFinding "user-writable"

  $allowedPath = "C:\Users\Brent\AppData\Local\Temp\curl.exe"
  $allowed = Invoke-LocalCoreBinaryJson -Command @{
    command = "evaluate_process_snapshot"
    process_observations = @(
      (New-ProcessObservation 99 $allowedPath "curl.exe https://example.invalid/benign-fixture" $false)
    )
    process_monitor_policy = @{
      suspicious_threshold = 40
      allowed_image_paths = @($allowedPath)
    }
  } -InputJsonPath $inputJson -Repo $repo -Binary $binary -Timeout $TimeoutSeconds

  if ($allowed.ok -ne $true -or @($allowed.findings).Count -ne 0 -or [int]$allowed.skipped_processes -ne 0) {
    throw "release local-core process snapshot did not honor exact normalized allowlist policy: $(Get-BoundedText ($allowed | ConvertTo-Json -Compress -Depth 8))"
  }

  $missing = Invoke-LocalCoreBinaryJson -Command @{
    command = "evaluate_process_snapshot"
  } -InputJsonPath $inputJson -Repo $repo -Binary $binary -Timeout $TimeoutSeconds
  if ($missing.ok -ne $false -or [string]$missing.error -notlike "*process_observations is required*") {
    throw "release local-core process snapshot did not fail visibly when process_observations was absent: $(Get-BoundedText ($missing | ConvertTo-Json -Compress -Depth 8))"
  }

  $malformed = Invoke-LocalCoreBinaryFailure -Command @{
    command = "evaluate_process_snapshot"
    process_observations = @(
      @{
        pid = 123
        image_path = "C:\Windows\System32\notepad.exe"
        auto_quarantine = $true
      }
    )
  } -InputJsonPath $inputJson -Repo $repo -Binary $binary -Timeout $TimeoutSeconds
  if ([string]$malformed.stderr -notlike "*auto_quarantine*") {
    throw "release local-core malformed process snapshot failure did not name the rejected field: $(Get-BoundedText ($malformed | ConvertTo-Json -Compress -Depth 8))"
  }

  Write-Host "Avorax release local-core process snapshot smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Observed processes: $($snapshot.observed_processes)"
  Write-Host "Skipped processes: $($snapshot.skipped_processes)"
  Write-Host "Findings: $(@($snapshot.findings).Count)"
  Write-Host "Allowed findings: $(@($allowed.findings).Count)"
  Write-Host "Malformed input exit code: $($malformed.exit_code)"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "ZENTOR_LEGACY_DATA_DIR" $previousLegacyDataDir
  if (Test-Path -LiteralPath $tempRoot) {
    $resolvedTemp = (Resolve-Path -LiteralPath $tempRoot).Path
    $systemTemp = [System.IO.Path]::GetTempPath()
    if (-not $resolvedTemp.StartsWith($systemTemp, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to remove unexpected process snapshot temp root: $resolvedTemp"
    }
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction Stop
  }
}
