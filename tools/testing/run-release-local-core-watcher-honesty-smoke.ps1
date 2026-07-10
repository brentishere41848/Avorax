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
    throw "Release local-core watcher honesty smoke expects zentor_local_core.exe, got: $resolved"
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
        throw "release local-core watcher honesty smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core watcher honesty smoke timed out after ${Timeout}s."
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
        throw "release local-core emitted non-JSON stdout during watcher honesty smoke: $(Get-BoundedText $trimmed)"
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

function Assert-WatcherLimitation {
  param(
    [object]$Watcher,
    [string]$Expected
  )
  if (-not (@($Watcher.limitations) | Where-Object { $_ -eq $Expected })) {
    throw "release local-core watcher response did not include required limitation '$Expected': $(Get-BoundedText ($Watcher | ConvertTo-Json -Compress -Depth 8))"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-watcher-honesty-" + [System.Guid]::NewGuid().ToString("N"))
$watchRoot = Join-Path $tempRoot "watch-root"
$missingRoot = Join-Path $tempRoot "missing-root"
$unsafeFile = Join-Path $tempRoot "not-a-directory.txt"
$inputJson = Join-Path $tempRoot "local-core-command.json"

try {
  New-Item -ItemType Directory -Path $watchRoot -Force | Out-Null
  [System.IO.File]::WriteAllText(
    $unsafeFile,
    "benign watcher honesty fixture`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $started = Invoke-LocalCoreBinaryJson @{
    command = "start_watch"
    paths = @($missingRoot, $unsafeFile, $watchRoot)
  } $inputJson $repo $binary $TimeoutSeconds
  if ($started.ok -ne $true) {
    throw "release local-core start_watch failed: $(Get-BoundedText ($started | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($started.watcher.active -ne $true -or $started.watcher.mode -ne "userModeBestEffort") {
    throw "release local-core start_watch did not report best-effort active plan for the accessible directory: $(Get-BoundedText ($started | ConvertTo-Json -Compress -Depth 8))"
  }
  $watchedPaths = @($started.watcher.watched_paths)
  if ($watchedPaths.Count -ne 1 -or $watchedPaths[0] -ne $watchRoot) {
    throw "release local-core start_watch did not keep exactly the accessible watch root: $(Get-BoundedText ($started | ConvertTo-Json -Compress -Depth 8))"
  }
  foreach ($limitation in @(
      "existing-accessible-paths-only",
      "one-shot-watch-plan-only",
      "no-persistent-service-monitor",
      "no-kernel-pre-execution-blocking",
      "unsafe-or-uninspectable-paths-ignored"
    )) {
    Assert-WatcherLimitation $started.watcher $limitation
  }

  $empty = Invoke-LocalCoreBinaryJson @{
    command = "start_watch"
    paths = @()
  } $inputJson $repo $binary $TimeoutSeconds
  if ($empty.ok -ne $true -or $empty.watcher.active -ne $false -or $empty.watcher.mode -ne "stopped") {
    throw "release local-core start_watch with no paths did not report stopped: $(Get-BoundedText ($empty | ConvertTo-Json -Compress -Depth 8))"
  }
  foreach ($limitation in @(
      "existing-accessible-paths-only",
      "one-shot-watch-plan-only",
      "no-persistent-service-monitor",
      "no-kernel-pre-execution-blocking",
      "no-watch-paths-requested"
    )) {
    Assert-WatcherLimitation $empty.watcher $limitation
  }

  $stopped = Invoke-LocalCoreBinaryJson @{ command = "stop_watch" } $inputJson $repo $binary $TimeoutSeconds
  if ($stopped.ok -ne $true -or $stopped.watcher.active -ne $false -or $stopped.watcher.mode -ne "stopped") {
    throw "release local-core stop_watch did not report stopped state: $(Get-BoundedText ($stopped | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($stopped.watcher.watched_paths).Count -ne 0) {
    throw "release local-core stop_watch reported watched paths after stop: $(Get-BoundedText ($stopped | ConvertTo-Json -Compress -Depth 8))"
  }

  Write-Host "Avorax release local-core watcher honesty smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Watch root: $watchRoot"
  Write-Host "Started mode: $($started.watcher.mode)"
  Write-Host "Started active: $($started.watcher.active)"
  Write-Host "Started limitations: $(@($started.watcher.limitations) -join ', ')"
  Write-Host "Empty-plan mode: $($empty.watcher.mode)"
  Write-Host "Stop mode: $($stopped.watcher.mode)"
} finally {
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
