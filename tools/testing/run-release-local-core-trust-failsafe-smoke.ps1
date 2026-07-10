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
    throw "Release local-core trust fail-safe smoke expects zentor_local_core.exe, got: $resolved"
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
        throw "release local-core emitted non-JSON stdout during trust fail-safe smoke: $(Get-BoundedText $trimmed)"
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

function Initialize-ReleaseSmokeEngineDirectories {
  param([string]$EngineRoot)

  New-Item -ItemType Directory -Path (Join-Path $EngineRoot "signatures") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $EngineRoot "rules") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $EngineRoot "ml") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $EngineRoot "trust") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $EngineRoot "config") -Force | Out-Null
}

function Write-ReleaseSmokeTrustJson {
  param(
    [string]$Path,
    [string[]]$Hashes
  )
  $store = [ordered]@{ hashes = @($Hashes) }
  [System.IO.File]::WriteAllText(
    $Path,
    ($store | ConvertTo-Json -Depth 4) + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )
}

function Invoke-InvalidTrustStoreScenario {
  param(
    [string]$Repo,
    [string]$Binary,
    [string]$ScenarioName,
    [string]$InvalidStoreName,
    [string]$ExpectedDiagnostic,
    [int]$Timeout
  )

  $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-trust-failsafe-" + $ScenarioName + "-" + [System.Guid]::NewGuid().ToString("N"))
  $dataRoot = Join-Path $tempRoot "data"
  $legacyRoot = Join-Path $tempRoot "legacy-data"
  $quarantineRoot = Join-Path $tempRoot "quarantine"
  $engineRoot = Join-Path $tempRoot "engine"
  $allowlistFile = Join-Path $tempRoot "allowlist.json"
  $fixture = Join-Path $tempRoot "safe-release-trust-failsafe.txt"
  $inputJson = Join-Path $tempRoot "local-core-command.json"

  try {
    New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null
    Set-Content -LiteralPath $fixture -Value "harmless-known-bad-fixture" -NoNewline -Encoding ASCII
    Initialize-ReleaseSmokeEngineDirectories $engineRoot

    $trustDir = Join-Path $engineRoot "trust"
    if ($InvalidStoreName -eq "avorax_known_good.atrust") {
      Write-ReleaseSmokeTrustJson (Join-Path $trustDir "avorax_known_good.atrust") @("not-a-sha256")
    } elseif ($InvalidStoreName -eq "zentor_known_bad_test.ztrust") {
      Write-ReleaseSmokeTrustJson (Join-Path $trustDir "avorax_known_good.atrust") @()
      Write-ReleaseSmokeTrustJson (Join-Path $trustDir "zentor_known_bad_test.ztrust") @("not-a-sha256")
    } else {
      throw "unknown invalid trust scenario store: $InvalidStoreName"
    }

    $env:AVORAX_DATA_DIR = $dataRoot
    $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
    $env:AVORAX_QUARANTINE_DIR = $quarantineRoot
    $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
    $env:AVORAX_ENGINE_DIR = $engineRoot

    $scan = Invoke-LocalCoreBinaryJson @{
      command = "scan_file"
      path = $fixture
      action_mode = "autoQuarantineConfirmedOnly"
      scan_kind = "custom"
    } $inputJson $Repo $Binary $Timeout

    $errors = @($scan.scan_errors)
    if ($scan.status -ne "engineUnavailable") {
      throw "release local-core did not fail safe for $ScenarioName trust validation failure: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
    }
    if ($scan.files_scanned -ne 0 -or $scan.threats_found -ne 0 -or @($scan.threats).Count -ne 0) {
      throw "release local-core reported scan/threat results from invalid $ScenarioName trust store: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
    }
    if ($scan.skipped_files -lt 1) {
      throw "release local-core did not report the target as skipped after invalid $ScenarioName trust validation: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
    }
    if (-not ($errors | Where-Object { $_ -like "*$ExpectedDiagnostic*" })) {
      throw "release local-core did not expose the $ScenarioName trust diagnostic: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
    }
    if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
      throw "release local-core removed the source fixture after invalid $ScenarioName trust validation"
    }
    $payloads = @()
    if (Test-Path -LiteralPath $quarantineRoot) {
      $payloads = @(Get-ChildItem -LiteralPath $quarantineRoot -Recurse -File -ErrorAction Stop | Where-Object { $_.Name -like "*.avoraxq" })
    }
    if ($payloads.Count -ne 0) {
      throw "release local-core quarantined payloads after invalid $ScenarioName trust validation: $($payloads[0].FullName)"
    }

    return [ordered]@{
      scenario = $ScenarioName
      status = $scan.status
      skipped_files = $scan.skipped_files
      diagnostic = $errors[0]
    }
  } finally {
    if (Test-Path -LiteralPath $tempRoot) {
      Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  $knownGood = Invoke-InvalidTrustStoreScenario $repo $binary "known-good" "avorax_known_good.atrust" "native known-good store contains malformed SHA-256 value" $TimeoutSeconds
  $knownBad = Invoke-InvalidTrustStoreScenario $repo $binary "known-bad" "zentor_known_bad_test.ztrust" "native known-bad store contains malformed SHA-256 value" $TimeoutSeconds

  Write-Host "Avorax release local-core trust-store fail-safe smoke test passed."
  Write-Host "Binary: $binary"
  foreach ($result in @($knownGood, $knownBad)) {
    Write-Host "Scenario: $($result.scenario)"
    Write-Host "Status: $($result.status)"
    Write-Host "Skipped files: $($result.skipped_files)"
    Write-Host "Diagnostic: $($result.diagnostic)"
  }
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "ZENTOR_LEGACY_DATA_DIR" $previousLegacyDataDir
  Restore-EnvVar "AVORAX_QUARANTINE_DIR" $previousQuarantineDir
  Restore-EnvVar "ZENTOR_ALLOWLIST_FILE" $previousAllowlistFile
  Restore-EnvVar "AVORAX_ENGINE_DIR" $previousEngineDir
}
