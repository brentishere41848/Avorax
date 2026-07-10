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
    throw "Release local-core quick-scan unsafe archive path smoke expects zentor_local_core.exe, got: $resolved"
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
        throw "release local-core quick-scan unsafe archive path smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core quick-scan unsafe archive path smoke timed out after ${Timeout}s."
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
        throw "release local-core emitted non-JSON stdout during quick-scan unsafe archive path smoke: $(Get-BoundedText $trimmed)"
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

function New-ZipWithEntryBytes {
  param(
    [array]$Entries
  )

  Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
  Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
  $memory = [System.IO.MemoryStream]::new()
  try {
    $archive = [System.IO.Compression.ZipArchive]::new(
      $memory,
      [System.IO.Compression.ZipArchiveMode]::Create,
      $true
    )
    try {
      foreach ($item in $Entries) {
        $entry = $archive.CreateEntry($item.EntryName, [System.IO.Compression.CompressionLevel]::NoCompression)
        $entryStream = $entry.Open()
        try {
          [byte[]]$entryBytes = $item.Bytes
          $entryStream.Write($entryBytes, 0, $entryBytes.Length)
        } finally {
          $entryStream.Dispose()
        }
      }
    } finally {
      $archive.Dispose()
    }
    return $memory.ToArray()
  } finally {
    $memory.Dispose()
  }
}

function Write-ZipWithEntries {
  param(
    [string]$ZipPath,
    [array]$Entries
  )

  Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
  Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
  $stream = [System.IO.File]::Open(
    $ZipPath,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::ReadWrite,
    [System.IO.FileShare]::None
  )
  try {
    $archive = [System.IO.Compression.ZipArchive]::new(
      $stream,
      [System.IO.Compression.ZipArchiveMode]::Create,
      $true
    )
    try {
      foreach ($item in $Entries) {
        $entry = $archive.CreateEntry($item.EntryName, [System.IO.Compression.CompressionLevel]::NoCompression)
        $entryStream = $entry.Open()
        try {
          [byte[]]$entryBytes = $item.Bytes
          $entryStream.Write($entryBytes, 0, $entryBytes.Length)
        } finally {
          $entryStream.Dispose()
        }
      }
    } finally {
      $archive.Dispose()
    }
  } finally {
    $stream.Dispose()
  }
}

function New-ZipEntry {
  param(
    [string]$EntryName,
    [byte[]]$Bytes
  )
  [ordered]@{
    EntryName = $EntryName
    Bytes = $Bytes
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-quickscan-unsafe-archive-path-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
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
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "signatures") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "rules") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "ml") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "trust") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "config") -Force | Out-Null
  [System.IO.File]::WriteAllText(
    $allowlistFile,
    "[]`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $benignBytes = [System.Text.Encoding]::ASCII.GetBytes("benign unsafe archive path review fixture")
  $manifestBytes = [System.Text.Encoding]::ASCII.GetBytes("benign package manifest fixture")
  $innerAppxBytes = New-ZipWithEntryBytes @(
    (New-ZipEntry "../evil.exe" $benignBytes),
    (New-ZipEntry "AppxManifest.xml" $manifestBytes)
  )
  $carrierFixtures = @(
    [ordered]@{
      FileName = "unsafe-release-archive.zip"
      Entries = @(
        (New-ZipEntry "../evil.exe" $benignBytes),
        (New-ZipEntry "safe/readme.txt" $manifestBytes)
      )
    },
    [ordered]@{
      FileName = "unsafe-release-library.jar"
      Entries = @(
        (New-ZipEntry "C:\Windows\Temp\Evil.class" $benignBytes),
        (New-ZipEntry "META-INF/MANIFEST.MF" $manifestBytes)
      )
    },
    [ordered]@{
      FileName = "unsafe-release-store.appx"
      Entries = @(
        (New-ZipEntry "\Windows\Temp\evil.exe" $benignBytes),
        (New-ZipEntry "AppxManifest.xml" $manifestBytes)
      )
    },
    [ordered]@{
      FileName = "unsafe-release-store.appxbundle"
      Entries = @(
        (New-ZipEntry "packages/store.appx" $innerAppxBytes),
        (New-ZipEntry "AppxBundleManifest.xml" $manifestBytes)
      )
    }
  )
  foreach ($fixture in $carrierFixtures) {
    Write-ZipWithEntries (Join-Path $downloadsRoot $fixture.FileName) $fixture.Entries
  }
  $benignFile = Join-Path $downloadsRoot "benign-release-note.txt"
  [System.IO.File]::WriteAllText(
    $benignFile,
    "benign release quick-scan unsafe archive path smoke file`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_ENGINE_DIR = $engineRoot

  $scan = Invoke-LocalCoreBinaryJson @{
    command = "quick_scan_selected_paths"
    paths = @($downloadsRoot)
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "quick"
  } $inputJson $repo $binary $TimeoutSeconds

  $expectedCarrierCount = @($carrierFixtures).Count
  if ($scan.status -ne "threatsFound") {
    throw "release local-core quick_scan_selected_paths did not return a threat status for unsafe archive path fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $filesScanned = if ($null -ne $scan.files_scanned) { [int64]$scan.files_scanned } else { 0 }
  if ($filesScanned -lt $expectedCarrierCount) {
    throw "release local-core quick_scan_selected_paths did not scan every unsafe archive path fixture: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $quarantinedFiles = if ($null -ne $scan.quarantined_files) { [int64]$scan.quarantined_files } else { 0 }
  if ($quarantinedFiles -ne 0) {
    throw "release local-core quick_scan_selected_paths quarantined review-only unsafe archive path fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($scan.scan_errors).Count -ne 0) {
    throw "release local-core quick_scan_selected_paths reported scan errors during unsafe archive path smoke: $(Get-BoundedText ($scan.scan_errors | ConvertTo-Json -Compress -Depth 8))"
  }

  foreach ($fixture in $carrierFixtures) {
    $carrierFile = Join-Path $downloadsRoot $fixture.FileName
    $threat = @($scan.threats) | Where-Object {
      $_.file_name -eq $fixture.FileName -and
      $_.detection_type -eq "heuristic" -and
      $_.status -eq "detected" -and
      $_.recommended_action -eq "review" -and
      $_.risk_score.verdict -eq "suspicious"
    } | Select-Object -First 1
    if ($null -eq $threat) {
      throw "release local-core quick_scan_selected_paths did not report a review-only unsafe archive path finding for $($fixture.FileName): $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
    }
    $zipSlipReason = @($threat.risk_score.reasons) | Where-Object {
      $_.id -eq "archive_zip_slip" -and
      $_.title -like "*Unsafe archive path blocked" -and
      $_.detail -like "*path traversal entries*"
    } | Select-Object -First 1
    if ($null -eq $zipSlipReason) {
      throw "release local-core quick_scan_selected_paths did not include unsafe archive path evidence for $($fixture.FileName): $(Get-BoundedText ($threat | ConvertTo-Json -Compress -Depth 12))"
    }
    $limitedReason = @($threat.risk_score.reasons) | Where-Object {
      $_.id -eq "archive_content_scan_limited" -and
      $_.title -eq "Archive content scan limited" -and
      $_.detail -like "*did not extract files or treat unscanned archive content as clean*"
    } | Select-Object -First 1
    if ($null -eq $limitedReason) {
      throw "release local-core quick_scan_selected_paths did not include fail-visible archive content limit evidence for $($fixture.FileName): $(Get-BoundedText ($threat | ConvertTo-Json -Compress -Depth 12))"
    }
    if ([string]$threat.reason_summary -notlike "*Unsafe archive path blocked*") {
      throw "release local-core quick_scan_selected_paths did not summarize unsafe archive path evidence for $($fixture.FileName): $(Get-BoundedText ($threat | ConvertTo-Json -Compress -Depth 12))"
    }
    if (-not (Test-Path -LiteralPath $carrierFile -PathType Leaf)) {
      throw "release local-core quick_scan_selected_paths removed a review-only unsafe archive path fixture: $carrierFile"
    }
  }
  if (-not (Test-Path -LiteralPath $benignFile -PathType Leaf)) {
    throw "release local-core quick_scan_selected_paths removed the benign non-matching fixture"
  }

  $list = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $inputJson $repo $binary $TimeoutSeconds
  if ($list.ok -ne $true) {
    throw "release local-core list_quarantine failed after unsafe archive path quick scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($list.records).Count -ne 0) {
    throw "release local-core created quarantine records after review-only unsafe archive path scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }

  Write-Host "Avorax release local-core quick-scan unsafe archive path smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Engine dir: $engineRoot"
  Write-Host "Scan root: $downloadsRoot"
  Write-Host "Unsafe archive carriers: $expectedCarrierCount"
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
