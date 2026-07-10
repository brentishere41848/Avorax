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
    throw "Release local-core quick-scan archive encryption/unsupported smoke expects zentor_local_core.exe, got: $resolved"
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
        throw "release local-core quick-scan archive encryption/unsupported smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core quick-scan archive encryption/unsupported smoke timed out after ${Timeout}s."
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
        throw "release local-core emitted non-JSON stdout during quick-scan archive encryption/unsupported smoke: $(Get-BoundedText $trimmed)"
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

function New-OpaqueZipBytes {
  param(
    [string]$EntryName,
    [uint16]$Flags,
    [uint16]$Method,
    [byte[]]$Body = ([System.Text.Encoding]::ASCII.GetBytes("benign opaque archive-entry placeholder"))
  )

  $nameBytes = [System.Text.Encoding]::ASCII.GetBytes($EntryName)
  $memory = [System.IO.MemoryStream]::new()
  try {
    $writer = [System.IO.BinaryWriter]::new($memory, [System.Text.Encoding]::ASCII, $true)
    try {
      $writer.Write([byte[]](0x50, 0x4b, 0x03, 0x04))
      $writer.Write([uint16]20)
      $writer.Write([uint16]$Flags)
      $writer.Write([uint16]$Method)
      $writer.Write([uint16]0)
      $writer.Write([uint16]0)
      $writer.Write([uint32]0)
      $writer.Write([uint32]$Body.Length)
      $writer.Write([uint32]$Body.Length)
      $writer.Write([uint16]$nameBytes.Length)
      $writer.Write([uint16]0)
      $writer.Write($nameBytes)
      $writer.Write($Body)
      $writer.Flush()
      return $memory.ToArray()
    } finally {
      $writer.Dispose()
    }
  } finally {
    $memory.Dispose()
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-quickscan-archive-encryption-unsupported-smoke-" + [System.Guid]::NewGuid().ToString("N"))
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

  $encryptedZipBytes = New-OpaqueZipBytes "payload/encrypted-release-entry.bin" 0x0001 0
  $encryptedJarBytes = New-OpaqueZipBytes "payload/encrypted-release-entry.bin" 0x0001 0
  $encryptedAppxBytes = New-OpaqueZipBytes "assets/encrypted-release-entry.bin" 0x0001 0
  $encryptedNestedAppxBytes = New-OpaqueZipBytes "assets/encrypted-release-entry.bin" 0x0001 0
  $encryptedBundleBytes = New-ZipWithEntryBytes @(
    (New-ZipEntry "packages/store.appx" $encryptedNestedAppxBytes),
    (New-ZipEntry "AppxBundleManifest.xml" ([System.Text.Encoding]::ASCII.GetBytes("benign encrypted bundle manifest fixture")))
  )

  $unsupportedZipBytes = New-OpaqueZipBytes "payload/unsupported-release-entry.bin" 0 99
  $unsupportedJarBytes = New-OpaqueZipBytes "payload/unsupported-release-entry.bin" 0 99
  $unsupportedAppxBytes = New-OpaqueZipBytes "assets/unsupported-release-entry.bin" 0 99
  $unsupportedNestedAppxBytes = New-OpaqueZipBytes "assets/unsupported-release-entry.bin" 0 99
  $unsupportedBundleBytes = New-ZipWithEntryBytes @(
    (New-ZipEntry "packages/store.appx" $unsupportedNestedAppxBytes),
    (New-ZipEntry "AppxBundleManifest.xml" ([System.Text.Encoding]::ASCII.GetBytes("benign unsupported bundle manifest fixture")))
  )

  $carrierFixtures = @(
    [ordered]@{
      FileName = "encrypted-release-archive.zip"
      Bytes = $encryptedZipBytes
    },
    [ordered]@{
      FileName = "encrypted-release-library.jar"
      Bytes = $encryptedJarBytes
    },
    [ordered]@{
      FileName = "encrypted-release-store.appx"
      Bytes = $encryptedAppxBytes
    },
    [ordered]@{
      FileName = "encrypted-release-store.appxbundle"
      Bytes = $encryptedBundleBytes
    },
    [ordered]@{
      FileName = "unsupported-release-archive.zip"
      Bytes = $unsupportedZipBytes
    },
    [ordered]@{
      FileName = "unsupported-release-library.jar"
      Bytes = $unsupportedJarBytes
    },
    [ordered]@{
      FileName = "unsupported-release-store.appx"
      Bytes = $unsupportedAppxBytes
    },
    [ordered]@{
      FileName = "unsupported-release-store.appxbundle"
      Bytes = $unsupportedBundleBytes
    }
  )
  foreach ($fixture in $carrierFixtures) {
    [System.IO.File]::WriteAllBytes((Join-Path $downloadsRoot $fixture.FileName), $fixture.Bytes)
  }

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
  if ($scan.status -ne "completedWithErrors") {
    throw "release local-core quick_scan_selected_paths did not return completedWithErrors for encrypted/unsupported archive fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $filesScanned = if ($null -ne $scan.files_scanned) { [int64]$scan.files_scanned } else { 0 }
  if ($filesScanned -lt $expectedCarrierCount) {
    throw "release local-core quick_scan_selected_paths did not scan every encrypted/unsupported archive fixture: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $skippedFiles = if ($null -ne $scan.skipped_files) { [int64]$scan.skipped_files } else { 0 }
  if ($skippedFiles -lt $expectedCarrierCount) {
    throw "release local-core quick_scan_selected_paths did not mark every encrypted/unsupported archive fixture as incomplete/not clean: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([int64]$scan.threats_found -ne 0 -or @($scan.threats).Count -ne 0) {
    throw "release local-core quick_scan_selected_paths treated encrypted/unsupported archive fixtures as threats instead of incomplete scans: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $quarantinedFiles = if ($null -ne $scan.quarantined_files) { [int64]$scan.quarantined_files } else { 0 }
  if ($quarantinedFiles -ne 0) {
    throw "release local-core quick_scan_selected_paths quarantined encrypted/unsupported archive fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([string]$scan.message -notlike "*skipped files were not reported clean*") {
    throw "release local-core quick_scan_selected_paths did not make incomplete encrypted/unsupported archive scan status user-visible: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }

  foreach ($fixture in $carrierFixtures) {
    $carrierFile = Join-Path $downloadsRoot $fixture.FileName
    $limitError = @($scan.scan_errors) | Where-Object {
      [string]$_ -like "*$($fixture.FileName)*" -and
      [string]$_ -like "*archive_content_scan_limited*" -and
      [string]$_ -like "*Archive content scan limited*" -and
      [string]$_ -like "*did not extract files or treat unscanned archive content as clean*"
    } | Select-Object -First 1
    if ($null -eq $limitError) {
      throw "release local-core quick_scan_selected_paths did not include archive encryption/unsupported scan error for $($fixture.FileName): $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
    }
    if (-not (Test-Path -LiteralPath $carrierFile -PathType Leaf)) {
      throw "release local-core quick_scan_selected_paths removed an encrypted/unsupported archive fixture: $carrierFile"
    }
  }

  $list = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $inputJson $repo $binary $TimeoutSeconds
  if ($list.ok -ne $true) {
    throw "release local-core list_quarantine failed after archive encryption/unsupported quick scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($list.records).Count -ne 0) {
    throw "release local-core created quarantine records after archive encryption/unsupported scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }

  Write-Host "Avorax release local-core quick-scan archive encryption/unsupported smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Engine dir: $engineRoot"
  Write-Host "Scan root: $downloadsRoot"
  Write-Host "Archive encryption/unsupported carriers: $expectedCarrierCount"
  Write-Host "Files scanned: $filesScanned"
  Write-Host "Skipped files: $skippedFiles"
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
