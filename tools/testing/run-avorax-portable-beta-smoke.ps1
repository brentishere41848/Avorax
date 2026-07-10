param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$ArchivePath = "dist\Avorax-Portable-Beta-0.1.0-beta.1.zip",
  [string]$ReportPath = ".workflow\ultracode\avorax-hardening\results\portable-beta-archive-smoke.json"
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
. (Join-Path $repo "tools\security\avorax-security-gate-tools.ps1")
$script:PortableMaxArchiveEntries = 512
$script:PortableMaxEntryBytes = 268435456
$script:PortableMaxTotalBytes = 536870912
$script:PortableMaxCompressionRatio = 1000.0

function Resolve-AvoraxPortableSmokeRepoChild {
  param(
    [string]$PathValue,
    [string]$Description
  )
  $candidate = $PathValue
  if (-not [System.IO.Path]::IsPathRooted($candidate)) { $candidate = Join-Path $repo $candidate }
  $rootFull = [System.IO.Path]::GetFullPath($repo).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($candidate)
  $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if ($pathFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
      -not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must stay inside the repository: $pathFull"
  }
  Assert-AvoraxNoReparsePath $pathFull $Description
  return $pathFull
}

function Test-AvoraxPortableSafeZipPath {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Contains([char]0) -or $Value.Length -gt 4096) { return $false }
  $normalized = $Value.Replace('\', '/')
  if ($normalized.StartsWith('/') -or $normalized.Contains(':') -or $normalized.Contains('//')) { return $false }
  $trimmed = $normalized.TrimEnd('/')
  if ([string]::IsNullOrWhiteSpace($trimmed)) { return $false }
  foreach ($segment in $trimmed.Split('/')) {
    if ([string]::IsNullOrWhiteSpace($segment) -or $segment -eq "." -or $segment -eq "..") { return $false }
    if ($segment -match '[\x00-\x1F]') { return $false }
  }
  return $true
}

function Expand-AvoraxPortableArchiveSafely {
  param(
    [string]$Archive,
    [string]$Destination
  )
  Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
  $archiveFile = Get-AvoraxGateFile $Archive "portable beta archive"
  $destinationRoot = New-AvoraxGateDirectory $Destination "portable beta extraction root"
  $rootFull = [System.IO.Path]::GetFullPath($destinationRoot).TrimEnd('\', '/')
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  $stream = [System.IO.File]::Open($archiveFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  $zip = $null
  try {
    $zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
    $entries = @($zip.Entries)
    if ($entries.Count -eq 0 -or $entries.Count -gt $script:PortableMaxArchiveEntries) {
      throw "Portable beta archive entry count is outside 1..$script:PortableMaxArchiveEntries."
    }
    $seen = @{}
    [int64]$declaredTotal = 0
    foreach ($entry in $entries) {
      if (-not (Test-AvoraxPortableSafeZipPath $entry.FullName)) {
        throw "Portable beta archive contains an unsafe entry path: $($entry.FullName)"
      }
      $normalized = $entry.FullName.Replace('\', '/').TrimEnd('/')
      $key = $normalized.ToLowerInvariant()
      if ($seen.ContainsKey($key)) { throw "Portable beta archive contains a duplicate entry path: $normalized" }
      $seen[$key] = $true
      if ([int64]$entry.Length -lt 0 -or [int64]$entry.Length -gt $script:PortableMaxEntryBytes) {
        throw "Portable beta archive entry exceeds the size limit: $normalized"
      }
      $declaredTotal += [int64]$entry.Length
      if ($declaredTotal -gt $script:PortableMaxTotalBytes) {
        throw "Portable beta archive exceeds the total uncompressed size limit."
      }
      if ([int64]$entry.Length -gt 0) {
        if ([int64]$entry.CompressedLength -le 0) {
          throw "Portable beta archive entry has an invalid compressed length: $normalized"
        }
        $ratio = [double]$entry.Length / [double]$entry.CompressedLength
        if ($ratio -gt $script:PortableMaxCompressionRatio) {
          throw "Portable beta archive entry exceeds the compression-ratio limit: $normalized"
        }
      }

      $destinationPath = [System.IO.Path]::GetFullPath((Join-Path $rootFull ($normalized -replace '/', '\')))
      if (-not $destinationPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Portable beta archive entry escaped the extraction root: $normalized"
      }
      $isDirectory = $entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')
      if ($isDirectory) {
        New-AvoraxGateDirectory $destinationPath "portable beta archive directory" | Out-Null
        continue
      }
      New-AvoraxGateDirectory (Split-Path $destinationPath -Parent) "portable beta archive file directory" | Out-Null
      $input = $entry.Open()
      $output = [System.IO.File]::Open($destinationPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
      try {
        $buffer = [byte[]]::new(65536)
        [int64]$written = 0
        while ($true) {
          $read = $input.Read($buffer, 0, $buffer.Length)
          if ($read -le 0) { break }
          $written += $read
          if ($written -gt [int64]$entry.Length -or $written -gt $script:PortableMaxEntryBytes) {
            throw "Portable beta archive entry expanded beyond its declared/allowed size: $normalized"
          }
          $output.Write($buffer, 0, $read)
        }
        if ($written -ne [int64]$entry.Length) {
          throw "Portable beta archive entry length mismatch after extraction: $normalized"
        }
      } finally {
        $output.Dispose()
        $input.Dispose()
      }
      Get-AvoraxGateFile $destinationPath "extracted portable beta file" | Out-Null
    }
    return [ordered]@{
      entries = $entries.Count
      declared_uncompressed_bytes = $declaredTotal
    }
  } finally {
    if ($null -ne $zip) { $zip.Dispose() }
    $stream.Dispose()
  }
}

function Read-AvoraxPortableSmokeJson {
  param(
    [string]$Path,
    [string]$Description
  )
  $json = Read-AvoraxGateTextFileBounded $Path 4194304 $Description
  if ([string]::IsNullOrWhiteSpace($json)) { throw "$Description is empty." }
  try { $value = ConvertFrom-Json -InputObject $json -ErrorAction Stop } catch {
    throw "$Description is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($value -is [array] -or -not ($value -is [pscustomobject])) { throw "$Description must be one JSON object." }
  return $value
}

function New-AvoraxPortableAdversarialZip {
  param(
    [string]$Path,
    [object[]]$Entries
  )
  Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
  Assert-AvoraxNoReparsePath $Path "portable adversarial ZIP fixture"
  $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  $zip = $null
  try {
    $zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
    foreach ($fixture in $Entries) {
      $entry = $zip.CreateEntry([string]$fixture.name, [System.IO.Compression.CompressionLevel]::Optimal)
      $entryStream = $entry.Open()
      try {
        if ($fixture.PSObject.Properties.Name -contains "zero_bytes") {
          $remaining = [int64]$fixture.zero_bytes
          $buffer = [byte[]]::new(65536)
          while ($remaining -gt 0) {
            $count = [int][Math]::Min([int64]$buffer.Length, $remaining)
            $entryStream.Write($buffer, 0, $count)
            $remaining -= $count
          }
        } else {
          $bytes = [System.Text.Encoding]::ASCII.GetBytes([string]$fixture.text)
          $entryStream.Write($bytes, 0, $bytes.Length)
        }
      } finally {
        $entryStream.Dispose()
      }
    }
  } finally {
    if ($null -ne $zip) { $zip.Dispose() }
    $stream.Dispose()
  }
  Get-AvoraxGateFile $Path "portable adversarial ZIP fixture" | Out-Null
}

function Assert-AvoraxPortableArchiveRejected {
  param(
    [string]$Name,
    [string]$Archive,
    [string]$Destination,
    [string]$ExpectedDiagnostic
  )
  try {
    Expand-AvoraxPortableArchiveSafely $Archive $Destination | Out-Null
  } catch {
    $diagnostic = [string]$_.Exception.Message
    if ($diagnostic.IndexOf($ExpectedDiagnostic, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
      throw "$Name archive fixture failed with an unexpected diagnostic: $diagnostic"
    }
    return [ordered]@{
      name = $Name
      rejected = $true
      diagnostic_contains = $ExpectedDiagnostic
    }
  }
  throw "$Name archive fixture unexpectedly passed safe extraction."
}

function Assert-AvoraxPortableManifest {
  param(
    [string]$Root,
    [object]$Manifest
  )
  if ($Manifest.schema_version -ne 1 -or $Manifest.product -ne "Avorax Portable Scanner Beta" -or
      $Manifest.package_type -ne "portable-manual-user-mode-scanner") {
    throw "Portable beta manifest identity/schema mismatch."
  }
  if ($Manifest.verification.status.ready -ne $true -or
      [int64]$Manifest.verification.status.native_signature_count -le 0 -or
      [int64]$Manifest.verification.status.native_rule_count -le 0 -or
      $Manifest.verification.status.native_self_test -ne $true -or
      $Manifest.verification.lifecycle.restore_sha256_verified -ne $true -or
      $Manifest.verification.lifecycle.delete_payload_removed -ne $true) {
    throw "Portable beta manifest does not contain required ready/lifecycle evidence."
  }
  foreach ($field in @(
    "live_malware_included", "standard_eicar_file_included", "defender_exclusion_required",
    "machine_wide_changes", "service_or_driver_installation", "persistent_monitoring_claimed",
    "pre_execution_blocking_claimed", "secure_erase_claimed", "archive_code_signed"
  )) {
    if ($Manifest.safety.PSObject.Properties.Name -notcontains $field -or $Manifest.safety.PSObject.Properties[$field].Value -ne $false) {
      throw "Portable beta manifest safety.$field must be present and false."
    }
  }

  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  $seen = @{}
  foreach ($entry in @($Manifest.files)) {
    if (-not ($entry.path -is [string]) -or -not (Test-AvoraxPortableSafeZipPath $entry.path)) {
      throw "Portable beta manifest contains an unsafe file path."
    }
    $key = $entry.path.Replace('\', '/').ToLowerInvariant()
    if ($seen.ContainsKey($key)) { throw "Portable beta manifest contains duplicate file path: $($entry.path)" }
    $seen[$key] = $true
    if (-not ($entry.sha256 -is [string]) -or $entry.sha256 -cnotmatch '^[a-f0-9]{64}$') {
      throw "Portable beta manifest contains an invalid SHA-256 for $($entry.path)."
    }
    if (-not ($entry.bytes -is [int] -or $entry.bytes -is [long]) -or [int64]$entry.bytes -lt 0) {
      throw "Portable beta manifest contains an invalid byte count for $($entry.path)."
    }
    $fileFull = [System.IO.Path]::GetFullPath((Join-Path $rootFull ($entry.path -replace '/', '\')))
    if (-not $fileFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Portable beta manifest file escaped extraction root: $($entry.path)"
    }
    $file = Get-AvoraxGateFile $fileFull "portable beta manifest file"
    $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
    if ($item.Length -ne [int64]$entry.bytes) { throw "Portable beta manifest byte count mismatch: $($entry.path)" }
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($hash -cne $entry.sha256) { throw "Portable beta manifest SHA-256 mismatch: $($entry.path)" }
  }
  $actualFiles = @(Get-ChildItem -LiteralPath $rootFull -File -Recurse -Force -ErrorAction Stop)
  if ($actualFiles.Count -ne $seen.Count + 1) {
    throw "Portable beta archive file count does not equal manifest inventory plus manifest."
  }
  foreach ($file in $actualFiles) {
    $relative = $file.FullName.Substring($rootFull.Length).TrimStart('\', '/').Replace('\', '/')
    if ($relative -ne "portable-manifest.json" -and -not $seen.ContainsKey($relative.ToLowerInvariant())) {
      throw "Portable beta archive contains an unmanifested file: $relative"
    }
  }
  return $seen.Count
}

function Remove-AvoraxPortableSmokeTemp {
  param(
    [AllowNull()][string]$Path,
    [string]$TempBase,
    [string]$Prefix
  )
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
  $baseFull = [System.IO.Path]::GetFullPath($TempBase).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $parent = [System.IO.Directory]::GetParent($pathFull)
  $leaf = [System.IO.Path]::GetFileName($pathFull)
  if ($null -eq $parent -or -not $parent.FullName.TrimEnd('\', '/').Equals($baseFull, [StringComparison]::OrdinalIgnoreCase) -or
      $leaf -notmatch ('^' + [regex]::Escape($Prefix) + '[0-9a-f]{32}$')) {
    throw "Refusing to remove unverified portable smoke temp directory: $pathFull"
  }
  Get-AvoraxGateDirectory $pathFull "portable smoke temp directory" | Out-Null
  Remove-Item -LiteralPath $pathFull -Recurse -Force -ErrorAction Stop
}

$archive = Resolve-AvoraxPortableSmokeRepoChild $ArchivePath "portable beta smoke archive"
if ([System.IO.Path]::GetExtension($archive) -ne ".zip") { throw "Portable beta smoke archive must use .zip." }
$reportFull = Resolve-AvoraxPortableSmokeRepoChild $ReportPath "portable beta archive smoke report"
Remove-AvoraxGateRegularFileIfPresent $reportFull "previous portable beta archive smoke report"
$startedAt = Get-Date
$tempBase = Get-AvoraxGateDirectory ([System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())) "Windows temporary directory"
$extractRoot = Join-Path $tempBase ("avorax-portable-archive-smoke-" + [Guid]::NewGuid().ToString("N"))
$probeData = Join-Path $tempBase ("avorax-portable-runtime-smoke-" + [Guid]::NewGuid().ToString("N"))
$failureMessage = $null
$archiveEvidence = $null
$manifestCount = 0
$statusEvidence = $null
$lifecycleEvidence = $null
$negativeCases = @()

try {
  New-AvoraxGateDirectory $probeData "portable extracted runtime probe data" | Out-Null
  $traversalZip = Join-Path $probeData "traversal.zip"
  New-AvoraxPortableAdversarialZip $traversalZip @(
    [pscustomobject]@{ name = "../escape.txt"; text = "harmless traversal fixture" }
  )
  $negativeCases += Assert-AvoraxPortableArchiveRejected "parent-traversal" $traversalZip (Join-Path $probeData "traversal-out") "unsafe entry path"
  if (Test-Path -LiteralPath (Join-Path $probeData "escape.txt")) { throw "Traversal ZIP fixture wrote outside its extraction root." }

  $duplicateZip = Join-Path $probeData "duplicate.zip"
  New-AvoraxPortableAdversarialZip $duplicateZip @(
    [pscustomobject]@{ name = "same.txt"; text = "harmless duplicate one" },
    [pscustomobject]@{ name = "SAME.txt"; text = "harmless duplicate two" }
  )
  $negativeCases += Assert-AvoraxPortableArchiveRejected "case-insensitive-duplicate" $duplicateZip (Join-Path $probeData "duplicate-out") "duplicate entry path"

  $ratioZip = Join-Path $probeData "ratio.zip"
  New-AvoraxPortableAdversarialZip $ratioZip @(
    [pscustomobject]@{ name = "harmless-zeroes.bin"; zero_bytes = 8388608 }
  )
  $negativeCases += Assert-AvoraxPortableArchiveRejected "compression-ratio" $ratioZip (Join-Path $probeData "ratio-out") "compression-ratio limit"

  $archiveHashBefore = (Get-FileHash -LiteralPath (Get-AvoraxGateFile $archive "portable beta smoke archive") -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  $archiveEvidence = Expand-AvoraxPortableArchiveSafely $archive $extractRoot
  $archiveHashAfter = (Get-FileHash -LiteralPath $archive -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($archiveHashBefore -cne $archiveHashAfter) { throw "Portable beta archive changed during verification." }

  $manifest = Read-AvoraxPortableSmokeJson (Join-Path $extractRoot "portable-manifest.json") "portable beta manifest"
  $manifestCount = Assert-AvoraxPortableManifest $extractRoot $manifest
  $tamperedManifest = ConvertFrom-Json -InputObject ($manifest | ConvertTo-Json -Depth 100) -ErrorAction Stop
  $tamperedManifest.files[0].sha256 = "0" * 64
  try {
    Assert-AvoraxPortableManifest $extractRoot $tamperedManifest | Out-Null
    throw "Tampered portable manifest unexpectedly passed hash validation."
  } catch {
    $diagnostic = [string]$_.Exception.Message
    if ($diagnostic.IndexOf("manifest SHA-256 mismatch", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
      throw "Tampered portable manifest failed for an unexpected reason: $diagnostic"
    }
    $negativeCases += [ordered]@{
      name = "tampered-manifest-hash"
      rejected = $true
      diagnostic_contains = "manifest SHA-256 mismatch"
    }
  }

  $statusReport = Join-Path $probeData "status.json"
  $null = & (Join-Path $extractRoot "Avorax-Portable.ps1") -Action Status -DataRoot $probeData -ReportPath $statusReport -TimeoutSeconds 120
  $status = Read-AvoraxPortableSmokeJson $statusReport "extracted portable status report"
  if ($status.tool -ne "avorax-status" -or $status.ready -ne $true -or
      [int64]$status.native_signature_count -le 0 -or [int64]$status.native_rule_count -le 0 -or
      $status.native_self_test -ne $true -or $status.ipc -ne "stdio" -or $status.network_exposed -ne $false) {
    throw "Extracted portable status did not prove ready local stdio/no-network operation."
  }
  $statusEvidence = [ordered]@{
    ready = $true
    native_signature_count = [int64]$status.native_signature_count
    native_rule_count = [int64]$status.native_rule_count
    native_self_test = $true
    ipc = "stdio"
    network_exposed = $false
  }

  $extractedLifecycleReport = Join-Path $extractRoot "verification\extracted-lifecycle.json"
  $null = & (Join-Path $extractRoot "tools\windows\avorax-installed-core-lifecycle-probe.ps1") `
    -LocalCorePath (Join-Path $extractRoot "zentor_local_core.exe") `
    -EvidenceRoot $extractRoot `
    -ReportPath $extractedLifecycleReport `
    -TimeoutSeconds 120
  $lifecycle = Read-AvoraxPortableSmokeJson $extractedLifecycleReport "extracted portable lifecycle report"
  if ($lifecycle.status -ne "passed" -or $lifecycle.operations.restore.fixture_sha256_verified -ne $true -or
      $lifecycle.operations.restore.payload_removed -ne $true -or
      $lifecycle.operations.delete.source_absent -ne $true -or
      $lifecycle.operations.delete.payload_removed -ne $true -or
      $lifecycle.cleanup.isolated_temp_removed -ne $true) {
    throw "Extracted portable lifecycle did not preserve required postconditions."
  }
  $lifecycleEvidence = [ordered]@{
    status = "passed"
    restore_sha256_verified = $true
    restore_payload_removed = $true
    delete_source_absent = $true
    delete_payload_removed = $true
    isolated_temp_removed = $true
  }
} catch {
  $failureMessage = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
}

try {
  Remove-AvoraxPortableSmokeTemp $extractRoot $tempBase "avorax-portable-archive-smoke-"
  Remove-AvoraxPortableSmokeTemp $probeData $tempBase "avorax-portable-runtime-smoke-"
} catch {
  $cleanupError = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
  if ([string]::IsNullOrWhiteSpace($failureMessage)) { $failureMessage = $cleanupError } else {
    $failureMessage = Get-AvoraxGateBoundedDiagnostic ($failureMessage + " Cleanup also failed: " + $cleanupError)
  }
}

$statusValue = "passed"
if (-not [string]::IsNullOrWhiteSpace($failureMessage)) { $statusValue = "failed" }
$report = [ordered]@{
  schema_version = 1
  status = $statusValue
  tool = "avorax-portable-beta-archive-smoke"
  started_at_utc = $startedAt.ToUniversalTime().ToString("o")
  completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  elapsed_seconds = [Math]::Round(((Get-Date) - $startedAt).TotalSeconds, 3)
  archive_path = $archive
  archive_sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  archive_limits = [ordered]@{
    max_entries = $script:PortableMaxArchiveEntries
    max_entry_bytes = $script:PortableMaxEntryBytes
    max_total_bytes = $script:PortableMaxTotalBytes
    max_compression_ratio = $script:PortableMaxCompressionRatio
  }
  archive_evidence = $archiveEvidence
  manifest_file_count = $manifestCount
  status_evidence = $statusEvidence
  lifecycle_evidence = $lifecycleEvidence
  negative_cases = @($negativeCases)
  negative_case_count = @($negativeCases).Count
  cleanup_verified = -not (Test-Path -LiteralPath $extractRoot) -and -not (Test-Path -LiteralPath $probeData)
  safety = [ordered]@{
    live_malware_used = $false
    standard_eicar_file_created = $false
    defender_exclusion_required = $false
    machine_wide_changes = $false
    service_installation_attempted = $false
    driver_installation_attempted = $false
    persistent_monitoring_claimed = $false
    pre_execution_blocking_claimed = $false
    archive_code_signed = $false
  }
  error = if ($statusValue -eq "passed") { $null } else { $failureMessage }
}
Write-AvoraxGateJsonFileAtomic $reportFull $report 12 "portable beta archive smoke report"
if ($statusValue -ne "passed") { throw "Avorax portable beta archive smoke failed: $failureMessage" }

Write-Host "Avorax portable beta extracted-archive smoke passed."
Write-Host "Manifest files: $manifestCount"
Write-Host "Archive SHA-256: $($report.archive_sha256)"
Write-Host "Report: $reportFull"
