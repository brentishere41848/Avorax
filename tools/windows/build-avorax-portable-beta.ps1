param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$Version = "0.1.0-beta.1",
  [string]$LocalCorePath = "",
  [string]$OutputRoot = "",
  [string]$ArchivePath = "",
  [string]$ReportPath = ".workflow\ultracode\avorax-hardening\results\portable-beta-build-report.json",
  [switch]$ReplaceExisting
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
. (Join-Path $repo "tools\security\avorax-security-gate-tools.ps1")

function Resolve-AvoraxPortableRepoChildPath {
  param(
    [string]$Root,
    [string]$ConfiguredPath,
    [string]$Description
  )
  $candidate = $ConfiguredPath
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $Root $candidate
  }
  if ($candidate.Contains([char]0) -or $candidate.Length -gt 4096) {
    throw "$Description path is invalid."
  }
  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($candidate)
  $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if ($pathFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
      -not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must stay inside the repository: $pathFull"
  }
  Assert-AvoraxNoReparsePath $pathFull $Description
  return $pathFull
}

function Resolve-AvoraxPortableDistChildPath {
  param(
    [string]$DistRoot,
    [string]$ConfiguredPath,
    [string]$Description
  )
  $pathFull = Resolve-AvoraxPortableRepoChildPath $repo $ConfiguredPath $Description
  $distFull = [System.IO.Path]::GetFullPath($DistRoot).TrimEnd('\', '/')
  $prefix = $distFull + [System.IO.Path]::DirectorySeparatorChar
  if ($pathFull.Equals($distFull, [StringComparison]::OrdinalIgnoreCase) -or
      -not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must stay inside the repository dist directory: $pathFull"
  }
  return $pathFull
}

function Copy-AvoraxPortableFile {
  param(
    [string]$Source,
    [string]$Destination,
    [string]$Description
  )
  $sourceFile = Get-AvoraxGateFile $Source $Description
  Assert-AvoraxNoReparsePath $Destination "$Description destination"
  New-AvoraxGateDirectory (Split-Path $Destination -Parent) "$Description destination directory" | Out-Null
  Copy-Item -LiteralPath $sourceFile -Destination $Destination -Force -ErrorAction Stop
  Get-AvoraxGateFile $Destination "$Description copied file" | Out-Null
}

function Copy-AvoraxPortableTree {
  param(
    [string]$Source,
    [string]$Destination,
    [string]$Description
  )
  $sourceRoot = Get-AvoraxGateDirectory $Source $Description
  $destinationRoot = New-AvoraxGateDirectory $Destination "$Description destination"
  $items = @(Get-ChildItem -LiteralPath $sourceRoot -Force -Recurse -ErrorAction Stop)
  foreach ($item in $items) {
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Description must not include reparse points: $($item.FullName)"
    }
  }
  foreach ($directory in @($items | Where-Object { $_ -is [System.IO.DirectoryInfo] } | Sort-Object { $_.FullName.Length })) {
    $relative = $directory.FullName.Substring($sourceRoot.Length).TrimStart('\', '/')
    if (-not [string]::IsNullOrWhiteSpace($relative)) {
      New-AvoraxGateDirectory (Join-Path $destinationRoot $relative) "$Description child directory" | Out-Null
    }
  }
  foreach ($file in @($items | Where-Object { $_ -is [System.IO.FileInfo] })) {
    $relative = $file.FullName.Substring($sourceRoot.Length).TrimStart('\', '/')
    Copy-AvoraxPortableFile $file.FullName (Join-Path $destinationRoot $relative) "$Description child file"
  }
}

function Write-AvoraxPortableTextFileAtomic {
  param(
    [string]$Path,
    [string]$Text,
    [string]$Description
  )
  Assert-AvoraxNoReparsePath $Path $Description
  $directory = New-AvoraxGateDirectory (Split-Path $Path -Parent) "$Description directory"
  $temporary = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [Guid]::NewGuid().ToString("N") + ".tmp")
  try {
    [System.IO.File]::WriteAllText($temporary, $Text, [System.Text.UTF8Encoding]::new($false))
    Get-AvoraxGateFile $temporary "temporary $Description" | Out-Null
    [System.IO.File]::Move($temporary, $Path)
  } finally {
    Remove-AvoraxGateRegularFileIfPresent $temporary "temporary $Description"
  }
}

function Remove-AvoraxPortableOutputDirectory {
  param(
    [string]$Path,
    [string]$DistRoot,
    [string]$Description
  )
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $distFull = [System.IO.Path]::GetFullPath($DistRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $leaf = [System.IO.Path]::GetFileName($pathFull)
  $prefix = $distFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
      $leaf -notmatch '^Avorax-Portable-Beta-[A-Za-z0-9._-]+$') {
    throw "Refusing to remove unverified $Description directory: $pathFull"
  }
  Get-AvoraxGateDirectory $pathFull $Description | Out-Null
  Remove-Item -LiteralPath $pathFull -Recurse -Force -ErrorAction Stop
}

function Remove-AvoraxPortableStageDirectory {
  param(
    [AllowNull()][string]$Path,
    [string]$DistRoot
  )
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
  $distFull = [System.IO.Path]::GetFullPath($DistRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $parent = [System.IO.Directory]::GetParent($pathFull)
  $leaf = [System.IO.Path]::GetFileName($pathFull)
  if ($null -eq $parent -or -not $parent.FullName.TrimEnd('\', '/').Equals($distFull, [StringComparison]::OrdinalIgnoreCase) -or
      $leaf -notmatch '^\.avorax-portable-stage-[0-9a-f]{32}$') {
    throw "Refusing to remove unverified portable stage directory: $pathFull"
  }
  Get-AvoraxGateDirectory $pathFull "portable stage directory" | Out-Null
  Remove-Item -LiteralPath $pathFull -Recurse -Force -ErrorAction Stop
}

function Remove-AvoraxPortableProbeData {
  param(
    [AllowNull()][string]$Path,
    [string]$TempRoot
  )
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
  $tempFull = [System.IO.Path]::GetFullPath($TempRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $parent = [System.IO.Directory]::GetParent($pathFull)
  $leaf = [System.IO.Path]::GetFileName($pathFull)
  if ($null -eq $parent -or -not $parent.FullName.TrimEnd('\', '/').Equals($tempFull, [StringComparison]::OrdinalIgnoreCase) -or
      $leaf -notmatch '^avorax-portable-build-probe-[0-9a-f]{32}$') {
    throw "Refusing to remove unverified portable probe data: $pathFull"
  }
  Get-AvoraxGateDirectory $pathFull "portable build probe data" | Out-Null
  Remove-Item -LiteralPath $pathFull -Recurse -Force -ErrorAction Stop
}

function Read-AvoraxPortableJsonFile {
  param(
    [string]$Path,
    [string]$Description
  )
  $json = Read-AvoraxGateTextFileBounded $Path 2097152 $Description
  if ([string]::IsNullOrWhiteSpace($json)) { throw "$Description is empty: $Path" }
  try {
    $value = ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    throw "$Description is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($value -is [array] -or -not ($value -is [pscustomobject])) {
    throw "$Description must be one JSON object."
  }
  return $value
}

function Get-AvoraxPortableFileInventory {
  param([string]$Root)
  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
  $rows = @()
  foreach ($file in @(Get-ChildItem -LiteralPath $rootFull -File -Recurse -Force -ErrorAction Stop | Sort-Object FullName)) {
    if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Portable output contains a reparse-point file: $($file.FullName)"
    }
    $relative = $file.FullName.Substring($rootFull.Length).TrimStart('\', '/') -replace '\\', '/'
    $rows += [ordered]@{
      path = $relative
      sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
      bytes = [int64]$file.Length
    }
  }
  return @($rows)
}

if ($Version -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
  throw "Portable beta Version contains unsupported characters."
}
$dist = New-AvoraxGateDirectory (Join-Path $repo "dist") "repository dist directory"
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
  $OutputRoot = Join-Path $dist ("Avorax-Portable-Beta-" + $Version)
}
if ([string]::IsNullOrWhiteSpace($ArchivePath)) {
  $ArchivePath = Join-Path $dist ("Avorax-Portable-Beta-" + $Version + ".zip")
}
$output = Resolve-AvoraxPortableDistChildPath $dist $OutputRoot "portable beta output"
$archive = Resolve-AvoraxPortableDistChildPath $dist $ArchivePath "portable beta archive"
if ([System.IO.Path]::GetFileName($output) -notmatch '^Avorax-Portable-Beta-[A-Za-z0-9._-]+$') {
  throw "Portable beta output directory name is invalid: $output"
}
if ([System.IO.Path]::GetExtension($archive) -ne ".zip") {
  throw "Portable beta archive must use a .zip extension: $archive"
}
$reportFull = Resolve-AvoraxPortableRepoChildPath $repo $ReportPath "portable beta build report"
$binaryCandidate = $LocalCorePath
if ([string]::IsNullOrWhiteSpace($binaryCandidate)) {
  $binaryCandidate = Join-Path $repo "target\release\zentor_local_core.exe"
}
$binary = Get-AvoraxGateFile ([System.IO.Path]::GetFullPath($binaryCandidate)) "portable beta release local-core"
if ([System.IO.Path]::GetFileName($binary) -ine "zentor_local_core.exe") {
  throw "Portable beta builder expects zentor_local_core.exe, got: $binary"
}

$startedAt = Get-Date
$stage = Join-Path $dist (".avorax-portable-stage-" + [Guid]::NewGuid().ToString("N"))
$tempBase = Get-AvoraxGateDirectory ([System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())) "Windows temporary directory"
$probeData = Join-Path $tempBase ("avorax-portable-build-probe-" + [Guid]::NewGuid().ToString("N"))
$outputCreated = $false
$failureMessage = $null
$statusEvidence = $null
$lifecycleEvidence = $null
$manifest = $null
$archiveSha256 = $null

Remove-AvoraxGateRegularFileIfPresent $reportFull "previous portable beta build report"
try {
  if (Test-Path -LiteralPath $output) {
    if (-not $ReplaceExisting) {
      throw "Portable beta output already exists; pass -ReplaceExisting to replace this verified dist child: $output"
    }
    Remove-AvoraxPortableOutputDirectory $output $dist "portable beta output"
  }
  if (Test-Path -LiteralPath $archive) {
    if (-not $ReplaceExisting) {
      throw "Portable beta archive already exists; pass -ReplaceExisting to replace this regular file: $archive"
    }
    Remove-AvoraxGateRegularFileIfPresent $archive "existing portable beta archive"
  }

  New-AvoraxGateDirectory $stage "portable beta stage" | Out-Null
  Copy-AvoraxPortableFile $binary (Join-Path $stage "zentor_local_core.exe") "portable beta local-core"
  $stageEngine = New-AvoraxGateDirectory (Join-Path $stage "engine") "portable beta engine directory"
  foreach ($engineArea in @("signatures", "rules", "ml", "trust")) {
    Copy-AvoraxPortableTree (Join-Path $repo "assets\zentor_native\$engineArea") (Join-Path $stageEngine $engineArea) "portable beta native engine $engineArea"
  }
  Write-AvoraxGateJsonFileAtomic (Join-Path $stageEngine "config\engine.default.json") ([ordered]@{
    product = "Avorax Portable Scanner Beta"
    engine = "Avorax Native Engine"
    installed_layout_version = 1
    compatibility_engines_enabled = $false
    persistent_monitoring = $false
    pre_execution_blocking = $false
  }) 4 "portable beta engine config"

  $stageWindowsTools = New-AvoraxGateDirectory (Join-Path $stage "tools\windows") "portable beta Windows tools"
  foreach ($tool in @(
    "avorax-local-scan.ps1",
    "avorax-quarantine.ps1",
    "avorax-status.ps1",
    "avorax-watch-scan.ps1",
    "avorax-allowlist.ps1",
    "avorax-core-health-probe.ps1",
    "avorax-installed-core-lifecycle-probe.ps1"
  )) {
    Copy-AvoraxPortableFile (Join-Path $repo "tools\windows\$tool") (Join-Path $stageWindowsTools $tool) "portable beta $tool"
  }
  Copy-AvoraxPortableFile (Join-Path $repo "tools\security\avorax-security-gate-tools.ps1") (Join-Path $stage "tools\security\avorax-security-gate-tools.ps1") "portable beta security helpers"
  Copy-AvoraxPortableFile (Join-Path $repo "tools\windows\avorax-portable-beta.ps1") (Join-Path $stage "Avorax-Portable.ps1") "portable beta launcher"
  Copy-AvoraxPortableFile (Join-Path $repo "docs\portable-beta.md") (Join-Path $stage "README.md") "portable beta README"
  foreach ($document in @("limitations.md", "safe-malware-testing.md", "quarantine.md")) {
    Copy-AvoraxPortableFile (Join-Path $repo "docs\$document") (Join-Path $stage "docs\$document") "portable beta $document"
  }

  Write-AvoraxPortableTextFileAtomic (Join-Path $stage "Avorax-Status.cmd") @'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Avorax-Portable.ps1" -Action Status
echo.
pause
'@ "portable status command"
  Write-AvoraxPortableTextFileAtomic (Join-Path $stage "Avorax-Quick-Scan.cmd") @'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Avorax-Portable.ps1" -Action QuickScan
echo.
pause
'@ "portable quick scan command"

  [System.IO.Directory]::Move($stage, $output)
  $stage = $null
  $outputCreated = $true
  New-AvoraxGateDirectory $probeData "portable build probe data" | Out-Null
  $statusReport = Join-Path $probeData "status.json"
  $null = & (Join-Path $output "Avorax-Portable.ps1") `
    -Action Status `
    -DataRoot $probeData `
    -ReportPath $statusReport `
    -TimeoutSeconds 120
  $status = Read-AvoraxPortableJsonFile $statusReport "portable packaged status report"
  if ($status.tool -ne "avorax-status" -or $status.ready -ne $true -or
      $status.engine_status -ne "available" -or $status.native_engine_status -ne "ready" -or
      [int64]$status.native_signature_count -le 0 -or [int64]$status.native_rule_count -le 0 -or
      $status.native_self_test -ne $true -or $status.ipc -ne "stdio" -or $status.network_exposed -ne $false) {
    throw "Portable packaged status did not prove a ready local stdio/no-network native engine."
  }
  $statusEvidence = [ordered]@{
    status = "passed"
    ready = $true
    engine_status = [string]$status.engine_status
    native_engine_status = [string]$status.native_engine_status
    native_signature_count = [int64]$status.native_signature_count
    native_rule_count = [int64]$status.native_rule_count
    native_self_test = [bool]$status.native_self_test
    ipc = [string]$status.ipc
    network_exposed = [bool]$status.network_exposed
  }
  Write-AvoraxGateJsonFileAtomic (Join-Path $output "verification\portable-status.json") $statusEvidence 6 "portable status evidence"

  $lifecycleReport = Join-Path $output "verification\portable-lifecycle.json"
  $null = & (Join-Path $output "tools\windows\avorax-installed-core-lifecycle-probe.ps1") `
    -LocalCorePath (Join-Path $output "zentor_local_core.exe") `
    -EvidenceRoot $output `
    -ReportPath $lifecycleReport `
    -TimeoutSeconds 120
  $lifecycle = Read-AvoraxPortableJsonFile $lifecycleReport "portable packaged lifecycle report"
  if ($lifecycle.status -ne "passed" -or $lifecycle.tool -ne "avorax-installed-core-lifecycle-probe" -or
      $lifecycle.operations.restore.fixture_sha256_verified -ne $true -or
      $lifecycle.operations.restore.payload_removed -ne $true -or
      $lifecycle.operations.delete.source_absent -ne $true -or
      $lifecycle.operations.delete.payload_removed -ne $true -or
      $lifecycle.cleanup.isolated_temp_removed -ne $true) {
    throw "Portable packaged lifecycle report is missing required postconditions."
  }
  $lifecycleEvidence = [ordered]@{
    status = "passed"
    scan_restore = $true
    list = $true
    restore_sha256_verified = $true
    restore_payload_removed = $true
    scan_delete = $true
    delete_source_absent = $true
    delete_payload_removed = $true
    isolated_temp_removed = $true
  }

  Remove-AvoraxPortableProbeData $probeData $tempBase
  $probeData = $null

  $inventory = @(Get-AvoraxPortableFileInventory $output)
  if ($inventory.Count -lt 10) {
    throw "Portable beta inventory is unexpectedly small: $($inventory.Count) files."
  }
  $manifest = [ordered]@{
    schema_version = 1
    product = "Avorax Portable Scanner Beta"
    version = $Version
    package_type = "portable-manual-user-mode-scanner"
    created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    files = $inventory
    verification = [ordered]@{
      status = $statusEvidence
      lifecycle = $lifecycleEvidence
    }
    safety = [ordered]@{
      live_malware_included = $false
      standard_eicar_file_included = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_or_driver_installation = $false
      persistent_monitoring_claimed = $false
      pre_execution_blocking_claimed = $false
      secure_erase_claimed = $false
      archive_code_signed = $false
    }
    limitations = @(
      "manual scans and finite explicit-folder user-mode watch only",
      "not a Microsoft Defender replacement",
      "no Windows service, startup persistence, driver, or pre-execution blocking",
      "local ZIP is not code-signed and is not a production release artifact"
    )
  }
  Write-AvoraxGateJsonFileAtomic (Join-Path $output "portable-manifest.json") $manifest 12 "portable beta manifest"

  Compress-Archive -Path (Join-Path $output "*") -DestinationPath $archive -CompressionLevel Optimal -ErrorAction Stop
  $archiveFile = Get-AvoraxGateFile $archive "portable beta ZIP archive"
  $archiveItem = Get-Item -LiteralPath $archiveFile -Force -ErrorAction Stop
  if ($archiveItem.Length -le 0) { throw "Portable beta ZIP archive is empty." }
  $archiveSha256 = (Get-FileHash -LiteralPath $archiveFile -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
} catch {
  $failureMessage = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
}

try {
  Remove-AvoraxPortableStageDirectory $stage $dist
  Remove-AvoraxPortableProbeData $probeData $tempBase
  if (-not [string]::IsNullOrWhiteSpace($failureMessage)) {
    Remove-AvoraxGateRegularFileIfPresent $archive "failed portable beta archive"
    if ($outputCreated) {
      Remove-AvoraxPortableOutputDirectory $output $dist "failed portable beta output"
    }
  }
} catch {
  $cleanupError = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
  if ([string]::IsNullOrWhiteSpace($failureMessage)) {
    $failureMessage = $cleanupError
  } else {
    $failureMessage = Get-AvoraxGateBoundedDiagnostic ($failureMessage + " Cleanup also failed: " + $cleanupError)
  }
}

$buildStatus = "passed"
if (-not [string]::IsNullOrWhiteSpace($failureMessage)) { $buildStatus = "failed" }
$buildReport = [ordered]@{
  schema_version = 1
  status = $buildStatus
  tool = "build-avorax-portable-beta"
  version = $Version
  started_at_utc = $startedAt.ToUniversalTime().ToString("o")
  completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  elapsed_seconds = [Math]::Round(((Get-Date) - $startedAt).TotalSeconds, 3)
  output_root = if ($buildStatus -eq "passed") { $output } else { $null }
  archive_path = if ($buildStatus -eq "passed") { $archive } else { $null }
  archive_sha256 = if ($buildStatus -eq "passed") { $archiveSha256 } else { $null }
  local_core_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  status_evidence = $statusEvidence
  lifecycle_evidence = $lifecycleEvidence
  manifest_file_count = if ($null -ne $manifest) { @($manifest.files).Count } else { 0 }
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
  error = if ($buildStatus -eq "passed") { $null } else { $failureMessage }
}
Write-AvoraxGateJsonFileAtomic $reportFull $buildReport 12 "portable beta build report"

if ($buildStatus -ne "passed") {
  throw "Avorax portable beta build failed: $failureMessage"
}
Write-Host "Avorax portable beta build passed."
Write-Host "Output: $output"
Write-Host "Archive: $archive"
Write-Host "Archive SHA-256: $archiveSha256"
Write-Host "Build report: $reportFull"
Write-Host "Limit: portable manual/finite user-mode scanner only; no service, driver, persistence, or pre-execution claim."
