param(
  [Parameter(Mandatory = $true)]
  [string]$MsiPath,
  [Parameter(Mandatory = $true)]
  [string]$PythonPath,
  [string]$ReportDirectory = "dist\windows-msi\verification",
  [string]$TemporaryBasePath = "",
  [switch]$KeepExtracted
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")

$maxTemporaryRootLength = 120
$maxInstallerLogBytes = 8MB
$maxSmokeReportBytes = 1MB
$maxMsiBytes = 512MB
$maxPayloadFiles = 10000
$maxPayloadBytes = 2GB

function Assert-ChildPath {
  param(
    [string]$Path,
    [string]$Base,
    [string]$Description
  )

  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $prefix = $baseFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must resolve inside $baseFull`: $pathFull"
  }
  return $pathFull
}

function Remove-OwnedExtractionRoot {
  param(
    [string]$Path,
    [string]$Base
  )

  $baseFull = Get-AvoraxGateDirectory $Base "MSI verification temporary base"
  $pathFull = Get-AvoraxGateDirectory $Path "owned MSI extraction root"
  Assert-ChildPath $pathFull $baseFull "Owned MSI extraction root" | Out-Null
  $leaf = Split-Path $pathFull -Leaf
  if ($leaf -notmatch '^avorax-msi-admin-[a-f0-9]{32}$') {
    throw "Refusing to remove an extraction root with an unexpected name: $pathFull"
  }

  $reparseItems = @(
    Get-ChildItem -LiteralPath $pathFull -Force -Recurse -ErrorAction Stop |
      Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 }
  )
  if ($reparseItems.Count -ne 0) {
    throw "Refusing to recursively remove an extraction root containing reparse points: $pathFull"
  }

  Remove-Item -LiteralPath $pathFull -Recurse -Force -ErrorAction Stop
  if (Test-Path -LiteralPath $pathFull) {
    throw "MSI extraction root still exists after cleanup: $pathFull"
  }
}

function Write-AtomicUtf8Json {
  param(
    [string]$Path,
    [object]$Value
  )

  $target = [System.IO.Path]::GetFullPath($Path)
  if (Test-Path -LiteralPath $target) {
    Get-AvoraxGateFile $target "existing MSI verification report" | Out-Null
  }
  $temporary = $target + ".tmp-" + [Guid]::NewGuid().ToString("N")
  try {
    $json = $Value | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText(
      $temporary,
      $json + [Environment]::NewLine,
      [System.Text.UTF8Encoding]::new($false)
    )
    Get-AvoraxGateFile $temporary "temporary MSI verification report" | Out-Null
    Move-Item -LiteralPath $temporary -Destination $target -Force -ErrorAction Stop
  } finally {
    if (Test-Path -LiteralPath $temporary) {
      Remove-AvoraxGateRegularFileIfPresent $temporary "temporary MSI verification report"
    }
  }
}

function Get-InstallerFailureDiagnostic {
  param([string]$LogPath)

  if (-not (Test-Path -LiteralPath $LogPath)) {
    return "Windows Installer did not produce a log."
  }
  $log = Get-AvoraxGateFile $LogPath "MSI administrative extraction log"
  $length = (Get-Item -LiteralPath $log -Force -ErrorAction Stop).Length
  if ($length -gt $maxInstallerLogBytes) {
    return "Windows Installer log exceeded $maxInstallerLogBytes bytes."
  }
  $matches = @(
    Select-String -LiteralPath $log -Pattern 'Product: .* -- Error [0-9]+\.|Error [0-9]+\.' -ErrorAction Stop |
      Select-Object -Last 3
  )
  if ($matches.Count -eq 0) {
    return "No bounded Windows Installer error line was found in the log."
  }
  return Get-AvoraxGateBoundedDiagnostic (($matches | ForEach-Object Line) -join " ") 2048
}

$repoRoot = Get-AvoraxGateDirectory (
  [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
) "Avorax repository root"
$msi = Get-AvoraxGateFile ([System.IO.Path]::GetFullPath($MsiPath)) "MSI package"
if ([System.IO.Path]::GetExtension($msi) -ine ".msi") {
  throw "MSI package must have a .msi extension: $msi"
}
$msiBytes = (Get-Item -LiteralPath $msi -Force -ErrorAction Stop).Length
if ($msiBytes -le 0 -or $msiBytes -gt $maxMsiBytes) {
  throw "MSI package size must be between 1 and $maxMsiBytes bytes: $msiBytes"
}
$msiSha256 = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
$python = Get-AvoraxRequiredTool ([System.IO.Path]::GetFullPath($PythonPath)) "Python interpreter"
$smokeScript = Get-AvoraxGateFile (
  (Join-Path $repoRoot "tools\packaging\smoke_local_core.py")
) "packaged local-core smoke script"

$reportPathFull = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ReportDirectory))
Assert-ChildPath $reportPathFull $repoRoot "MSI verification report directory" | Out-Null
$reportRoot = New-AvoraxGateDirectory $reportPathFull "MSI verification report directory"

if ([string]::IsNullOrWhiteSpace($TemporaryBasePath)) {
  $TemporaryBasePath = if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    $env:RUNNER_TEMP
  } else {
    $env:TEMP
  }
}
if ([string]::IsNullOrWhiteSpace($TemporaryBasePath)) {
  throw "A local temporary base path is required for MSI verification."
}
$temporaryBase = Get-AvoraxGateDirectory (
  [System.IO.Path]::GetFullPath($TemporaryBasePath)
) "MSI verification temporary base"
$extractRoot = Join-Path $temporaryBase (
  "avorax-msi-admin-" + [Guid]::NewGuid().ToString("N")
)
if ($extractRoot.Length -gt $maxTemporaryRootLength) {
  throw "MSI verification temporary root would be $($extractRoot.Length) characters; maximum is $maxTemporaryRootLength. Pass -TemporaryBasePath with a shorter local directory."
}
$extractRoot = New-AvoraxGateDirectory $extractRoot "owned MSI extraction root"

$installerLog = Join-Path $reportRoot "msi-admin-extract.log"
$smokeReport = Join-Path $reportRoot "windows-msi-extracted-core-smoke.json"
$verificationReport = Join-Path $reportRoot "windows-msi-administrative-verification.json"
$installedRoot = ""
$fileCount = 0
$payloadBytes = 0
$longestPayloadPathLength = 0
$msiexecResult = $null
try {
  foreach ($output in @($installerLog, $smokeReport, $verificationReport)) {
    Remove-AvoraxGateRegularFileIfPresent $output "prior MSI verification output"
  }

  $msiexec = Get-AvoraxRequiredTool (
    (Join-Path $env:SystemRoot "System32\msiexec.exe")
  ) "Windows Installer executable"
  $msiexecResult = Invoke-AvoraxGateCommandDiagnostic `
    -Tool $msiexec `
    -Arguments @("/a", $msi, "/qn", "TARGETDIR=$extractRoot", "/l*v", $installerLog) `
    -DisplayName "MSI administrative extraction" `
    -MaxLength 2048
  if ($msiexecResult.exit_code -ne 0) {
    $diagnostic = Get-InstallerFailureDiagnostic $installerLog
    throw "MSI administrative extraction failed with exit code $($msiexecResult.exit_code). $diagnostic Installer log: $installerLog"
  }

  $msiAfter = Get-AvoraxGateFile $msi "MSI package after administrative extraction"
  $msiBytesAfter = (Get-Item -LiteralPath $msiAfter -Force -ErrorAction Stop).Length
  $msiSha256After = (Get-FileHash -LiteralPath $msiAfter -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($msiBytesAfter -ne $msiBytes -or $msiSha256After -ne $msiSha256) {
    throw "MSI package changed during administrative extraction; refusing to execute extracted content."
  }

  $payloadItems = @(Get-ChildItem -LiteralPath $extractRoot -Force -Recurse -ErrorAction Stop)
  $reparseItems = @(
    $payloadItems |
      Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 }
  )
  if ($reparseItems.Count -ne 0) {
    throw "Administrative image contains unexpected reparse points. Installer log: $installerLog"
  }
  $payloadFiles = @($payloadItems | Where-Object { $_ -is [System.IO.FileInfo] })
  $fileCount = $payloadFiles.Count
  if ($fileCount -eq 0) {
    throw "Administrative image contains no files. Installer log: $installerLog"
  }
  if ($fileCount -gt $maxPayloadFiles) {
    throw "Administrative image contains $fileCount files; maximum is $maxPayloadFiles."
  }
  $payloadBytes = [int64](($payloadFiles | Measure-Object -Property Length -Sum).Sum)
  if ($payloadBytes -le 0 -or $payloadBytes -gt $maxPayloadBytes) {
    throw "Administrative image size must be between 1 and $maxPayloadBytes bytes: $payloadBytes"
  }
  $longestPayloadPathLength = ($payloadFiles.FullName | ForEach-Object Length | Measure-Object -Maximum).Maximum

  $apps = @($payloadFiles | Where-Object Name -eq "Avorax.exe")
  if ($apps.Count -ne 1) {
    throw "Expected exactly one administratively extracted Avorax.exe, found $($apps.Count). Installer log: $installerLog"
  }
  $installedRoot = $apps[0].Directory.FullName
  foreach ($name in @(
    "avorax_core_service.exe",
    "avorax_guard_service.exe",
    "avorax_update_service.exe",
    "install-manifest.json"
  )) {
    Get-AvoraxGateFile (Join-Path $installedRoot $name) "administrative image $name" | Out-Null
  }
  Get-AvoraxGateDirectory (Join-Path $installedRoot "engine") "administrative image engine directory" | Out-Null

  $smokeResult = Invoke-AvoraxGateCommandDiagnostic `
    -Tool $python `
    -Arguments @(
      $smokeScript,
      "--core", (Join-Path $installedRoot "avorax_core_service.exe"),
      "--engine-root", $installedRoot,
      "--report", $smokeReport
    ) `
    -DisplayName "extracted MSI local-core smoke" `
    -MaxLength 4096 `
    -WorkingDirectory $repoRoot
  if ($smokeResult.exit_code -ne 0) {
    throw "Extracted MSI local-core smoke failed with exit code $($smokeResult.exit_code): $($smokeResult.output) Installer log: $installerLog"
  }
  if (-not (Test-Path -LiteralPath $smokeReport)) {
    throw "Extracted MSI local-core smoke exited successfully but did not produce its required report: $smokeReport"
  }
  $smokeJson = Read-AvoraxGateTextFileBounded $smokeReport $maxSmokeReportBytes "extracted MSI smoke report"
  $smokeEvidence = ConvertFrom-Json -InputObject $smokeJson -ErrorAction Stop
  if ($smokeEvidence.status -ne "passed") {
    throw "Extracted MSI smoke report did not record status=passed. Installer log: $installerLog"
  }
  if ($smokeEvidence.fixture_policy.live_malware_used -ne $false -or
      $smokeEvidence.fixture_policy.machine_wide_changes -ne $false -or
      $smokeEvidence.fixture_policy.network_access_required -ne $false -or
      $smokeEvidence.fixture_policy.standard_eicar_string_written -ne $false) {
    throw "Extracted MSI smoke report violates the benign, non-installing fixture policy. Installer log: $installerLog"
  }
} finally {
  if (-not $KeepExtracted -and (Test-Path -LiteralPath $extractRoot)) {
    Remove-OwnedExtractionRoot $extractRoot $temporaryBase
  }
}

$report = [ordered]@{
  schema_version = 1
  status = "passed"
  msi = [ordered]@{
    file = Split-Path $msi -Leaf
    bytes = [int64]$msiBytes
    sha256 = $msiSha256
  }
  administrative_extraction = [ordered]@{
    msiexec_exit_code = [int]$msiexecResult.exit_code
    file_count = [int]$fileCount
    payload_bytes = [int64]$payloadBytes
    longest_payload_path_length = [int]$longestPayloadPathLength
    temporary_root_length = [int]$extractRoot.Length
    temporary_root_removed = (-not $KeepExtracted)
  }
  smoke_report = Split-Path $smokeReport -Leaf
  fixture_policy = [ordered]@{
    live_malware_used = $false
    machine_wide_changes = $false
    network_access_required = $false
    standard_eicar_string_written = $false
  }
  technical_limits = @(
    "administrative extraction is not a normal MSI installation",
    "no service registration, service start, GUI click-through, driver, or pre-execution proof"
  )
}
Write-AtomicUtf8Json $verificationReport $report
$report | ConvertTo-Json -Depth 8 -Compress
