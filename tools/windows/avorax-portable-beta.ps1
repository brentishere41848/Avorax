param(
  [ValidateSet(
    "Status",
    "QuickScan",
    "FullScan",
    "FileScan",
    "FolderScan",
    "Watch",
    "QuarantineList",
    "QuarantineRestore",
    "QuarantineDelete",
    "QuarantineRescan",
    "AllowlistList",
    "AllowlistAdd",
    "AllowlistRemove"
  )]
  [string]$Action = "Status",
  [string[]]$Path = @(),
  [string]$TargetPath = "",
  [string]$QuarantineId = "",
  [string]$AllowlistId = "",
  [switch]$ConfirmAction,
  [switch]$AutoQuarantineConfirmed,
  [switch]$FailOnThreat,
  [string]$DataRoot = "",
  [string]$ReportPath = "",
  [ValidateRange(1, 10)]
  [int]$DurationSeconds = 8,
  [ValidateRange(5, 3600)]
  [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = "Stop"
$bundleRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$securityTools = Join-Path $bundleRoot "tools\security\avorax-security-gate-tools.ps1"
if (-not (Test-Path -LiteralPath $securityTools -PathType Leaf)) {
  throw "Avorax portable security helpers are missing: $securityTools"
}
. $securityTools

function Resolve-AvoraxPortableDataRoot {
  param([string]$ConfiguredRoot)

  $candidate = $ConfiguredRoot
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $localAppData = [Environment]::GetEnvironmentVariable("LOCALAPPDATA", "Process")
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
      throw "LOCALAPPDATA is unavailable. Pass an explicit local -DataRoot."
    }
    $candidate = Join-Path $localAppData "Avorax\PortableBeta"
  }
  if (-not [System.IO.Path]::IsPathRooted($candidate) -or $candidate.Contains([char]0) -or $candidate.Length -gt 4096) {
    throw "Portable DataRoot must be an absolute local Windows path."
  }
  return New-AvoraxGateDirectory ([System.IO.Path]::GetFullPath($candidate)) "Avorax portable data root"
}

function Resolve-AvoraxPortableReportPath {
  param(
    [string]$Root,
    [string]$ConfiguredPath,
    [string]$ActionName
  )

  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmssfff")
    $candidate = Join-Path $Root ("reports\" + $stamp + "-" + $ActionName.ToLowerInvariant() + ".json")
  } elseif (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $Root $candidate
  }
  if ($candidate.Contains([char]0) -or $candidate.Length -gt 4096) {
    throw "Portable report path is invalid."
  }

  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($candidate)
  $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if ($pathFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
      -not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Portable reports must stay under DataRoot: $pathFull"
  }
  if ([System.IO.Path]::GetExtension($pathFull) -ne ".json") {
    throw "Portable reports must use a .json extension: $pathFull"
  }
  Assert-AvoraxNoReparsePath $pathFull "Avorax portable report"
  New-AvoraxGateDirectory (Split-Path $pathFull -Parent) "Avorax portable report directory" | Out-Null
  return $pathFull
}

function Initialize-AvoraxPortableAllowlist {
  param([string]$PathValue)
  Assert-AvoraxNoReparsePath $PathValue "Avorax portable allowlist"
  if (Test-Path -LiteralPath $PathValue) {
    Get-AvoraxGateFile $PathValue "Avorax portable allowlist" | Out-Null
    return
  }

  $directory = New-AvoraxGateDirectory (Split-Path $PathValue -Parent) "Avorax portable config directory"
  $temporary = Join-Path $directory (".allowlist-" + [Guid]::NewGuid().ToString("N") + ".tmp")
  try {
    [System.IO.File]::WriteAllText($temporary, "[]", [System.Text.UTF8Encoding]::new($false))
    Get-AvoraxGateFile $temporary "temporary Avorax portable allowlist" | Out-Null
    [System.IO.File]::Move($temporary, $PathValue)
  } finally {
    Remove-AvoraxGateRegularFileIfPresent $temporary "temporary Avorax portable allowlist"
  }
}

function Read-AvoraxPortableReport {
  param(
    [string]$PathValue,
    [string]$ExpectedTool
  )
  $json = Read-AvoraxGateTextFileBounded $PathValue 2097152 "Avorax portable action report"
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "Avorax portable action report is empty: $PathValue"
  }
  try {
    $report = ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    throw "Avorax portable action report is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($report -is [array] -or -not ($report -is [pscustomobject])) {
    throw "Avorax portable action report must be one JSON object."
  }
  if ($report.PSObject.Properties.Name -notcontains "tool" -or $report.tool -ne $ExpectedTool) {
    throw "Avorax portable action report tool mismatch; expected $ExpectedTool."
  }
  return $report
}

$binary = Get-AvoraxGateFile (Join-Path $bundleRoot "zentor_local_core.exe") "Avorax portable local-core executable"
if ([System.IO.Path]::GetFileName($binary) -ine "zentor_local_core.exe") {
  throw "Avorax portable beta requires the canonical zentor_local_core.exe name."
}
$engineRoot = Get-AvoraxGateDirectory (Join-Path $bundleRoot "engine") "Avorax portable engine directory"
$windowsTools = Get-AvoraxGateDirectory (Join-Path $bundleRoot "tools\windows") "Avorax portable Windows tools directory"
$data = Resolve-AvoraxPortableDataRoot $DataRoot
$quarantineRoot = New-AvoraxGateDirectory (Join-Path $data "Quarantine") "Avorax portable quarantine directory"
$allowlistFile = Join-Path $data "config\allowlist.json"
Initialize-AvoraxPortableAllowlist $allowlistFile
$report = Resolve-AvoraxPortableReportPath $data $ReportPath $Action

Write-Host "Avorax Portable Scanner Beta"
Write-Host "Mode: manual scans and finite user-mode watch only"
Write-Host "Action: $Action"
Write-Host "Data: $data"

$expectedTool = ""
if ($Action -eq "Status") {
  $statusScript = Get-AvoraxGateFile (Join-Path $windowsTools "avorax-status.ps1") "Avorax portable status wrapper"
  $null = & $statusScript `
    -RepoRoot $data `
    -RequireReady `
    -LocalCorePath $binary `
    -ReportPath $report `
    -EngineRoot $engineRoot `
    -TimeoutSeconds $TimeoutSeconds
  $expectedTool = "avorax-status"
} elseif ($Action -in @("QuickScan", "FullScan", "FileScan", "FolderScan")) {
  $scanType = switch ($Action) {
    "QuickScan" { "Quick" }
    "FullScan" { "Full" }
    "FileScan" { "File" }
    "FolderScan" { "Folder" }
  }
  $scanScript = Get-AvoraxGateFile (Join-Path $windowsTools "avorax-local-scan.ps1") "Avorax portable local scan wrapper"
  $parameters = @{
    RepoRoot = $data
    ScanType = $scanType
    Path = @($Path)
    LocalCorePath = $binary
    ReportPath = $report
    DataRoot = $data
    QuarantineRoot = $quarantineRoot
    AllowlistFile = $allowlistFile
    EngineRoot = $engineRoot
    TimeoutSeconds = $TimeoutSeconds
  }
  if ($AutoQuarantineConfirmed) { $parameters.AutoQuarantineConfirmed = $true }
  if ($FailOnThreat) { $parameters.FailOnThreat = $true }
  $null = & $scanScript @parameters
  $expectedTool = "avorax-local-scan"
} elseif ($Action -eq "Watch") {
  $watchScript = Get-AvoraxGateFile (Join-Path $windowsTools "avorax-watch-scan.ps1") "Avorax portable finite watch wrapper"
  $parameters = @{
    RepoRoot = $data
    Path = @($Path)
    LocalCorePath = $binary
    ReportPath = $report
    DataRoot = $data
    QuarantineRoot = $quarantineRoot
    AllowlistFile = $allowlistFile
    EngineRoot = $engineRoot
    DurationSeconds = $DurationSeconds
    TimeoutSeconds = $TimeoutSeconds
  }
  if ($AutoQuarantineConfirmed) { $parameters.AutoQuarantineConfirmed = $true }
  if ($FailOnThreat) { $parameters.FailOnThreat = $true }
  $null = & $watchScript @parameters
  $expectedTool = "avorax-watch-scan"
} elseif ($Action -like "Quarantine*") {
  $quarantineAction = switch ($Action) {
    "QuarantineList" { "List" }
    "QuarantineRestore" { "Restore" }
    "QuarantineDelete" { "Delete" }
    "QuarantineRescan" { "Rescan" }
  }
  $quarantineScript = Get-AvoraxGateFile (Join-Path $windowsTools "avorax-quarantine.ps1") "Avorax portable quarantine wrapper"
  $parameters = @{
    RepoRoot = $data
    Action = $quarantineAction
    QuarantineId = $QuarantineId
    LocalCorePath = $binary
    ReportPath = $report
    DataRoot = $data
    QuarantineRoot = $quarantineRoot
    EngineRoot = $engineRoot
    TimeoutSeconds = $TimeoutSeconds
  }
  if ($ConfirmAction) { $parameters.ConfirmAction = $true }
  $null = & $quarantineScript @parameters
  $expectedTool = "avorax-quarantine"
} else {
  $allowlistAction = switch ($Action) {
    "AllowlistList" { "List" }
    "AllowlistAdd" { "Add" }
    "AllowlistRemove" { "Remove" }
  }
  $allowlistScript = Get-AvoraxGateFile (Join-Path $windowsTools "avorax-allowlist.ps1") "Avorax portable allowlist wrapper"
  $parameters = @{
    RepoRoot = $data
    Action = $allowlistAction
    TargetPath = $TargetPath
    AllowlistId = $AllowlistId
    LocalCorePath = $binary
    ReportPath = $report
    AllowlistFile = $allowlistFile
    TimeoutSeconds = $TimeoutSeconds
  }
  if ($ConfirmAction) { $parameters.ConfirmAction = $true }
  $null = & $allowlistScript @parameters
  $expectedTool = "avorax-allowlist"
}

$result = Read-AvoraxPortableReport $report $expectedTool
if ($expectedTool -eq "avorax-status" -and $result.ready -ne $true) {
  throw "Avorax portable engine is not ready. See report: $report"
}
if ($expectedTool -eq "avorax-local-scan" -and [int64]$result.scan_error_count -gt 0) {
  throw "Avorax portable scan completed with $($result.scan_error_count) visible scan error(s). See report: $report"
}

Write-Host "Avorax portable action completed successfully."
Write-Host "Report: $report"
Write-Host "Limit: this portable beta is not persistent background or pre-execution protection."
