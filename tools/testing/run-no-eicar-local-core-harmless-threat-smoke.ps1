param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [string]$ReportPath = "",
  [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")

function Resolve-NoEicarSmokeReportPath {
  param(
    [string]$Path,
    [string]$RepositoryRoot
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Join-Path $RepositoryRoot ".workflow\ultracode\avorax-hardening\results\no-eicar-harmless-threat-smoke.json"
  } elseif (-not [System.IO.Path]::IsPathRooted($Path)) {
    $Path = Join-Path $RepositoryRoot $Path
  }

  $rootFull = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path)
  Assert-AvoraxNoReparsePath $pathFull "no-EICAR harmless-threat smoke report"
  if ($pathFull.TrimEnd('\', '/').Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "no-EICAR harmless-threat smoke report must be a child path inside the repository root."
  }
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "no-EICAR harmless-threat smoke report must stay under $RepositoryRoot`: $pathFull"
  }
  $pathFull
}

function Resolve-OptionalLocalCorePathForReport {
  param(
    [string]$RepositoryRoot,
    [string]$ConfiguredPath
  )

  if ([string]::IsNullOrWhiteSpace($ConfiguredPath)) {
    return Join-Path $RepositoryRoot "target\release\zentor_local_core.exe"
  }
  [System.IO.Path]::GetFullPath($ConfiguredPath)
}

$repo = Get-AvoraxGateDirectory (Resolve-Path -LiteralPath $RepoRoot).Path "repository root"
$underlyingSmoke = Get-AvoraxGateFile (Join-Path $PSScriptRoot "run-release-local-core-smoke.ps1") "release local-core safe hash fixture smoke"
$report = Resolve-NoEicarSmokeReportPath $ReportPath $repo
$started = Get-Date
$status = "failed"
$errorMessage = $null

try {
  & $underlyingSmoke -RepoRoot $repo -LocalCorePath $LocalCorePath -TimeoutSeconds $TimeoutSeconds
  $status = "passed"
} catch {
  $errorMessage = Get-AvoraxGateBoundedDiagnostic $_.Exception.Message
}

$elapsed = ((Get-Date) - $started).TotalSeconds
$body = [ordered]@{
  schema_version = 1
  status = $status
  repository = $repo
  started_at_utc = $started.ToUniversalTime().ToString("o")
  completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  elapsed_seconds = [Math]::Round($elapsed, 1)
  local_core_path = Resolve-OptionalLocalCorePathForReport $repo $LocalCorePath
  underlying_script = $underlyingSmoke
  fixture_policy = [ordered]@{
    live_malware_used = $false
    standard_eicar_file_created = $false
    standard_eicar_string_written = $false
    defender_exclusion_required = $false
    machine_wide_changes = $false
    network_access_required = $false
    fixture_description = "Harmless exact-hash known-bad bytes generated in an isolated temporary directory; no standard EICAR content."
  }
  verified_flow = @(
    "detect-only scan reports threatsFound without quarantine",
    "confirmed-only mode quarantines the harmless exact-hash fixture",
    "quarantine payload uses a safe .avoraxq extension",
    "list_quarantine returns the quarantined record",
    "restore_quarantine_item restores the original fixture bytes"
  )
  limits = @(
    "release local-core binary proof only",
    "no installed UI click-through evidence",
    "no installed service or driver evidence",
    "no pre-execution blocking claim"
  )
  error = $errorMessage
}
Write-AvoraxGateJsonFileAtomic $report $body 6 "no-EICAR harmless-threat smoke report"

if ($status -ne "passed") {
  throw "no-EICAR harmless-threat smoke failed: $errorMessage"
}

Write-Host "Avorax no-EICAR harmless-threat smoke passed."
Write-Host "Report: $report"
