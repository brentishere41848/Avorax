param(
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\selftest_report.json")
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
. (Join-Path $RepoRoot "tools\windows\avorax-system32-tools.ps1")

function Assert-AvoraxRepoChildPath([string]$Path, [string]$Base, [string]$DisplayName) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$DisplayName must resolve to a child path inside the Avorax repository root, not the repository root itself."
  }
  Assert-AvoraxPathUnder $pathFull $Base $DisplayName
}

Assert-AvoraxNoReparsePath $ReportPath "process guard self-test report"
Assert-AvoraxPathUnder $ReportPath $RepoRoot "process guard self-test report"
Assert-AvoraxRepoChildPath $ReportPath $RepoRoot "process guard self-test report"
$ReportDir = New-AvoraxRegularDirectory (Split-Path $ReportPath) "process guard self-test report directory" $RepoRoot
$running = $false
$service = ""
$errors = @()
$commandDiagnostics = [ordered]@{}
try {
  $sc = Get-AvoraxSystem32Tool "sc.exe"
  $commandDiagnostics.service_query = Invoke-AvoraxCommandDiagnostic $sc @("query", "ZentorProcessGuard") "sc query ZentorProcessGuard" 32768
  $service = $commandDiagnostics.service_query.output
  if ($commandDiagnostics.service_query.exit_code -ne 0) {
    $errors = @("sc query ZentorProcessGuard failed with exit code $($commandDiagnostics.service_query.exit_code): $(Get-AvoraxBoundedDiagnostic $service 4096)")
  }
  $running = $service -match "RUNNING"
} catch {
  $running = $false
  $errors = @(Get-AvoraxBoundedDiagnostic $_.Exception.Message 4096)
}
$report = [ordered]@{
  zentor_version = "0.1.12"
  timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
  process_guard = @{
    installed = ($service -match "SERVICE_NAME")
    running = $running
    monitor_only = $true
    pre_execution_deny = $false
  }
  command_diagnostics = $commandDiagnostics
  overall_result = if ($running) { "pass" } else { "fail" }
  errors = $errors
}
Write-AvoraxJsonFileAtomic $ReportPath $report 6 "process guard self-test report" $RepoRoot
if (-not $running) { exit 1 }
