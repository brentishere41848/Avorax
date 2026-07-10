param(
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\uninstall_report.json"),
  [switch]$ConfirmDriverUninstall
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

Assert-AvoraxNoReparsePath $ReportPath "process guard uninstall report"
Assert-AvoraxPathUnder $ReportPath $RepoRoot "process guard uninstall report"
Assert-AvoraxRepoChildPath $ReportPath $RepoRoot "process guard uninstall report"
$ReportDir = New-AvoraxRegularDirectory (Split-Path $ReportPath) "process guard uninstall report directory" $RepoRoot
$setupScript = Get-AvoraxRegularFile (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") "driver setup script"
$powerShell = Get-AvoraxRegularFile ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$setupReportPath = Join-Path $ReportDir "setup_report.json"
$commandDiagnostics = [ordered]@{}
try {
  if (-not $ConfirmDriverUninstall) {
    throw "Refusing to uninstall the Avorax process-guard test driver without -ConfirmDriverUninstall."
  }
  $commandDiagnostics.setup = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $setupScript, "-RequireAdmin", "-ReportPath", $setupReportPath) "process guard setup check" 32768
  if ($commandDiagnostics.setup.exit_code -ne 0) {
    throw "Process guard setup check failed with exit code $($commandDiagnostics.setup.exit_code): $($commandDiagnostics.setup.output)"
  }
  [void](Get-AvoraxRegularFile $setupReportPath "driver setup report")
  Assert-AvoraxPathUnder $setupReportPath $RepoRoot "driver setup report"
  $sc = Get-AvoraxSystem32Tool "sc.exe"
  $commandErrors = @()
  $commandDiagnostics.service_stop = Invoke-AvoraxCommandDiagnostic $sc @("stop", "ZentorProcessGuard") "sc stop ZentorProcessGuard"
  if ($commandDiagnostics.service_stop.exit_code -ne 0) {
    $commandErrors += "sc stop ZentorProcessGuard failed with exit code $($commandDiagnostics.service_stop.exit_code): $($commandDiagnostics.service_stop.output)"
  }
  $commandDiagnostics.service_delete = Invoke-AvoraxCommandDiagnostic $sc @("delete", "ZentorProcessGuard") "sc delete ZentorProcessGuard"
  if ($commandDiagnostics.service_delete.exit_code -ne 0) {
    $commandErrors += "sc delete ZentorProcessGuard failed with exit code $($commandDiagnostics.service_delete.exit_code): $($commandDiagnostics.service_delete.output)"
  }
  if ($commandErrors.Count -gt 0) {
    throw ($commandErrors -join "; ")
  }
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    uninstalled = $true
    quarantine_deleted = $false
    command_diagnostics = $commandDiagnostics
    errors = @()
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 8 "process guard uninstall report" $RepoRoot
} catch {
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    uninstalled = $false
    quarantine_deleted = $false
    command_diagnostics = $commandDiagnostics
    errors = @(Get-AvoraxBoundedDiagnostic $_.Exception.Message 4096)
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 8 "process guard uninstall report" $RepoRoot
  throw
}
