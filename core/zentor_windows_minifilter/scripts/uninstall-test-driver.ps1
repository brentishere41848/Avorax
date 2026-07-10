param(
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\uninstall_report.json"),
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

Assert-AvoraxNoReparsePath $ReportPath "minifilter uninstall report"
Assert-AvoraxPathUnder $ReportPath $RepoRoot "minifilter uninstall report"
Assert-AvoraxRepoChildPath $ReportPath $RepoRoot "minifilter uninstall report"
$ReportDir = New-AvoraxRegularDirectory (Split-Path $ReportPath) "minifilter uninstall report directory" $RepoRoot
$setupScript = Get-AvoraxRegularFile (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") "driver setup script"
$powerShell = Get-AvoraxRegularFile ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$setupReportPath = Join-Path $ReportDir "setup_report.json"
$commandDiagnostics = [ordered]@{}

try {
  if (-not $ConfirmDriverUninstall) {
    throw "Refusing to uninstall the Avorax test minifilter without -ConfirmDriverUninstall."
  }
  $commandDiagnostics.setup = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $setupScript, "-RequireAdmin", "-ReportPath", $setupReportPath) "minifilter setup check" 32768
  if ($commandDiagnostics.setup.exit_code -ne 0) {
    throw "Driver setup check failed with exit code $($commandDiagnostics.setup.exit_code): $($commandDiagnostics.setup.output)"
  }
  [void](Get-AvoraxRegularFile $setupReportPath "driver setup report")
  Assert-AvoraxPathUnder $setupReportPath $RepoRoot "driver setup report"
  $fltmc = Get-AvoraxSystem32Tool "fltmc.exe"
  $sc = Get-AvoraxSystem32Tool "sc.exe"
  $commandErrors = @()
  $commandDiagnostics.filter_unload = Invoke-AvoraxCommandDiagnostic $fltmc @("unload", "ZentorAvFilter") "fltmc unload ZentorAvFilter"
  if ($commandDiagnostics.filter_unload.exit_code -ne 0) {
    $commandErrors += "fltmc unload ZentorAvFilter failed with exit code $($commandDiagnostics.filter_unload.exit_code): $($commandDiagnostics.filter_unload.output)"
  }
  $commandDiagnostics.service_delete = Invoke-AvoraxCommandDiagnostic $sc @("delete", "ZentorAvFilter") "sc delete ZentorAvFilter"
  if ($commandDiagnostics.service_delete.exit_code -ne 0) {
    $commandErrors += "sc delete ZentorAvFilter failed with exit code $($commandDiagnostics.service_delete.exit_code): $($commandDiagnostics.service_delete.output)"
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
  Write-AvoraxJsonFileAtomic $ReportPath $report 8 "minifilter uninstall report" $RepoRoot
} catch {
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    uninstalled = $false
    quarantine_deleted = $false
    command_diagnostics = $commandDiagnostics
    errors = @(Get-AvoraxBoundedDiagnostic $_.Exception.Message 4096)
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 8 "minifilter uninstall report" $RepoRoot
  throw
}

Write-Host "ZentorAvFilter test driver was stopped/removed if it was installed. User quarantine data was not deleted."
