param(
  [switch]$RequireAdmin,
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\setup_report.json")
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
. (Join-Path $repoRoot "tools\windows\avorax-system32-tools.ps1")

$miniFilterCheck = Get-AvoraxRegularFile (Join-Path $PSScriptRoot "..\..\zentor_windows_minifilter\scripts\setup-dev-env-check.ps1") "minifilter driver setup script"
Assert-AvoraxPathUnder $miniFilterCheck $repoRoot "minifilter driver setup script"
$powerShell = Get-AvoraxRegularFile ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
if ($RequireAdmin) {
  $setupDiagnostic = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $miniFilterCheck, "-RequireAdmin", "-ReportPath", $ReportPath) "process guard minifilter setup check" 32768
} else {
  $setupDiagnostic = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $miniFilterCheck, "-ReportPath", $ReportPath) "process guard minifilter setup check" 32768
}
if ($setupDiagnostic.exit_code -ne 0) {
  throw "Process guard minifilter setup check failed with exit code $($setupDiagnostic.exit_code): $($setupDiagnostic.output)"
}
