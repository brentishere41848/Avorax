param(
  [switch]$RequireAdmin,
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\setup_report.json")
)

$ErrorActionPreference = "Stop"
$miniFilterCheck = Join-Path $PSScriptRoot "..\..\pasus_windows_minifilter\scripts\setup-dev-env-check.ps1"
if ($RequireAdmin) {
  & $miniFilterCheck -RequireAdmin -ReportPath $ReportPath
} else {
  & $miniFilterCheck -ReportPath $ReportPath
}
