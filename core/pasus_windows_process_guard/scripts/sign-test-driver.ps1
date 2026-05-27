param(
  [string]$BuildOutputDir = $(Join-Path $PSScriptRoot "..\driver"),
  [string]$CertificateThumbprint,
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\signing_report.json")
)

$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot "..\..\pasus_windows_minifilter\scripts\sign-test-driver.ps1") -BuildOutputDir $BuildOutputDir -CertificateThumbprint $CertificateThumbprint -ReportPath $ReportPath
