param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [ValidateSet("x64")]
  [string]$Platform = "x64",
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\build_report.json")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null
$project = Join-Path $PSScriptRoot "..\driver\PasusProcessGuard.vcxproj"

try {
  & (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") -ReportPath (Join-Path (Split-Path $ReportPath) "setup_report.json")
  $setup = Get-Content -Raw -LiteralPath (Join-Path (Split-Path $ReportPath) "setup_report.json") | ConvertFrom-Json
  $msbuild = $setup.checks.msbuild
  if (-not (Test-Path -LiteralPath $project)) { throw "PasusProcessGuard.vcxproj was not found at $project" }
  & $msbuild $project /p:Configuration=$Configuration /p:Platform=$Platform /m
  if ($LASTEXITCODE -ne 0) { throw "PasusProcessGuard build failed." }
  $artifacts = Get-ChildItem -LiteralPath (Split-Path $project) -Recurse -Include "*.sys","*.inf","*.cat" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName
  [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    driver = "PasusProcessGuard"
    built = $true
    artifacts = @($artifacts)
    monitor_only = $true
    errors = @()
  } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
} catch {
  [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    driver = "PasusProcessGuard"
    built = $false
    monitor_only = $true
    errors = @($_.Exception.Message)
  } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  throw
}
