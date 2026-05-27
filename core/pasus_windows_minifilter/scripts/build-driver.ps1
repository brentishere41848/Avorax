param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [ValidateSet("x64")]
  [string]$Platform = "x64",
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\build_report.json")
)

$ErrorActionPreference = "Stop"
$outDir = Split-Path $ReportPath
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$project = Join-Path $PSScriptRoot "..\driver\PasusAvFilter.vcxproj"

try {
  & (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") -ReportPath (Join-Path $outDir "setup_report.json")
  if (-not (Test-Path -LiteralPath $project)) {
    throw "PasusAvFilter.vcxproj was not found at $project"
  }
  $setup = Get-Content -Raw -LiteralPath (Join-Path $outDir "setup_report.json") | ConvertFrom-Json
  $msbuild = $setup.checks.msbuild
  $configs = if ($Configuration -eq "Release") { @("Release") } else { @("Debug", "Release") }
  $artifacts = @()
  foreach ($config in $configs) {
    & $msbuild $project /p:Configuration=$config /p:Platform=$Platform /m
    if ($LASTEXITCODE -ne 0) { throw "PasusAvFilter $config build failed." }
    $outputRoot = Join-Path (Split-Path $project) "x64\$config"
    $artifacts += Get-ChildItem -LiteralPath (Split-Path $project) -Recurse -Include "*.sys","*.inf","*.cat" -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty FullName
  }
  $report = [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    driver = "PasusAvFilter"
    built = $true
    configuration = $Configuration
    platform = $Platform
    artifacts = @($artifacts | Sort-Object -Unique)
    static_driver_verifier = "not_run"
    inf_validation = "inf2cat_available"
    errors = @()
  }
  $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  Write-Host "PasusAvFilter driver build completed."
} catch {
  $report = [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    driver = "PasusAvFilter"
    built = $false
    configuration = $Configuration
    platform = $Platform
    artifacts = @()
    errors = @($_.Exception.Message)
  }
  $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  throw
}
