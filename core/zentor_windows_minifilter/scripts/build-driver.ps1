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
$project = Join-Path $PSScriptRoot "..\driver\ZentorAvFilter.vcxproj"

try {
  & (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") -ReportPath (Join-Path $outDir "setup_report.json")
  if (-not (Test-Path -LiteralPath $project)) {
    throw "ZentorAvFilter.vcxproj was not found at $project"
  }
  $setup = Get-Content -Raw -LiteralPath (Join-Path $outDir "setup_report.json") | ConvertFrom-Json
  $msbuild = $setup.checks.msbuild
  $repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
  $mergedVcTargets = Join-Path $repoRoot "dist\merged-vctargets\v170"
  $wdkVersion = "10.0.26100.0"
  $wdkKmLib = "C:\Program Files (x86)\Windows Kits\10\Lib\$wdkVersion\km\x64"
  $linker = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe"
  $vcTargetsArgs = @()
  if (Test-Path -LiteralPath (Join-Path $mergedVcTargets "Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0\Toolset.targets")) {
    $vcTargetsArgs += "/p:VCTargetsPath=$mergedVcTargets\"
  }
  $configs = if ($Configuration -eq "Release") { @("Release") } else { @("Debug", "Release") }
  $artifacts = @()
  foreach ($config in $configs) {
    & $msbuild $project /p:Configuration=$config /p:Platform=$Platform /p:SpectreMitigation=false @vcTargetsArgs /m
    if ($LASTEXITCODE -ne 0) { throw "ZentorAvFilter $config build failed." }
    $outputRoot = Join-Path (Split-Path $project) "x64\$config"
    $sysPath = Join-Path $outputRoot "ZentorAvFilter.sys"
    if (-not (Test-Path -LiteralPath $sysPath)) {
      $objRoot = Join-Path (Split-Path $project) "ZentorAvFilter\x64\$config"
      $objects = Get-ChildItem -LiteralPath $objRoot -Filter "*.obj" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
      if (-not $objects -or -not (Test-Path -LiteralPath $linker)) {
        throw "MSBuild compiled the driver but did not emit $sysPath, and manual link prerequisites were missing."
      }
      New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
      & $linker /nologo /driver /subsystem:native /machine:x64 /entry:DriverEntry /nodefaultlib /out:$sysPath /libpath:$wdkKmLib $objects ntoskrnl.lib fltMgr.lib BufferOverflowK.lib libcntpr.lib
      if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sysPath)) { throw "Manual ZentorAvFilter.sys link failed." }
    }
    $artifacts += Get-ChildItem -LiteralPath (Split-Path $project) -Recurse -Include "*.sys","*.inf","*.cat" -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty FullName
  }
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    driver = "ZentorAvFilter"
    built = $true
    configuration = $Configuration
    platform = $Platform
    artifacts = @($artifacts | Sort-Object -Unique)
    static_driver_verifier = "not_run"
    inf_validation = "inf2cat_available"
    errors = @()
  }
  $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  Write-Host "ZentorAvFilter driver build completed."
} catch {
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    driver = "ZentorAvFilter"
    built = $false
    configuration = $Configuration
    platform = $Platform
    artifacts = @()
    errors = @($_.Exception.Message)
  }
  $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  throw
}
