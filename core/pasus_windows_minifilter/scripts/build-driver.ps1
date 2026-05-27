param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [ValidateSet("x64")]
  [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
$project = Join-Path $PSScriptRoot "..\driver\PasusAvFilter.vcxproj"

if (-not (Test-Path -LiteralPath $project)) {
  throw "PasusAvFilter.vcxproj was not found at $project"
}

$msbuild = Get-Command msbuild.exe -ErrorAction SilentlyContinue
if (-not $msbuild) {
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path -LiteralPath $vswhere) {
    $install = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($install) {
      $candidate = Join-Path $install "MSBuild\Current\Bin\MSBuild.exe"
      if (Test-Path -LiteralPath $candidate) {
        $msbuild = Get-Item $candidate
      }
    }
  }
}

if (-not $msbuild) {
  throw "MSBuild was not found. Install Visual Studio with Desktop C++ and Windows Driver Kit integration."
}

$wdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
if (-not (Test-Path -LiteralPath $wdkRoot)) {
  throw "Windows Driver Kit was not found at $wdkRoot. Install the Windows 10/11 WDK before building the driver."
}

& $msbuild.Source $project /p:Configuration=$Configuration /p:Platform=$Platform /m
if ($LASTEXITCODE -ne 0) {
  throw "PasusAvFilter driver build failed."
}

Write-Host "PasusAvFilter driver build completed."
