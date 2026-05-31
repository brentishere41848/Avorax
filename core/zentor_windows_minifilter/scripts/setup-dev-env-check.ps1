param(
  [switch]$RequireAdmin,
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\setup_report.json")
)

$ErrorActionPreference = "Stop"

function Test-Admin {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-MSBuild {
  $cmd = Get-Command msbuild.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path -LiteralPath $vswhere) {
    $install = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($install) {
      $candidate = Join-Path $install "MSBuild\Current\Bin\MSBuild.exe"
      if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
  }
  return $null
}

function Find-Tool([string]$Name) {
  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
  if (Test-Path -LiteralPath $kits) {
    $candidate = Get-ChildItem -LiteralPath $kits -Recurse -Filter $Name -ErrorAction SilentlyContinue |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($candidate) { return $candidate.FullName }
  }
  return $null
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$outDir = Split-Path $ReportPath
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$admin = Test-Admin
$msbuild = Find-MSBuild
$wdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
$signtool = Find-Tool "signtool.exe"
$inf2cat = Find-Tool "inf2cat.exe"
$fltmc = Find-Tool "fltmc.exe"
$sc = Find-Tool "sc.exe"
$testSigningRaw = (& bcdedit /enum 2>$null | Out-String)
$testSigning = $testSigningRaw -match "testsigning\s+Yes"
$secureBoot = $false
try { $secureBoot = Confirm-SecureBootUEFI } catch { $secureBoot = $false }

$checks = [ordered]@{
  windows_version = [Environment]::OSVersion.VersionString
  powershell_version = $PSVersionTable.PSVersion.ToString()
  administrator = $admin
  msbuild = $msbuild
  wdk_root = if (Test-Path -LiteralPath $wdkRoot) { $wdkRoot } else { $null }
  signtool = $signtool
  inf2cat = $inf2cat
  fltmc = $fltmc
  sc = $sc
  test_signing_enabled = $testSigning
  secure_boot_enabled = $secureBoot
  repo_root = $repoRoot.Path
  output_writable = $true
}

$errors = @()
if ($RequireAdmin -and -not $admin) { $errors += "Run this script from an elevated PowerShell session." }
if (-not $msbuild) { $errors += "Install Visual Studio Build Tools with Desktop C++ workload, or run from an EWDK Developer Command Prompt." }
if (-not (Test-Path -LiteralPath $wdkRoot)) { $errors += "Install the Windows Driver Kit. Expected: $wdkRoot" }
if (-not $signtool) { $errors += "signtool.exe was not found. Install WDK signing tools." }
if (-not $inf2cat) { $errors += "inf2cat.exe was not found. Install WDK tools." }
if (-not $fltmc) { $errors += "fltmc.exe was not found. This Windows install cannot manage minifilters from this shell." }
if (-not $sc) { $errors += "sc.exe was not found." }
if ($secureBoot -and -not $testSigning) { $errors += "Secure Boot is enabled and TESTSIGNING is off. Test-signed drivers will not load." }

$report = [ordered]@{
  zentor_version = "0.1.12"
  timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
  checks = $checks
  passed = ($errors.Count -eq 0)
  errors = $errors
  install_instructions = @(
    "Install Visual Studio Build Tools with Desktop development with C++.",
    "Install Windows Driver Kit for Windows 10/11.",
    "For test driver loading, use a disposable VM and manually enable TESTSIGNING with: bcdedit /set testsigning on",
    "Restart after changing TESTSIGNING. Avorax scripts never enable it silently."
  )
}

$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
if ($errors.Count -gt 0) {
  $errors | ForEach-Object { Write-Error $_ }
  exit 1
}

Write-Host "Avorax Windows driver development environment check passed."
