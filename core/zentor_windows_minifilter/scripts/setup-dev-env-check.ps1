param(
  [switch]$RequireAdmin,
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\setup_report.json")
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
. (Join-Path $repoRoot "tools\windows\avorax-system32-tools.ps1")

function Test-LocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Assert-NoReparsePath([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Description path is required."
  }
  if (-not (Test-LocalWindowsPath $Path)) {
    throw "$Description must be an absolute local Windows drive path: $Path"
  }
  $current = [System.IO.Path]::GetFullPath($Path)
  while ($true) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not traverse a reparse point: $current"
      }
    }
    $parent = [System.IO.Directory]::GetParent($current)
    if ($null -eq $parent) { break }
    if ($parent.FullName -eq $current) { break }
    $current = $parent.FullName
  }
}

function Assert-PathUnder([string]$Path, [string]$Base, [string]$Description) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  $pathFull = [System.IO.Path]::GetFullPath($Path)
  if ($pathFull.TrimEnd('\', '/').Equals($baseFull.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    return
  }
  if (-not $pathFull.StartsWith($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must stay under $Base`: $Path"
  }
}

function Assert-RepoChildPath([string]$Path, [string]$Base, [string]$Description) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must resolve to a child path inside the Avorax repository root, not the repository root itself."
  }
  Assert-PathUnder $pathFull $Base $Description
}

function Get-SafeItem([string]$Path, [string]$Description, [string]$Kind) {
  Assert-NoReparsePath $Path $Description
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $Path"
  }
  if ($Kind -eq "file" -and -not ($item -is [System.IO.FileInfo])) {
    throw "$Description is not a regular file: $Path"
  }
  if ($Kind -eq "directory" -and -not ($item -is [System.IO.DirectoryInfo])) {
    throw "$Description is not a directory: $Path"
  }
  $item.FullName
}

function Get-SafeFileOrNull([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  try {
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return $null }
    return Get-SafeItem $Path $Description "file"
  } catch {
    Add-ToolDiscoveryError "$Description validation failed for $Path`: $($_.Exception.Message)"
    return $null
  }
}

function Get-SafeDirectoryOrNull([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  try {
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return $null }
    return Get-SafeItem $Path $Description "directory"
  } catch {
    Add-ToolDiscoveryError "$Description validation failed for $Path`: $($_.Exception.Message)"
    return $null
  }
}

function New-SafeDirectory([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  Assert-PathUnder $Path $repoRoot $Description
  if (-not (Test-Path -LiteralPath $Path)) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }
  Get-SafeItem $Path $Description "directory"
}

function Remove-RegularFileIfPresent([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  [void](Get-SafeItem $Path $Description "file")
  Remove-Item -LiteralPath $Path -Force
}

function Get-BoundedDiagnostic([object]$Value, [int]$MaxLength = 2048) {
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return "" }
  $text = $text.Trim()
  if ($text.Length -le $MaxLength) { return $text }
  return $text.Substring(0, $MaxLength) + "...<truncated>"
}

function Add-ToolDiscoveryError([string]$Message) {
  if ($null -eq $script:toolDiscoveryErrors) {
    $script:toolDiscoveryErrors = @()
  }
  $script:toolDiscoveryErrors += Get-BoundedDiagnostic $Message
}

function Find-SafeFileInTree([string]$Root, [string]$Name, [scriptblock]$Predicate, [string]$Description) {
  $safeRoot = Get-SafeDirectoryOrNull $Root "$Description root"
  if (-not $safeRoot) { return $null }

  try {
    $candidates = @(
      Get-ChildItem -LiteralPath $safeRoot -Recurse -Filter $Name -File -ErrorAction Stop |
        Where-Object {
          (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) -and (& $Predicate $_)
        } |
        Sort-Object FullName -Descending
    )
  } catch {
    Add-ToolDiscoveryError "$Description enumeration failed under $safeRoot`: $($_.Exception.Message)"
    return $null
  }

  if ($candidates.Count -eq 0) { return $null }

  try {
    return Get-SafeItem $candidates[0].FullName "$Description candidate" "file"
  } catch {
    Add-ToolDiscoveryError "$Description candidate validation failed: $($_.Exception.Message)"
    return $null
  }
}

function Write-JsonFileAtomic([string]$Path, [object]$Value, [int]$Depth, [string]$Description) {
  $directory = New-SafeDirectory (Split-Path $Path) "$Description directory"
  Assert-NoReparsePath $Path $Description
  Assert-PathUnder $Path $repoRoot $Description
  if (Test-Path -LiteralPath $Path) {
    [void](Get-SafeItem $Path $Description "file")
  }
  $target = [System.IO.Path]::GetFullPath($Path)
  $tempPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".tmp")
  $backupPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".bak")
  try {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempPath, ($Value | ConvertTo-Json -Depth $Depth), $encoding)
    [void](Get-SafeItem $tempPath "$Description temporary file" "file")
    if (Test-Path -LiteralPath $target) {
      [System.IO.File]::Replace($tempPath, $target, $backupPath)
    } else {
      [System.IO.File]::Move($tempPath, $target)
    }
  } finally {
    Remove-RegularFileIfPresent $tempPath "$Description temporary file"
    Remove-RegularFileIfPresent $backupPath "$Description backup file"
  }
}

function Test-Admin {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-MSBuild {
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  $vswhere = Get-SafeFileOrNull $vswhere "Visual Studio vswhere executable"
  if ($vswhere) {
    $installDiagnostic = Invoke-AvoraxCommandDiagnostic $vswhere @("-latest", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath") "vswhere latest VC tools" 32768
    if ($installDiagnostic.exit_code -ne 0) {
      Add-ToolDiscoveryError "vswhere latest VC tools failed with exit code $($installDiagnostic.exit_code): $($installDiagnostic.output)"
    }
    $install = $installDiagnostic.output
    if (-not $install) {
      $fallbackDiagnostic = Invoke-AvoraxCommandDiagnostic $vswhere @("-latest", "-products", "*", "-property", "installationPath") "vswhere latest products" 32768
      if ($fallbackDiagnostic.exit_code -ne 0) {
        Add-ToolDiscoveryError "vswhere latest products failed with exit code $($fallbackDiagnostic.exit_code): $($fallbackDiagnostic.output)"
      }
      $install = $fallbackDiagnostic.output
    }
    if ($install) {
      foreach ($relative in @("MSBuild\Current\Bin\amd64\MSBuild.exe", "MSBuild\Current\Bin\MSBuild.exe")) {
        $candidate = Join-Path $install $relative
        $msbuild = Get-SafeFileOrNull $candidate "MSBuild executable"
        if ($msbuild) { return $msbuild }
      }
    }
  }
  $roots = @("${env:ProgramFiles(x86)}\Microsoft Visual Studio", "${env:ProgramFiles}\Microsoft Visual Studio")
  foreach ($root in $roots) {
    $msbuild = Find-SafeFileInTree $root "MSBuild.exe" {
      param($Candidate)
      return $Candidate.FullName -match "MSBuild\\Current\\Bin(\\amd64)?\\MSBuild.exe$"
    } "MSBuild fallback discovery"
    if ($msbuild) { return $msbuild }
  }
  return $null
}

function Find-System32ToolOrNull([string]$Name) {
  try {
    return Get-AvoraxSystem32Tool $Name
  } catch {
    $script:system32ToolErrors[$Name] = $_.Exception.Message
    return $null
  }
}

function Find-Tool([string]$Name) {
  $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
  return Find-SafeFileInTree $kits $Name {
    param($Candidate)
    return $true
  } "$Name WDK tool discovery"
}

$outDir = Split-Path $ReportPath
Assert-NoReparsePath $ReportPath "driver setup report"
Assert-PathUnder $ReportPath $repoRoot "driver setup report"
Assert-RepoChildPath $ReportPath $repoRoot "driver setup report"
[void](New-SafeDirectory $outDir "driver setup report directory")

$toolDiscoveryErrors = @()
$system32ToolErrors = @{}
$admin = Test-Admin
$msbuild = Find-MSBuild
$wdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
$wdkRootSafe = Get-SafeDirectoryOrNull $wdkRoot "Windows Driver Kit root"
$signtool = Find-Tool "signtool.exe"
$inf2cat = Find-Tool "inf2cat.exe"
$fltmc = Find-System32ToolOrNull "fltmc.exe"
$sc = Find-System32ToolOrNull "sc.exe"
$bcdedit = Find-System32ToolOrNull "bcdedit.exe"
$testSigningRaw = ""
$testSigningProbeError = $null
if ($bcdedit) {
  $bcdeditDiagnostic = Invoke-AvoraxCommandDiagnostic $bcdedit @("/enum") "bcdedit /enum" 32768
  $bcdeditText = $bcdeditDiagnostic.output
  if ($bcdeditDiagnostic.exit_code -ne 0) {
    $testSigningProbeError = Get-BoundedDiagnostic "bcdedit /enum failed with exit code $($bcdeditDiagnostic.exit_code)`: $bcdeditText"
  } else {
    $testSigningRaw = $bcdeditText
  }
}
$testSigning = $testSigningRaw -match "testsigning\s+Yes"
$secureBoot = $null
$secureBootProbeError = $null
try {
  $secureBoot = Confirm-SecureBootUEFI
} catch {
  $secureBootProbeError = Get-BoundedDiagnostic $_.Exception.Message
}

$checks = [ordered]@{
  windows_version = [Environment]::OSVersion.VersionString
  powershell_version = $PSVersionTable.PSVersion.ToString()
  administrator = $admin
  msbuild = $msbuild
  wdk_root = $wdkRootSafe
  signtool = $signtool
  inf2cat = $inf2cat
  fltmc = $fltmc
  sc = $sc
  test_signing_enabled = $testSigning
  test_signing_probe_error = $testSigningProbeError
  secure_boot_enabled = $secureBoot
  secure_boot_probe_error = $secureBootProbeError
  tool_discovery_errors = $toolDiscoveryErrors
  repo_root = $repoRoot
  output_writable = $true
}

$errors = @()
foreach ($discoveryError in $toolDiscoveryErrors) {
  $errors += "Tool discovery error: $discoveryError"
}
if ($RequireAdmin -and -not $admin) { $errors += "Run this script from an elevated PowerShell session." }
if (-not $msbuild) { $errors += "Install Visual Studio Build Tools with Desktop C++ workload in Program Files so MSBuild can be resolved without ambient PATH lookup." }
if (-not $wdkRootSafe) { $errors += "Install the Windows Driver Kit. Expected: $wdkRoot" }
if (-not $signtool) { $errors += "signtool.exe was not found. Install WDK signing tools." }
if (-not $inf2cat) { $errors += "inf2cat.exe was not found. Install WDK tools." }
if (-not $fltmc) { $errors += "fltmc.exe was not found or is unsafe. $($system32ToolErrors['fltmc.exe'])" }
if (-not $sc) { $errors += "sc.exe was not found or is unsafe. $($system32ToolErrors['sc.exe'])" }
if (-not $bcdedit) { $errors += "bcdedit.exe was not found or is unsafe. $($system32ToolErrors['bcdedit.exe'])" }
if ($testSigningProbeError) { $errors += "TESTSIGNING status could not be verified: $testSigningProbeError" }
if ($secureBootProbeError) {
  $errors += "Secure Boot status could not be verified: $secureBootProbeError"
} elseif ($secureBoot -and -not $testSigning) {
  $errors += "Secure Boot is enabled and TESTSIGNING is off. Test-signed drivers will not load."
}

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

Write-JsonFileAtomic $ReportPath $report 6 "driver setup report"
if ($errors.Count -gt 0) {
  $errors | ForEach-Object { Write-Error $_ }
  exit 1
}

Write-Host "Avorax Windows driver development environment check passed."
