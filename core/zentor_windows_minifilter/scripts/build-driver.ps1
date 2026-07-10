param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [ValidateSet("x64")]
  [string]$Platform = "x64",
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\build_report.json")
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
. (Join-Path $repoRoot "tools\security\avorax-security-gate-tools.ps1")
. (Join-Path $repoRoot "tools\windows\avorax-system32-tools.ps1")
$maxJsonBytes = 1048576
$maxJsonDiagnosticChars = 4096

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

function Get-SafeFile([string]$Path, [string]$Description) {
  Get-SafeItem $Path $Description "file"
}

function Get-BoundedDiagnostic([object]$Value, [int]$MaxLength = $script:maxJsonDiagnosticChars) {
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return "" }
  $text = $text.Trim()
  if ($text.Length -le $MaxLength) { return $text }
  return $text.Substring(0, $MaxLength) + "...<truncated>"
}

function Read-JsonFile([string]$Path, [string]$Description) {
  $file = Get-SafeFile $Path $Description
  try {
    $json = Read-AvoraxGateTextFileBounded $file $script:maxJsonBytes $Description
    return ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    $message = Get-BoundedDiagnostic $_.Exception.Message
    if ($message.StartsWith("$Description exceeds ")) {
      throw $message
    }
    throw "$Description is not valid bounded JSON: $message"
  }
}

function Get-SafeDirectory([string]$Path, [string]$Description) {
  Get-SafeItem $Path $Description "directory"
}

function Get-SafeFilesInDirectory([string]$Path, [string]$Filter, [string]$Description) {
  $directory = Get-SafeDirectory $Path "$Description directory"
  @(Get-ChildItem -LiteralPath $directory -Filter $Filter -File -ErrorAction Stop |
    Sort-Object FullName |
    ForEach-Object { Get-SafeFile $_.FullName $Description })
}

function Get-SafeFilesInTree([string]$Path, [string[]]$Include, [string]$Description) {
  $directory = Get-SafeDirectory $Path "$Description root"
  @(Get-ChildItem -LiteralPath $directory -Recurse -Include $Include -File -ErrorAction Stop |
    Sort-Object FullName |
    ForEach-Object { Get-SafeFile $_.FullName $Description })
}

function New-SafeDirectory([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  Assert-PathUnder $Path $repoRoot $Description
  if (-not (Test-Path -LiteralPath $Path)) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }
  Get-SafeDirectory $Path $Description
}

function Remove-RegularFileIfPresent([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  [void](Get-SafeFile $Path $Description)
  Remove-Item -LiteralPath $Path -Force
}

function Write-JsonFileAtomic([string]$Path, [object]$Value, [int]$Depth, [string]$Description) {
  $directory = New-SafeDirectory (Split-Path $Path) "$Description directory"
  Assert-NoReparsePath $Path $Description
  Assert-PathUnder $Path $repoRoot $Description
  if (Test-Path -LiteralPath $Path) {
    [void](Get-SafeFile $Path $Description)
  }
  $target = [System.IO.Path]::GetFullPath($Path)
  $tempPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".tmp")
  $backupPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".bak")
  try {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempPath, ($Value | ConvertTo-Json -Depth $Depth), $encoding)
    [void](Get-SafeFile $tempPath "$Description temporary file")
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

Assert-NoReparsePath $ReportPath "driver build report"
Assert-PathUnder $ReportPath $repoRoot "driver build report"
Assert-RepoChildPath $ReportPath $repoRoot "driver build report"
$outDir = New-SafeDirectory (Split-Path $ReportPath) "driver build report directory"
$project = Join-Path $PSScriptRoot "..\driver\ZentorAvFilter.vcxproj"
$setupScript = Get-SafeFile (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") "driver setup script"
$powerShell = Get-SafeFile ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$setupReportPath = Join-Path $outDir "setup_report.json"
$commandDiagnostics = [ordered]@{}

try {
  $commandDiagnostics.setup = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $setupScript, "-ReportPath", $setupReportPath) "minifilter setup check" 32768
  if ($commandDiagnostics.setup.exit_code -ne 0) {
    throw "Driver setup check failed with exit code $($commandDiagnostics.setup.exit_code): $($commandDiagnostics.setup.output)"
  }
  $project = Get-SafeFile $project "ZentorAvFilter project"
  $setup = Read-JsonFile $setupReportPath "driver setup report"
  $msbuild = Get-SafeFile $setup.checks.msbuild "MSBuild executable"
  $mergedVcTargets = Join-Path $repoRoot "dist\merged-vctargets\v170"
  $wdkVersion = "10.0.26100.0"
  $wdkKmLib = "C:\Program Files (x86)\Windows Kits\10\Lib\$wdkVersion\km\x64"
  $linker = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe"
  $vcTargetsArgs = @()
  $toolsetTargets = Join-Path $mergedVcTargets "Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0\Toolset.targets"
  if (Test-Path -LiteralPath $toolsetTargets) {
    [void](Get-SafeFile $toolsetTargets "merged VC toolset targets")
    $vcTargetsArgs += "/p:VCTargetsPath=$mergedVcTargets\"
  }
  $configs = if ($Configuration -eq "Release") { @("Release") } else { @("Debug", "Release") }
  $artifacts = @()
  foreach ($config in $configs) {
    $msbuildArgs = @($project, "/p:Configuration=$config", "/p:Platform=$Platform", "/p:SpectreMitigation=false") + $vcTargetsArgs + @("/m")
    $msbuildKey = "msbuild_$config"
    $commandDiagnostics[$msbuildKey] = Invoke-AvoraxCommandDiagnostic $msbuild $msbuildArgs "MSBuild ZentorAvFilter $config" 32768
    $msbuildDiagnostic = $commandDiagnostics[$msbuildKey]
    if ($msbuildDiagnostic.exit_code -ne 0) {
      throw "ZentorAvFilter $config build failed with exit code $($msbuildDiagnostic.exit_code): $(Get-BoundedDiagnostic $msbuildDiagnostic.output)"
    }
    $outputRoot = Join-Path (Split-Path $project) "x64\$config"
    $sysPath = Join-Path $outputRoot "ZentorAvFilter.sys"
    if (-not (Test-Path -LiteralPath $sysPath)) {
      $objRoot = Join-Path (Split-Path $project) "ZentorAvFilter\x64\$config"
      $objects = Get-SafeFilesInDirectory $objRoot "*.obj" "driver object file"
      $linkerPath = if (Test-Path -LiteralPath $linker) { Get-SafeFile $linker "manual linker executable" } else { $null }
      if (-not $objects -or -not $linkerPath) {
        throw "MSBuild compiled the driver but did not emit $sysPath, and manual link prerequisites were missing."
      }
      [void](New-SafeDirectory $outputRoot "driver output directory")
      $linkArgs = @("/nologo", "/driver", "/subsystem:native", "/machine:x64", "/entry:DriverEntry", "/nodefaultlib", "/out:$sysPath", "/libpath:$wdkKmLib") + @($objects) + @("ntoskrnl.lib", "fltMgr.lib", "BufferOverflowK.lib", "libcntpr.lib")
      $linkKey = "link_$config"
      $commandDiagnostics[$linkKey] = Invoke-AvoraxCommandDiagnostic $linkerPath $linkArgs "link ZentorAvFilter $config" 32768
      $linkDiagnostic = $commandDiagnostics[$linkKey]
      if ($linkDiagnostic.exit_code -ne 0 -or -not (Test-Path -LiteralPath $sysPath)) {
        throw "Manual ZentorAvFilter.sys link failed with exit code $($linkDiagnostic.exit_code): $(Get-BoundedDiagnostic $linkDiagnostic.output)"
      }
    }
    [void](Get-SafeFile $sysPath "built ZentorAvFilter driver")
    $artifacts += Get-SafeFilesInTree (Split-Path $project) @("*.sys", "*.inf", "*.cat") "driver build artifact"
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
    command_diagnostics = $commandDiagnostics
    errors = @()
  }
  Write-JsonFileAtomic $ReportPath $report 6 "driver build report"
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
    command_diagnostics = $commandDiagnostics
    errors = @(Get-BoundedDiagnostic $_.Exception.Message)
  }
  Write-JsonFileAtomic $ReportPath $report 6 "driver build report"
  throw
}
