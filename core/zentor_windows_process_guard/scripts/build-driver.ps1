param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [ValidateSet("x64")]
  [string]$Platform = "x64",
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\build_report.json")
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

Assert-NoReparsePath $ReportPath "process-guard build report"
Assert-PathUnder $ReportPath $repoRoot "process-guard build report"
Assert-RepoChildPath $ReportPath $repoRoot "process-guard build report"
$outDir = New-SafeDirectory (Split-Path $ReportPath) "process-guard build report directory"
$project = Join-Path $PSScriptRoot "..\driver\ZentorProcessGuard.vcxproj"
$setupScript = Get-SafeFile (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") "process-guard setup script"
$powerShell = Get-SafeFile ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$setupReportPath = Join-Path $outDir "setup_report.json"
$commandDiagnostics = [ordered]@{}

try {
  $commandDiagnostics.setup = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $setupScript, "-ReportPath", $setupReportPath) "process guard setup check" 32768
  if ($commandDiagnostics.setup.exit_code -ne 0) {
    throw "Process guard setup check failed with exit code $($commandDiagnostics.setup.exit_code): $($commandDiagnostics.setup.output)"
  }
  $setup = Read-JsonFile $setupReportPath "process-guard setup report"
  $msbuild = Get-SafeFile $setup.checks.msbuild "MSBuild executable"
  $project = Get-SafeFile $project "ZentorProcessGuard project"
  $msbuildArgs = @($project, "/p:Configuration=$Configuration", "/p:Platform=$Platform", "/m")
  $commandDiagnostics.msbuild = Invoke-AvoraxCommandDiagnostic $msbuild $msbuildArgs "MSBuild ZentorProcessGuard $Configuration" 32768
  if ($commandDiagnostics.msbuild.exit_code -ne 0) {
    throw "ZentorProcessGuard build failed with exit code $($commandDiagnostics.msbuild.exit_code): $(Get-BoundedDiagnostic $commandDiagnostics.msbuild.output)"
  }
  $artifacts = Get-SafeFilesInTree (Split-Path $project) @("*.sys", "*.inf", "*.cat") "process-guard build artifact"
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    driver = "ZentorProcessGuard"
    built = $true
    artifacts = @($artifacts)
    monitor_only = $true
    command_diagnostics = $commandDiagnostics
    errors = @()
  }
  Write-JsonFileAtomic $ReportPath $report 6 "process-guard build report"
} catch {
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    driver = "ZentorProcessGuard"
    built = $false
    monitor_only = $true
    command_diagnostics = $commandDiagnostics
    errors = @(Get-BoundedDiagnostic $_.Exception.Message)
  }
  Write-JsonFileAtomic $ReportPath $report 6 "process-guard build report"
  throw
}
