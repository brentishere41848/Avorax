param(
  [string]$RepoRoot = $(Resolve-Path "."),
  [string]$DotnetPath = $env:AVORAX_DOTNET,
  [string]$CargoPath = $env:CARGO,
  [string]$FlutterPath = $env:AVORAX_FLUTTER,
  [string]$ReportPath = "",
  [switch]$HostOnly
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")

$errors = @()
$warnings = @()
$checks = @()
$maxDiagnosticChars = 4096

function Get-BoundedPrereqDiagnostic {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  if ($text.Length -le $maxDiagnosticChars) { return $text }
  return $text.Substring(0, $maxDiagnosticChars) + "...<truncated>"
}

function Add-PrereqError([string]$Message) {
  $bounded = Get-BoundedPrereqDiagnostic $Message
  $script:errors += $bounded
  Write-Error $bounded -ErrorAction Continue
}

function Add-PrereqWarning([string]$Message) {
  $bounded = Get-BoundedPrereqDiagnostic $Message
  $script:warnings += $bounded
  Write-Warning $bounded
}

function Add-PrereqCheck([string]$Name, [string]$Status, [string]$Detail = "") {
  $script:checks += [ordered]@{
    name = $Name
    status = $Status
    detail = Get-BoundedPrereqDiagnostic $Detail
  }
}

function Add-PrereqSkipped([string]$Name, [string]$Detail) {
  Add-PrereqCheck $Name "skipped" $Detail
}

function Require-PrereqFile([string]$Path, [string]$Description) {
  try {
    $file = Get-AvoraxGateFile $Path $Description
    Add-PrereqCheck $Description "pass" $file
    return $file
  } catch {
    Add-PrereqError "$Description is missing or unsafe: $(Get-BoundedPrereqDiagnostic $_.Exception.Message)"
    Add-PrereqCheck $Description "fail" $_.Exception.Message
    return $null
  }
}

function Require-PrereqDirectory([string]$Path, [string]$Description) {
  try {
    $directory = Get-AvoraxGateDirectory $Path $Description
    Add-PrereqCheck $Description "pass" $directory
    return $directory
  } catch {
    Add-PrereqError "$Description is missing or unsafe: $(Get-BoundedPrereqDiagnostic $_.Exception.Message)"
    Add-PrereqCheck $Description "fail" $_.Exception.Message
    return $null
  }
}

function Require-PrereqTool([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    Add-PrereqError "$Description path is required; refusing ambient PATH lookup."
    Add-PrereqCheck $Description "fail" "explicit path missing"
    return $null
  }
  Require-PrereqFile $Path $Description
}

function Test-DotnetSdk([AllowNull()][string]$Dotnet) {
  if ([string]::IsNullOrWhiteSpace($Dotnet)) { return $false }
  $sdkList = Invoke-AvoraxGateCommandDiagnostic $Dotnet @("--list-sdks") ".NET SDK inventory" 8192 $root
  if ($sdkList.exit_code -ne 0) {
    Add-PrereqError ".NET SDK inventory failed with exit code $($sdkList.exit_code): $($sdkList.output)"
    Add-PrereqCheck ".NET SDK inventory" "fail" $sdkList.output
    return $false
  }
  $sdks = @($sdkList.output -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($sdks.Count -eq 0) {
    Add-PrereqError ".NET SDK is not installed at the explicit dotnet path; dotnet.exe exists but --list-sdks returned no SDKs."
    Add-PrereqCheck ".NET SDK inventory" "fail" "no SDKs returned by dotnet --list-sdks"
    return $false
  }
  Add-PrereqCheck ".NET SDK inventory" "pass" (($sdks | Select-Object -First 5) -join "; ")
  return $true
}

function Read-PrereqText([string]$Path, [string]$Description) {
  $file = Require-PrereqFile $Path $Description
  if (-not $file) { return $null }
  try {
    return Read-AvoraxGateTextFileBounded $file 1048576 $Description
  } catch {
    Add-PrereqError "$Description could not be read safely: $(Get-BoundedPrereqDiagnostic $_.Exception.Message)"
    return $null
  }
}

function Write-PrereqReport([bool]$Ok) {
  if ([string]::IsNullOrWhiteSpace($script:ResolvedReportPath)) { return }
  try {
    $report = [ordered]@{
      ok = $Ok
      timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
      repo_root = $root
      mode = $(if ($HostOnly) { "host_only" } else { "full" })
      tool_paths = [ordered]@{
        dotnet = $DotnetPath
        cargo = $CargoPath
        flutter = $FlutterPath
      }
      checks = @($checks)
      errors = @($errors)
        warnings = @($warnings)
    }
    Write-AvoraxGateJsonFileAtomic $script:ResolvedReportPath $report 8 "release prerequisite report"
  } catch {
    Add-PrereqError "Could not write release prerequisite report: $(Get-BoundedPrereqDiagnostic $_.Exception.Message)"
  }
}

function Resolve-PrereqReportPath([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Join-Path $root "dist\release-prereq\release_prereq_report.json"
  } elseif (-not [System.IO.Path]::IsPathRooted($Path)) {
    $Path = Join-Path $root $Path
  }
  $full = [System.IO.Path]::GetFullPath($Path)
  $repoPrefix = $root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  if ($full -ne $root -and -not $full.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    Add-PrereqError "Release prerequisite report path must resolve inside the repository: $full"
    return ""
  }
  return $full
}

function Test-SymlinkSupport {
  $base = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-symlink-preflight-" + [guid]::NewGuid().ToString("N"))
  try {
    [System.IO.Directory]::CreateDirectory($base) | Out-Null
    $target = Join-Path $base "target.txt"
    $link = Join-Path $base "link.txt"
    [System.IO.File]::WriteAllText($target, "avorax symlink preflight")
    New-Item -ItemType SymbolicLink -Path $link -Target $target -ErrorAction Stop | Out-Null
    return $true
  } catch {
    Add-PrereqError "Windows symlink support is unavailable for Flutter plugin builds: $(Get-BoundedPrereqDiagnostic $_.Exception.Message). Enable Developer Mode or use an approved symlink-capable Windows build host; this script will not change that setting."
    Add-PrereqCheck "Windows symlink support" "fail" $_.Exception.Message
    return $false
  } finally {
    if (Test-Path -LiteralPath $base) {
      try {
        Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop
      } catch {
        Add-PrereqWarning "Could not remove symlink preflight temp directory $base`: $(Get-BoundedPrereqDiagnostic $_.Exception.Message)"
      }
    }
  }
}

$script:ResolvedReportPath = ""

try {
  $resolvedRepoRoot = (Resolve-Path -LiteralPath $RepoRoot -ErrorAction Stop).ProviderPath
} catch {
  $resolvedRepoRoot = $RepoRoot
}

$root = Require-PrereqDirectory $resolvedRepoRoot "repository root"
if (-not $root) {
  Write-PrereqReport $false
  throw "Avorax release prerequisite check failed with $($errors.Count) error(s)."
}

$script:ResolvedReportPath = Resolve-PrereqReportPath $ReportPath

$dotnet = Require-PrereqTool $DotnetPath ".NET SDK dotnet executable"
$cargo = Require-PrereqTool $CargoPath "Cargo executable"
$flutter = Require-PrereqTool $FlutterPath "Flutter executable"
if ($dotnet) {
  [void](Test-DotnetSdk $dotnet)
}

$androidBuildGradle = Join-Path $root "apps\zentor_client\android\build.gradle.kts"
$androidSettingsGradle = Join-Path $root "apps\zentor_client\android\settings.gradle.kts"
$androidGradleLock = Join-Path $root "apps\zentor_client\android\gradle.lockfile"
$gradleWrapperProperties = Join-Path $root "apps\zentor_client\android\gradle\wrapper\gradle-wrapper.properties"
$releaseApp = Join-Path $root "apps\zentor_client\build\windows\x64\runner\Release\Avorax.exe"
$stageDir = Join-Path $root "dist\windows-msi\stage"

$androidBuildText = Read-PrereqText $androidBuildGradle "Android build.gradle.kts"
if ($androidBuildText) {
  if ($androidBuildText -notmatch "dependencyLocking\s*\{" -or $androidBuildText -notmatch "lockAllConfigurations\(\)") {
    Add-PrereqError "Android Gradle dependency locking is not enabled for all subprojects."
    Add-PrereqCheck "Android Gradle dependency locking" "fail" "dependencyLocking lockAllConfigurations missing"
  } else {
    Add-PrereqCheck "Android Gradle dependency locking" "pass" "lockAllConfigurations configured"
  }
}

$androidSettingsText = Read-PrereqText $androidSettingsGradle "Android settings.gradle.kts"
if ($androidSettingsText) {
  foreach ($requiredPlugin in @(
    'id("dev.flutter.flutter-plugin-loader") version "1.0.0"',
    'id("com.android.application") version "9.0.1"',
    'id("org.jetbrains.kotlin.android") version "2.3.20"'
  )) {
    if (-not $androidSettingsText.Contains($requiredPlugin)) {
      Add-PrereqError "Android Gradle plugin pin is missing: $requiredPlugin"
      Add-PrereqCheck "Android Gradle plugin pin $requiredPlugin" "fail" "missing"
    } else {
      Add-PrereqCheck "Android Gradle plugin pin $requiredPlugin" "pass" "present"
    }
  }
}

$wrapperText = Read-PrereqText $gradleWrapperProperties "Gradle wrapper properties"
if ($wrapperText) {
  if (-not $wrapperText.Contains("distributionUrl=https\://services.gradle.org/distributions/gradle-9.1.0-all.zip")) {
    Add-PrereqError "Gradle wrapper distribution URL is not pinned to Gradle 9.1.0-all."
    Add-PrereqCheck "Gradle wrapper distribution URL" "fail" "unexpected or missing"
  } else {
    Add-PrereqCheck "Gradle wrapper distribution URL" "pass" "Gradle 9.1.0-all"
  }
  if (-not $wrapperText.Contains("distributionSha256Sum=b84e04fa845fecba48551f425957641074fcc00a88a84d2aae5808743b35fc85")) {
    Add-PrereqError "Gradle wrapper distributionSha256Sum is missing or unexpected."
    Add-PrereqCheck "Gradle wrapper distribution hash" "fail" "unexpected or missing"
  } else {
    Add-PrereqCheck "Gradle wrapper distribution hash" "pass" "b84e04fa845fecba48551f425957641074fcc00a88a84d2aae5808743b35fc85"
  }
}

if (-not (Test-Path -LiteralPath $androidGradleLock)) {
  Add-PrereqSkipped "Android Gradle dependency lockfile" "not required for the Windows antivirus release path; generate on an Android-capable host before any Android publishing"
} else {
  Require-PrereqFile $androidGradleLock "Android Gradle dependency lockfile" | Out-Null
}

if ($HostOnly) {
  foreach ($releaseExe in @(
    "target\release\zentor_local_core.exe",
    "target\release\zentor_guard_service.exe",
    "target\release\avorax_update_service.exe"
  )) {
    Add-PrereqSkipped "Rust release service $releaseExe" "host-only mode checks build host prerequisites before release artifacts exist"
  }
  Add-PrereqSkipped "Flutter Windows release Avorax.exe" "host-only mode checks build host prerequisites before release artifacts exist"
  Add-PrereqSkipped "Windows installer stage" "host-only mode checks build host prerequisites before installer staging exists"
} else {
  foreach ($releaseExe in @(
    "target\release\zentor_local_core.exe",
    "target\release\zentor_guard_service.exe",
    "target\release\avorax_update_service.exe"
  )) {
    Require-PrereqFile (Join-Path $root $releaseExe) "Rust release service $releaseExe" | Out-Null
  }

  if (-not (Test-Path -LiteralPath $releaseApp)) {
    Add-PrereqError "Flutter Windows release app is missing: $releaseApp. Build a real Avorax.exe before installer staging; placeholders are not release evidence."
    Add-PrereqCheck "Flutter Windows release Avorax.exe" "fail" $releaseApp
  } else {
    Require-PrereqFile $releaseApp "Flutter Windows release Avorax.exe" | Out-Null
  }

  if (-not (Test-Path -LiteralPath $stageDir)) {
    Add-PrereqError "Windows installer stage is missing: $stageDir"
    Add-PrereqCheck "Windows installer stage" "fail" $stageDir
  } else {
    Require-PrereqDirectory $stageDir "Windows installer stage" | Out-Null
  }
}

[void](Test-SymlinkSupport)

if ($flutter) {
  $flutterClientDir = Require-PrereqDirectory (Join-Path $root "apps\zentor_client") "Flutter client directory"
  if ($flutterClientDir) {
    $doctor = Invoke-AvoraxGateCommandDiagnostic $flutter @("doctor", "-v") "Flutter doctor" 32768 $flutterClientDir
    if ($doctor.exit_code -ne 0) {
      Add-PrereqError "Flutter doctor failed with exit code $($doctor.exit_code): $($doctor.output)"
      Add-PrereqCheck "Flutter doctor" "fail" $doctor.output
    } else {
      Add-PrereqCheck "Flutter doctor command" "pass" "exit=0"
    }
    if ($doctor.output -match "Unable to locate Android SDK") {
      Add-PrereqSkipped "Android SDK" "not required for the Windows antivirus release path; Flutter doctor reports missing Android SDK"
    } else {
      Add-PrereqCheck "Android SDK" "pass" "Flutter doctor did not report missing Android SDK"
    }
    if ($doctor.output -match "Visual Studio is missing necessary components" -or $doctor.output -match "Desktop development with C\+\+") {
      Add-PrereqError "Visual Studio Desktop C++ build components are missing according to Flutter doctor; Windows Avorax.exe cannot be release-built on this host."
      Add-PrereqCheck "Visual Studio Desktop C++ components" "fail" "Flutter doctor reports missing components"
    } else {
      Add-PrereqCheck "Visual Studio Desktop C++ components" "pass" "Flutter doctor did not report missing components"
    }
  }
}

if ($dotnet) {
  $toolManifest = Join-Path $root "dotnet-tools.json"
  $toolManifestText = Read-PrereqText $toolManifest ".NET tool manifest"
  if ($toolManifestText) {
    if ($toolManifestText -notmatch '"wix"' -or $toolManifestText -notmatch '"version"\s*:\s*"6\.0\.2"') {
      Add-PrereqError ".NET tool manifest does not pin WiX 6.0.2."
      Add-PrereqCheck ".NET WiX tool pin" "fail" "WiX 6.0.2 pin missing"
    } else {
      Add-PrereqCheck ".NET WiX tool pin" "pass" "WiX 6.0.2"
    }
  }
}

if ($errors.Count -gt 0) {
  Write-PrereqReport $false
  throw "Avorax release prerequisite check failed with $($errors.Count) error(s)."
}

Write-PrereqReport $true
Write-Host "Avorax release prerequisite check passed."
