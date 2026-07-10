param(
  [string]$SelfTestReport = $(Join-Path (Resolve-Path ".") "dist\windows-driver-validation\selftest_report.json"),
  [string]$CargoPath = $env:CARGO,
  [string]$PythonPath = $env:AVORAX_PYTHON,
  [string]$DotnetPath = $env:AVORAX_DOTNET,
  [string]$FlutterPath = $env:AVORAX_FLUTTER,
  [switch]$DriverFeatureEnabled,
  [switch]$AiFeatureEnabled = $true
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")
$root = Resolve-Path "."
$errors = @()
$maxDiagnosticChars = 4096
$maxJsonBytes = 1048576

function Get-BoundedDiagnostic {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  if ($text.Length -le $maxDiagnosticChars) { return $text }
  return $text.Substring(0, $maxDiagnosticChars) + "...[truncated]"
}

function Add-Error([string]$Message) {
  $bounded = Get-BoundedDiagnostic $Message
  $script:errors += $bounded
  Write-Error $bounded -ErrorAction Continue
}

function Test-LocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Assert-NoReparsePath([string]$Path, [string]$Description) {
  if (-not (Test-LocalWindowsPath $Path)) {
    Add-Error "$Description must be on a local Windows drive path: $Path"
    return $false
  }
  $current = [System.IO.Path]::GetFullPath($Path)
  while ($true) {
    if (Test-Path -LiteralPath $current) {
      try {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      } catch {
        Add-Error "$Description path component is uninspectable: $current"
        return $false
      }
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Add-Error "$Description must not traverse a reparse point: $current"
        return $false
      }
    }
    $parent = [System.IO.Directory]::GetParent($current)
    if ($null -eq $parent) { break }
    if ($parent.FullName -eq $current) { break }
    $current = $parent.FullName
  }
  return $true
}

function Require-Item([string]$Path, [string]$Description, [string]$Kind) {
  if (-not (Assert-NoReparsePath $Path $Description)) {
    return $null
  }
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  } catch {
    Add-Error "$Description is missing or uninspectable: $Path"
    return $null
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Add-Error "$Description must not be a reparse point: $Path"
    return $null
  }
  if ($Kind -eq "file" -and -not ($item -is [System.IO.FileInfo])) {
    Add-Error "$Description is not a regular file: $Path"
    return $null
  }
  if ($Kind -eq "directory" -and -not ($item -is [System.IO.DirectoryInfo])) {
    Add-Error "$Description is not a directory: $Path"
    return $null
  }
  return $item.FullName
}

function Require-File([string]$Path, [string]$Description) {
  Require-Item $Path $Description "file"
}

function Require-Directory([string]$Path, [string]$Description) {
  Require-Item $Path $Description "directory"
}

function Assert-RepoChildPath([string]$Path, [string]$Base, [string]$Description) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    Add-Error "$Description must resolve to a child path inside the Avorax repository root, not the repository root itself."
    return $false
  }
  $basePrefix = $baseFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Add-Error "$Description must resolve inside the Avorax repository root: $pathFull"
    return $false
  }
  return $true
}

function Resolve-ReleaseGateInputFilePath([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    Add-Error "$Description path is required."
    return ""
  }
  $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
    $Path
  } else {
    Join-Path $root $Path
  }
  $full = [System.IO.Path]::GetFullPath($candidate)
  if (-not (Assert-NoReparsePath $full $Description)) {
    return ""
  }
  if (-not (Assert-RepoChildPath $full $root $Description)) {
    return ""
  }
  return $full
}

function Get-RegularFiles([string]$Directory, [string]$Filter, [string]$Description) {
  if (-not $Directory) { return @() }
  try {
    @(Get-ChildItem -LiteralPath $Directory -File -Filter $Filter -ErrorAction Stop |
      Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 })
  } catch {
    Add-Error "Could not enumerate $Description in $Directory`: $(Get-BoundedDiagnostic $_.Exception.Message)"
    @()
  }
}

function Get-JsonBooleanProperty([object]$Object, [string]$Name, [string]$Description) {
  if ($null -eq $Object) {
    Add-Error "$Description object is missing."
    return $null
  }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property) {
    Add-Error "$Description.$Name is missing."
    return $null
  }
  if (-not ($property.Value -is [bool])) {
    $type = if ($null -eq $property.Value) { "null" } else { $property.Value.GetType().Name }
    Add-Error "$Description.$Name must be a JSON boolean, got $type."
    return $null
  }
  return [bool]$property.Value
}

function Read-JsonFile([string]$Path, [string]$Description) {
  $file = Require-File $Path $Description
  if (-not $file) { return $null }
  try {
    $json = Read-AvoraxGateTextFileBounded $file $maxJsonBytes $Description
    return ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    $message = Get-BoundedDiagnostic $_.Exception.Message
    if ($message.StartsWith("$Description exceeds ")) {
      Add-Error $message
    } else {
      Add-Error "$Description is not valid bounded JSON: $message"
    }
    return $null
  }
}

function Invoke-ReleaseGateCommand([string]$Tool, [string[]]$Arguments, [string]$DisplayName, [string]$WorkingDirectory = $null) {
  if (-not $Tool) {
    Add-Error "$DisplayName could not run because its executable was unavailable."
    return $false
  }
  $diagnostic = Invoke-AvoraxGateCommandDiagnostic $Tool $Arguments $DisplayName 32768 $WorkingDirectory
  if ($diagnostic.exit_code -ne 0) {
    Add-Error "$DisplayName failed with exit code $($diagnostic.exit_code): $($diagnostic.output)"
    return $false
  }
  return $true
}

function Invoke-ReleaseGateScript([string]$ScriptPath, [string[]]$Arguments, [string]$DisplayName) {
  if (-not $script:powerShell) {
    Add-Error "$DisplayName could not run because the current PowerShell executable was unavailable."
    return $false
  }
  if (-not $ScriptPath) {
    Add-Error "$DisplayName could not run because its script path was unavailable."
    return $false
  }
  $scriptArguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $ScriptPath) + @($Arguments)
  Invoke-ReleaseGateCommand $script:powerShell $scriptArguments $DisplayName
}

$SelfTestReport = Resolve-ReleaseGateInputFilePath $SelfTestReport "driver self-test report"
if ([string]::IsNullOrWhiteSpace($SelfTestReport)) {
  throw "Driver self-test report path was not safe to inspect."
}

$cargo = if ([string]::IsNullOrWhiteSpace($CargoPath)) {
  Add-Error "Cargo executable path is required. Set CARGO or pass -CargoPath; refusing ambient cargo lookup."
  $null
} else {
  Require-File $CargoPath "Cargo executable"
}

$python = if ([string]::IsNullOrWhiteSpace($PythonPath)) {
  Add-Error "Python executable path is required. Set AVORAX_PYTHON or pass -PythonPath; refusing ambient python lookup."
  $null
} else {
  Require-File $PythonPath "Python executable"
}

$dotnet = if ([string]::IsNullOrWhiteSpace($DotnetPath)) {
  Add-Error ".NET SDK dotnet executable path is required. Set AVORAX_DOTNET or pass -DotnetPath; refusing ambient dotnet lookup."
  $null
} else {
  Require-File $DotnetPath ".NET SDK dotnet executable"
}

$flutter = if ([string]::IsNullOrWhiteSpace($FlutterPath)) {
  Add-Error "Flutter executable path is required. Set AVORAX_FLUTTER or pass -FlutterPath; refusing ambient flutter lookup."
  $null
} else {
  Require-File $FlutterPath "Flutter executable"
}

$script:powerShell = Require-File ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"

try {
  $brandingCheck = Require-File (Join-Path $root "tools\branding\branding-check.ps1") "Branding check script"
  if ($brandingCheck) {
    [void](Invoke-ReleaseGateScript $brandingCheck @("-Root", [string]$root) "Branding check")
  }
} catch {
  Add-Error "Branding check failed: $($_.Exception.Message)"
}

try {
  $noMalwareGate = Require-File (Join-Path $root "tools\security\zentor-no-malware-binaries-gate.ps1") "No-malware-binaries gate script"
  if ($noMalwareGate -and $python) {
    [void](Invoke-ReleaseGateScript $noMalwareGate @("-RepoRoot", [string]$root, "-PythonPath", $python) "No-malware-binaries gate")
  }
} catch {
  Add-Error "No-malware-binaries gate failed: $($_.Exception.Message)"
}

try {
  $dependencyEvidenceGate = Require-File (Join-Path $root "tools\security\avorax-dependency-evidence.ps1") "Dependency evidence gate script"
  if ($dependencyEvidenceGate) {
    $dependencyEvidenceReport = Join-Path $root "dist\dependency-evidence\dependency_evidence.json"
    [void](Invoke-ReleaseGateScript $dependencyEvidenceGate @("-RepoRoot", [string]$root, "-ReportPath", $dependencyEvidenceReport) "Dependency evidence gate")
  }
} catch {
  Add-Error "Dependency evidence gate failed: $($_.Exception.Message)"
}

$report = Read-JsonFile $SelfTestReport "driver self-test report"
if ($report) {
  if ($report.overall_result -ne "pass" -and $DriverFeatureEnabled) {
    Add-Error "Driver feature is enabled but protection self-test did not pass."
  }
  if ($DriverFeatureEnabled) {
    $driverProperty = $report.PSObject.Properties["driver"]
    if ($null -eq $driverProperty -or $null -eq $driverProperty.Value -or -not ($driverProperty.Value -is [pscustomobject])) {
      Add-Error "Driver feature is enabled but driver self-test report is missing a driver object."
    } else {
      $communicationPortOk = Get-JsonBooleanProperty $driverProperty.Value "communication_port_ok" "driver self-test report driver"
      if ($null -ne $communicationPortOk -and -not $communicationPortOk) {
        Add-Error "Driver feature is enabled but driver communication port is not OK."
      }
    }
  }
}

$metadataPath = Join-Path $root "assets\models\zentor_static_malware_model.metadata.json"
$modelPath = Join-Path $root "assets\models\zentor_static_malware_model.onnx"
if ($AiFeatureEnabled) {
  $modelFile = Require-File $modelPath "AI model file"
  $metadata = Read-JsonFile $metadataPath "AI metadata file"
  if ($metadata) {
    $productionReady = Get-JsonBooleanProperty $metadata "production_ready" "AI model metadata"
    if ($productionReady -eq $false) {
      Write-Warning "AI model is development-only; release must not enable AI-only auto-quarantine."
    }
  }
}

$dist = Join-Path $root "dist"
$distRoot = Require-Directory $dist "dist directory"
if ($distRoot) {
  $badArtifacts = Get-RegularFiles $distRoot "*" "dist installer artifacts" |
    Where-Object { $_.Name -match "\.(msi|exe)$" -and $_.Name -notlike "Avorax-AntiVirus-*-x64*" }
  foreach ($artifact in $badArtifacts) {
    Add-Error "Installer artifact is not Avorax-AntiVirus named: $($artifact.Name)"
  }
}

$smokeTest = Join-Path $root "tools\windows\avorax-installed-smoke-test.ps1"
$smokeTestFile = Require-File $smokeTest "Installed smoke test script"

$stageTest = Join-Path $root "tools\windows\avorax-installer-stage-test.ps1"
$stageTestFile = Require-File $stageTest "Installer stage test script"

$prereqCheck = Join-Path $root "tools\windows\avorax-release-prereq-check.ps1"
$prereqCheckFile = Require-File $prereqCheck "Release prerequisite check script"
if ($prereqCheckFile -and $cargo -and $dotnet -and $flutter) {
  $prereqReport = Join-Path $root "dist\release-prereq\release_prereq_report.json"
  [void](Invoke-ReleaseGateScript $prereqCheckFile @(
      "-RepoRoot",
      [string]$root,
      "-DotnetPath",
      $dotnet,
      "-CargoPath",
      $cargo,
      "-FlutterPath",
      $flutter,
      "-ReportPath",
      $prereqReport
    ) "Release prerequisite check")
}

$appUpdateService = Join-Path $root "apps\zentor_client\lib\core\updates\update_service.dart"
$appUpdateServiceFile = Require-File $appUpdateService "Flutter update service source"
if ($appUpdateServiceFile) {
  $updateSource = Read-AvoraxGateTextFileBounded $appUpdateServiceFile $maxJsonBytes "Flutter update service source"
  foreach ($blocked in @("setup.exe", ".msi", "msiexec", "launchUrl")) {
    if ($updateSource -match [regex]::Escape($blocked)) {
      Add-Error "Normal app update flow still references external installer behavior: $blocked"
    }
  }
  if ($updateSource -notmatch "\.aup") {
    Add-Error "Normal app update flow does not require .aup update packages."
  }
}

$stage = Join-Path $root "dist\windows-msi\stage"
$stageRoot = Require-Directory $stage "Installer stage"
if ($stageRoot) {
  foreach ($required in @(
    "Avorax.exe",
    "avorax_core_service.exe",
    "avorax_guard_service.exe",
    "avorax_update_service.exe",
    "engine\config\engine.default.json",
    "engine\signatures\avorax_core.asig",
    "engine\rules\avorax_core.arule",
    "engine\ml\avorax_native_model.amodel",
    "engine\trust\avorax_known_good.atrust",
    "engine\trust\avorax_release_manifest.json",
    "tools\windows\avorax-installed-smoke-test.ps1",
    "tools\windows\avorax-installed-core-lifecycle-probe.ps1",
    "tools\windows\avorax-local-scan.ps1",
    "tools\windows\avorax-quarantine.ps1",
    "tools\security\avorax-security-gate-tools.ps1",
    "install-manifest.json"
  )) {
    Require-File (Join-Path $stageRoot $required) "Installer stage payload $required" | Out-Null
  }

  if ($stageTestFile) {
    try {
      [void](Invoke-ReleaseGateScript $stageTestFile @("-StagePath", $stageRoot) "Installer stage test")
    } catch {
      Add-Error "Installer stage test failed: $($_.Exception.Message)"
    }
  }
}

foreach ($artifact in @(
  "Avorax-AntiVirus-*-x64.msi",
  "Avorax-AntiVirus-*-x64-setup.exe"
)) {
  if (-not $distRoot -or -not (Get-RegularFiles $distRoot $artifact "required installer artifact $artifact")) {
    Add-Error "Required installer artifact is missing from dist: $artifact"
  }
}

if ($cargo) {
  $guardCrate = Require-Directory (Join-Path $root "core\zentor_guard_service") "guard-service crate"
  if ($guardCrate) {
    [void](Invoke-ReleaseGateCommand $cargo @("test", "--", "--test-threads=1") "Guard Service tests" $guardCrate)
  }
}

if ($cargo) {
  $localCoreCrate = Require-Directory (Join-Path $root "core\zentor_local_core") "local-core crate"
  if ($localCoreCrate) {
    [void](Invoke-ReleaseGateCommand $cargo @("test", "--", "--test-threads=1") "Local core tests" $localCoreCrate)
  }
}

if ($flutter) {
  $flutterClient = Require-Directory (Join-Path $root "apps\zentor_client") "Flutter client directory"
  if ($flutterClient) {
    [void](Invoke-ReleaseGateCommand $flutter @("test") "Flutter tests" $flutterClient)
  }
}

$falsePositiveGate = Require-File (Join-Path $root "tools\security\zentor-false-positive-gate.ps1") "False-positive gate script"
if ($falsePositiveGate -and $cargo) {
  [void](Invoke-ReleaseGateScript $falsePositiveGate @("-RepoRoot", [string]$root, "-CargoPath", $cargo) "False-positive gate")
}

$protectionScriptArgs = @("-RepoRoot", [string]$root, "-SelfTestReport", $SelfTestReport)
if ($cargo) {
  $protectionScriptArgs += @("-CargoPath", $cargo)
}
if ($DriverFeatureEnabled) {
  $protectionScriptArgs += @("-DriverFeatureEnabled")
}
$protectionGate = Require-File (Join-Path $root "tools\security\zentor-protection-gate.ps1") "Protection gate script"
if ($protectionGate -and $cargo) {
  [void](Invoke-ReleaseGateScript $protectionGate $protectionScriptArgs "Protection gate")
}

$performanceGate = Require-File (Join-Path $root "tools\perf\zentor-performance-gate.ps1") "Performance gate script"
if ($performanceGate -and $cargo -and $python) {
  [void](Invoke-ReleaseGateScript $performanceGate @("-RepoRoot", [string]$root, "-CargoPath", $cargo, "-PythonPath", $python) "Performance gate")
}

if ($errors.Count -gt 0) {
  throw "Avorax release gate failed with $($errors.Count) error(s)."
}

Write-Host "Avorax release gate passed."
