param(
  [string]$InstallPath,
  [string]$ProgramDataPath,
  [switch]$RequireGuardRunning
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")
. (Join-Path $PSScriptRoot "avorax-core-health-probe.ps1")
$lifecycleProbeScript = Join-Path $PSScriptRoot "avorax-installed-core-lifecycle-probe.ps1"
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

function Add-CheckError([string]$Message) {
  $bounded = Get-BoundedDiagnostic $Message
  $script:errors += $bounded
  Write-Error $bounded -ErrorAction Continue
}

function Test-LocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Test-NoReparsePath([string]$Path, [string]$Description) {
  if (-not (Test-LocalWindowsPath $Path)) {
    Add-CheckError "$Description must be on a local Windows drive path: $Path"
    return $false
  }
  $current = [System.IO.Path]::GetFullPath($Path)
  while ($true) {
    if (Test-Path -LiteralPath $current) {
      try {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      } catch {
        Add-CheckError "$Description path component is uninspectable: $current"
        return $false
      }
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Add-CheckError "$Description must not traverse a reparse point: $current"
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

function Get-CheckedEnvironmentRoot([string[]]$Names, [string]$Description) {
  $diagnostics = @()
  foreach ($name in $Names) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
      $diagnostics += "$name is not set or is empty"
      continue
    }
    $root = $value.Trim()
    if (-not (Test-LocalWindowsPath $root)) {
      $diagnostics += "$name must be a local Windows drive path: $root"
      continue
    }
    if (-not (Test-NoReparsePath $root "$Description root")) {
      $diagnostics += "$name failed path safety checks"
      continue
    }
    return [System.IO.Path]::GetFullPath($root)
  }
  Add-CheckError "$Description root is unavailable: $($diagnostics -join '; ')"
  return $null
}

function Resolve-ExplicitSmokePath([string]$Path, [string]$Description) {
  if (-not (Test-NoReparsePath $Path $Description)) {
    return $Path
  }
  return [System.IO.Path]::GetFullPath($Path)
}

function Resolve-InstalledAvoraxSmokePath([AllowNull()][string]$Path) {
  if (-not [string]::IsNullOrWhiteSpace($Path)) {
    return Resolve-ExplicitSmokePath $Path "InstallPath"
  }
  $programFilesRoot = Get-CheckedEnvironmentRoot @("ProgramFiles", "ProgramW6432", "PROGRAMFILES") "ProgramFiles"
  if (-not $programFilesRoot) { return "" }
  return Join-Path $programFilesRoot "Avorax"
}

function Resolve-AvoraxProgramDataSmokePath([AllowNull()][string]$Path) {
  if (-not [string]::IsNullOrWhiteSpace($Path)) {
    return Resolve-ExplicitSmokePath $Path "ProgramDataPath"
  }
  $programDataRoot = Get-CheckedEnvironmentRoot @("ProgramData", "PROGRAMDATA") "ProgramData"
  if (-not $programDataRoot) { return "" }
  return Join-Path $programDataRoot "Avorax"
}

function Assert-NotRepositoryPath([string]$Path, [string]$RepoRoot, [string]$Description) {
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $repoFull = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd('\', '/')
  $repoPrefix = $repoFull + [System.IO.Path]::DirectorySeparatorChar
  if ($pathFull.Equals($repoFull, [StringComparison]::OrdinalIgnoreCase) -or
      $pathFull.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Add-CheckError "$Description must not resolve inside the Avorax repository; installed smoke tests require installed Program Files and ProgramData targets."
    return $false
  }
  return $true
}

function Require-Item([string]$Path, [string]$Description, [string]$Kind) {
  if (-not (Test-NoReparsePath $Path $Description)) {
    return $null
  }
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  } catch {
    Add-CheckError "$Description is missing or uninspectable: $Path"
    return $null
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Add-CheckError "$Description must not be a reparse point: $Path"
    return $null
  }
  if ($Kind -eq "file" -and -not ($item -is [System.IO.FileInfo])) {
    Add-CheckError "$Description is not a regular file: $Path"
    return $null
  }
  if ($Kind -eq "directory" -and -not ($item -is [System.IO.DirectoryInfo])) {
    Add-CheckError "$Description is not a directory: $Path"
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

function Count-RegularFiles([string]$Path, [string]$Filter, [string]$Description) {
  $directory = Require-Directory $Path $Description
  if (-not $directory) {
    return 0
  }
  try {
    return (Get-ChildItem -LiteralPath $directory -Filter $Filter -File -ErrorAction Stop |
      Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 } |
      Measure-Object).Count
  } catch {
    Add-CheckError "Could not enumerate $Description files matching $Filter`: $(Get-BoundedDiagnostic $_.Exception.Message)"
    return 0
  }
}

function Get-JsonPropertyValue([object]$Object, [string]$Name, [string]$Description) {
  if ($null -eq $Object) {
    Add-CheckError "$Description object is missing."
    return $null
  }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property) {
    Add-CheckError "$Description.$Name is missing."
    return $null
  }
  return $property.Value
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
      Add-CheckError $message
    } else {
      Add-CheckError "$Description is not valid bounded JSON: $message"
    }
    return $null
  }
}

function Test-SafeManifestRelativePath([object]$Value) {
  if (-not ($Value -is [string]) -or [string]::IsNullOrWhiteSpace($Value)) {
    return $false
  }
  $normalized = $Value -replace '/', '\'
  if ([System.IO.Path]::IsPathRooted($normalized)) { return $false }
  if ($normalized.StartsWith('\') -or $normalized.EndsWith('\') -or $normalized.Contains('\\')) { return $false }
  if ($normalized -match '(^|\\)\.\.(\\|$)') { return $false }
  if ($normalized -match '(^|\\)\.(\\|$)') { return $false }
  if ($normalized -match '[\x00-\x1F]') { return $false }
  return $true
}

function Test-Sha256Hex([object]$Value) {
  return ($Value -is [string] -and $Value -match '^[A-Fa-f0-9]{64}$')
}

function Test-NonNegativeJsonInteger([object]$Value) {
  if ($Value -is [bool]) { return $false }
  if (-not ($Value -is [int] -or $Value -is [long])) { return $false }
  return ([int64]$Value -ge 0)
}

function Get-RequiredService([string]$Name, [string]$Description) {
  try {
    return Get-Service -Name $Name -ErrorAction Stop
  } catch {
    Add-CheckError "$Description is not installed or could not be inspected: $(Get-BoundedDiagnostic $_.Exception.Message)"
    return $null
  }
}

$InstallPath = Resolve-InstalledAvoraxSmokePath $InstallPath
$ProgramDataPath = Resolve-AvoraxProgramDataSmokePath $ProgramDataPath
$repoRoot = Require-Directory ([System.IO.Path]::GetFullPath((Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path)) "Avorax repository root"
if (-not $repoRoot) { throw "Avorax repository root was not found or safe to inspect." }
if (-not (Assert-NotRepositoryPath $InstallPath $repoRoot "InstallPath")) {
  throw "InstallPath was not safe to inspect as an installed target: $InstallPath"
}
if (-not (Assert-NotRepositoryPath $ProgramDataPath $repoRoot "ProgramDataPath")) {
  throw "ProgramDataPath was not safe to inspect as an installed target: $ProgramDataPath"
}

Write-Host "Avorax installed smoke test"
Write-Host "InstallPath: $InstallPath"
Write-Host "ProgramDataPath: $ProgramDataPath"

$installRoot = Require-Directory $InstallPath "Install directory"
$programDataRoot = Require-Directory $ProgramDataPath "ProgramData root"
Require-File (Join-Path $InstallPath "Avorax.exe") "Avorax app executable" | Out-Null
$coreAliasExe = Require-File (Join-Path $InstallPath "avorax_core_service.exe") "Avorax Core Service alias executable"
$coreExe = Require-File (Join-Path $InstallPath "zentor_local_core.exe") "canonical installed local-core executable"
$lifecycleProbe = Require-File $lifecycleProbeScript "installed core lifecycle probe"
if ($coreAliasExe -and $coreExe) {
  $aliasHash = (Get-FileHash -LiteralPath $coreAliasExe -Algorithm SHA256).Hash
  $canonicalHash = (Get-FileHash -LiteralPath $coreExe -Algorithm SHA256).Hash
  if ($aliasHash -ne $canonicalHash) {
    Add-CheckError "Avorax Core Service alias does not match the canonical installed local-core executable."
  }
}
Require-File (Join-Path $InstallPath "avorax_guard_service.exe") "Avorax Guard Service executable" | Out-Null
Require-File (Join-Path $InstallPath "avorax_update_service.exe") "Avorax Update Service executable" | Out-Null
Require-Directory (Join-Path $InstallPath "engine") "Avorax Native Engine directory" | Out-Null
Require-File (Join-Path $InstallPath "engine\config\engine.default.json") "Engine default config" | Out-Null
Require-File (Join-Path $InstallPath "engine\ml\avorax_native_model.amodel") "Native ML model" | Out-Null
Require-File (Join-Path $InstallPath "engine\ml\avorax_native_model.metadata.json") "Native ML metadata" | Out-Null
Require-File (Join-Path $InstallPath "engine\trust\avorax_known_good.atrust") "Known-good trust pack" | Out-Null
Require-File (Join-Path $InstallPath "engine\trust\avorax_known_bad_test.atrust") "Known-bad test trust pack" | Out-Null
$manifest = Read-JsonFile (Join-Path $InstallPath "engine\trust\avorax_release_manifest.json") "Avorax release manifest"
if ($manifest) {
  $product = Get-JsonPropertyValue $manifest "product" "Avorax release manifest"
  if ($product -ne "Avorax Anti-Virus") {
    Add-CheckError "Avorax release manifest product is invalid."
  }
  $version = Get-JsonPropertyValue $manifest "version" "Avorax release manifest"
  if (-not ($version -is [string]) -or [string]::IsNullOrWhiteSpace($version)) {
    Add-CheckError "Avorax release manifest version must be a non-empty JSON string."
  }
  $files = Get-JsonPropertyValue $manifest "files" "Avorax release manifest"
  $manifestPaths = @()
  $seenManifestPaths = @{}
  if ($null -eq $files -or -not ($files -is [array])) {
    Add-CheckError "Avorax release manifest files must be a JSON array."
  } else {
    $index = 0
    foreach ($entry in $files) {
      $description = "Avorax release manifest files[$index]"
      if ($null -eq $entry -or -not ($entry -is [pscustomobject])) {
        Add-CheckError "$description must be a JSON object."
        $index += 1
        continue
      }
      $normalizedPath = $null
      $path = Get-JsonPropertyValue $entry "path" $description
      if (-not (Test-SafeManifestRelativePath $path)) {
        Add-CheckError "$description.path must be a safe relative path."
      } else {
        $normalizedPath = ($path -replace '/', '\')
        $manifestPaths += $normalizedPath
        $key = $normalizedPath.ToLowerInvariant()
        if ($seenManifestPaths.ContainsKey($key)) {
          Add-CheckError "Avorax release manifest contains duplicate path: $normalizedPath"
        } else {
          $seenManifestPaths[$key] = $true
        }
      }
      $sha256 = Get-JsonPropertyValue $entry "sha256" $description
      $sha256Valid = Test-Sha256Hex $sha256
      if (-not $sha256Valid) {
        Add-CheckError "$description.sha256 must be a 64-character SHA-256 hex string."
      }
      $bytes = Get-JsonPropertyValue $entry "bytes" $description
      $bytesValid = Test-NonNegativeJsonInteger $bytes
      if (-not $bytesValid) {
        Add-CheckError "$description.bytes must be a non-negative JSON integer."
      }
      if ($normalizedPath) {
        $installedFile = Require-File (Join-Path $InstallPath $normalizedPath) "$description installed file"
        if ($installedFile) {
          $installedItem = Get-Item -LiteralPath $installedFile -Force -ErrorAction Stop
          if ($sha256Valid) {
            $actualSha256 = (Get-FileHash -LiteralPath $installedFile -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualSha256 -ne $sha256.ToLowerInvariant()) {
              Add-CheckError "$description.sha256 does not match installed file hash for $normalizedPath."
            }
          }
          if ($bytesValid -and $installedItem.Length -ne [int64]$bytes) {
            Add-CheckError "$description.bytes does not match installed file length for $normalizedPath."
          }
        }
      }
      $index += 1
    }
  }
  foreach ($trusted in @(
    "Avorax.exe",
    "avorax_core_service.exe",
    "avorax_guard_service.exe",
    "engine\signatures\avorax_core.asig",
    "engine\rules\avorax_core.arule",
    "engine\ml\avorax_native_model.amodel"
  )) {
    if ($manifestPaths -notcontains $trusted) {
      Add-CheckError "Avorax release manifest does not include: $trusted"
    }
  }
}

$signatureCount = Count-RegularFiles (Join-Path $InstallPath "engine\signatures") "*.asig" "Avorax signature directory"
$ruleCount = Count-RegularFiles (Join-Path $InstallPath "engine\rules") "*.arule" "Avorax rule directory"
if ($signatureCount -le 0) {
  Add-CheckError "No installed Avorax signature packs were found under engine\signatures."
}
if ($ruleCount -le 0) {
  Add-CheckError "No installed Avorax rule packs were found under engine\rules."
}

foreach ($dir in @("config", "logs", "events", "Quarantine", "scans", "cache", "reports", "migration")) {
  Require-Directory (Join-Path $ProgramDataPath $dir) "ProgramData $dir directory" | Out-Null
}
foreach ($dir in @("updates", "updates\staging", "updates\rollback", "updates\logs")) {
  Require-Directory (Join-Path $ProgramDataPath $dir) "ProgramData $dir directory" | Out-Null
}
Require-File (Join-Path $ProgramDataPath "reports\install_report.json") "Install report" | Out-Null

$coreService = Get-RequiredService "avorax_core_service" "Avorax Core Service"
if ($coreService -and $coreService.Status -ne "Running") {
  Add-CheckError "Avorax Core Service is installed but not running. Status: $($coreService.Status)"
}

$guardService = Get-RequiredService "avorax_guard_service" "Avorax Guard Service"
if ($guardService -and $RequireGuardRunning -and $guardService.Status -ne "Running") {
  Add-CheckError "Avorax Guard Service is installed but not running. Status: $($guardService.Status)"
}

$updateService = Get-RequiredService "avorax_update_service" "Avorax Update Service"

if ($coreExe) {
  try {
    $coreHealth = Invoke-AvoraxCoreHealthProbe -CoreExe $coreExe -WorkingDirectory $InstallPath
    if (-not [string]::IsNullOrWhiteSpace([string]$coreHealth.stderr)) {
      Add-CheckError "Avorax Core Service health command wrote stderr: $(Get-BoundedDiagnostic $coreHealth.stderr)"
    }
    if ($coreHealth.health.engine_status -ne "available") {
      Add-CheckError "Installed Avorax engine_status is not available: $($coreHealth.health.engine_status)"
    }
    if ($coreHealth.health.native_engine_status -ne "ready") {
      Add-CheckError "Installed Avorax native_engine_status is not ready: $($coreHealth.health.native_engine_status)"
    }
    if ([int64]$coreHealth.health.native_signature_count -le 0) {
      Add-CheckError "Installed Avorax health reports no native signatures."
    }
    if ([int64]$coreHealth.health.native_rule_count -le 0) {
      Add-CheckError "Installed Avorax health reports no native rules."
    }
    if ($coreHealth.health.native_self_test -ne $true) {
      Add-CheckError "Installed Avorax native self-test did not pass."
    }
  } catch {
    Add-CheckError "Avorax Core Service structured health probe failed: $(Get-BoundedDiagnostic $_.Exception.Message)"
  }
}

if ($errors.Count -eq 0 -and $coreExe -and $lifecycleProbe) {
  $lifecycleReportPath = Join-Path $ProgramDataPath "reports\installed_core_lifecycle_report.json"
  try {
    $null = & $lifecycleProbe `
      -LocalCorePath $coreExe `
      -EvidenceRoot $ProgramDataPath `
      -ReportPath $lifecycleReportPath `
      -TimeoutSeconds 120
    $lifecycleReport = Read-JsonFile $lifecycleReportPath "installed core lifecycle report"
    if ($null -eq $lifecycleReport) {
      Add-CheckError "Installed core lifecycle probe did not produce a readable report."
    } else {
      if ($lifecycleReport.status -ne "passed" -or $lifecycleReport.tool -ne "avorax-installed-core-lifecycle-probe") {
        Add-CheckError "Installed core lifecycle report did not record a passed structured probe."
      }
      if ($lifecycleReport.local_core_sha256 -ne $canonicalHash.ToLowerInvariant()) {
        Add-CheckError "Installed core lifecycle report executable hash does not match the canonical installed core."
      }
      if ($lifecycleReport.operations.scan_restore.source_removed -ne $true -or
          $lifecycleReport.operations.list.record_found -ne $true -or
          $lifecycleReport.operations.restore.fixture_sha256_verified -ne $true -or
          $lifecycleReport.operations.restore.payload_removed -ne $true -or
          $lifecycleReport.operations.scan_delete.source_removed -ne $true -or
          $lifecycleReport.operations.delete.source_absent -ne $true -or
          $lifecycleReport.operations.delete.payload_removed -ne $true) {
        Add-CheckError "Installed core lifecycle report is missing required scan/quarantine/restore/delete postconditions."
      }
      if ($lifecycleReport.cleanup.isolated_temp_removed -ne $true -or
          $lifecycleReport.safety.machine_wide_changes -ne $false -or
          $lifecycleReport.safety.installed_service_mediation_claimed -ne $false -or
          $lifecycleReport.safety.pre_execution_blocking_claimed -ne $false) {
        Add-CheckError "Installed core lifecycle report did not preserve cleanup and user-mode safety boundaries."
      }
    }
  } catch {
    Add-CheckError "Installed core lifecycle probe failed: $(Get-BoundedDiagnostic $_.Exception.Message)"
  }
}

if ($errors.Count -gt 0) {
  throw "Avorax installed smoke test failed with $($errors.Count) error(s)."
}

Write-Host "Avorax installed smoke test passed."
