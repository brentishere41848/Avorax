param(
  [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path,
  [string]$CargoPath = $env:CARGO,
  [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")
$maxDiagnosticChars = 4096
$maxJsonBytes = 1048576

function Fail($Message) {
  Write-Error $Message
  exit 1
}

function Get-BoundedDiagnostic {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  if ($text.Length -le $maxDiagnosticChars) { return $text }
  return $text.Substring(0, $maxDiagnosticChars) + "...[truncated]"
}

function Invoke-ZneGateCommand([string]$Tool, [string[]]$Arguments, [string]$DisplayName, [string]$WorkingDirectory) {
  if (-not $Tool) {
    Fail "$DisplayName could not run because its executable was unavailable."
  }
  $diagnostic = Invoke-AvoraxGateCommandDiagnostic $Tool $Arguments $DisplayName 32768 $WorkingDirectory
  if ($diagnostic.exit_code -ne 0) {
    Fail "$DisplayName failed with exit code $($diagnostic.exit_code): $($diagnostic.output)"
  }
}

function Read-JsonFile([string]$Path, [string]$Description) {
  try {
    $json = Read-AvoraxGateTextFileBounded $Path $maxJsonBytes $Description
    return ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    $message = Get-BoundedDiagnostic $_.Exception.Message
    if ($message.StartsWith("$Description exceeds ")) {
      Fail $message
    } else {
      Fail "$Description is not valid bounded JSON: $message"
    }
  }
}

function Write-JsonReportAtomic([string]$Path, [object]$Value, [int]$Depth, [string]$Description) {
  Assert-AvoraxNoReparsePath $Path $Description
  $target = [System.IO.Path]::GetFullPath($Path)
  $directory = New-AvoraxGateDirectory (Split-Path $target) "$Description directory"
  if (Test-Path -LiteralPath $target) {
    Get-AvoraxGateFile $target "existing $Description" | Out-Null
  }

  $tempReport = Join-Path $directory ("." + (Split-Path $target -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".tmp")
  $backupReport = Join-Path $directory ("." + (Split-Path $target -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".bak")
  $encoding = New-Object System.Text.UTF8Encoding($false)
  try {
    [System.IO.File]::WriteAllText($tempReport, ($Value | ConvertTo-Json -Depth $Depth), $encoding)
    Get-AvoraxGateFile $tempReport "temporary $Description" | Out-Null
    if (Test-Path -LiteralPath $target) {
      [System.IO.File]::Replace($tempReport, $target, $backupReport)
    } else {
      [System.IO.File]::Move($tempReport, $target)
    }
  } finally {
    Remove-AvoraxGateRegularFileIfPresent $tempReport "temporary $Description"
    Remove-AvoraxGateRegularFileIfPresent $backupReport "$Description backup file"
  }
}

function Assert-RepoChildPath([string]$Path, [string]$Base, [string]$Description) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "$Description must resolve to a child path inside the Avorax repository root, not the repository root itself."
  }
  $basePrefix = $baseFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "$Description must resolve inside the repository: $pathFull"
  }
}

function Get-JsonProperty($Object, [string]$Name, [string]$Description) {
  if ($null -eq $Object) {
    Fail "$Description object is missing."
  }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property) {
    Fail "$Description.$Name is missing."
  }
  return $property.Value
}

function Get-JsonBooleanProperty($Object, [string]$Name, [string]$Description) {
  $value = Get-JsonProperty $Object $Name $Description
  if (-not ($value -is [bool])) {
    $type = if ($null -eq $value) { "null" } else { $value.GetType().Name }
    Fail "$Description.$Name must be a JSON boolean, got $type."
  }
  return [bool]$value
}

function Get-JsonSha256Property($Object, [string]$Name, [string]$Description) {
  $value = Get-JsonProperty $Object $Name $Description
  if (-not ($value -is [string]) -or $value -notmatch '^[A-Fa-f0-9]{64}$') {
    $type = if ($null -eq $value) { "null" } else { $value.GetType().Name }
    Fail "$Description.$Name must be a 64-character lowercase or uppercase SHA-256 hex string, got $type."
  }
  return $value.ToLowerInvariant()
}

function Get-JsonPositiveIntegerProperty($Object, [string]$Name, [string]$Description) {
  $value = Get-JsonProperty $Object $Name $Description
  if (-not ($value -is [int] -or $value -is [long])) {
    $type = if ($null -eq $value) { "null" } else { $value.GetType().Name }
    Fail "$Description.$Name must be a JSON integer, got $type."
  }
  $integer = [int64]$value
  if ($integer -lt 1) {
    Fail "$Description.$Name must be at least 1."
  }
  return $integer
}

$repo = Get-AvoraxGateDirectory ([System.IO.Path]::GetFullPath((Resolve-Path $RepoRoot).Path)) "Repository root"
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
  $ReportPath = Join-Path $repo "zne_release_gate_report.json"
} elseif (-not [System.IO.Path]::IsPathRooted($ReportPath)) {
  $ReportPath = Join-Path $repo $ReportPath
}
$reportPathFull = [System.IO.Path]::GetFullPath($ReportPath)
Assert-AvoraxNoReparsePath $reportPathFull "ZNE release gate report"
Assert-RepoChildPath $reportPathFull $repo "ZNE release gate report path"
$cargo = Get-AvoraxRequiredTool $CargoPath "Cargo executable"

$required = @(
  "core/zentor_native_engine/Cargo.toml",
  "core/zentor_local_core/Cargo.toml",
  "core/zentor_guard_service/Cargo.toml",
  "assets/zentor_native/signatures/zentor_core.zsig",
  "assets/zentor_native/signatures/zentor_core.metadata.json",
  "assets/zentor_native/rules/zentor_rules.zrule",
  "assets/zentor_native/rules/zentor_rules.metadata.json",
  "assets/zentor_native/ml/zentor_native_model.zmodel",
  "assets/zentor_native/ml/zentor_native_model.metadata.json",
  "assets/zentor_native/trust/zentor_known_good.ztrust",
  "assets/zentor_native/trust/zentor_known_bad_test.ztrust"
)

foreach ($path in $required) {
  Get-AvoraxGateFile (Join-Path $repo $path) "required ZNE artifact $path" | Out-Null
}

$metadata = Read-JsonFile (Join-Path $repo "assets/zentor_native/ml/zentor_native_model.metadata.json") "ZNE ML metadata"
$productionReady = Get-JsonBooleanProperty $metadata "production_ready" "ZNE ML metadata"
if (-not $productionReady) {
  Write-Host "Native ML is development-only; AI-only auto-quarantine must remain disabled."
}

$signatureMetadata = Read-JsonFile (Join-Path $repo "assets/zentor_native/signatures/zentor_core.metadata.json") "ZNE signature metadata"
$signaturePackSha256 = Get-JsonSha256Property $signatureMetadata "pack_sha256" "ZNE signature metadata"
$signatureCount = Get-JsonPositiveIntegerProperty $signatureMetadata "signature_count" "ZNE signature metadata"

$nativeManifest = Get-AvoraxGateFile (Join-Path $repo "core\zentor_native_engine\Cargo.toml") "ZNE native-engine Cargo manifest"
$localCoreManifest = Get-AvoraxGateFile (Join-Path $repo "core\zentor_local_core\Cargo.toml") "ZNE local-core Cargo manifest"
$guardManifest = Get-AvoraxGateFile (Join-Path $repo "core\zentor_guard_service\Cargo.toml") "ZNE guard-service Cargo manifest"
Invoke-ZneGateCommand $cargo @("build", "--manifest-path", $nativeManifest, "--bin", "zentor-signature-compiler") "ZNE signature compiler build" $repo
Invoke-ZneGateCommand $cargo @("test", "--manifest-path", $nativeManifest, "--", "--test-threads=1") "ZNE native engine tests" $repo
Invoke-ZneGateCommand $cargo @("test", "--manifest-path", $localCoreManifest, "--", "--test-threads=1") "ZNE local core tests" $repo
Invoke-ZneGateCommand $cargo @("test", "--manifest-path", $guardManifest, "--", "--test-threads=1") "ZNE guard service tests" $repo

$oldBrand = "Pa" + "sus"
$oldBrandUpper = "PA" + "SUS"
$oldBrandLower = "pa" + "sus"
$oldAntiCheat = "anti" + "-cheat"
$oldFairPlay = "fair" + " play"
$oldGamingProtection = "gaming" + " protection"
$oldGameSetup = "game" + " setup"
$oldPlayerSession = "player" + " session"
$oldMatchTelemetry = "match" + " telemetry"
$badPattern = "ClamAV through Avorax local core|YARA Rules|bundled ClamAV|$oldBrand|$oldBrandUpper|$oldBrandLower|$oldAntiCheat|$oldFairPlay|$oldGamingProtection|$oldGameSetup|$oldPlayerSession|$oldMatchTelemetry"
$uiRoot = Get-AvoraxGateDirectory (Join-Path $repo "apps\zentor_client\lib") "Flutter UI source root"
$uiTextExtensions = @(".dart", ".tsx", ".ts")
$badUi = @()
foreach ($file in Get-ChildItem -LiteralPath $uiRoot -Recurse -File -Force -ErrorAction Stop) {
  if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "UI source file must not be a reparse point: $($file.FullName)"
  }
  if ($uiTextExtensions -notcontains $file.Extension.ToLowerInvariant()) { continue }
  $content = Read-AvoraxGateTextFileBounded $file.FullName $maxJsonBytes "Flutter UI source file"
  if ($content -match $badPattern) {
    $badUi += $file.FullName
  }
}
if ($badUi.Count -gt 0) {
  $badUi | ForEach-Object { Write-Error "User-facing UI still contains old primary-engine or gaming copy: $_" }
  Fail "User-facing UI still contains old primary-engine or gaming copy."
}

$status = @{
  native_engine = "pass"
  signatures = $signatureCount
  signature_pack_sha256 = $signaturePackSha256
  rules = Get-JsonPositiveIntegerProperty (Read-JsonFile (Join-Path $repo "assets/zentor_native/rules/zentor_rules.metadata.json") "ZNE rules metadata") "rule_count" "ZNE rules metadata"
  compatibility_engines_enabled_by_default = $false
}

Write-JsonReportAtomic $reportPathFull $status 4 "ZNE release gate report"
Write-Host "ZNE release gate passed. Report: $reportPathFull"
