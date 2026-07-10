param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [string]$ReportPath = ".workflow\ultracode\avorax-hardening\results\installed-core-health-probe.json"
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
. (Join-Path $repo "tools\windows\avorax-core-health-probe.ps1")

function Resolve-RepoChildReportPath {
  param([string]$Root, [string]$PathValue)
  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
  $candidate = $PathValue
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $rootFull $candidate
  }
  $full = [System.IO.Path]::GetFullPath($candidate)
  $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Installed core health probe report must be inside the repository: $full"
  }
  return $full
}

function Write-JsonFileAtomic {
  param([string]$PathValue, [object]$Body)
  $directory = Split-Path -Parent $PathValue
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
  $temporary = Join-Path $directory (".tmp-" + [Guid]::NewGuid().ToString("N") + ".json")
  $backup = Join-Path $directory (".bak-" + [Guid]::NewGuid().ToString("N") + ".json")
  [System.IO.File]::WriteAllText($temporary, ($Body | ConvertTo-Json -Depth 100) + "`r`n", [System.Text.UTF8Encoding]::new($false))
  if (Test-Path -LiteralPath $PathValue -PathType Leaf) {
    [System.IO.File]::Replace($temporary, $PathValue, $backup, $true)
    if (Test-Path -LiteralPath $backup -PathType Leaf) { Remove-Item -LiteralPath $backup -Force }
  } else {
    [System.IO.File]::Move($temporary, $PathValue)
  }
}

function New-ValidHealthFixture {
  [ordered]@{
    ok = $true
    engine_status = "available"
    native_engine_status = "ready"
    native_signature_count = 2
    native_rule_count = 1
    native_self_test = $true
    core_service_status = "running"
    guard_status = "off"
    driver_status = "missing"
    process_monitor_status = "notActive"
    behavior_monitor_status = "notActive"
    reputation_status = "unavailable"
    ipc = "stdio"
    network_exposed = $false
    install_path = "C:\Program Files\Avorax"
    engine_directory = "C:\Program Files\Avorax\engine"
  }
}

function Assert-ParserRejects {
  param(
    [string]$Name,
    [string]$Stdout,
    [string]$ExpectedDiagnostic,
    [int]$ExitCode = 0
  )
  try {
    ConvertFrom-AvoraxCoreHealthOutput $Stdout "fixture stderr" $ExitCode | Out-Null
  } catch {
    $diagnostic = [string]$_.Exception.Message
    if ($diagnostic.IndexOf($ExpectedDiagnostic, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
      throw "$Name rejected with the wrong diagnostic: $diagnostic"
    }
    return [ordered]@{
      name = $Name
      expected_diagnostic = $ExpectedDiagnostic
      rejected = $true
    }
  }
  throw "$Name parser fixture unexpectedly succeeded."
}

$binaryCandidate = $LocalCorePath
if ([string]::IsNullOrWhiteSpace($binaryCandidate)) {
  $binaryCandidate = Join-Path $repo "target\release\zentor_local_core.exe"
}
if (-not (Test-Path -LiteralPath $binaryCandidate -PathType Leaf)) {
  throw "Release local-core binary is missing: $binaryCandidate"
}
$binary = (Resolve-Path -LiteralPath $binaryCandidate).Path
if ([System.IO.Path]::GetFileName($binary) -ne "zentor_local_core.exe") {
  throw "Installed core health probe smoke expects zentor_local_core.exe, got: $binary"
}

$validBody = New-ValidHealthFixture
$validJson = $validBody | ConvertTo-Json -Compress
$validResult = ConvertFrom-AvoraxCoreHealthOutput $validJson "" 0
if ($validResult.health.ok -ne $true -or $validResult.response_count -ne 1) {
  throw "Valid structured health fixture was not accepted."
}
$progressResult = ConvertFrom-AvoraxCoreHealthOutput ("{`"type`":`"progress`"}`r`n" + $validJson) "" 0
if ($progressResult.health.ipc -ne "stdio") {
  throw "Progress-prefixed structured health fixture was not accepted."
}

$cases = @()
$cases += Assert-ParserRejects "non-json-ok-substring" 'noise "ok":true noise' "non-JSON stdout"
$missingField = New-ValidHealthFixture
$missingField.Remove("native_self_test")
$cases += Assert-ParserRejects "missing-required-field" ($missingField | ConvertTo-Json -Compress) "missing required field: native_self_test"
$notOk = New-ValidHealthFixture
$notOk.ok = $false
$notOk.error = "fixture rejection"
$cases += Assert-ParserRejects "explicit-not-ok" ($notOk | ConvertTo-Json -Compress) "reported ok=false"
$cases += Assert-ParserRejects "multiple-health-responses" ($validJson + "`r`n" + $validJson) "expected exactly one JSON response"
$networkExposed = New-ValidHealthFixture
$networkExposed.network_exposed = $true
$cases += Assert-ParserRejects "network-exposed" ($networkExposed | ConvertTo-Json -Compress) "network_exposed=false"
$wrongIpc = New-ValidHealthFixture
$wrongIpc.ipc = "tcp"
$cases += Assert-ParserRejects "non-stdio-ipc" ($wrongIpc | ConvertTo-Json -Compress) "ipc=stdio"
$cases += Assert-ParserRejects "nonzero-exit" $validJson "exited with 7" 7

$runtime = Invoke-AvoraxCoreHealthProbe -CoreExe $binary -WorkingDirectory $repo
if ($runtime.health.ok -ne $true -or $runtime.health.ipc -ne "stdio" -or $runtime.health.network_exposed -ne $false) {
  throw "Release local-core runtime health probe did not return the required local structured boundary."
}

$reportFull = Resolve-RepoChildReportPath $repo $ReportPath
Write-JsonFileAtomic $reportFull ([ordered]@{
  schema_version = 1
  generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  status = "passed"
  tool = "avorax-installed-core-health-probe-smoke"
  local_core_path = $binary
  parser_rejection_cases = $cases
  parser_rejection_count = $cases.Count
  runtime = [ordered]@{
    ok = [bool]$runtime.health.ok
    ipc = [string]$runtime.health.ipc
    network_exposed = [bool]$runtime.health.network_exposed
    engine_status = [string]$runtime.health.engine_status
    native_engine_status = [string]$runtime.health.native_engine_status
    native_signature_count = [int64]$runtime.health.native_signature_count
    native_rule_count = [int64]$runtime.health.native_rule_count
    native_self_test = [bool]$runtime.health.native_self_test
    stderr = [string]$runtime.stderr
  }
  safety = [ordered]@{
    live_malware_used = $false
    standard_eicar_string_written = $false
    defender_exclusion_required = $false
    machine_wide_changes = $false
    service_installation_attempted = $false
    driver_installation_attempted = $false
    pre_execution_blocking_claimed = $false
    installed_runtime_claimed = $false
  }
  limitations = @(
    "release-binary-health-probe-not-installed-service-e2e",
    "installed-service-and-packaged-ui-proof-remains-blocked-by-host-prerequisites"
  )
})

Write-Host "Avorax installed core structured health probe smoke passed."
Write-Host "Parser rejection cases: $($cases.Count)"
Write-Host "Runtime IPC: $($runtime.health.ipc)"
Write-Host "Runtime network exposed: $($runtime.health.network_exposed)"
Write-Host "Report: $reportFull"
