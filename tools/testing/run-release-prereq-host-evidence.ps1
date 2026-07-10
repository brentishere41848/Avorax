param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$DotnetPath = "",
  [string]$CargoPath = "",
  [string]$FlutterPath = "",
  [string]$ReportPath = "",
  [string]$PrereqScriptPath = ""
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")

function Resolve-RepoChildPath {
  param(
    [string]$Path,
    [string]$RepositoryRoot,
    [string]$Description
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Description path is required."
  }
  if (-not [System.IO.Path]::IsPathRooted($Path)) {
    $Path = Join-Path $RepositoryRoot $Path
  }
  $rootFull = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
  $full = [System.IO.Path]::GetFullPath($Path)
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if ($full.TrimEnd('\', '/').Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
      -not $full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must resolve inside the repository: $full"
  }
  Assert-AvoraxNoReparsePath $full $Description
  $full
}

function Resolve-ToolPathOrEmpty {
  param(
    [string]$ConfiguredPath,
    [string]$PreferredPath,
    [string]$Description
  )

  if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
    return (Get-AvoraxGateFile $ConfiguredPath $Description)
  }
  if (-not [string]::IsNullOrWhiteSpace($PreferredPath) -and
      (Test-Path -LiteralPath $PreferredPath -PathType Leaf)) {
    return (Get-AvoraxGateFile $PreferredPath $Description)
  }
  ""
}

function Read-JsonObject {
  param(
    [string]$Path,
    [string]$Description
  )

  $json = Read-AvoraxGateTextFileBounded $Path 2097152 $Description
  if ([string]::IsNullOrWhiteSpace($json)) {
    throw "$Description is empty: $Path"
  }
  try {
    $value = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "$Description is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($value -is [array] -or $null -eq $value -or $value -isnot [pscustomobject]) {
    throw "$Description must be a single JSON object."
  }
  $value
}

function Get-RequiredProperty {
  param(
    [object]$Object,
    [string]$Name,
    [string]$Description
  )

  if ($null -eq $Object -or $Object -isnot [pscustomobject]) {
    throw "$Description must be a JSON object."
  }
  if (-not ($Object.PSObject.Properties.Name -contains $Name)) {
    throw "$Description is missing required property '$Name'."
  }
  $Object.$Name
}

function Get-CheckByName {
  param(
    [object[]]$Checks,
    [string]$Name
  )

  foreach ($check in $Checks) {
    if ($check.name -eq $Name) { return $check }
  }
  throw "release prerequisite report is missing required check: $Name"
}

function Assert-CheckStatus {
  param(
    [object[]]$Checks,
    [string]$Name,
    [string[]]$AllowedStatuses
  )

  $check = Get-CheckByName $Checks $Name
  $status = [string](Get-RequiredProperty $check "status" "release prerequisite report check $Name")
  if ($AllowedStatuses -notcontains $status) {
    throw "release prerequisite report check $Name has unexpected status '$status'; expected one of $($AllowedStatuses -join ', ')."
  }
  $check
}

function Assert-ReleasePrereqReport {
  param(
    [string]$Path,
    [string]$RepositoryRoot,
    [int]$ExitCode
  )

  $report = Read-JsonObject $Path "release prerequisite host evidence report"
  $ok = Get-RequiredProperty $report "ok" "release prerequisite host evidence report"
  if ($ok -isnot [bool]) {
    throw "release prerequisite host evidence report ok must be a JSON boolean."
  }
  $mode = [string](Get-RequiredProperty $report "mode" "release prerequisite host evidence report")
  if ($mode -ne "host_only") {
    throw "release prerequisite host evidence report mode must be host_only, found $mode."
  }
  $repo = [System.IO.Path]::GetFullPath([string](Get-RequiredProperty $report "repo_root" "release prerequisite host evidence report"))
  $expectedRepo = [System.IO.Path]::GetFullPath($RepositoryRoot)
  if (-not $repo.TrimEnd('\', '/').Equals($expectedRepo.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    throw "release prerequisite host evidence report repo_root mismatch: $repo"
  }
  [void](Get-RequiredProperty $report "timestamp_utc" "release prerequisite host evidence report")
  [void](Get-RequiredProperty $report "tool_paths" "release prerequisite host evidence report")
  $checks = @(Get-RequiredProperty $report "checks" "release prerequisite host evidence report")
  if ($checks.Count -lt 15) {
    throw "release prerequisite host evidence report must include detailed checks, found $($checks.Count)."
  }
  $errors = @(Get-RequiredProperty $report "errors" "release prerequisite host evidence report")
  [void](Get-RequiredProperty $report "warnings" "release prerequisite host evidence report")

  [void](Assert-CheckStatus $checks "repository root" @("pass"))
  [void](Assert-CheckStatus $checks "Cargo executable" @("pass"))
  [void](Assert-CheckStatus $checks "Flutter executable" @("pass"))
  [void](Assert-CheckStatus $checks "Flutter client directory" @("pass"))
  [void](Assert-CheckStatus $checks "Flutter doctor command" @("pass", "fail"))
  [void](Assert-CheckStatus $checks "Android SDK" @("pass", "skipped"))
  [void](Assert-CheckStatus $checks "Windows symlink support" @("pass", "fail"))
  [void](Assert-CheckStatus $checks "Visual Studio Desktop C++ components" @("pass", "fail"))
  [void](Assert-CheckStatus $checks "Flutter Windows release Avorax.exe" @("skipped"))
  [void](Assert-CheckStatus $checks "Windows installer stage" @("skipped"))
  [void](Assert-CheckStatus $checks "Rust release service target\release\zentor_local_core.exe" @("skipped"))
  [void](Assert-CheckStatus $checks "Rust release service target\release\zentor_guard_service.exe" @("skipped"))
  [void](Assert-CheckStatus $checks "Rust release service target\release\avorax_update_service.exe" @("skipped"))

  if ($ok) {
    if ($ExitCode -ne 0) {
      throw "release prerequisite host evidence reported ok=true but prerequisite command exited $ExitCode."
    }
    if ($errors.Count -ne 0) {
      throw "release prerequisite host evidence reported ok=true but contains $($errors.Count) errors."
    }
    $failed = @($checks | Where-Object { $_.status -eq "fail" })
    if ($failed.Count -ne 0) {
      throw "release prerequisite host evidence reported ok=true but contains failing checks."
    }
    return "ready"
  }

  if ($ExitCode -eq 0) {
    throw "release prerequisite host evidence reported ok=false but prerequisite command exited 0."
  }
  if ($errors.Count -eq 0) {
    throw "release prerequisite host evidence reported ok=false but did not list blockers."
  }
  $joinedErrors = ($errors | ForEach-Object { [string]$_ }) -join "`n"
  if ($joinedErrors -notmatch "\.NET SDK" -and
      $joinedErrors -notmatch "Windows symlink support" -and
      $joinedErrors -notmatch "Visual Studio Desktop C\+\+") {
    throw "release prerequisite host blockers did not name a known actionable Windows build prerequisite."
  }
  "blocked"
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$script = if ([string]::IsNullOrWhiteSpace($PrereqScriptPath)) {
  Join-Path $repo "tools\windows\avorax-release-prereq-check.ps1"
} else {
  $PrereqScriptPath
}
$script = Get-AvoraxGateFile $script "release prerequisite checker"
$report = if ([string]::IsNullOrWhiteSpace($ReportPath)) {
  Join-Path $repo ".workflow\ultracode\avorax-hardening\results\small-threat-mvp-release-prereq-host.json"
} else {
  Resolve-RepoChildPath $ReportPath $repo "release prerequisite host evidence report"
}
$reportParent = Split-Path -Parent $report
if (-not (Test-Path -LiteralPath $reportParent -PathType Container)) {
  New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
}
Assert-AvoraxNoReparsePath $reportParent "release prerequisite host evidence report parent"

$dotnet = Resolve-ToolPathOrEmpty $DotnetPath "C:\Program Files\dotnet\dotnet.exe" ".NET SDK dotnet executable"
$cargo = Resolve-ToolPathOrEmpty $CargoPath "C:\Users\Brent\.cargo\bin\cargo.exe" "Cargo executable"
$flutter = Resolve-ToolPathOrEmpty $FlutterPath "C:\Users\Brent\develop\flutter\bin\flutter.bat" "Flutter executable"
$powershell = (Get-Command powershell.exe -ErrorAction Stop).Source

$arguments = @(
  "-NoProfile",
  "-ExecutionPolicy",
  "Bypass",
  "-File",
  $script,
  "-RepoRoot",
  $repo,
  "-ReportPath",
  $report,
  "-HostOnly"
)
if (-not [string]::IsNullOrWhiteSpace($dotnet)) {
  $arguments += @("-DotnetPath", $dotnet)
}
if (-not [string]::IsNullOrWhiteSpace($cargo)) {
  $arguments += @("-CargoPath", $cargo)
}
if (-not [string]::IsNullOrWhiteSpace($flutter)) {
  $arguments += @("-FlutterPath", $flutter)
}

$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  $output = & $powershell @arguments 2>&1
  $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
} finally {
  $ErrorActionPreference = $previousErrorActionPreference
}
if (-not (Test-Path -LiteralPath $report -PathType Leaf)) {
  throw "release prerequisite host evidence report was not written. Exit=$exitCode Output=$(Get-AvoraxGateBoundedDiagnostic ($output -join "`n"))"
}
$state = Assert-ReleasePrereqReport $report $repo $exitCode

Write-Host "Avorax release prerequisite host evidence captured: $state."
Write-Host "Report: $report"
