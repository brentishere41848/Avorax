param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$VerifierPath = $(Join-Path $PSScriptRoot "verify-small-threat-mvp.ps1"),
  [string]$ValidatorPath = $(Join-Path $PSScriptRoot "validate-small-threat-mvp-report.ps1"),
  [string]$PythonPath = "",
  [string]$FlutterPath = "",
  [string]$DartPath = "",
  [string]$PowerShell7Path = ""
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")

function Resolve-RepoChildFile {
  param(
    [string]$Path,
    [string]$RepositoryRoot,
    [string]$Description
  )

  $rootFull = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path)
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must stay inside the repository: $pathFull"
  }
  Get-AvoraxGateFile $pathFull $Description
}

function Read-JsonObject {
  param(
    [string]$Path,
    [string]$Description
  )

  $text = Read-AvoraxGateTextFileBounded $Path 2097152 $Description
  try {
    $value = ConvertFrom-AvoraxGateJsonPreservingStrings $text
  } catch {
    throw "$Description is not valid JSON: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
  if ($null -eq $value -or $value -isnot [pscustomobject]) {
    throw "$Description must be one JSON object."
  }
  $value
}

function Copy-JsonObject {
  param([object]$Value)

  ConvertFrom-AvoraxGateJsonPreservingStrings ($Value | ConvertTo-Json -Depth 12)
}

function Assert-NonEmptyString {
  param(
    [AllowNull()][object]$Value,
    [string]$Description
  )

  if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) {
    throw "$Description must be a non-empty string."
  }
  [string]$Value
}

function Invoke-ReportValidator {
  param(
    [string]$HostPath,
    [string]$HostName,
    [string]$ReportPath,
    [bool]$ExpectSuccess,
    [string]$ExpectedFailureText,
    [string]$RepositoryRoot,
    [string]$Validator
  )

  $arguments = @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $Validator,
    "-RepoRoot",
    $RepositoryRoot,
    "-ReportPath",
    $ReportPath
  )
  $result = Invoke-AvoraxGateCommandDiagnostic $HostPath $arguments "$HostName report validator" 8192 $RepositoryRoot
  if ($ExpectSuccess) {
    if ($result.exit_code -ne 0) {
      throw "$HostName rejected the authentic failed-step report: $($result.output)"
    }
    return
  }
  if ($result.exit_code -eq 0) {
    throw "$HostName accepted an adversarial failed-step report."
  }
  if ($result.output.IndexOf($ExpectedFailureText, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "$HostName rejected the adversarial report without the expected diagnostic '$ExpectedFailureText': $($result.output)"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$verifier = Resolve-RepoChildFile $VerifierPath $repo "small-threat MVP verifier"
$validator = Resolve-RepoChildFile $ValidatorPath $repo "small-threat MVP report validator"
$python = Get-AvoraxRequiredTool $PythonPath "failed-step smoke Python host"
$flutter = Get-AvoraxRequiredTool $FlutterPath "failed-step smoke Flutter host"
$dart = Get-AvoraxRequiredTool $DartPath "failed-step smoke Dart host"
$powerShell7 = Get-AvoraxRequiredTool $PowerShell7Path "failed-step smoke PowerShell 7 host"
$windowsPowerShell = Get-AvoraxRequiredTool (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source "failed-step smoke Windows PowerShell 5.1 host"
if ($powerShell7.Equals($windowsPowerShell, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Failed-step smoke requires distinct Windows PowerShell 5.1 and PowerShell 7 hosts."
}

$tempParent = New-AvoraxGateDirectory (Join-Path $repo ".workflow\ultracode\avorax-hardening\temporary-tests") "failed-step smoke temporary parent"
$tempRoot = Join-Path $tempParent ("checkpoint-2253-failed-step-" + [System.Guid]::NewGuid().ToString("N"))
$tempRoot = New-AvoraxGateDirectory $tempRoot "failed-step smoke temporary root"
$reportPath = Join-Path $tempRoot "failed-report.json"
$statusTamperPath = Join-Path $tempRoot "status-tamper.json"
$terminalTamperPath = Join-Path $tempRoot "terminal-tamper.json"
$errorTamperPath = Join-Path $tempRoot "error-tamper.json"

try {
  $nestedArguments = @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $verifier,
    "-RepoRoot",
    $repo,
    "-PythonPath",
    $python,
    "-CargoPath",
    $python,
    "-FlutterPath",
    $flutter,
    "-DartPath",
    $dart,
    "-PowerShell7Path",
    $powerShell7,
    "-ReportPath",
    $reportPath,
    "-SkipFlutter"
  )
  $nested = Invoke-AvoraxGateCommandDiagnostic $windowsPowerShell $nestedArguments "intentional first-step verifier failure" 16384 $repo
  if ($nested.exit_code -eq 0) {
    throw "Verifier unexpectedly succeeded when Python was intentionally supplied as the Cargo executable."
  }
  if ($nested.output.IndexOf("local-core safe simulator scan reporting failed with exit code", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "Intentional verifier failure did not expose the expected first-step diagnostic: $($nested.output)"
  }

  $report = Read-JsonObject $reportPath "failed-step smoke report"
  if ([int64]$report.schema_version -ne 2) {
    throw "Failed-step smoke report schema_version must be 2."
  }
  if ($report.status -ne "failed" -or $report.failure_kind -ne "step") {
    throw "Failed-step smoke report must use status=failed and failure_kind=step."
  }
  $steps = @($report.steps)
  if ($steps.Count -ne 1) {
    throw "Failed-step smoke expected exactly one recorded step, found $($steps.Count)."
  }
  $step = $steps[0]
  if ($step.name -ne "local-core safe simulator scan reporting" -or $step.status -ne "failed") {
    throw "Failed-step smoke did not record the exact terminal failing step."
  }
  [void](Assert-NonEmptyString $step.command "failed-step command")
  $stepError = Assert-NonEmptyString $step.error "failed-step error"
  $topError = Assert-NonEmptyString $report.error "failed report top-level error"
  if ($stepError -cne $topError) {
    throw "Failed-step smoke requires the terminal step and top-level errors to match exactly."
  }
  try {
    $seconds = [double]$step.seconds
  } catch {
    throw "Failed-step seconds must be numeric."
  }
  if ($seconds -lt 0) {
    throw "Failed-step seconds must not be negative."
  }

  foreach ($validatorHost in @(
    [pscustomobject]@{ Path = $windowsPowerShell; Name = "Windows PowerShell 5.1" },
    [pscustomobject]@{ Path = $powerShell7; Name = "PowerShell 7" }
  )) {
    Invoke-ReportValidator $validatorHost.Path $validatorHost.Name $reportPath $true "" $repo $validator
  }

  $statusTamper = Copy-JsonObject $report
  $statusTamper.steps[0].status = "passed"
  $statusTamper.steps[0].error = $null
  Write-AvoraxGateJsonFileAtomic $statusTamperPath $statusTamper 12 "failed-step status-tamper report"

  $terminalTamper = Copy-JsonObject $report
  $terminalTamper.steps = @($terminalTamper.steps) + [pscustomobject][ordered]@{
    name = "benign post-failure marker"
    command = "not executed"
    seconds = 0
    status = "passed"
    error = $null
  }
  Write-AvoraxGateJsonFileAtomic $terminalTamperPath $terminalTamper 12 "failed-step terminal-tamper report"

  $errorTamper = Copy-JsonObject $report
  $errorTamper.steps[0].error = $null
  Write-AvoraxGateJsonFileAtomic $errorTamperPath $errorTamper 12 "failed-step error-tamper report"

  foreach ($validatorHost in @(
    [pscustomobject]@{ Path = $windowsPowerShell; Name = "Windows PowerShell 5.1" },
    [pscustomobject]@{ Path = $powerShell7; Name = "PowerShell 7" }
  )) {
    Invoke-ReportValidator $validatorHost.Path $validatorHost.Name $statusTamperPath $false "exactly one failed step" $repo $validator
    Invoke-ReportValidator $validatorHost.Path $validatorHost.Name $terminalTamperPath $false "terminal step" $repo $validator
    Invoke-ReportValidator $validatorHost.Path $validatorHost.Name $errorTamperPath $false "must be a non-empty string" $repo $validator
  }

  Write-Host "PASS small-threat MVP failed-step report smoke (one authentic failure and six adversarial validator rejections)."
} finally {
  foreach ($path in @($reportPath, $statusTamperPath, $terminalTamperPath, $errorTamperPath)) {
    Remove-AvoraxGateRegularFileIfPresent $path "failed-step smoke temporary report"
  }
  if (Test-Path -LiteralPath $tempRoot) {
    $checkedTempRoot = Get-AvoraxGateDirectory $tempRoot "failed-step smoke temporary root cleanup"
    $remaining = @(Get-ChildItem -LiteralPath $checkedTempRoot -Force -ErrorAction Stop)
    if ($remaining.Count -ne 0) {
      throw "Failed-step smoke refuses to remove non-empty temporary root: $checkedTempRoot"
    }
    [System.IO.Directory]::Delete($checkedTempRoot, $false)
  }
}
