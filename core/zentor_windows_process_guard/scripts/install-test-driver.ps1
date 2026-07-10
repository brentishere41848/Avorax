param(
  [string]$InfPath = $(Join-Path $PSScriptRoot "..\driver\ZentorProcessGuard.inf"),
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\install_report.json"),
  [switch]$ConfirmDriverInstall
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
. (Join-Path $RepoRoot "tools\windows\avorax-system32-tools.ps1")

function Assert-AvoraxRepoChildPath([string]$Path, [string]$Base, [string]$DisplayName) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$DisplayName must resolve to a child path inside the Avorax repository root, not the repository root itself."
  }
  Assert-AvoraxPathUnder $pathFull $Base $DisplayName
}

Assert-AvoraxNoReparsePath $ReportPath "process guard install report"
Assert-AvoraxPathUnder $ReportPath $RepoRoot "process guard install report"
Assert-AvoraxRepoChildPath $ReportPath $RepoRoot "process guard install report"
$ReportDir = New-AvoraxRegularDirectory (Split-Path $ReportPath) "process guard install report directory" $RepoRoot
$setupScript = Get-AvoraxRegularFile (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") "driver setup script"
$powerShell = Get-AvoraxRegularFile ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$setupReportPath = Join-Path $ReportDir "setup_report.json"
$commandDiagnostics = [ordered]@{}
try {
  if (-not $ConfirmDriverInstall) {
    throw "Refusing to install the Avorax process-guard test driver without -ConfirmDriverInstall."
  }
  $commandDiagnostics.setup = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $setupScript, "-RequireAdmin", "-ReportPath", $setupReportPath) "process guard setup check" 32768
  if ($commandDiagnostics.setup.exit_code -ne 0) {
    throw "Process guard setup check failed with exit code $($commandDiagnostics.setup.exit_code): $($commandDiagnostics.setup.output)"
  }
  [void](Get-AvoraxRegularFile $setupReportPath "driver setup report")
  Assert-AvoraxPathUnder $setupReportPath $RepoRoot "driver setup report"
  $bcdedit = Get-AvoraxSystem32Tool "bcdedit.exe"
  $pnputil = Get-AvoraxSystem32Tool "pnputil.exe"
  $sc = Get-AvoraxSystem32Tool "sc.exe"
  $inf = Get-AvoraxRegularFile $InfPath "driver INF"
  Assert-AvoraxPathUnder $inf $RepoRoot "driver INF"
  $commandDiagnostics.testsigning_probe = Invoke-AvoraxCommandDiagnostic $bcdedit @("/enum") "bcdedit /enum"
  if ($commandDiagnostics.testsigning_probe.exit_code -ne 0) {
    throw "TESTSIGNING status could not be verified: bcdedit /enum failed with exit code $($commandDiagnostics.testsigning_probe.exit_code): $($commandDiagnostics.testsigning_probe.output)"
  }
  $testSigning = $commandDiagnostics.testsigning_probe.output -match "testsigning\s+Yes"
  if (-not $testSigning) { throw "Windows TESTSIGNING is not enabled. Avorax will not enable it automatically." }
  $commandDiagnostics.driver_install = Invoke-AvoraxCommandDiagnostic $pnputil @("/add-driver", $inf, "/install") "pnputil /add-driver ZentorProcessGuard"
  if ($commandDiagnostics.driver_install.exit_code -ne 0) {
    throw "pnputil failed to install ZentorProcessGuard with exit code $($commandDiagnostics.driver_install.exit_code): $($commandDiagnostics.driver_install.output)"
  }
  $commandDiagnostics.service_start = Invoke-AvoraxCommandDiagnostic $sc @("start", "ZentorProcessGuard") "sc start ZentorProcessGuard"
  if ($commandDiagnostics.service_start.exit_code -ne 0) {
    throw "sc start ZentorProcessGuard failed with exit code $($commandDiagnostics.service_start.exit_code): $($commandDiagnostics.service_start.output)"
  }
  $commandDiagnostics.service_query = Invoke-AvoraxCommandDiagnostic $sc @("query", "ZentorProcessGuard") "sc query ZentorProcessGuard"
  if ($commandDiagnostics.service_query.exit_code -ne 0) {
    throw "sc query ZentorProcessGuard failed with exit code $($commandDiagnostics.service_query.exit_code): $($commandDiagnostics.service_query.output)"
  }
  if ($commandDiagnostics.service_query.output -notmatch "STATE\s*:\s*\d+\s+RUNNING") {
    throw "ZentorProcessGuard was not running after start: $($commandDiagnostics.service_query.output)"
  }
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    installed = $true
    running = $true
    monitor_only = $true
    command_diagnostics = $commandDiagnostics
    errors = @()
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 8 "process guard install report" $RepoRoot
} catch {
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    installed = $false
    running = $false
    monitor_only = $true
    command_diagnostics = $commandDiagnostics
    errors = @(Get-AvoraxBoundedDiagnostic $_.Exception.Message 4096)
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 8 "process guard install report" $RepoRoot
  throw
}
