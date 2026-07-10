param(
  [string]$InfPath = $(Join-Path $PSScriptRoot "..\driver\ZentorAvFilter.inf"),
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\install_report.json"),
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

Assert-AvoraxNoReparsePath $ReportPath "minifilter install report"
Assert-AvoraxPathUnder $ReportPath $RepoRoot "minifilter install report"
Assert-AvoraxRepoChildPath $ReportPath $RepoRoot "minifilter install report"
$ReportDir = New-AvoraxRegularDirectory (Split-Path $ReportPath) "minifilter install report directory" $RepoRoot
$setupScript = Get-AvoraxRegularFile (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") "driver setup script"
$powerShell = Get-AvoraxRegularFile ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$setupReportPath = Join-Path $ReportDir "setup_report.json"
$commandDiagnostics = [ordered]@{}
try {
  if (-not $ConfirmDriverInstall) {
    throw "Refusing to install the Avorax test minifilter without -ConfirmDriverInstall."
  }
  $commandDiagnostics.setup = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $setupScript, "-RequireAdmin", "-ReportPath", $setupReportPath) "minifilter setup check" 32768
  if ($commandDiagnostics.setup.exit_code -ne 0) {
    throw "Driver setup check failed with exit code $($commandDiagnostics.setup.exit_code): $($commandDiagnostics.setup.output)"
  }
  [void](Get-AvoraxRegularFile $setupReportPath "driver setup report")
  Assert-AvoraxPathUnder $setupReportPath $RepoRoot "driver setup report"
  $bcdedit = Get-AvoraxSystem32Tool "bcdedit.exe"
  $pnputil = Get-AvoraxSystem32Tool "pnputil.exe"
  $fltmc = Get-AvoraxSystem32Tool "fltmc.exe"
  $inf = Get-AvoraxRegularFile $InfPath "driver INF"
  Assert-AvoraxPathUnder $inf $RepoRoot "driver INF"
  $commandDiagnostics.testsigning_probe = Invoke-AvoraxCommandDiagnostic $bcdedit @("/enum") "bcdedit /enum"
  if ($commandDiagnostics.testsigning_probe.exit_code -ne 0) {
    throw "TESTSIGNING status could not be verified: bcdedit /enum failed with exit code $($commandDiagnostics.testsigning_probe.exit_code): $($commandDiagnostics.testsigning_probe.output)"
  }
  $testSigning = $commandDiagnostics.testsigning_probe.output -match "testsigning\s+Yes"
  if (-not $testSigning) {
    throw "Windows TESTSIGNING is not enabled. Avorax will not enable it automatically. Read enable-test-signing-warning.md and enable it manually only in a development VM."
  }
  $commandDiagnostics.driver_install = Invoke-AvoraxCommandDiagnostic $pnputil @("/add-driver", $inf, "/install") "pnputil /add-driver ZentorAvFilter"
  if ($commandDiagnostics.driver_install.exit_code -ne 0) {
    throw "pnputil failed to install ZentorAvFilter with exit code $($commandDiagnostics.driver_install.exit_code): $($commandDiagnostics.driver_install.output)"
  }
  $commandDiagnostics.filter_load = Invoke-AvoraxCommandDiagnostic $fltmc @("load", "ZentorAvFilter") "fltmc load ZentorAvFilter"
  if ($commandDiagnostics.filter_load.exit_code -ne 0) {
    throw "fltmc failed to load ZentorAvFilter with exit code $($commandDiagnostics.filter_load.exit_code): $($commandDiagnostics.filter_load.output)"
  }
  $commandDiagnostics.filter_query = Invoke-AvoraxCommandDiagnostic $fltmc @("filters") "fltmc filters"
  if ($commandDiagnostics.filter_query.exit_code -ne 0) {
    throw "fltmc filters failed with exit code $($commandDiagnostics.filter_query.exit_code): $($commandDiagnostics.filter_query.output)"
  }
  $loaded = $commandDiagnostics.filter_query.output -match "ZentorAvFilter"
  if (-not $loaded) {
    throw "ZentorAvFilter was not listed after load: $($commandDiagnostics.filter_query.output)"
  }
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    installed = $true
    running = $loaded
    test_signed = $true
    production_signed = $false
    communication_port_ok = $false
    command_diagnostics = $commandDiagnostics
    errors = @()
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 8 "minifilter install report" $RepoRoot
} catch {
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    installed = $false
    running = $false
    command_diagnostics = $commandDiagnostics
    errors = @(Get-AvoraxBoundedDiagnostic $_.Exception.Message 4096)
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 8 "minifilter install report" $RepoRoot
  throw
}
