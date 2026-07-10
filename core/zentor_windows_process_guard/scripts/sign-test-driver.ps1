param(
  [string]$BuildOutputDir = $(Join-Path $PSScriptRoot "..\driver"),
  [string]$CertificateThumbprint,
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\signing_report.json")
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

$ReportDir = New-AvoraxRegularDirectory (Split-Path $ReportPath) "process guard signing report directory" $RepoRoot
Assert-AvoraxNoReparsePath $ReportPath "process guard signing report"
Assert-AvoraxPathUnder $ReportPath $RepoRoot "process guard signing report"
$buildOutput = Get-AvoraxRegularDirectory $BuildOutputDir "process guard build output directory"
Assert-AvoraxRepoChildPath $buildOutput $RepoRoot "process guard build output directory"
$signScript = Get-AvoraxRegularFile (Join-Path $RepoRoot "core\zentor_windows_minifilter\scripts\sign-test-driver.ps1") "shared driver signing script"
Assert-AvoraxPathUnder $signScript $RepoRoot "shared driver signing script"
$powerShell = Get-AvoraxRegularFile ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$signReportPath = Join-Path $ReportDir (Split-Path $ReportPath -Leaf)

$signDiagnostic = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $signScript, "-BuildOutputDir", $buildOutput, "-CertificateThumbprint", $CertificateThumbprint, "-ReportPath", $signReportPath) "process guard shared signing script" 32768
if ($signDiagnostic.exit_code -ne 0) {
  throw "Process guard shared signing script failed with exit code $($signDiagnostic.exit_code): $($signDiagnostic.output)"
}
