param(
  [string]$BuildOutputDir = $(Join-Path $PSScriptRoot "..\driver"),
  [string]$CertificateThumbprint,
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\signing_report.json")
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

$ReportDir = New-AvoraxRegularDirectory (Split-Path $ReportPath) "driver signing report directory" $RepoRoot
Assert-AvoraxNoReparsePath $ReportPath "driver signing report"
Assert-AvoraxPathUnder $ReportPath $RepoRoot "driver signing report"
$BuildOutputDir = Get-AvoraxRegularDirectory $BuildOutputDir "driver signing build output directory"
Assert-AvoraxRepoChildPath $BuildOutputDir $RepoRoot "driver signing build output directory"
$setupScript = Get-AvoraxRegularFile (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") "driver setup script"
$powerShell = Get-AvoraxRegularFile ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$setupReportPath = Join-Path $ReportDir "setup_report.json"
$commandDiagnostics = @()

try {
  $setupDiagnostic = Invoke-AvoraxCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $setupScript, "-ReportPath", $setupReportPath) "minifilter setup check" 32768
  $commandDiagnostics += [ordered]@{
    phase = "setup"
    command = $setupDiagnostic
  }
  if ($setupDiagnostic.exit_code -ne 0) {
    throw "Driver setup check failed with exit code $($setupDiagnostic.exit_code): $($setupDiagnostic.output)"
  }
  $setup = Read-AvoraxJsonFile $setupReportPath "driver setup report"
  $signtool = Get-AvoraxRegularFile $setup.checks.signtool "signtool executable"
  if (-not $CertificateThumbprint) {
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction Stop | Where-Object { $_.Subject -like "*Avorax Driver Test Certificate*" } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) { throw "No Avorax Driver Test Certificate found. Run create-test-cert.ps1 first." }
    $CertificateThumbprint = $cert.Thumbprint
  }
  $CertificateThumbprint = ($CertificateThumbprint -replace '\s+', '').ToUpperInvariant()
  if ($CertificateThumbprint -notmatch '^[A-F0-9]{40}$') {
    throw "Certificate thumbprint must be a 40-character SHA-1 hex string."
  }
  $targets = Get-ChildItem -LiteralPath $BuildOutputDir -Recurse -Include "*.sys","*.cat" -File -ErrorAction Stop |
    Sort-Object FullName |
    ForEach-Object {
      $target = Get-AvoraxRegularFile $_.FullName "driver signing target"
      Assert-AvoraxPathUnder $target $RepoRoot "driver signing target"
      $target
  }
  if (-not $targets) { throw "No .sys or .cat files found under $BuildOutputDir" }
  foreach ($target in $targets) {
    $targetDiagnostics = [ordered]@{
      file = $target
      sign = $null
      verify = $null
    }
    $commandDiagnostics += $targetDiagnostics
    $targetDiagnostics.sign = Invoke-AvoraxCommandDiagnostic $signtool @("sign", "/fd", "SHA256", "/sha1", $CertificateThumbprint, "/tr", "https://timestamp.digicert.com", "/td", "SHA256", $target) "signtool sign $target"
    if ($targetDiagnostics.sign.exit_code -ne 0) {
      throw "signtool failed for $target with exit code $($targetDiagnostics.sign.exit_code): $($targetDiagnostics.sign.output)"
    }
    $targetDiagnostics.verify = Invoke-AvoraxCommandDiagnostic $signtool @("verify", "/pa", $target) "signtool verify $target"
    if ($targetDiagnostics.verify.exit_code -ne 0) {
      throw "signature verification failed for $target with exit code $($targetDiagnostics.verify.exit_code): $($targetDiagnostics.verify.output)"
    }
  }
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    signed = $true
    production_signed = $false
    certificate_thumbprint = $CertificateThumbprint
    files = @($targets)
    command_diagnostics = @($commandDiagnostics)
    errors = @()
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 10 "driver signing report" $RepoRoot
} catch {
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    signed = $false
    production_signed = $false
    command_diagnostics = @($commandDiagnostics)
    errors = @(Get-AvoraxBoundedDiagnostic $_.Exception.Message 4096)
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 10 "driver signing report" $RepoRoot
  throw
}
