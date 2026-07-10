param(
  [string]$CertName = "Avorax Driver Test Certificate",
  [string]$CertOutputDir = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\cert"),
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\cert_report.json"),
  [switch]$ConfirmCreateTestCertificate
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

if ([string]::IsNullOrWhiteSpace($CertName) -or $CertName -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,80}$') {
  throw "Certificate name contains unsafe characters."
}
$CertOutputDir = New-AvoraxRegularDirectory $CertOutputDir "driver test certificate output directory" $RepoRoot
Assert-AvoraxRepoChildPath $CertOutputDir $RepoRoot "driver test certificate output directory"
[void](New-AvoraxRegularDirectory (Split-Path $ReportPath) "driver test certificate report directory" $RepoRoot)
Assert-AvoraxNoReparsePath $ReportPath "driver test certificate report"
Assert-AvoraxPathUnder $ReportPath $RepoRoot "driver test certificate report"

try {
  if (-not $ConfirmCreateTestCertificate) {
    throw "Refusing to create the Avorax development test certificate without -ConfirmCreateTestCertificate."
  }
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeyLength 2048 -HashAlgorithm SHA256
  $cerPath = Join-Path $CertOutputDir "ZentorDriverTest.cer"
  Assert-AvoraxNoReparsePath $cerPath "driver test certificate export"
  Assert-AvoraxPathUnder $cerPath $RepoRoot "driver test certificate export"
  if (Test-Path -LiteralPath $cerPath) {
    [void](Get-AvoraxRegularFile $cerPath "driver test certificate export")
  }
  Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
  [void](Get-AvoraxRegularFile $cerPath "driver test certificate export")
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    created = $true
    certificate_thumbprint = $cert.Thumbprint
    certificate_path = $cerPath
    production_signing = $false
    warning = "Development certificate only. Production kernel signing requires Microsoft Hardware Dev Center."
    errors = @()
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 5 "driver test certificate report" $RepoRoot
  Write-Host "Created Avorax development test certificate: $($cert.Thumbprint)"
} catch {
  $report = [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    created = $false
    production_signing = $false
    errors = @(Get-AvoraxBoundedDiagnostic $_.Exception.Message 4096)
  }
  Write-AvoraxJsonFileAtomic $ReportPath $report 5 "driver test certificate report" $RepoRoot
  throw
}
