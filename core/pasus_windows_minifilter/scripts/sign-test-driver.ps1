param(
  [string]$BuildOutputDir = $(Join-Path $PSScriptRoot "..\driver"),
  [string]$CertificateThumbprint,
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\signing_report.json")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null

try {
  & (Join-Path $PSScriptRoot "setup-dev-env-check.ps1") -ReportPath (Join-Path (Split-Path $ReportPath) "setup_report.json")
  $setup = Get-Content -Raw -LiteralPath (Join-Path (Split-Path $ReportPath) "setup_report.json") | ConvertFrom-Json
  $signtool = $setup.checks.signtool
  if (-not $CertificateThumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*Pasus Driver Test Certificate*" } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) { throw "No Pasus Driver Test Certificate found. Run create-test-cert.ps1 first." }
    $CertificateThumbprint = $cert.Thumbprint
  }
  $targets = Get-ChildItem -LiteralPath $BuildOutputDir -Recurse -Include "*.sys","*.cat" -ErrorAction SilentlyContinue
  if (-not $targets) { throw "No .sys or .cat files found under $BuildOutputDir" }
  foreach ($target in $targets) {
    & $signtool sign /fd SHA256 /sha1 $CertificateThumbprint /tr http://timestamp.digicert.com /td SHA256 $target.FullName
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $($target.FullName)" }
    & $signtool verify /pa $target.FullName
    if ($LASTEXITCODE -ne 0) { throw "signature verification failed for $($target.FullName)" }
  }
  [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    signed = $true
    production_signed = $false
    certificate_thumbprint = $CertificateThumbprint
    files = @($targets.FullName)
    errors = @()
  } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
} catch {
  [ordered]@{
    pasus_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    signed = $false
    production_signed = $false
    errors = @($_.Exception.Message)
  } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  throw
}
