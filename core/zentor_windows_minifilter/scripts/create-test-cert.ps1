param(
  [string]$CertName = "Avorax Driver Test Certificate",
  [string]$CertOutputDir = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\cert"),
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\cert_report.json")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $CertOutputDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null

try {
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeyLength 2048 -HashAlgorithm SHA256
  $cerPath = Join-Path $CertOutputDir "ZentorDriverTest.cer"
  Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
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
  $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  Write-Host "Created Avorax development test certificate: $($cert.Thumbprint)"
} catch {
  [ordered]@{
    zentor_version = "0.1.12"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    created = $false
    errors = @($_.Exception.Message)
  } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
  throw
}
