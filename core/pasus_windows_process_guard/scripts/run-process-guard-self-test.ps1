param(
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-process-guard-validation\selftest_report.json")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null
$running = $false
try {
  $service = sc.exe query PasusProcessGuard 2>$null | Out-String
  $running = $service -match "RUNNING"
} catch { $running = $false }
[ordered]@{
  pasus_version = "0.1.12"
  timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
  process_guard = @{
    installed = ($service -match "SERVICE_NAME")
    running = $running
    monitor_only = $true
    pre_execution_deny = $false
  }
  overall_result = if ($running) { "pass" } else { "fail" }
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
if (-not $running) { exit 1 }
