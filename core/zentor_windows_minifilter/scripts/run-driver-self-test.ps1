param(
  [string]$GuardServicePath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "core\zentor_guard_service\target\release\zentor_guard_service.exe"),
  [string]$ReportPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\selftest_report.json")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null

if (-not (Test-Path -LiteralPath $GuardServicePath)) {
  throw "Avorax Guard Service executable was not found: $GuardServicePath. Build core/zentor_guard_service first."
}

$cmdFile = Join-Path (Split-Path $ReportPath) "driver_self_test_command.json"
[System.IO.File]::WriteAllText($cmdFile, '{"command":"driver_self_test"}' + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
$quotedCmd = '"' + $cmdFile + '"'
$quotedExe = '"' + $GuardServicePath + '"'
$raw = cmd.exe /d /c "type $quotedCmd | $quotedExe" 2>&1
if ($LASTEXITCODE -ne 0) {
  throw "Avorax Guard Service self-test command failed. $raw"
}
if (-not $raw) {
  throw "Avorax Guard Service self-test produced no output."
}
$event = $raw | ConvertFrom-Json
$report = $event.message | ConvertFrom-Json
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
if ($report.overall_result -ne "pass") {
  Write-Host "Protection self-test failed. See $ReportPath"
  exit 1
}
Write-Host "Protection self-test passed: $ReportPath"
