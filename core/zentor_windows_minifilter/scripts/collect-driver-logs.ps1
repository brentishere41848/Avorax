param(
  [string]$OutputPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\driver_logs.txt")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null

"=== fltmc filters ===" | Set-Content -LiteralPath $OutputPath
fltmc filters 2>&1 | Add-Content -LiteralPath $OutputPath
"`n=== ZentorAvFilter service ===" | Add-Content -LiteralPath $OutputPath
sc.exe query ZentorAvFilter 2>&1 | Add-Content -LiteralPath $OutputPath
"`n=== Recent System Events ===" | Add-Content -LiteralPath $OutputPath
Get-WinEvent -LogName System -MaxEvents 100 |
  Where-Object { $_.ProviderName -match "Service Control Manager|FilterManager|Avorax" } |
  Format-List TimeCreated,ProviderName,Id,LevelDisplayName,Message |
  Out-String | Add-Content -LiteralPath $OutputPath

Write-Host "Collected driver logs: $OutputPath"
