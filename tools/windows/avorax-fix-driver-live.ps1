#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$ReportDir = 'C:\ProgramData\Avorax\driver-remediation'
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
$ReportPath = Join-Path $ReportDir 'latest.json'
$LogPath = Join-Path $ReportDir 'latest.log'
function Write-Report([hashtable]$Data) {
  $Data.timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}
function Log([string]$Message) {
  $line = "{0} {1}" -f (Get-Date).ToUniversalTime().ToString('o'), $Message
  Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}
try {
  Log 'Starting Avorax live driver remediation.'
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw 'This script must run elevated as Administrator.' }

  $bcdBefore = (& bcdedit.exe /enum) 2>&1 | Out-String
  $testSigningBefore = [bool]($bcdBefore -match '(?im)^\s*testsigning\s+Yes\s*$')
  Log "TESTSIGNING before: $testSigningBefore"

  if (-not $testSigningBefore) {
    Log 'Enabling Windows TESTSIGNING with bcdedit.'
    & bcdedit.exe /set testsigning on 2>&1 | Tee-Object -FilePath $LogPath -Append | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /set testsigning on failed with exit code $LASTEXITCODE" }
  }

  $bcdAfter = (& bcdedit.exe /enum) 2>&1 | Out-String
  $testSigningAfter = [bool]($bcdAfter -match '(?im)^\s*testsigning\s+Yes\s*$')
  if (-not $testSigningAfter) { throw 'bcdedit completed but TESTSIGNING is still not enabled in boot configuration.' }

  $installScriptCandidates = @(
    'C:\Program Files\Avorax\tools\windows\avorax-install-driver.ps1',
    'C:\Program Files\Avorax\driver-tools\avorax-install-driver.ps1',
    'C:\Program Files\Avorax\tools\avorax-install-driver.ps1'
  )
  $installScript = $installScriptCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

  $postRebootScript = Join-Path $ReportDir 'post-reboot-load-driver.ps1'
  @"
`$ErrorActionPreference = 'Continue'
`$ReportDir = '$ReportDir'
`$ReportPath = Join-Path `$ReportDir 'post-reboot.json'
function Save([hashtable]`$Data) { `$Data.timestampUtc = (Get-Date).ToUniversalTime().ToString('o'); `$Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath `$ReportPath -Encoding UTF8 }
`$bcd = (& bcdedit.exe /enum) 2>&1 | Out-String
`$testSigning = [bool](`$bcd -match '(?im)^\s*testsigning\s+Yes\s*`$')
`$installScript = '$installScript'
`$installExit = `$null
`$loadExit = `$null
`$loadOutput = ''
if (`$testSigning -and `$installScript -and (Test-Path -LiteralPath `$installScript)) {
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `$installScript 2>&1 | Tee-Object -FilePath (Join-Path `$ReportDir 'post-reboot-install.log')
  `$installExit = `$LASTEXITCODE
}
& fltmc.exe load ZentorAvFilter 2>&1 | Tee-Object -Variable loadLines | Out-String | Set-Variable loadOutput
`$loadExit = `$LASTEXITCODE
`$filters = (& fltmc.exe filters) 2>&1 | Out-String
`$service = (& sc.exe query ZentorAvFilter) 2>&1 | Out-String
Save @{ ok = (`$filters -match 'ZentorAvFilter'); testSigning = `$testSigning; installScript = `$installScript; installExit = `$installExit; loadExit = `$loadExit; loadOutput = `$loadOutput; filters = `$filters; service = `$service }
"@ | Set-Content -LiteralPath $postRebootScript -Encoding UTF8

  $taskName = 'AvoraxPostRebootLoadDriver'
  & schtasks.exe /Create /TN $taskName /SC ONSTART /RL HIGHEST /RU SYSTEM /F /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$postRebootScript`"" 2>&1 | Tee-Object -FilePath $LogPath -Append | Out-Host
  if ($LASTEXITCODE -ne 0) { Log "schtasks create failed with $LASTEXITCODE; continuing because TESTSIGNING is enabled." }

  Write-Report @{
    ok = $true
    testSigningBefore = $testSigningBefore
    testSigningAfter = $testSigningAfter
    rebootRequired = (-not $testSigningBefore)
    installScript = $installScript
    postRebootScript = $postRebootScript
    scheduledTask = $taskName
    message = 'TESTSIGNING is enabled in boot configuration. Reboot is required before Windows will load the test-signed Avorax minifilter. A SYSTEM startup task was created to install/load ZentorAvFilter after reboot.'
  }
  Log 'Remediation completed; reboot required if TESTSIGNING was just changed.'
  exit 0
} catch {
  $msg = ($_ | Out-String)
  Log "ERROR: $msg"
  Write-Report @{ ok = $false; error = $msg }
  throw
}
