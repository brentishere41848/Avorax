#Requires -RunAsAdministrator
param(
  [switch]$ConfirmTestSigningChange,
  [switch]$ConfirmPostRebootTask,
  [string]$ReportDir,
  [string]$InstallRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot "avorax-system32-tools.ps1")
$MaxLogChars = 262144
$MaxLogBlockChars = 32768

function Test-LocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}
function Assert-NoReparsePath([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Description path is required."
  }
  if (-not (Test-LocalWindowsPath $Path)) {
    throw "$Description must be an absolute local Windows drive path: $Path"
  }
  $current = [System.IO.Path]::GetFullPath($Path)
  while ($true) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not traverse a reparse point: $current"
      }
    }
    $parent = [System.IO.Directory]::GetParent($current)
    if ($null -eq $parent) { break }
    if ($parent.FullName -eq $current) { break }
    $current = $parent.FullName
  }
}
function New-SafeDirectory([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  if (-not (Test-Path -LiteralPath $Path)) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not ($item -is [System.IO.DirectoryInfo])) {
    throw "$Description is not a directory: $Path"
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $Path"
  }
  $item.FullName
}
function Get-RegularFile([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not ($item -is [System.IO.FileInfo])) {
    throw "$Description is not a regular file: $Path"
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $Path"
  }
  $item.FullName
}
function Get-CheckedEnvironmentRoot([string[]]$Names, [string]$Description) {
  $diagnostics = @()
  foreach ($name in $Names) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
      $diagnostics += "$name is not set or is empty"
      continue
    }
    $root = $value.Trim()
    if (-not (Test-LocalWindowsPath $root)) {
      $diagnostics += "$name must be a local Windows drive path: $root"
      continue
    }
    Assert-NoReparsePath $root "$Description root"
    return [System.IO.Path]::GetFullPath($root)
  }
  throw "$Description root is unavailable: $($diagnostics -join '; ')"
}
function Resolve-DriverRemediationReportDir([AllowNull()][string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    $programDataRoot = Get-CheckedEnvironmentRoot @('ProgramData', 'PROGRAMDATA') 'driver remediation ProgramData'
    return Join-Path (Join-Path $programDataRoot 'Avorax') 'driver-remediation'
  }
  Assert-NoReparsePath $Path 'driver remediation report directory'
  [System.IO.Path]::GetFullPath($Path)
}
function Resolve-InstalledAvoraxRoot([AllowNull()][string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    $programFilesRoot = Get-CheckedEnvironmentRoot @('ProgramFiles', 'ProgramW6432', 'PROGRAMFILES') 'installed Avorax ProgramFiles'
    return Join-Path $programFilesRoot 'Avorax'
  }
  Assert-NoReparsePath $Path 'installed Avorax root'
  [System.IO.Path]::GetFullPath($Path)
}
function Remove-RegularFileIfPresent([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  [void](Get-RegularFile $Path $Description)
  Remove-Item -LiteralPath $Path -Force
}
function Write-TextFileAtomic([string]$Path, [string]$Value, [string]$Description) {
  $directory = New-SafeDirectory (Split-Path $Path) "$Description directory"
  Assert-NoReparsePath $Path $Description
  if (Test-Path -LiteralPath $Path) {
    [void](Get-RegularFile $Path $Description)
  }
  $target = [System.IO.Path]::GetFullPath($Path)
  $tempPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString('N') + ".tmp")
  $backupPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString('N') + ".bak")
  try {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempPath, $Value, $encoding)
    [void](Get-RegularFile $tempPath "$Description temporary file")
    if (Test-Path -LiteralPath $target) {
      [System.IO.File]::Replace($tempPath, $target, $backupPath)
    } else {
      [System.IO.File]::Move($tempPath, $target)
    }
  } finally {
    Remove-RegularFileIfPresent $tempPath "$Description temporary file"
    Remove-RegularFileIfPresent $backupPath "$Description backup file"
  }
}
$ReportDir = Resolve-DriverRemediationReportDir $ReportDir
$InstallRoot = Resolve-InstalledAvoraxRoot $InstallRoot
$ReportPath = Join-Path $ReportDir 'latest.json'
$LogPath = Join-Path $ReportDir 'latest.log'
[void](New-SafeDirectory $ReportDir 'driver remediation report directory')
function Write-Report([hashtable]$Data) {
  $Data.timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  Write-TextFileAtomic $ReportPath ($Data | ConvertTo-Json -Depth 8) 'driver remediation report'
}
function Limit-LogText([string]$Text, [int]$Limit) {
  if ($null -eq $Text) { return '' }
  if ($Text.Length -le $Limit) { return $Text }
  return $Text.Substring(0, $Limit) + [Environment]::NewLine + '...[truncated]'
}
function Read-ExistingLogTextBounded([string]$Path) {
  $logFile = Get-RegularFile $Path 'driver remediation log'
  $stream = [System.IO.File]::Open($logFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $maxBytes = [int64]$MaxLogChars * 4
    $truncated = $stream.Length -gt $maxBytes
    $length = [int][System.Math]::Min($maxBytes, $stream.Length)
    if ($truncated) {
      [void]$stream.Seek(-$length, [System.IO.SeekOrigin]::End)
    }
    $buffer = [byte[]]::new($length)
    $offset = 0
    while ($offset -lt $length) {
      $read = $stream.Read($buffer, $offset, $length - $offset)
      if ($read -le 0) {
        throw "driver remediation log could not be read completely: $logFile"
      }
      $offset += $read
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $existing = $encoding.GetString($buffer, 0, $length)
    if ($existing.Length -gt $MaxLogChars) {
      $existing = $existing.Substring($existing.Length - $MaxLogChars)
    }
    if ($truncated) {
      return "Previous driver remediation log exceeded $MaxLogChars characters; retaining newest entries." + [Environment]::NewLine + $existing
    }
    return $existing
  } finally {
    $stream.Dispose()
  }
}
function Append-LogTextAtomic([string]$Text) {
  Assert-NoReparsePath $LogPath 'driver remediation log'
  $existing = ''
  if (Test-Path -LiteralPath $LogPath) {
    $existing = Read-ExistingLogTextBounded $LogPath
  }
  $entry = Limit-LogText $Text $MaxLogBlockChars
  $separator = if ([string]::IsNullOrEmpty($existing) -or $existing.EndsWith([Environment]::NewLine)) { '' } else { [Environment]::NewLine }
  $combined = $existing + $separator + $entry + [Environment]::NewLine
  if ($combined.Length -gt $MaxLogChars) {
    $combined = "Driver remediation log exceeded $MaxLogChars characters; retaining newest entries." + [Environment]::NewLine +
      $combined.Substring($combined.Length - $MaxLogChars)
  }
  Write-TextFileAtomic $LogPath $combined 'driver remediation log'
}
function Log([string]$Message) {
  $line = "{0} {1}" -f (Get-Date).ToUniversalTime().ToString('o'), $Message
  Append-LogTextAtomic $line
}
function Log-CommandOutput([string]$Title, [object]$Output, [int]$ExitCode) {
  $text = ($Output | Out-String).TrimEnd()
  Append-LogTextAtomic ("=== $Title ===" + [Environment]::NewLine + "ExitCode: $ExitCode" + [Environment]::NewLine + (Limit-LogText $text $MaxLogBlockChars))
}
function Get-WindowsToolRoot {
  $diagnostics = @()
  foreach ($name in @('SystemRoot', 'WINDIR')) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
      $diagnostics += "$name is not set or is empty"
      continue
    }
    $root = $value.Trim()
    if (-not (Test-LocalWindowsPath $root)) {
      $diagnostics += "$name must be a local Windows drive path: $root"
      continue
    }
    try {
      Assert-NoReparsePath $root "$name Windows System32 tool root"
      return [System.IO.Path]::GetFullPath($root)
    } catch {
      $diagnostics += "$name Windows System32 tool root rejected: $($_.Exception.Message)"
      continue
    }
  }
  throw "Windows System32 tool root is unavailable: $($diagnostics -join '; ')"
}
function Get-System32Tool([string]$Name) {
  $allowed = @('bcdedit.exe', 'fltmc.exe', 'sc.exe', 'schtasks.exe', 'powershell.exe')
  if ($Name -notin $allowed) {
    throw "Unsupported System32 tool: $Name"
  }
  $root = Get-WindowsToolRoot
  $candidate = if ($Name -eq 'powershell.exe') {
    Join-Path (Join-Path (Join-Path $root 'System32') 'WindowsPowerShell\v1.0') $Name
  } else {
    Join-Path (Join-Path $root 'System32') $Name
  }
  Assert-NoReparsePath $candidate "System32 tool $Name"
  $item = Get-Item -LiteralPath $candidate -ErrorAction Stop
  if (-not ($item -is [System.IO.FileInfo])) {
    throw "System32 tool is not a regular file: $candidate"
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing to launch reparse-point System32 tool: $candidate"
  }
  $item.FullName
}
function ConvertTo-PowerShellSingleQuotedLiteral([string]$Value) {
  "'" + ($Value -replace "'", "''") + "'"
}
function Find-RegularScript([string[]]$Candidates) {
  foreach ($candidate in $Candidates) {
    try {
      return Get-RegularFile $candidate 'install script candidate'
    } catch [System.Management.Automation.ItemNotFoundException] {
      continue
    } catch {
      Log "Unable to inspect install script candidate ${candidate}: $($_.Exception.Message)"
    }
  }
  $null
}
try {
  Log 'Starting Avorax live driver remediation.'
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw 'This script must run elevated as Administrator.' }

  $bcdedit = Get-System32Tool 'bcdedit.exe'
  $fltmc = Get-System32Tool 'fltmc.exe'
  $sc = Get-System32Tool 'sc.exe'
  $schtasks = Get-System32Tool 'schtasks.exe'
  $powershell = Get-System32Tool 'powershell.exe'

  $bcdBeforeDiagnostic = Invoke-AvoraxCommandDiagnostic $bcdedit @("/enum") "bcdedit /enum" 32768
  $bcdBefore = $bcdBeforeDiagnostic.output
  if ($bcdBeforeDiagnostic.exit_code -ne 0) {
    throw "Unable to inspect TESTSIGNING state before remediation; bcdedit /enum failed with exit code $($bcdBeforeDiagnostic.exit_code): $bcdBefore"
  }
  $testSigningBefore = [bool]($bcdBefore -match '(?im)^\s*testsigning\s+Yes\s*$')
  Log "TESTSIGNING before: $testSigningBefore"

  if (-not $testSigningBefore) {
    if (-not $ConfirmTestSigningChange) {
      throw 'Refusing to enable Windows TESTSIGNING without -ConfirmTestSigningChange. Use only on a development VM or test machine.'
    }
    Log 'Enabling Windows TESTSIGNING with bcdedit.'
    $bcdSetDiagnostic = Invoke-AvoraxCommandDiagnostic $bcdedit @("/set", "testsigning", "on") "bcdedit /set testsigning on" 4096
    $bcdSetOutput = $bcdSetDiagnostic.output
    $bcdSetExit = $bcdSetDiagnostic.exit_code
    Log-CommandOutput 'bcdedit /set testsigning on' $bcdSetOutput $bcdSetExit
    Write-Host $bcdSetOutput
    if ($bcdSetExit -ne 0) { throw "bcdedit /set testsigning on failed with exit code $bcdSetExit" }
  }

  $bcdAfterDiagnostic = Invoke-AvoraxCommandDiagnostic $bcdedit @("/enum") "bcdedit /enum after remediation" 32768
  $bcdAfter = $bcdAfterDiagnostic.output
  if ($bcdAfterDiagnostic.exit_code -ne 0) {
    throw "Unable to inspect TESTSIGNING state after remediation; bcdedit /enum failed with exit code $($bcdAfterDiagnostic.exit_code): $bcdAfter"
  }
  $testSigningAfter = [bool]($bcdAfter -match '(?im)^\s*testsigning\s+Yes\s*$')
  if (-not $testSigningAfter) { throw 'bcdedit completed but TESTSIGNING is still not enabled in boot configuration.' }

  $installScriptCandidates = @(
    Join-Path $InstallRoot 'tools\windows\avorax-install-driver.ps1',
    Join-Path $InstallRoot 'driver-tools\avorax-install-driver.ps1',
    Join-Path $InstallRoot 'tools\avorax-install-driver.ps1'
  )
  $installScript = Find-RegularScript $installScriptCandidates

  $postRebootScript = Join-Path $ReportDir 'post-reboot-load-driver.ps1'
  $reportDirLiteral = ConvertTo-PowerShellSingleQuotedLiteral $ReportDir
  $bcdeditLiteral = ConvertTo-PowerShellSingleQuotedLiteral $bcdedit
  $fltmcLiteral = ConvertTo-PowerShellSingleQuotedLiteral $fltmc
  $scLiteral = ConvertTo-PowerShellSingleQuotedLiteral $sc
  $powershellLiteral = ConvertTo-PowerShellSingleQuotedLiteral $powershell
  $installScriptLiteral = if ($installScript) { ConvertTo-PowerShellSingleQuotedLiteral $installScript } else { '$null' }
  $postRebootScriptContent = @"
`$ErrorActionPreference = 'Continue'
`$ReportDir = $reportDirLiteral
`$ReportPath = Join-Path `$ReportDir 'post-reboot.json'
function Test-LocalWindowsPath([string]`$Path) {
  `$normalized = `$Path -replace '/', '\'
  return `$normalized -match '^[A-Za-z]:\\'
}
function Assert-NoReparsePath([string]`$Path, [string]`$Description) {
  if ([string]::IsNullOrWhiteSpace(`$Path)) { throw "`$Description path is required." }
  if (-not (Test-LocalWindowsPath `$Path)) { throw "`$Description must be an absolute local Windows drive path: `$Path" }
  `$current = [System.IO.Path]::GetFullPath(`$Path)
  while (`$true) {
    if (Test-Path -LiteralPath `$current) {
      `$item = Get-Item -LiteralPath `$current -Force -ErrorAction Stop
      if ((`$item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "`$Description must not traverse a reparse point: `$current"
      }
    }
    `$parent = [System.IO.Directory]::GetParent(`$current)
    if (`$null -eq `$parent) { break }
    if (`$parent.FullName -eq `$current) { break }
    `$current = `$parent.FullName
  }
}
function New-SafeDirectory([string]`$Path, [string]`$Description) {
  Assert-NoReparsePath `$Path `$Description
  if (-not (Test-Path -LiteralPath `$Path)) { [System.IO.Directory]::CreateDirectory(`$Path) | Out-Null }
  `$item = Get-Item -LiteralPath `$Path -Force -ErrorAction Stop
  if (-not (`$item -is [System.IO.DirectoryInfo]) -or ((`$item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "`$Description is not a non-reparse directory: `$Path"
  }
  `$item.FullName
}
function Get-RegularFile([string]`$Path, [string]`$Description) {
  Assert-NoReparsePath `$Path `$Description
  `$item = Get-Item -LiteralPath `$Path -Force -ErrorAction Stop
  if (-not (`$item -is [System.IO.FileInfo]) -or ((`$item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "`$Description is not a regular non-reparse file: `$Path"
  }
  `$item.FullName
}
function Limit-Text([string]`$Text, [int]`$Limit = 32768) {
  if (`$null -eq `$Text) { return '' }
  if (`$Text.Length -le `$Limit) { return `$Text }
  return `$Text.Substring(0, `$Limit) + [Environment]::NewLine + '...[truncated]'
}
`$CommandOutputByteLimit = 1048576
`$CommandTimeoutMs = 120000
function ConvertTo-CommandArgument([AllowNull()][string]`$Value) {
  if (`$null -eq `$Value) { return '""' }
  if (`$Value -notmatch '[\s"]') { return `$Value }
  return '"' + `$Value.Replace('"', '\"') + '"'
}
function Join-CommandArguments([AllowNull()][string[]]`$Arguments) {
  if (`$null -eq `$Arguments -or `$Arguments.Count -eq 0) { return '' }
  (@(`$Arguments) | ForEach-Object { ConvertTo-CommandArgument `$_ }) -join ' '
}
function New-CommandTempFile([string]`$Description) {
  `$directory = New-SafeDirectory `$ReportDir 'post-reboot command output directory'
  `$path = Join-Path `$directory ('post-reboot-command-' + [System.Guid]::NewGuid().ToString('N') + '.tmp')
  `$stream = [System.IO.File]::Open(`$path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
  `$stream.Dispose()
  return (Get-RegularFile `$path `$Description)
}
function Remove-CommandTempFile([AllowNull()][string]`$Path, [string]`$Description) {
  if ([string]::IsNullOrWhiteSpace(`$Path)) { return }
  if (-not (Test-Path -LiteralPath `$Path)) { return }
  [void](Get-RegularFile `$Path `$Description)
  Remove-Item -LiteralPath `$Path -Force
}
function Read-CommandOutputFile([AllowNull()][string]`$Path, [int]`$MaxLength, [string]`$Description) {
  if (`$MaxLength -le 0 -or `$MaxLength -gt [int]::MaxValue) {
    throw "`$Description maximum diagnostic length must be positive and fit a PowerShell string buffer."
  }
  if ([string]::IsNullOrWhiteSpace(`$Path) -or -not (Test-Path -LiteralPath `$Path)) { return '' }
  `$file = Get-RegularFile `$Path `$Description
  `$stream = [System.IO.File]::Open(`$file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    `$length = [int][System.Math]::Min([int64]`$MaxLength, `$stream.Length)
    if (`$length -eq 0) {
      if (`$stream.Length -gt `$MaxLength) { return '...[truncated]' }
      return ''
    }
    `$buffer = [byte[]]::new(`$length)
    `$offset = 0
    while (`$offset -lt `$length) {
      `$read = `$stream.Read(`$buffer, `$offset, `$length - `$offset)
      if (`$read -le 0) { throw "`$Description could not be read completely: `$file" }
      `$offset += `$read
    }
    `$text = [System.Text.Encoding]::Default.GetString(`$buffer, 0, `$length).Trim()
    if (`$stream.Length -gt `$MaxLength) {
      return (Limit-Text (`$text + [Environment]::NewLine + '...[truncated]') `$MaxLength)
    }
    return `$text
  } finally {
    `$stream.Dispose()
  }
}
function Test-CommandOutputWithinLimit([string[]]`$Paths, [string]`$Description) {
  foreach (`$path in `$Paths) {
    if ([string]::IsNullOrWhiteSpace(`$path) -or -not (Test-Path -LiteralPath `$path)) { continue }
    `$file = Get-RegularFile `$path `$Description
    `$item = Get-Item -LiteralPath `$file -Force -ErrorAction Stop
    if (`$item.Length -gt `$CommandOutputByteLimit) { return `$false }
  }
  return `$true
}
function Stop-CommandDiagnosticProcess([AllowNull()][System.Diagnostics.Process]`$Process, [string]`$Reason, [string]`$Description) {
  if (`$null -eq `$Process -or `$Process.HasExited) { return }
  try {
    `$Process.Kill()
    if (-not `$Process.WaitForExit(5000)) {
      throw "`$Description did not exit within 5000 ms after `$Reason."
    }
  } catch {
    throw "Could not stop `$Description after `$Reason`: `$(`$_.Exception.Message)"
  }
}
function Invoke-PostRebootCommandDiagnostic([string]`$Tool, [string[]]`$Arguments, [string]`$DisplayName, [int]`$MaxLength = 4096) {
  `$stdoutPath = New-CommandTempFile "`$DisplayName stdout"
  `$stderrPath = New-CommandTempFile "`$DisplayName stderr"
  `$process = `$null
  `$exitCode = -1
  `$timedOut = `$false
  `$outputLimitExceeded = `$false
  try {
    `$startArgs = @{
      FilePath = `$Tool
      RedirectStandardOutput = `$stdoutPath
      RedirectStandardError = `$stderrPath
      WindowStyle = 'Hidden'
      PassThru = `$true
    }
    `$argumentList = Join-CommandArguments `$Arguments
    if (-not [string]::IsNullOrWhiteSpace(`$argumentList)) { `$startArgs.ArgumentList = `$argumentList }
    `$process = Start-Process @startArgs
    `$deadline = [DateTime]::UtcNow.AddMilliseconds(`$CommandTimeoutMs)
    while (-not `$process.HasExited) {
      Start-Sleep -Milliseconds 100
      if (-not (Test-CommandOutputWithinLimit @(`$stdoutPath, `$stderrPath) `$DisplayName)) {
        `$outputLimitExceeded = `$true
        Stop-CommandDiagnosticProcess `$process 'output limit' `$DisplayName
        break
      }
      if ([DateTime]::UtcNow -ge `$deadline) {
        `$timedOut = `$true
        Stop-CommandDiagnosticProcess `$process 'timeout' `$DisplayName
        break
      }
    }
    if (`$process.HasExited) { `$exitCode = `$process.ExitCode }
    if (-not (Test-CommandOutputWithinLimit @(`$stdoutPath, `$stderrPath) `$DisplayName)) { `$outputLimitExceeded = `$true }
    `$outputParts = @()
    `$stdout = Read-CommandOutputFile `$stdoutPath `$MaxLength "`$DisplayName stdout"
    if (-not [string]::IsNullOrWhiteSpace(`$stdout)) { `$outputParts += `$stdout }
    `$stderr = Read-CommandOutputFile `$stderrPath `$MaxLength "`$DisplayName stderr"
    if (-not [string]::IsNullOrWhiteSpace(`$stderr)) { `$outputParts += `$stderr }
    if (`$timedOut) { `$outputParts += "`$DisplayName timed out after `$CommandTimeoutMs ms." }
    if (`$outputLimitExceeded) { `$outputParts += "`$DisplayName exceeded the `$CommandOutputByteLimit byte diagnostic output limit." }
    [ordered]@{
      command = `$DisplayName
      exit_code = `$exitCode
      output = Limit-Text (`$outputParts -join [Environment]::NewLine) `$MaxLength
    }
  } finally {
    Remove-CommandTempFile `$stdoutPath "`$DisplayName stdout"
    Remove-CommandTempFile `$stderrPath "`$DisplayName stderr"
  }
}
function Save([hashtable]`$Data) {
  `$Data.timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  `$reportDirectory = New-SafeDirectory (Split-Path `$ReportPath) 'post-reboot report directory'
  Assert-NoReparsePath `$ReportPath 'post-reboot report'
  if (Test-Path -LiteralPath `$ReportPath) { [void](Get-RegularFile `$ReportPath 'post-reboot report') }
  `$target = [System.IO.Path]::GetFullPath(`$ReportPath)
  `$tempPath = Join-Path `$reportDirectory ('post-reboot-' + [System.Guid]::NewGuid().ToString('N') + '.tmp')
  `$backupPath = Join-Path `$reportDirectory ('post-reboot-' + [System.Guid]::NewGuid().ToString('N') + '.bak')
  try {
    `$encoding = New-Object System.Text.UTF8Encoding(`$false)
    [System.IO.File]::WriteAllText(`$tempPath, (`$Data | ConvertTo-Json -Depth 8), `$encoding)
    [void](Get-RegularFile `$tempPath 'temporary post-reboot report')
    if (Test-Path -LiteralPath `$target) {
      [System.IO.File]::Replace(`$tempPath, `$target, `$backupPath)
    } else {
      [System.IO.File]::Move(`$tempPath, `$target)
    }
  } finally {
    if (Test-Path -LiteralPath `$tempPath) {
      [void](Get-RegularFile `$tempPath 'temporary post-reboot report')
      Remove-Item -LiteralPath `$tempPath -Force
    }
    if (Test-Path -LiteralPath `$backupPath) {
      [void](Get-RegularFile `$backupPath 'post-reboot report backup file')
      Remove-Item -LiteralPath `$backupPath -Force
    }
  }
}
`$Bcdedit = Get-RegularFile $bcdeditLiteral 'bcdedit tool'
`$Fltmc = Get-RegularFile $fltmcLiteral 'fltmc tool'
`$Sc = Get-RegularFile $scLiteral 'sc tool'
`$PowerShell = Get-RegularFile $powershellLiteral 'PowerShell tool'
`$bcdDiagnostic = Invoke-PostRebootCommandDiagnostic `$Bcdedit @('/enum') 'bcdedit /enum' 32768
`$bcd = `$bcdDiagnostic.output
`$testSigning = (`$bcdDiagnostic.exit_code -eq 0) -and [bool](`$bcd -match '(?im)^\s*testsigning\s+Yes\s*`$')
`$installScript = $installScriptLiteral
`$installExit = `$null
`$installOutput = ''
`$loadExit = `$null
`$loadOutput = ''
if (`$testSigning -and `$installScript) {
  try {
    `$installScript = Get-RegularFile `$installScript 'post-reboot install script'
    `$installDiagnostic = Invoke-PostRebootCommandDiagnostic `$PowerShell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', `$installScript) 'post-reboot install script' 32768
    `$installOutput = `$installDiagnostic.output
    `$installExit = `$installDiagnostic.exit_code
  } catch {
    `$installExit = 'inspect_or_install_failed: ' + `$_.Exception.Message
  }
}
`$loadDiagnostic = Invoke-PostRebootCommandDiagnostic `$Fltmc @('load', 'ZentorAvFilter') 'fltmc load ZentorAvFilter' 32768
`$loadOutput = `$loadDiagnostic.output
`$loadExit = `$loadDiagnostic.exit_code
`$filtersDiagnostic = Invoke-PostRebootCommandDiagnostic `$Fltmc @('filters') 'fltmc filters' 32768
`$filters = `$filtersDiagnostic.output
`$serviceDiagnostic = Invoke-PostRebootCommandDiagnostic `$Sc @('query', 'ZentorAvFilter') 'sc query ZentorAvFilter' 32768
`$service = `$serviceDiagnostic.output
Save @{ ok = ((`$filtersDiagnostic.exit_code -eq 0) -and (`$filters -match 'ZentorAvFilter')); testSigning = `$testSigning; bcdExit = `$bcdDiagnostic.exit_code; bcdOutput = (Limit-Text `$bcd); installScript = `$installScript; installExit = `$installExit; installOutput = (Limit-Text `$installOutput); loadExit = `$loadExit; loadOutput = (Limit-Text `$loadOutput); filtersExit = `$filtersDiagnostic.exit_code; filters = (Limit-Text `$filters); serviceExit = `$serviceDiagnostic.exit_code; service = (Limit-Text `$service) }
"@
  Write-TextFileAtomic $postRebootScript $postRebootScriptContent 'post-reboot driver remediation script'

  $taskName = 'AvoraxPostRebootLoadDriver'
  $scheduledTaskCreated = $false
  $postRebootTaskError = $null
  if ($ConfirmPostRebootTask) {
    $taskCommand = '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f $powershell, $postRebootScript
    $schtasksDiagnostic = Invoke-AvoraxCommandDiagnostic $schtasks @("/Create", "/TN", $taskName, "/SC", "ONSTART", "/RL", "HIGHEST", "/RU", "SYSTEM", "/F", "/TR", $taskCommand) "schtasks /Create /TN $taskName" 4096
    $schtasksOutput = $schtasksDiagnostic.output
    $schtasksExit = $schtasksDiagnostic.exit_code
    Log-CommandOutput "schtasks /Create /TN $taskName" $schtasksOutput $schtasksExit
    Write-Host $schtasksOutput
    if ($schtasksExit -ne 0) {
      $postRebootTaskError = Limit-LogText "schtasks create failed with $schtasksExit`: $schtasksOutput" 4096
      Log "schtasks create failed with $schtasksExit; requested post-reboot task was not created."
    } else {
      $scheduledTaskCreated = $true
    }
  } else {
    Log 'Skipping SYSTEM startup task creation because -ConfirmPostRebootTask was not supplied.'
  }

  if ($ConfirmPostRebootTask -and -not $scheduledTaskCreated) {
    Write-Report @{
      ok = $false
      partial = $true
      testSigningBefore = $testSigningBefore
      testSigningAfter = $testSigningAfter
      rebootRequired = (-not $testSigningBefore)
      installScript = $installScript
      postRebootScript = $postRebootScript
      scheduledTask = $null
      postRebootTaskError = $postRebootTaskError
      message = 'TESTSIGNING is enabled in boot configuration, but the requested SYSTEM startup task could not be created. Reboot/install is not fully automated; inspect postRebootTaskError and run the generated script manually only on an approved development VM.'
    }
    Log 'Remediation incomplete: requested SYSTEM startup task could not be created.'
    exit 1
  }

  Write-Report @{
    ok = $true
    testSigningBefore = $testSigningBefore
    testSigningAfter = $testSigningAfter
    rebootRequired = (-not $testSigningBefore)
    installScript = $installScript
    postRebootScript = $postRebootScript
    scheduledTask = if ($scheduledTaskCreated) { $taskName } else { $null }
    message = if ($scheduledTaskCreated) {
      'TESTSIGNING is enabled in boot configuration. Reboot is required before Windows will load the test-signed Avorax minifilter. A SYSTEM startup task was created to install/load ZentorAvFilter after reboot.'
    } else {
      'TESTSIGNING is enabled in boot configuration. Reboot is required before Windows will load the test-signed Avorax minifilter. No SYSTEM startup task was created because -ConfirmPostRebootTask was not supplied.'
    }
  }
  Log 'Remediation completed; reboot required if TESTSIGNING was just changed.'
  exit 0
} catch {
  $msg = Limit-LogText ($_ | Out-String) $MaxLogBlockChars
  Log "ERROR: $msg"
  Write-Report @{ ok = $false; error = $msg }
  throw
}
