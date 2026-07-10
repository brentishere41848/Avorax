$ErrorActionPreference = 'Stop'
$script:AvoraxCommandOutputByteLimit = 1048576
$script:AvoraxCommandTimeoutMs = 120000

function Get-AvoraxWindowsRoot {
  $diagnostics = @()
  foreach ($name in @('SystemRoot', 'WINDIR')) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
      $diagnostics += "$name is not set or is empty"
      continue
    }
    $root = $value.Trim()
    if ($root -notmatch '^[A-Za-z]:\\') {
      $diagnostics += "$name must be a local Windows drive path: $root"
      continue
    }
    try {
      Assert-AvoraxNoReparsePath $root "$name Windows System32 tool root"
      return [System.IO.Path]::GetFullPath($root)
    } catch {
      $diagnostics += "$name Windows System32 tool root rejected: $(Get-AvoraxBoundedDiagnostic $_.Exception.Message)"
      continue
    }
  }
  throw "Windows System32 tool root is unavailable: $($diagnostics -join '; ')"
}

function Get-AvoraxBoundedDiagnostic([object]$Value, [int]$MaxLength = 4096) {
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return "" }
  $text = $text.Trim()
  if ($text.Length -le $MaxLength) { return $text }
  return $text.Substring(0, $MaxLength) + "...<truncated>"
}

function ConvertTo-AvoraxCommandArgument([AllowNull()][string]$Value) {
  if ($null -eq $Value) { return '""' }
  if ($Value -notmatch '[\s"]') { return $Value }
  return '"' + $Value.Replace('"', '\"') + '"'
}

function Join-AvoraxCommandArguments([AllowNull()][string[]]$Arguments) {
  if ($null -eq $Arguments -or $Arguments.Count -eq 0) { return "" }
  (@($Arguments) | ForEach-Object { ConvertTo-AvoraxCommandArgument $_ }) -join ' '
}

function New-AvoraxCommandTempFile([string]$DisplayName) {
  try {
    return [System.IO.Path]::GetTempFileName()
  } catch {
    throw "Could not allocate $DisplayName command output file: $(Get-AvoraxBoundedDiagnostic $_.Exception.Message)"
  }
}

function Remove-AvoraxCommandTempFile([AllowNull()][string]$Path, [string]$DisplayName) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  try {
    Remove-AvoraxRegularFileIfPresent $Path "$DisplayName command output"
  } catch {
    throw "Could not remove $DisplayName command output file: $(Get-AvoraxBoundedDiagnostic $_.Exception.Message)"
  }
}

function Read-AvoraxCommandOutputFile([string]$Path, [int]$MaxLength, [string]$DisplayName) {
  if ($MaxLength -le 0 -or $MaxLength -gt [int]::MaxValue) {
    throw "$DisplayName maximum diagnostic length must be positive and fit a PowerShell string buffer."
  }
  if (-not (Test-Path -LiteralPath $Path)) { return "" }
  $file = Get-AvoraxRegularFile $Path "$DisplayName command output"
  $stream = [System.IO.File]::Open(
    $file,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )
  try {
    $length = [int][System.Math]::Min([int64]$MaxLength, $stream.Length)
    if ($length -eq 0) {
      if ($stream.Length -gt $MaxLength) { return "...<truncated>" }
      return ""
    }
    $buffer = [byte[]]::new($length)
    $offset = 0
    while ($offset -lt $length) {
      $read = $stream.Read($buffer, $offset, $length - $offset)
      if ($read -le 0) {
        throw "$DisplayName command output could not be read completely: $file"
      }
      $offset += $read
    }
    $text = [System.Text.Encoding]::Default.GetString($buffer, 0, $length).Trim()
    if ($stream.Length -gt $MaxLength) {
      if ([string]::IsNullOrWhiteSpace($text)) { return "...<truncated>" }
      return $text + "...<truncated>"
    }
    return $text
  } finally {
    $stream.Dispose()
  }
}

function Test-AvoraxCommandOutputWithinLimit([string[]]$Paths, [string]$DisplayName) {
  foreach ($path in $Paths) {
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $file = Get-AvoraxRegularFile $path "$DisplayName command output"
    $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
    if ($item.Length -gt $script:AvoraxCommandOutputByteLimit) {
      return $false
    }
  }
  return $true
}

function Stop-AvoraxCommandDiagnosticProcess([AllowNull()][System.Diagnostics.Process]$Process, [string]$Reason, [string]$DisplayName) {
  if ($null -eq $Process -or $Process.HasExited) { return }
  try {
    $Process.Kill()
    if (-not $Process.WaitForExit(5000)) {
      throw "$DisplayName did not exit within 5000 ms after $Reason."
    }
  } catch {
    throw "Could not stop $DisplayName after $Reason`: $(Get-AvoraxBoundedDiagnostic $_.Exception.Message)"
  }
}

function Invoke-AvoraxCommandDiagnostic([string]$Tool, [string[]]$Arguments, [string]$DisplayName, [int]$MaxLength = 4096) {
  $stdoutPath = New-AvoraxCommandTempFile "$DisplayName stdout"
  $stderrPath = New-AvoraxCommandTempFile "$DisplayName stderr"
  $process = $null
  $exitCode = -1
  $timedOut = $false
  $outputLimitExceeded = $false
  try {
    $startArgs = @{
      FilePath = $Tool
      RedirectStandardOutput = $stdoutPath
      RedirectStandardError = $stderrPath
      WindowStyle = 'Hidden'
      PassThru = $true
    }
    $argumentList = Join-AvoraxCommandArguments $Arguments
    if (-not [string]::IsNullOrWhiteSpace($argumentList)) {
      $startArgs.ArgumentList = $argumentList
    }
    $process = Start-Process @startArgs
    $deadline = [DateTime]::UtcNow.AddMilliseconds($script:AvoraxCommandTimeoutMs)
    while (-not $process.HasExited) {
      Start-Sleep -Milliseconds 100
      if (-not (Test-AvoraxCommandOutputWithinLimit @($stdoutPath, $stderrPath) $DisplayName)) {
        $outputLimitExceeded = $true
        Stop-AvoraxCommandDiagnosticProcess $process "output limit" $DisplayName
        break
      }
      if ([DateTime]::UtcNow -ge $deadline) {
        $timedOut = $true
        Stop-AvoraxCommandDiagnosticProcess $process "timeout" $DisplayName
        break
      }
    }
    if ($process.HasExited) {
      [void]$process.WaitForExit()
      $process.Refresh()
      $exitCode = [int]$process.ExitCode
    }
    if (-not (Test-AvoraxCommandOutputWithinLimit @($stdoutPath, $stderrPath) $DisplayName)) {
      $outputLimitExceeded = $true
    }
    $outputParts = @()
    $stdout = Read-AvoraxCommandOutputFile $stdoutPath $MaxLength "$DisplayName stdout"
    if (-not [string]::IsNullOrWhiteSpace($stdout)) { $outputParts += $stdout }
    $stderr = Read-AvoraxCommandOutputFile $stderrPath $MaxLength "$DisplayName stderr"
    if (-not [string]::IsNullOrWhiteSpace($stderr)) { $outputParts += $stderr }
    if ($timedOut) {
      $outputParts += "$DisplayName timed out after $script:AvoraxCommandTimeoutMs ms."
    }
    if ($outputLimitExceeded) {
      $outputParts += "$DisplayName exceeded the $script:AvoraxCommandOutputByteLimit byte diagnostic output limit."
    }
    [pscustomobject][ordered]@{
      command = $DisplayName
      exit_code = $exitCode
      output = Get-AvoraxBoundedDiagnostic ($outputParts -join "`n") $MaxLength
    }
  } finally {
    Remove-AvoraxCommandTempFile $stdoutPath "$DisplayName stdout"
    Remove-AvoraxCommandTempFile $stderrPath "$DisplayName stderr"
  }
}

function Get-AvoraxSystem32Tool([string]$Name) {
  $allowed = @(
    'bcdedit.exe',
    'cmd.exe',
    'fltmc.exe',
    'pnputil.exe',
    'sc.exe',
    'schtasks.exe',
    'shutdown.exe'
  )
  if ($Name -notin $allowed) {
    throw "Unsupported Avorax System32 tool: $Name"
  }

  $root = Get-AvoraxWindowsRoot

  $candidate = Join-Path (Join-Path $root 'System32') $Name
  Assert-AvoraxNoReparsePath $candidate "System32 tool $Name"
  $item = Get-Item -LiteralPath $candidate -ErrorAction Stop
  if (-not ($item -is [System.IO.FileInfo])) {
    throw "System32 tool is not a regular file: $candidate"
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing to launch reparse-point System32 tool: $candidate"
  }
  $item.FullName
}

function Get-AvoraxRegularFile([string]$Path, [string]$DisplayName) {
  $item = Get-Item -LiteralPath $Path -ErrorAction Stop
  if (-not ($item -is [System.IO.FileInfo])) {
    throw "$DisplayName is not a regular file: $Path"
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing to use reparse-point $DisplayName`: $Path"
  }
  $item.FullName
}

function Read-AvoraxTextFileBounded([string]$Path, [int64]$MaxBytes, [string]$DisplayName) {
  if ($MaxBytes -le 0 -or $MaxBytes -gt [int]::MaxValue) {
    throw "$DisplayName maximum byte count must be positive and fit a PowerShell byte buffer."
  }

  $file = Get-AvoraxRegularFile $Path $DisplayName
  $stream = [System.IO.File]::Open(
    $file,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )
  try {
    if ($stream.Length -gt $MaxBytes) {
      throw "$DisplayName exceeds the JSON size limit of $MaxBytes bytes: $file"
    }

    $length = [int]$stream.Length
    if ($length -eq 0) { return "" }

    $buffer = [byte[]]::new($length)
    $offset = 0
    while ($offset -lt $length) {
      $read = $stream.Read($buffer, $offset, $length - $offset)
      if ($read -le 0) {
        throw "$DisplayName could not be read completely: $file"
      }
      $offset += $read
    }

    if ($length -ge 3 -and $buffer[0] -eq 0xEF -and $buffer[1] -eq 0xBB -and $buffer[2] -eq 0xBF) {
      return [System.Text.Encoding]::UTF8.GetString($buffer, 3, $length - 3)
    }
    if ($length -ge 2 -and $buffer[0] -eq 0xFF -and $buffer[1] -eq 0xFE) {
      return [System.Text.Encoding]::Unicode.GetString($buffer, 2, $length - 2)
    }
    if ($length -ge 2 -and $buffer[0] -eq 0xFE -and $buffer[1] -eq 0xFF) {
      return [System.Text.Encoding]::BigEndianUnicode.GetString($buffer, 2, $length - 2)
    }

    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    return $utf8.GetString($buffer)
  } finally {
    $stream.Dispose()
  }
}

function Read-AvoraxJsonFile([string]$Path, [string]$DisplayName, [int64]$MaxBytes = 1048576) {
  try {
    $json = Read-AvoraxTextFileBounded $Path $MaxBytes $DisplayName
    return ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    $message = Get-AvoraxBoundedDiagnostic $_.Exception.Message
    if ($message.StartsWith("$DisplayName exceeds ")) {
      throw $message
    }
    throw "$DisplayName is not valid bounded JSON: $message"
  }
}

function Test-AvoraxLocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Assert-AvoraxNoReparsePath([string]$Path, [string]$DisplayName) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$DisplayName path is required."
  }
  if (-not (Test-AvoraxLocalWindowsPath $Path)) {
    throw "$DisplayName must be an absolute local Windows drive path: $Path"
  }
  $current = [System.IO.Path]::GetFullPath($Path)
  while ($true) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$DisplayName must not traverse a reparse point: $current"
      }
    }
    $parent = [System.IO.Directory]::GetParent($current)
    if ($null -eq $parent) { break }
    if ($parent.FullName -eq $current) { break }
    $current = $parent.FullName
  }
}

function Assert-AvoraxPathUnder([string]$Path, [string]$Base, [string]$DisplayName) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  $pathFull = [System.IO.Path]::GetFullPath($Path)
  if ($pathFull.TrimEnd('\', '/').Equals($baseFull.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    return
  }
  if (-not $pathFull.StartsWith($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$DisplayName must stay under $Base`: $Path"
  }
}

function Get-AvoraxRegularDirectory([string]$Path, [string]$DisplayName) {
  Assert-AvoraxNoReparsePath $Path $DisplayName
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not ($item -is [System.IO.DirectoryInfo])) {
    throw "$DisplayName is not a directory: $Path"
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing to use reparse-point $DisplayName`: $Path"
  }
  $item.FullName
}

function New-AvoraxRegularDirectory([string]$Path, [string]$DisplayName, [string]$Base = $null) {
  Assert-AvoraxNoReparsePath $Path $DisplayName
  if (-not [string]::IsNullOrWhiteSpace($Base)) {
    Assert-AvoraxPathUnder $Path $Base $DisplayName
  }
  if (-not (Test-Path -LiteralPath $Path)) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }
  Get-AvoraxRegularDirectory $Path $DisplayName
}

function Remove-AvoraxRegularFileIfPresent([string]$Path, [string]$DisplayName) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  [void](Get-AvoraxRegularFile $Path $DisplayName)
  Remove-Item -LiteralPath $Path -Force
}

function Write-AvoraxJsonFileAtomic([string]$Path, [object]$Value, [int]$Depth, [string]$DisplayName, [string]$Base = $null) {
  Write-AvoraxTextFileAtomic $Path ($Value | ConvertTo-Json -Depth $Depth) $DisplayName $Base
}

function Write-AvoraxTextFileAtomic([string]$Path, [string]$Value, [string]$DisplayName, [string]$Base = $null) {
  $directory = New-AvoraxRegularDirectory (Split-Path $Path) "$DisplayName directory" $Base
  Assert-AvoraxNoReparsePath $Path $DisplayName
  if (-not [string]::IsNullOrWhiteSpace($Base)) {
    Assert-AvoraxPathUnder $Path $Base $DisplayName
  }
  if (Test-Path -LiteralPath $Path) {
    [void](Get-AvoraxRegularFile $Path $DisplayName)
  }
  $target = [System.IO.Path]::GetFullPath($Path)
  $tempPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".tmp")
  $backupPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".bak")
  try {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempPath, $Value, $encoding)
    [void](Get-AvoraxRegularFile $tempPath "$DisplayName temporary file")
    if (Test-Path -LiteralPath $target) {
      [System.IO.File]::Replace($tempPath, $target, $backupPath)
    } else {
      [System.IO.File]::Move($tempPath, $target)
    }
  } finally {
    Remove-AvoraxRegularFileIfPresent $tempPath "$DisplayName temporary file"
    Remove-AvoraxRegularFileIfPresent $backupPath "$DisplayName backup file"
  }
}
