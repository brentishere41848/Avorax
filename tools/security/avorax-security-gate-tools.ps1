$ErrorActionPreference = "Stop"
$script:AvoraxGateCommandOutputByteLimit = 1048576
$script:AvoraxGateCommandTimeoutMs = 120000

function Test-AvoraxLocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Assert-AvoraxNoReparsePath([string]$Path, [string]$Description) {
  if (-not (Test-AvoraxLocalWindowsPath $Path)) {
    throw "$Description must be on a local Windows drive path: $Path"
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

function Get-AvoraxGateItem([string]$Path, [string]$Description, [string]$Kind) {
  Assert-AvoraxNoReparsePath $Path $Description
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $Path"
  }
  if ($Kind -eq "file" -and -not ($item -is [System.IO.FileInfo])) {
    throw "$Description is not a regular file: $Path"
  }
  if ($Kind -eq "directory" -and -not ($item -is [System.IO.DirectoryInfo])) {
    throw "$Description is not a directory: $Path"
  }
  $item.FullName
}

function Get-AvoraxGateFile([string]$Path, [string]$Description) {
  Get-AvoraxGateItem $Path $Description "file"
}

function Get-AvoraxGateDirectory([string]$Path, [string]$Description) {
  Get-AvoraxGateItem $Path $Description "directory"
}

function Get-AvoraxRequiredTool([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Description path is required. Refusing to launch an ambient command from PATH."
  }
  Get-AvoraxGateFile $Path $Description
}

function New-AvoraxGateDirectory([string]$Path, [string]$Description) {
  Assert-AvoraxNoReparsePath $Path $Description
  if (-not (Test-Path -LiteralPath $Path)) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }
  Get-AvoraxGateDirectory $Path $Description
}

function Remove-AvoraxGateRegularFileIfPresent([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  Get-AvoraxGateFile $Path $Description | Out-Null
  Remove-Item -LiteralPath $Path -Force
}

function Get-AvoraxGateBoundedDiagnostic([AllowNull()][object]$Value, [int]$MaxLength = 4096) {
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return "" }
  $text = $text.Trim()
  if ($text.Length -le $MaxLength) { return $text }
  return $text.Substring(0, $MaxLength) + "...<truncated>"
}

function ConvertTo-AvoraxGateCommandArgument([AllowNull()][string]$Value) {
  if ($null -eq $Value) { return '""' }
  if ($Value -notmatch '[\s"]') { return $Value }
  return '"' + $Value.Replace('"', '\"') + '"'
}

function Join-AvoraxGateCommandArguments([AllowNull()][string[]]$Arguments) {
  if ($null -eq $Arguments -or $Arguments.Count -eq 0) { return "" }
  (@($Arguments) | ForEach-Object { ConvertTo-AvoraxGateCommandArgument $_ }) -join ' '
}

function New-AvoraxGateCommandTempFile([string]$Description) {
  try {
    return Get-AvoraxGateFile ([System.IO.Path]::GetTempFileName()) $Description
  } catch {
    throw "Could not allocate $Description`: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
}

function Remove-AvoraxGateCommandTempFile([AllowNull()][string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  try {
    Remove-AvoraxGateRegularFileIfPresent $Path $Description
  } catch {
    throw "Could not remove $Description`: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
}

function Read-AvoraxGateCommandOutputFile([string]$Path, [int]$MaxLength, [string]$Description) {
  if ($MaxLength -le 0 -or $MaxLength -gt [int]::MaxValue) {
    throw "$Description maximum diagnostic length must be positive and fit a PowerShell string buffer."
  }
  if (-not (Test-Path -LiteralPath $Path)) { return "" }
  $file = Get-AvoraxGateFile $Path $Description
  $stream = [System.IO.File]::Open($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
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
        throw "$Description could not be read completely: $file"
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

function Test-AvoraxGateCommandOutputWithinLimit([string[]]$Paths, [string]$Description) {
  foreach ($path in $Paths) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { continue }
    $file = Get-AvoraxGateFile $path $Description
    $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
    if ($item.Length -gt $script:AvoraxGateCommandOutputByteLimit) { return $false }
  }
  return $true
}

function Stop-AvoraxGateCommandProcess([AllowNull()][System.Diagnostics.Process]$Process, [string]$Reason, [string]$Description) {
  if ($null -eq $Process -or $Process.HasExited) { return }
  try {
    $Process.Kill()
    if (-not $Process.WaitForExit(5000)) {
      throw "$Description did not exit within 5000 ms after $Reason."
    }
  } catch {
    throw "Could not stop $Description after $Reason`: $(Get-AvoraxGateBoundedDiagnostic $_.Exception.Message)"
  }
}

function Set-AvoraxGateSanitizedProcessEnvironment([System.Diagnostics.ProcessStartInfo]$StartInfo) {
  $environment = $StartInfo.EnvironmentVariables
  if ($null -eq $environment) {
    $environment = $StartInfo.Environment
  }
  if ($null -eq $environment) {
    throw "ProcessStartInfo did not expose an environment collection for sanitized gate command launch."
  }
  $environment.Clear()
  $variables = [System.Environment]::GetEnvironmentVariables("Process")
  $seen = @{}
  foreach ($key in $variables.Keys) {
    $name = [string]$key
    if ([string]::IsNullOrWhiteSpace($name)) { continue }
    if ($name -ieq "Path") { continue }
    if ($seen.ContainsKey($name)) { continue }
    $seen[$name] = $true
    $environment[$name] = [string]$variables[$key]
  }
  $pathValue = [System.Environment]::GetEnvironmentVariable("Path", "Process")
  if ([string]::IsNullOrWhiteSpace($pathValue)) {
    $pathValue = [System.Environment]::GetEnvironmentVariable("PATH", "Process")
  }
  if (-not [string]::IsNullOrWhiteSpace($pathValue)) {
    $environment["Path"] = $pathValue
  }
}

function Wait-AvoraxGateStreamCopy([AllowNull()][System.Threading.Tasks.Task]$Task, [string]$Description) {
  if ($null -eq $Task) { return }
  if (-not $Task.Wait(5000)) {
    throw "$Description did not finish copying command output."
  }
  if ($Task.IsFaulted) {
    throw "$Description failed while copying command output: $(Get-AvoraxGateBoundedDiagnostic $Task.Exception.GetBaseException().Message)"
  }
}

function Invoke-AvoraxGateCommandDiagnostic([string]$Tool, [string[]]$Arguments, [string]$DisplayName, [int]$MaxLength = 4096, [string]$WorkingDirectory = $null) {
  $stdoutPath = New-AvoraxGateCommandTempFile "$DisplayName stdout"
  $stderrPath = New-AvoraxGateCommandTempFile "$DisplayName stderr"
  $process = $null
  $stdoutStream = $null
  $stderrStream = $null
  $stdoutTask = $null
  $stderrTask = $null
  $exitCode = -1
  $timedOut = $false
  $outputLimitExceeded = $false
  try {
    $argumentList = Join-AvoraxGateCommandArguments $Arguments
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Tool
    $startInfo.Arguments = $argumentList
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    Set-AvoraxGateSanitizedProcessEnvironment $startInfo
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
      $startInfo.WorkingDirectory = Get-AvoraxGateDirectory $WorkingDirectory "$DisplayName working directory"
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $stdoutStream = [System.IO.File]::Open($stdoutPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $stderrStream = [System.IO.File]::Open($stderrPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
    $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($script:AvoraxGateCommandTimeoutMs)
    while (-not $process.HasExited) {
      Start-Sleep -Milliseconds 100
      if (-not (Test-AvoraxGateCommandOutputWithinLimit @($stdoutPath, $stderrPath) $DisplayName)) {
        $outputLimitExceeded = $true
        Stop-AvoraxGateCommandProcess $process "output limit" $DisplayName
        break
      }
      if ([DateTime]::UtcNow -ge $deadline) {
        $timedOut = $true
        Stop-AvoraxGateCommandProcess $process "timeout" $DisplayName
        break
      }
    }
    if ($process.HasExited) {
      [void]$process.WaitForExit()
      $process.Refresh()
      $exitCode = [int]$process.ExitCode
    }
    Wait-AvoraxGateStreamCopy $stdoutTask "$DisplayName stdout"
    Wait-AvoraxGateStreamCopy $stderrTask "$DisplayName stderr"
    if ($null -ne $stdoutStream) { $stdoutStream.Dispose(); $stdoutStream = $null }
    if ($null -ne $stderrStream) { $stderrStream.Dispose(); $stderrStream = $null }
    if (-not (Test-AvoraxGateCommandOutputWithinLimit @($stdoutPath, $stderrPath) $DisplayName)) {
      $outputLimitExceeded = $true
    }
    $outputParts = @()
    $stdout = Read-AvoraxGateCommandOutputFile $stdoutPath $MaxLength "$DisplayName stdout"
    if (-not [string]::IsNullOrWhiteSpace($stdout)) { $outputParts += $stdout }
    $stderr = Read-AvoraxGateCommandOutputFile $stderrPath $MaxLength "$DisplayName stderr"
    if (-not [string]::IsNullOrWhiteSpace($stderr)) { $outputParts += $stderr }
    if ($timedOut) { $outputParts += "$DisplayName timed out after $script:AvoraxGateCommandTimeoutMs ms." }
    if ($outputLimitExceeded) { $outputParts += "$DisplayName exceeded the $script:AvoraxGateCommandOutputByteLimit byte diagnostic output limit." }
    [pscustomobject][ordered]@{
      command = $DisplayName
      exit_code = $exitCode
      stdout = $stdout
      stderr = $stderr
      output = Get-AvoraxGateBoundedDiagnostic ($outputParts -join [Environment]::NewLine) $MaxLength
    }
  } finally {
    if ($null -ne $stdoutStream) { $stdoutStream.Dispose() }
    if ($null -ne $stderrStream) { $stderrStream.Dispose() }
    if ($null -ne $process) { $process.Dispose() }
    Remove-AvoraxGateCommandTempFile $stdoutPath "$DisplayName stdout"
    Remove-AvoraxGateCommandTempFile $stderrPath "$DisplayName stderr"
  }
}

function Read-AvoraxGateTextFileBounded([string]$Path, [int]$MaxBytes, [string]$Description) {
  if ($MaxBytes -le 0) {
    throw "$Description maximum byte count must be positive."
  }

  $file = Get-AvoraxGateFile ([System.IO.Path]::GetFullPath($Path)) $Description
  $stream = [System.IO.File]::Open(
    $file,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )
  try {
    if ($stream.Length -gt $MaxBytes) {
      throw "$Description exceeds $MaxBytes bytes: $file"
    }

    $length = [int]$stream.Length
    if ($length -eq 0) { return "" }

    $buffer = [byte[]]::new($length)
    $offset = 0
    while ($offset -lt $length) {
      $read = $stream.Read($buffer, $offset, $length - $offset)
      if ($read -le 0) {
        throw "$Description could not be read completely: $file"
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

function Write-AvoraxGateJsonFileAtomic([string]$Path, [object]$Value, [int]$Depth, [string]$Description) {
  Assert-AvoraxNoReparsePath $Path $Description
  $target = [System.IO.Path]::GetFullPath($Path)
  $directory = New-AvoraxGateDirectory (Split-Path $target) "$Description directory"
  if (Test-Path -LiteralPath $target) {
    Get-AvoraxGateFile $target "existing $Description" | Out-Null
  }

  $tempPath = Join-Path $directory ("." + (Split-Path $target -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".tmp")
  $backupPath = Join-Path $directory ("." + (Split-Path $target -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".bak")
  $encoding = New-Object System.Text.UTF8Encoding($false)
  try {
    [System.IO.File]::WriteAllText($tempPath, ($Value | ConvertTo-Json -Depth $Depth), $encoding)
    Get-AvoraxGateFile $tempPath "temporary $Description" | Out-Null
    if (Test-Path -LiteralPath $target) {
      [System.IO.File]::Replace($tempPath, $target, $backupPath)
    } else {
      [System.IO.File]::Move($tempPath, $target)
    }
  } finally {
    Remove-AvoraxGateRegularFileIfPresent $tempPath "temporary $Description"
    Remove-AvoraxGateRegularFileIfPresent $backupPath "$Description backup file"
  }
}
