param(
  [string]$RepoRoot = $(Join-Path $PSScriptRoot "..\.."),
  [string]$CargoPath = $env:CARGO,
  [switch]$BuildDriver,
  [switch]$InstallDriver,
  [switch]$ConfirmDriverInstall,
  [switch]$ProcessGuard,
  [string]$ReportPath
)

$ErrorActionPreference = "Stop"
$MaxSelfTestCommandOutputBytes = 1048576
$SelfTestCommandTimeoutMs = 120000

function Test-AvoraxLocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Assert-AvoraxNoReparsePath([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Description path is required."
  }
  if (-not (Test-AvoraxLocalWindowsPath $Path)) {
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

function Assert-AvoraxPathUnder([string]$Path, [string]$Base, [string]$Description) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  $pathFull = [System.IO.Path]::GetFullPath($Path)
  if ($pathFull.TrimEnd('\', '/').Equals($baseFull.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    return
  }
  if (-not $pathFull.StartsWith($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must stay under $Base`: $Path"
  }
}

function Assert-AvoraxRepoChildPath([string]$Path, [string]$Base, [string]$Description) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must resolve to a child path inside the Avorax repository root, not the repository root itself."
  }
  Assert-AvoraxPathUnder $pathFull $Base $Description
}

function Get-AvoraxSelfTestItem([string]$Path, [string]$Description, [string]$Kind) {
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

function Get-AvoraxSelfTestFile([string]$Path, [string]$Description) {
  Get-AvoraxSelfTestItem $Path $Description "file"
}

function Get-AvoraxSelfTestDirectory([string]$Path, [string]$Description) {
  Get-AvoraxSelfTestItem $Path $Description "directory"
}

function Get-AvoraxSelfTestTool([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Description path is required. Refusing to launch an ambient command from PATH."
  }
  Get-AvoraxSelfTestFile $Path $Description
}

function Get-AvoraxSelfTestBoundedDiagnostic([object]$Value, [int]$MaxLength = 4096) {
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return "" }
  $text = $text.Trim()
  if ($text.Length -le $MaxLength) { return $text }
  return $text.Substring(0, $MaxLength) + "...<truncated>"
}

function ConvertTo-AvoraxSelfTestCommandArgument([AllowNull()][string]$Value) {
  if ($null -eq $Value) { return '""' }
  if ($Value -notmatch '[\s"]') { return $Value }
  return '"' + $Value.Replace('"', '\"') + '"'
}

function Join-AvoraxSelfTestCommandArguments([AllowNull()][string[]]$Arguments) {
  if ($null -eq $Arguments -or $Arguments.Count -eq 0) { return "" }
  (@($Arguments) | ForEach-Object { ConvertTo-AvoraxSelfTestCommandArgument $_ }) -join ' '
}

function New-AvoraxSelfTestCommandTempFile([string]$Description) {
  try {
    return Get-AvoraxSelfTestFile ([System.IO.Path]::GetTempFileName()) $Description
  } catch {
    throw "Could not allocate $Description`: $(Get-AvoraxSelfTestBoundedDiagnostic $_.Exception.Message)"
  }
}

function Remove-AvoraxSelfTestCommandTempFile([AllowNull()][string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  try {
    if (Test-Path -LiteralPath $Path) {
      [void](Get-AvoraxSelfTestFile $Path $Description)
      Remove-Item -LiteralPath $Path -Force
    }
  } catch {
    throw "Could not remove $Description`: $(Get-AvoraxSelfTestBoundedDiagnostic $_.Exception.Message)"
  }
}

function Read-AvoraxSelfTestCommandOutput([string]$Path, [int]$MaxLength, [string]$Description) {
  if ($MaxLength -le 0 -or $MaxLength -gt [int]::MaxValue) {
    throw "$Description maximum diagnostic length must be positive and fit a PowerShell string buffer."
  }
  if (-not (Test-Path -LiteralPath $Path)) { return "" }
  $file = Get-AvoraxSelfTestFile $Path $Description
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
      if ($read -le 0) { throw "$Description could not be read completely: $file" }
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

function Test-AvoraxSelfTestCommandOutputWithinLimit([string[]]$Paths, [string]$Description) {
  foreach ($path in $Paths) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { continue }
    $file = Get-AvoraxSelfTestFile $path $Description
    $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
    if ($item.Length -gt $script:MaxSelfTestCommandOutputBytes) { return $false }
  }
  return $true
}

function Stop-AvoraxSelfTestCommandProcess([AllowNull()][System.Diagnostics.Process]$Process, [string]$Reason, [string]$Description) {
  if ($null -eq $Process -or $Process.HasExited) { return }
  try {
    $Process.Kill()
    if (-not $Process.WaitForExit(5000)) {
      throw "$Description did not exit within 5000 ms after $Reason."
    }
  } catch {
    throw "Could not stop $Description after $Reason`: $(Get-AvoraxSelfTestBoundedDiagnostic $_.Exception.Message)"
  }
}

function Invoke-AvoraxSelfTestCommandDiagnostic([string]$Tool, [string[]]$Arguments, [string]$DisplayName, [int]$MaxLength = 4096, [string]$WorkingDirectory = $null) {
  $stdoutPath = New-AvoraxSelfTestCommandTempFile "$DisplayName stdout"
  $stderrPath = New-AvoraxSelfTestCommandTempFile "$DisplayName stderr"
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
    $argumentList = Join-AvoraxSelfTestCommandArguments $Arguments
    if (-not [string]::IsNullOrWhiteSpace($argumentList)) {
      $startArgs.ArgumentList = $argumentList
    }
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
      $startArgs.WorkingDirectory = Get-AvoraxSelfTestDirectory $WorkingDirectory "$DisplayName working directory"
    }
    $process = Start-Process @startArgs
    $deadline = [DateTime]::UtcNow.AddMilliseconds($script:SelfTestCommandTimeoutMs)
    while (-not $process.HasExited) {
      Start-Sleep -Milliseconds 100
      if (-not (Test-AvoraxSelfTestCommandOutputWithinLimit @($stdoutPath, $stderrPath) $DisplayName)) {
        $outputLimitExceeded = $true
        Stop-AvoraxSelfTestCommandProcess $process "output limit" $DisplayName
        break
      }
      if ([DateTime]::UtcNow -ge $deadline) {
        $timedOut = $true
        Stop-AvoraxSelfTestCommandProcess $process "timeout" $DisplayName
        break
      }
    }
    if ($process.HasExited) {
      [void]$process.WaitForExit()
      $process.Refresh()
      $exitCode = [int]$process.ExitCode
    }
    if (-not (Test-AvoraxSelfTestCommandOutputWithinLimit @($stdoutPath, $stderrPath) $DisplayName)) {
      $outputLimitExceeded = $true
    }
    $outputParts = @()
    $stdout = Read-AvoraxSelfTestCommandOutput $stdoutPath $MaxLength "$DisplayName stdout"
    if (-not [string]::IsNullOrWhiteSpace($stdout)) { $outputParts += $stdout }
    $stderr = Read-AvoraxSelfTestCommandOutput $stderrPath $MaxLength "$DisplayName stderr"
    if (-not [string]::IsNullOrWhiteSpace($stderr)) { $outputParts += $stderr }
    if ($timedOut) { $outputParts += "$DisplayName timed out after $script:SelfTestCommandTimeoutMs ms." }
    if ($outputLimitExceeded) { $outputParts += "$DisplayName exceeded the $script:MaxSelfTestCommandOutputBytes byte diagnostic output limit." }
    [pscustomobject][ordered]@{
      command = $DisplayName
      exit_code = $exitCode
      output = Get-AvoraxSelfTestBoundedDiagnostic ($outputParts -join [Environment]::NewLine) $MaxLength
    }
  } finally {
    Remove-AvoraxSelfTestCommandTempFile $stdoutPath "$DisplayName stdout"
    Remove-AvoraxSelfTestCommandTempFile $stderrPath "$DisplayName stderr"
  }
}

$root = (Resolve-Path $RepoRoot).Path
[void](Get-AvoraxSelfTestDirectory $root "repository root")
if (-not $ReportPath) {
  $ReportPath = Join-Path $root "dist\windows-driver-validation\selftest_report.json"
}
Assert-AvoraxNoReparsePath $ReportPath "protection self-test report"
Assert-AvoraxPathUnder $ReportPath $root "protection self-test report"
Assert-AvoraxRepoChildPath $ReportPath $root "protection self-test report"
$cargo = Get-AvoraxSelfTestTool $CargoPath "Cargo executable"
$powerShell = Get-AvoraxSelfTestTool ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$miniScripts = Join-Path $root "core\zentor_windows_minifilter\scripts"
$processScripts = Join-Path $root "core\zentor_windows_process_guard\scripts"
$guardServiceDir = Get-AvoraxSelfTestDirectory (Join-Path $root "core\zentor_guard_service") "Guard Service crate directory"
$guardServiceExe = Join-Path $root "target\release\zentor_guard_service.exe"
$miniBuildScript = Get-AvoraxSelfTestFile (Join-Path $miniScripts "build-driver.ps1") "minifilter build script"
$miniInstallScript = Get-AvoraxSelfTestFile (Join-Path $miniScripts "install-test-driver.ps1") "minifilter install script"
$miniSelfTestScript = Get-AvoraxSelfTestFile (Join-Path $miniScripts "run-driver-self-test.ps1") "minifilter self-test script"
$processBuildScript = Get-AvoraxSelfTestFile (Join-Path $processScripts "build-driver.ps1") "process-guard build script"
$processInstallScript = Get-AvoraxSelfTestFile (Join-Path $processScripts "install-test-driver.ps1") "process-guard install script"

if ($BuildDriver) {
  $miniBuildDiagnostic = Invoke-AvoraxSelfTestCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $miniBuildScript) "minifilter build script" 32768
  if ($miniBuildDiagnostic.exit_code -ne 0) {
    throw "Minifilter build script failed with exit code $($miniBuildDiagnostic.exit_code): $($miniBuildDiagnostic.output)"
  }
  if ($ProcessGuard) {
    $processBuildDiagnostic = Invoke-AvoraxSelfTestCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $processBuildScript) "process-guard build script" 32768
    if ($processBuildDiagnostic.exit_code -ne 0) {
      throw "Process-guard build script failed with exit code $($processBuildDiagnostic.exit_code): $($processBuildDiagnostic.output)"
    }
  }
}

if ($InstallDriver) {
  if (-not $ConfirmDriverInstall) {
    throw "Refusing to install Avorax test drivers without -ConfirmDriverInstall. Use only on an approved development VM."
  }
  $miniInstallDiagnostic = Invoke-AvoraxSelfTestCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $miniInstallScript, "-ConfirmDriverInstall") "minifilter install script" 32768
  if ($miniInstallDiagnostic.exit_code -ne 0) {
    throw "Minifilter install script failed with exit code $($miniInstallDiagnostic.exit_code): $($miniInstallDiagnostic.output)"
  }
  if ($ProcessGuard) {
    $processInstallDiagnostic = Invoke-AvoraxSelfTestCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $processInstallScript, "-ConfirmDriverInstall") "process-guard install script" 32768
    if ($processInstallDiagnostic.exit_code -ne 0) {
      throw "Process-guard install script failed with exit code $($processInstallDiagnostic.exit_code): $($processInstallDiagnostic.output)"
    }
  }
}

$cargoDiagnostic = Invoke-AvoraxSelfTestCommandDiagnostic $cargo @("build", "--release") "cargo build --release" 32768 $guardServiceDir
if ($cargoDiagnostic.exit_code -ne 0) {
  throw "Guard Service release build failed with exit code $($cargoDiagnostic.exit_code): $($cargoDiagnostic.output)"
}

[void](Get-AvoraxSelfTestFile $guardServiceExe "Guard Service release executable")
$miniSelfTestDiagnostic = Invoke-AvoraxSelfTestCommandDiagnostic $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $miniSelfTestScript, "-GuardServicePath", $guardServiceExe, "-ReportPath", $ReportPath) "minifilter self-test script" 32768
if ($miniSelfTestDiagnostic.exit_code -ne 0) {
  throw "Minifilter self-test script failed with exit code $($miniSelfTestDiagnostic.exit_code): $($miniSelfTestDiagnostic.output)"
}
Write-Host "Avorax protection self-test report: $ReportPath"
