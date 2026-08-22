[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$LocalCorePath,

  [Parameter(Mandatory = $true)]
  [string]$GuardPath,

  [string]$RepoRoot = "",

  [ValidateRange(5, 120)]
  [int]$TimeoutSeconds = 45
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
  $RepoRoot = Join-Path $PSScriptRoot "..\.."
}

function Get-CanonicalFilePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [string]$Description
  )

  if (-not [System.IO.Path]::IsPathRooted($Path)) {
    throw "$Description path must be absolute: $Path"
  }
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw "$Description must be a regular non-reparse file: $Path"
  }
  return $item.FullName
}

function Assert-RepoReleaseBinary {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string]$Repository
  )

  $resolved = Get-CanonicalFilePath $Path "$Name release binary"
  $expectedParent = [System.IO.Path]::GetFullPath((Join-Path $Repository "target\release")).TrimEnd('\')
  $actualParent = [System.IO.Path]::GetDirectoryName($resolved).TrimEnd('\')
  if (-not $actualParent.Equals($expectedParent, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Name release binary must be directly under $expectedParent"
  }
  return $resolved
}

function Get-Sha256Hex {
  param([Parameter(Mandatory = $true)][string]$Path)

  $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
      return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
    } finally {
      $sha.Dispose()
    }
  } finally {
    $stream.Dispose()
  }
}

function New-HelperRequestJson {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedSha256
  )

  if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$') {
    throw "expected Authenticode helper SHA-256 must be exactly 64 lowercase hexadecimal characters; length=$($ExpectedSha256.Length)"
  }
  $units = @($Path.ToCharArray() | ForEach-Object { [int][char]$_ })
  return (@{
      schema_version = 1
      nonce = [guid]::NewGuid().ToString("D")
      path_utf16 = $units
      expected_sha256 = $ExpectedSha256
    } | ConvertTo-Json -Compress -Depth 4)
}

function Invoke-HelperMode {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Binary,

    [Parameter(Mandatory = $true)]
    [string]$Argument,

    [Parameter(Mandatory = $true)]
    [string]$RequestJson,

    [Parameter(Mandatory = $true)]
    [int]$Timeout
  )

  $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $Binary
  $startInfo.Arguments = $Argument
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardInput = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $process = [System.Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  $started = $false
  try {
    if (-not $process.Start()) {
      throw "failed to start Authenticode host $Binary"
    }
    $started = $true
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $deadline = [DateTime]::UtcNow.AddSeconds($Timeout)
    $inputTask = $process.StandardInput.WriteAsync($RequestJson)
    $remaining = [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if (-not $inputTask.Wait($remaining)) {
      throw "Authenticode host exceeded external $Timeout second smoke timeout while receiving its request: $Binary $Argument"
    }
    [void]$inputTask.GetAwaiter().GetResult()
    [void]$process.StandardInput.Close()
    $remaining = [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if (-not $process.WaitForExit($remaining)) {
      throw "Authenticode host exceeded external $Timeout second smoke timeout: $Binary $Argument"
    }
    if (-not $stdoutTask.Wait(5000) -or -not $stderrTask.Wait(5000)) {
      throw "Authenticode host output readers did not complete within 5000 ms"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($stdout.Length -gt 16384 -or $stderr.Length -gt 16384) {
      throw "Authenticode host output exceeded the 16384 character smoke bound"
    }
    return [pscustomobject]@{
      ExitCode = $process.ExitCode
      Stdout = $stdout
      Stderr = $stderr
    }
  } catch {
    $failure = $_.Exception.Message
    $cleanup = if ($started) { "already exited" } else { "not started" }
    if ($started -and -not $process.HasExited) {
      try {
        $process.Kill()
        $reaped = $process.WaitForExit(5000)
        $cleanup = "kill=ok; reaped=$reaped"
      } catch {
        $cleanup = "kill/reap error: $($_.Exception.Message)"
      }
    }
    throw "$failure; cleanup=$cleanup"
  } finally {
    $process.Dispose()
  }
}

function Assert-ClientVerdict {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Binary,

    [Parameter(Mandatory = $true)]
    [string]$Fixture,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedSha256,

    [Parameter(Mandatory = $true)]
    [bool]$ExpectedTrusted,

    [Parameter(Mandatory = $true)]
    [int]$Timeout
  )

  $request = New-HelperRequestJson $Fixture $ExpectedSha256
  $nonce = ($request | ConvertFrom-Json).nonce
  $result = Invoke-HelperMode $Binary "--avorax-authenticode-client-self-test-v1" $request $Timeout
  if ($result.ExitCode -ne 0) {
    throw "Authenticode client self-test failed with exit $($result.ExitCode): $($result.Stderr)"
  }
  $response = $result.Stdout | ConvertFrom-Json
  if ($response.schema_version -ne 1 -or $response.nonce -ne $nonce -or $response.status -ne "ok") {
    throw "Authenticode client self-test returned invalid success envelope: $($result.Stdout)"
  }
  if ([bool]$response.trusted -ne $ExpectedTrusted -or $null -ne $response.error) {
    throw "Authenticode client self-test returned unexpected verdict: $($result.Stdout)"
  }
}

function Assert-ClientHashMismatch {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Binary,

    [Parameter(Mandatory = $true)]
    [string]$Fixture,

    [Parameter(Mandatory = $true)]
    [int]$Timeout
  )

  $request = New-HelperRequestJson $Fixture ("0" * 64)
  $nonce = ($request | ConvertFrom-Json).nonce
  $result = Invoke-HelperMode $Binary "--avorax-authenticode-client-self-test-v1" $request $Timeout
  if ($result.ExitCode -ne 0) {
    throw "Authenticode mismatch self-test process failed with exit $($result.ExitCode): $($result.Stderr)"
  }
  $response = $result.Stdout | ConvertFrom-Json
  if ($response.schema_version -ne 1 -or $response.nonce -ne $nonce -or $response.status -ne "error") {
    throw "Authenticode mismatch self-test returned invalid error envelope: $($result.Stdout)"
  }
  if ($null -ne $response.trusted -or [string]::IsNullOrWhiteSpace([string]$response.error)) {
    throw "Authenticode mismatch self-test synthesized a verdict or omitted its error"
  }
  if ([string]$response.error -notlike "*does not match the bytes already scanned*") {
    throw "Authenticode mismatch self-test returned the wrong diagnostic: $($response.error)"
  }
}

$repo = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd('\')
$localCore = Assert-RepoReleaseBinary $LocalCorePath "Local Core" $repo
$guard = Assert-RepoReleaseBinary $GuardPath "Guard" $repo
$systemDirectory = [System.Environment]::SystemDirectory
$catalogFixture = Get-CanonicalFilePath (Join-Path $systemDirectory "WindowsPowerShell\v1.0\powershell.exe") "catalog-signed fixture"
$programFilesX86 = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFilesX86)
$embeddedFixture = Get-CanonicalFilePath (Join-Path $programFilesX86 "Microsoft\Edge\Application\msedge.exe") "embedded multi-signed fixture"
$catalogHash = Get-Sha256Hex $catalogFixture
$embeddedHash = Get-Sha256Hex $embeddedFixture
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$tempRoot = [System.IO.Path]::GetFullPath((Join-Path $tempBase ("avorax-auth-helper-smoke-" + [guid]::NewGuid().ToString("N"))))
if (-not $tempRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "isolated Authenticode smoke root escaped the system temporary directory"
}
$unsignedFixture = Join-Path $tempRoot "unsigned-benign-fixture.exe"

try {
  [void][System.IO.Directory]::CreateDirectory($tempRoot)
  [System.IO.File]::WriteAllText($unsignedFixture, "benign unsigned Authenticode helper fixture", [System.Text.Encoding]::ASCII)
  $unsignedHash = Get-Sha256Hex $unsignedFixture
  foreach ($hostBinary in @($localCore, $guard)) {
    Assert-ClientVerdict $hostBinary $embeddedFixture $embeddedHash $true $TimeoutSeconds
    Assert-ClientVerdict $hostBinary $catalogFixture $catalogHash $true $TimeoutSeconds
    Assert-ClientVerdict $hostBinary $unsignedFixture $unsignedHash $false $TimeoutSeconds
    Assert-ClientHashMismatch $hostBinary $embeddedFixture $TimeoutSeconds
  }
} finally {
  if (Test-Path -LiteralPath $tempRoot) {
    if (-not $tempRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "refusing to remove Authenticode smoke data outside the system temporary directory"
    }
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}

Write-Output "Release Authenticode isolated-helper smoke passed for Local Core and Guard."
Write-Output "Verified: mandatory hash-bound nonce IPC, embedded and catalog Microsoft trust, unsigned rejection, hash mismatch failure, no fixture execution."
Write-Output "Safety: benign installed fixtures only; no EICAR, live malware, network, installation, service/driver start, Defender change, publication, or protected-vault access."
