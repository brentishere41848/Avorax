param(
  [string]$Root = $(Join-Path ([System.IO.Path]::GetTempPath()) ("zentor-ransomware-sim-" + [guid]::NewGuid().ToString("N"))),
  [ValidateRange(1, 200)]
  [int]$FileCount = 40
)

$ErrorActionPreference = "Stop"

function Get-CheckedFullPath {
  param([Parameter(Mandatory = $true)][string]$Path)
  try {
    return [System.IO.Path]::GetFullPath($Path)
  } catch {
    throw "Unable to resolve simulator path '$Path': $($_.Exception.Message)"
  }
}

function Assert-NoReparsePath {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$StopAt
  )

  $current = $Path
  while ($true) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Simulator root must not use a reparse point: $current"
      }
    }
    if ($current.Equals($StopAt, [System.StringComparison]::OrdinalIgnoreCase)) {
      break
    }
    $parent = Split-Path -Parent $current
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent.Equals($current, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "Simulator root escaped the temporary directory boundary: $Path"
    }
    $current = $parent
  }
}

function Get-SimulatorContainedPath {
  param([Parameter(Mandatory = $true)][string]$Path)

  $full = Get-CheckedFullPath $Path
  $boundary = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if ($full.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase) -or
      -not $full.StartsWith($boundary, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Simulator file path escaped the isolated root: $full"
  }
  $parent = Split-Path -Parent $full
  Assert-NoReparsePath -Path $parent -StopAt $rootFull
  return $full
}

function Assert-SimulatorRegularFile {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Description
  )

  $target = Get-SimulatorContainedPath $Path
  $item = Get-Item -LiteralPath $target -Force -ErrorAction Stop
  if ($item.PSIsContainer) {
    throw "$Description is not a regular file: $target"
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $target"
  }
  return $target
}

function Write-SimulatorFileExclusive {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Value
  )

  $target = Get-SimulatorContainedPath $Path
  if (Test-Path -LiteralPath $target) {
    throw "Simulator fixture target already exists: $target"
  }
  $encoding = New-Object System.Text.UTF8Encoding($false)
  $stream = [System.IO.File]::Open($target, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  try {
    $writer = New-Object System.IO.StreamWriter($stream, $encoding)
    try {
      $writer.WriteLine($Value)
      $writer.Flush()
      $stream.Flush($true)
    } finally {
      $writer.Dispose()
    }
  } finally {
    $stream.Dispose()
  }
}

function Add-SimulatorFileLineExclusive {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Value
  )

  $target = Assert-SimulatorRegularFile -Path $Path -Description "Simulator fixture append target"
  $encoding = New-Object System.Text.UTF8Encoding($false)
  $stream = [System.IO.File]::Open($target, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  try {
    $writer = New-Object System.IO.StreamWriter($stream, $encoding)
    try {
      $writer.WriteLine($Value)
      $writer.Flush()
      $stream.Flush($true)
    } finally {
      $writer.Dispose()
    }
  } finally {
    $stream.Dispose()
  }
}

$tempRoot = (Get-CheckedFullPath ([System.IO.Path]::GetTempPath())).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
$rootFull = (Get-CheckedFullPath $Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
$tempBoundary = $tempRoot + [System.IO.Path]::DirectorySeparatorChar
if ($rootFull.Equals($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not $rootFull.StartsWith($tempBoundary, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "Simulator root must be an isolated child directory under the system temp path: $tempRoot"
}

Assert-NoReparsePath -Path $rootFull -StopAt $tempRoot

if (Test-Path -LiteralPath $rootFull) {
  $rootItem = Get-Item -LiteralPath $rootFull -Force
  if (-not $rootItem.PSIsContainer) {
    throw "Simulator root is not a directory: $rootFull"
  }
  $existing = Get-ChildItem -LiteralPath $rootFull -Force -ErrorAction Stop | Select-Object -First 1
  if ($null -ne $existing) {
    throw "Simulator root must be empty before use: $rootFull"
  }
} else {
  New-Item -ItemType Directory -Path $rootFull -Force | Out-Null
}

Assert-NoReparsePath -Path $rootFull -StopAt $tempRoot

for ($i = 0; $i -lt $FileCount; $i++) {
  $path = Join-Path $rootFull ("document-$i.txt")
  Write-SimulatorFileExclusive -Path $path -Value "Avorax safe ransomware simulator fixture $i"
}

for ($i = 0; $i -lt $FileCount; $i++) {
  $path = Join-Path $rootFull ("document-$i.txt")
  $renamed = Join-Path $rootFull ("document-$i.locked-test")
  if (Test-Path -LiteralPath $renamed) {
    throw "Simulator rename target already exists: $renamed"
  }
  Add-SimulatorFileLineExclusive -Path $path -Value "modified quickly by safe simulator"
  Assert-SimulatorRegularFile -Path $path -Description "Simulator rename source" | Out-Null
  Rename-Item -LiteralPath $path -NewName ("document-$i.locked-test")
}

Write-SimulatorFileExclusive -Path (Join-Path $rootFull "READ_ME_TEST_ONLY.txt") -Value "Safe Avorax simulator note. This is not a ransom note and contains no demand."

[ordered]@{
  ok = $true
  simulator = "zentor-benign-ransomware-simulator"
  root = $rootFull
  files_modified = $FileCount
  scope = "isolated empty temporary test directory only"
  warning = "This simulator is benign and must not be treated as a real malware sample."
} | ConvertTo-Json -Depth 4
