$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "avorax-security-gate-tools.ps1")

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$maxTextFileBytes = 1048576
$maxDiagnosticChars = 4096
$scanRoots = @(
  "apps\zentor_client\lib",
  "apps\zentor_client\test",
  "packages\zentor_protocol\lib",
  "installer\windows",
  "README.md",
  "docs\anti-virus-overview.md",
  "docs\architecture.md",
  "docs\client-ui.md",
  "docs\limitations.md",
  "docs\native-engine.md",
  "docs\real-time-protection.md",
  "docs\quarantine.md",
  "docs\recovery-vault.md"
)

$legacy = ("pa" + "sus")
$forbidden = @(
  $legacy,
  ("zentor" + " anti-virus"),
  ("zentor" + " native"),
  ("zentor" + " cloud"),
  ("zentor" + " guard"),
  ("zentor" + " core"),
  ("zentor" + " recovery"),
  ("zentor" + " quarantine"),
  ("zentor" + " checks"),
  ("zentor" + " scans"),
  ("anti" + "-cheat"),
  ("fair" + " play"),
  ("gaming" + " protection"),
  ("game" + " setup"),
  ("player" + " session"),
  ("match" + " telemetry"),
  ("fake" + " checkout"),
  ("fake" + " license"),
  ("fake" + " reviews"),
  ("fake" + " awards"),
  ("100" + "% protection"),
  ("perfect" + " protection"),
  ("best" + " antivirus"),
  ("guaranteed" + " protection"),
  ("certified" + " by av-test"),
  ("trusted" + " by millions")
)

$textExtensions = @(
  ".dart",
  ".md",
  ".json",
  ".yaml",
  ".yml",
  ".xml",
  ".wxs",
  ".wxl",
  ".ps1",
  ".sh",
  ".txt"
)

$violations = @()

function Add-GateFailure([string]$Message) {
  $script:violations += $Message
}

function Get-BoundedDiagnostic {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  if ($text.Length -le $maxDiagnosticChars) { return $text }
  return $text.Substring(0, $maxDiagnosticChars) + "...[truncated]"
}

function Get-SafeScanItem([string]$Path, [string]$Description) {
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  } catch {
    Add-GateFailure "$Description is missing or uninspectable: $(Get-BoundedDiagnostic $_.Exception.Message)"
    return $null
  }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Add-GateFailure "$Description must not be a reparse point: $($item.FullName)"
    return $null
  }
  if (-not ($item -is [System.IO.FileInfo]) -and -not ($item -is [System.IO.DirectoryInfo])) {
    Add-GateFailure "$Description is neither a regular file nor directory: $($item.FullName)"
    return $null
  }
  return $item
}

function Get-SafeTextFiles([System.IO.FileSystemInfo]$RootItem) {
  if ($RootItem -is [System.IO.FileInfo]) {
    return @($RootItem)
  }

  $results = @()
  $directories = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
  $directories.Push([System.IO.DirectoryInfo]$RootItem)
  while ($directories.Count -gt 0) {
    $directory = $directories.Pop()
    try {
      foreach ($childDirectory in Get-ChildItem -LiteralPath $directory.FullName -Directory -Force -ErrorAction Stop) {
        if (($childDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
          Add-GateFailure "Product-copy scan directory must not be a reparse point: $($childDirectory.FullName)"
          continue
        }
        $directories.Push($childDirectory)
      }
      foreach ($file in Get-ChildItem -LiteralPath $directory.FullName -File -Force -ErrorAction Stop) {
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
          Add-GateFailure "Product-copy scan file must not be a reparse point: $($file.FullName)"
          continue
        }
        if ($textExtensions -contains $file.Extension.ToLowerInvariant()) {
          $results += $file
        }
      }
    } catch {
      Add-GateFailure "Could not enumerate product-copy scan directory '$($directory.FullName)': $(Get-BoundedDiagnostic $_.Exception.Message)"
    }
  }
  return $results
}

function Read-LowerProductCopyText([System.IO.FileInfo]$File) {
  try {
    return (Read-AvoraxGateTextFileBounded $File.FullName $maxTextFileBytes "Product-copy scan file").ToLowerInvariant()
  } catch {
    Add-GateFailure "Could not read product-copy scan file '$($File.FullName)': $(Get-BoundedDiagnostic $_.Exception.Message)"
    return $null
  }
}

foreach ($relative in $scanRoots) {
  $path = Join-Path $root $relative
  if (-not (Test-Path -LiteralPath $path)) { continue }

  $item = Get-SafeScanItem $path "Product-copy scan root $relative"
  if (-not $item) { continue }
  $files = Get-SafeTextFiles $item

  foreach ($file in $files) {
    $content = Read-LowerProductCopyText $file
    if ($null -eq $content) { continue }
    foreach ($phrase in $forbidden) {
      if ($content.Contains($phrase)) {
        Add-GateFailure "$($file.FullName): forbidden product-copy phrase '$phrase'"
      }
    }
  }
}

if ($violations.Count -gt 0) {
  $violations | ForEach-Object { Write-Error $_ }
  exit 1
}

Write-Host "Avorax product copy gate passed."
