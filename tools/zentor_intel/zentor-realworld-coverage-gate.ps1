param(
  [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path,
  [string]$CargoPath = $env:CARGO
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")
$root = Get-AvoraxGateDirectory ([System.IO.Path]::GetFullPath((Resolve-Path $RepoRoot).Path)) "Repository root"
$cargo = Get-AvoraxRequiredTool $CargoPath "Cargo executable"

function Get-CoverageGateFiles([string]$Root) {
  $excludedParts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($part in @("target", "build", "archive", "dist", ".git", ".dart_tool", "node_modules")) {
    $excludedParts.Add($part) | Out-Null
  }
  $directories = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
  $directories.Push((Get-Item -LiteralPath $Root -Force -ErrorAction Stop))
  $files = @()
  while ($directories.Count -gt 0) {
    $directory = $directories.Pop()
    foreach ($childDirectory in Get-ChildItem -LiteralPath $directory.FullName -Directory -Force -ErrorAction Stop) {
      if ($excludedParts.Contains($childDirectory.Name)) { continue }
      if (($childDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Coverage gate directory must not be a reparse point: $($childDirectory.FullName)"
      }
      $directories.Push($childDirectory)
    }
    foreach ($file in Get-ChildItem -LiteralPath $directory.FullName -File -Force -ErrorAction Stop) {
      if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Coverage gate file must not be a reparse point: $($file.FullName)"
      }
      $files += $file
    }
  }
  return $files
}

function Invoke-CoverageGateCommand([string]$Tool, [string[]]$Arguments, [string]$DisplayName, [string]$WorkingDirectory) {
  if (-not $Tool) {
    throw "$DisplayName could not run because its executable was unavailable."
  }
  $diagnostic = Invoke-AvoraxGateCommandDiagnostic $Tool $Arguments $DisplayName 32768 $WorkingDirectory
  if ($diagnostic.exit_code -ne 0) {
    throw "$DisplayName failed with exit code $($diagnostic.exit_code): $($diagnostic.output)"
  }
}

$powerShell = Get-AvoraxRequiredTool ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) "PowerShell executable"
$brandingCheck = Get-AvoraxGateFile (Join-Path $root "tools\branding\branding-check.ps1") "Branding check script"
Invoke-CoverageGateCommand $powerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $brandingCheck, "-Root", $root) "Branding check" $root
$script:forbidden = @()
Get-CoverageGateFiles $root | ForEach-Object {
  if ($_.Extension.ToLowerInvariant() -in @(".vir", ".malware", ".sample")) {
    $script:forbidden += $_
  }
}
if ($script:forbidden) {
  $script:forbidden | ForEach-Object { Write-Error "Forbidden malware-like binary/sample extension: $($_.FullName)" }
  throw "Forbidden malware samples found."
}
$nativeManifest = Get-AvoraxGateFile (Join-Path $root "core\zentor_native_engine\Cargo.toml") "Native engine Cargo manifest"
Invoke-CoverageGateCommand $cargo @("test", "--manifest-path", $nativeManifest) "Avorax Native Engine tests" $root
Write-Host "Avorax real-world coverage gate passed."
