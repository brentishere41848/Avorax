param(
  [string]$OutputPath = $(Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "dist\windows-driver-validation\driver_logs.txt")
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
. (Join-Path $RepoRoot "tools\windows\avorax-system32-tools.ps1")

function Assert-AvoraxRepoChildPath([string]$Path, [string]$Base, [string]$DisplayName) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$DisplayName must resolve to a child path inside the Avorax repository root, not the repository root itself."
  }
  Assert-AvoraxPathUnder $pathFull $Base $DisplayName
}

Assert-AvoraxNoReparsePath $OutputPath "driver log output"
Assert-AvoraxPathUnder $OutputPath $RepoRoot "driver log output"
Assert-AvoraxRepoChildPath $OutputPath $RepoRoot "driver log output"
$OutputDir = New-AvoraxRegularDirectory (Split-Path $OutputPath) "driver log output directory" $RepoRoot

function Format-AvoraxDriverLogText([object]$Value) {
  $text = ($Value | Out-String).TrimEnd()
  if ($text.Length -le 32768) { return $text }
  return $text.Substring(0, 32768) + [Environment]::NewLine + "...[truncated]"
}

function Invoke-AvoraxDriverLogCommand([string]$Title, [string]$Tool, [string[]]$Arguments = @()) {
  $diagnostic = Invoke-AvoraxCommandDiagnostic $Tool $Arguments $Title 32768
  @(
    "=== $Title ==="
    "Tool: $Tool"
    "ExitCode: $($diagnostic.exit_code)"
    $diagnostic.output
  ) -join [Environment]::NewLine
}

$fltmc = Get-AvoraxSystem32Tool "fltmc.exe"
$sc = Get-AvoraxSystem32Tool "sc.exe"

$sections = @(
  "Avorax driver log collection"
  "TimestampUtc: $((Get-Date).ToUniversalTime().ToString("o"))"
  "OutputPath: $OutputPath"
  "OutputDir: $OutputDir"
  (Invoke-AvoraxDriverLogCommand "fltmc filters" $fltmc @("filters"))
  (Invoke-AvoraxDriverLogCommand "ZentorAvFilter service" $sc @("query", "ZentorAvFilter"))
)

try {
  $events = Get-WinEvent -LogName System -MaxEvents 100 |
    Where-Object { $_.ProviderName -match "Service Control Manager|FilterManager|Avorax" } |
    Format-List TimeCreated,ProviderName,Id,LevelDisplayName,Message
  $sections += @(
    "=== Recent System Events ==="
    (Format-AvoraxDriverLogText $events)
  )
} catch {
  $sections += @(
    "=== Recent System Events ==="
    "ERROR: $(Format-AvoraxDriverLogText $_.Exception.Message)"
  )
}

Write-AvoraxTextFileAtomic $OutputPath (($sections -join ([Environment]::NewLine + [Environment]::NewLine)) + [Environment]::NewLine) "driver log output" $RepoRoot

Write-Host "Collected driver logs: $OutputPath"
