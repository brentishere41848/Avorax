param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$CargoPath = "",
  [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"

function Resolve-ToolPath {
  param(
    [string]$ConfiguredPath,
    [string]$PreferredPath,
    [string]$FallbackName,
    [string]$Description
  )
  if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
    if (-not (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf)) {
      throw "$Description was configured but is not a file: $ConfiguredPath"
    }
    return (Resolve-Path -LiteralPath $ConfiguredPath).Path
  }
  if (-not [string]::IsNullOrWhiteSpace($PreferredPath) -and (Test-Path -LiteralPath $PreferredPath -PathType Leaf)) {
    return (Resolve-Path -LiteralPath $PreferredPath).Path
  }
  return $FallbackName
}

function Get-BoundedText {
  param([AllowNull()][object]$Value, [int]$MaxChars = 4096)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  $text = $text -replace "[`0-\x1F\x7F]+", " "
  if ($text.Length -le $MaxChars) { return $text }
  return $text.Substring(0, [Math]::Max(0, $MaxChars - 3)) + "..."
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$cargo = Resolve-ToolPath $CargoPath "C:\Users\Brent\.cargo\bin\cargo.exe" "cargo" "Cargo"
$manifest = Join-Path $repo "core\zentor_local_core\Cargo.toml"
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
  throw "Local-core manifest is missing: $manifest"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-safe-eicar-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$fixture = Join-Path $tempRoot "safe-eicar.com"
$inputJson = Join-Path $tempRoot "scan-command.json"
$previousPath = $env:PATH
$process = $null

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  Set-Content -LiteralPath $fixture -Value "ZENTOR-SAFE-EICAR-SIMULATOR-FILE" -NoNewline -Encoding ASCII

  $command = @{
    command = "scan_file"
    path = $fixture
    action_mode = "detectOnly"
    scan_kind = "custom"
  } | ConvertTo-Json -Compress
  [System.IO.File]::WriteAllText(
    $inputJson,
    $command + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $pathAdditions = @(
    "C:\Program Files\Git\cmd",
    "C:\Users\Brent\.cargo\bin"
  ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
  if ($pathAdditions.Count -gt 0) {
    $env:PATH = (($pathAdditions + @($env:PATH)) -join [System.IO.Path]::PathSeparator)
  }

  $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = "cmd.exe"
  $startInfo.WorkingDirectory = $repo
  $startInfo.Arguments = "/d /c `"type `"$inputJson`" | `"$cargo`" run --quiet --manifest-path `"$manifest`"`""
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true

  $process = [System.Diagnostics.Process]::Start($startInfo)

  if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    try {
      $process.Kill($true)
    } catch {
      throw "Safe EICAR smoke test timed out after ${TimeoutSeconds}s and failed to stop local-core: $(Get-BoundedText $_.Exception.Message)"
    }
    throw "Safe EICAR smoke test timed out after ${TimeoutSeconds}s."
  }

  $stdout = $process.StandardOutput.ReadToEnd()
  $stderr = $process.StandardError.ReadToEnd()
  if ($process.ExitCode -ne 0) {
    throw "local-core exited with $($process.ExitCode): $(Get-BoundedText $stderr)"
  }

  $jsonResponses = @()
  foreach ($line in ($stdout -split "`r?`n")) {
    $trimmed = $line.Trim()
    if ($trimmed.Length -eq 0) { continue }
    try {
      $jsonResponses += $trimmed | ConvertFrom-Json -ErrorAction Stop
    } catch {
      throw "local-core emitted non-JSON stdout during smoke test: $(Get-BoundedText $trimmed)"
    }
  }
  if ($jsonResponses.Count -eq 0) {
    throw "local-core produced no JSON response. stderr: $(Get-BoundedText $stderr)"
  }

  $body = $jsonResponses[-1]
  $threats = @($body.threats)
  $confirmedThreat = $threats | Where-Object {
    $_.confidence -eq "confirmed" -or $_.reason_summary -like "*safe simulator*" -or $_.reason_summary -like "*ZENTOR-SAFE*"
  } | Select-Object -First 1
  if ($body.status -ne "threatsFound") {
    throw "safe EICAR smoke scan did not return a threat status: $(Get-BoundedText ($body | ConvertTo-Json -Compress))"
  }
  if ($null -eq $confirmedThreat) {
    throw "safe EICAR smoke scan did not include a confirmed test threat: $(Get-BoundedText ($body | ConvertTo-Json -Compress))"
  }

  Write-Host "Avorax safe EICAR smoke test passed."
  Write-Host "Fixture: $fixture"
  Write-Host "Status: $($body.status)"
  Write-Host "Threats: $($threats.Count)"
  Write-Host "Action mode: detectOnly"
} finally {
  $env:PATH = $previousPath
  if ($null -ne $process -and -not $process.HasExited) {
    $process.Kill($true)
  }
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
