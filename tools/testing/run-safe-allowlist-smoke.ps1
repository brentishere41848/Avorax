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

function Invoke-LocalCoreJson {
  param(
    [hashtable]$Command,
    [string]$InputJsonPath,
    [string]$Repo,
    [string]$Cargo,
    [string]$Manifest,
    [int]$Timeout
  )

  $json = $Command | ConvertTo-Json -Compress
  [System.IO.File]::WriteAllText(
    $InputJsonPath,
    $json + "`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $process = $null
  try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "cmd.exe"
    $startInfo.WorkingDirectory = $Repo
    $startInfo.Arguments = "/d /c `"type `"$InputJsonPath`" | `"$Cargo`" run --quiet --manifest-path `"$Manifest`"`""
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
      } catch {
        throw "local-core timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "local-core timed out after ${Timeout}s."
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
      if ($trimmed.StartsWith("{`"type`":`"scan_progress`"")) { continue }
      try {
        $jsonResponses += $trimmed | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "local-core emitted non-JSON stdout during safe allowlist smoke test: $(Get-BoundedText $trimmed)"
      }
    }
    if ($jsonResponses.Count -eq 0) {
      throw "local-core produced no JSON response. stderr: $(Get-BoundedText $stderr)"
    }
    return $jsonResponses[-1]
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$cargo = Resolve-ToolPath $CargoPath "C:\Users\Brent\.cargo\bin\cargo.exe" "cargo" "Cargo"
$manifest = Join-Path $repo "core\zentor_local_core\Cargo.toml"
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
  throw "Local-core manifest is missing: $manifest"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-safe-allowlist-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$fixture = Join-Path $tempRoot "safe-eicar-allowlisted.com"
$inputJson = Join-Path $tempRoot "local-core-command.json"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$previousPath = $env:PATH
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  Set-Content -LiteralPath $fixture -Value "ZENTOR-SAFE-EICAR-SIMULATOR-FILE" -NoNewline -Encoding ASCII
  [System.IO.File]::WriteAllText(
    $allowlistFile,
    "[]",
    [System.Text.UTF8Encoding]::new($false)
  )

  $pathAdditions = @(
    "C:\Program Files\Git\cmd",
    "C:\Users\Brent\.cargo\bin"
  ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
  if ($pathAdditions.Count -gt 0) {
    $env:PATH = (($pathAdditions + @($env:PATH)) -join [System.IO.Path]::PathSeparator)
  }
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot

  $entry = Invoke-LocalCoreJson @{
    command = "add_allowlist_entry"
    path = $fixture
  } $inputJson $repo $cargo $manifest $TimeoutSeconds
  if ($entry.ok -ne $true -or [string]::IsNullOrWhiteSpace([string]$entry.entry.id)) {
    throw "safe allowlist smoke could not add the simulator allowlist entry: $(Get-BoundedText ($entry | ConvertTo-Json -Compress))"
  }
  if ([string]::IsNullOrWhiteSpace([string]$entry.entry.sha256)) {
    throw "safe allowlist smoke entry did not include hash evidence: $(Get-BoundedText ($entry | ConvertTo-Json -Compress))"
  }

  $scan = Invoke-LocalCoreJson @{
    command = "scan_file"
    path = $fixture
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "custom"
  } $inputJson $repo $cargo $manifest $TimeoutSeconds

  $threats = @($scan.threats)
  $allowlistedThreat = $threats | Where-Object {
    $_.status -eq "allowlisted" -and
    ($_.confidence -eq "confirmed" -or $_.reason_summary -like "*safe simulator*" -or $_.reason_summary -like "*ZENTOR-SAFE*")
  } | Select-Object -First 1
  if ($scan.status -ne "threatsFound") {
    throw "safe allowlist smoke scan did not surface the allowlisted simulator detection: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($null -eq $allowlistedThreat) {
    throw "safe allowlist smoke scan did not mark the simulator detection as allowlisted: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if ($scan.quarantined_files -ne 0) {
    throw "safe allowlist smoke quarantined an allowlisted simulator: $(Get-BoundedText ($scan | ConvertTo-Json -Compress))"
  }
  if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    throw "safe allowlist smoke moved or removed the allowlisted simulator fixture"
  }
  if (Test-Path -LiteralPath $quarantineRoot) {
    $payload = Get-ChildItem -LiteralPath $quarantineRoot -Recurse -File -ErrorAction Stop |
      Where-Object { $_.Name.EndsWith(".avoraxq", [System.StringComparison]::OrdinalIgnoreCase) } |
      Select-Object -First 1
    if ($null -ne $payload) {
      throw "safe allowlist smoke created a quarantine payload despite allowlist: $($payload.FullName)"
    }
  }

  Write-Host "Avorax safe allowlist smoke test passed."
  Write-Host "Fixture: $fixture"
  Write-Host "Status: $($scan.status)"
  Write-Host "Threats: $($threats.Count)"
  Write-Host "Threat status: $($allowlistedThreat.status)"
  Write-Host "Quarantined files: $($scan.quarantined_files)"
} finally {
  $env:PATH = $previousPath
  if ($null -eq $previousAllowlistFile) {
    if (Test-Path Env:\ZENTOR_ALLOWLIST_FILE) {
      Remove-Item Env:\ZENTOR_ALLOWLIST_FILE -ErrorAction Stop
    }
  } else {
    $env:ZENTOR_ALLOWLIST_FILE = $previousAllowlistFile
  }
  if ($null -eq $previousQuarantineDir) {
    if (Test-Path Env:\AVORAX_QUARANTINE_DIR) {
      Remove-Item Env:\AVORAX_QUARANTINE_DIR -ErrorAction Stop
    }
  } else {
    $env:AVORAX_QUARANTINE_DIR = $previousQuarantineDir
  }
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
