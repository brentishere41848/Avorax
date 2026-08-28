param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

function Get-BoundedText {
  param([AllowNull()][object]$Value, [int]$MaxChars = 4096)
  if ($null -eq $Value) { return "" }
  $text = ([string]$Value) -replace "[`0-\x1F\x7F]+", " "
  if ($text.Length -le $MaxChars) { return $text }
  return $text.Substring(0, [Math]::Max(0, $MaxChars - 3)) + "..."
}

function Restore-EnvVar {
  param([string]$Name, [AllowNull()][object]$Value)
  if ($null -eq $Value) {
    if (Test-Path -Path "Env:\$Name") {
      Remove-Item -Path "Env:\$Name" -ErrorAction Stop
    }
    return
  }
  Set-Item -Path "Env:\$Name" -Value $Value -ErrorAction Stop
}

function Resolve-LocalCoreBinary {
  param([string]$Repo, [string]$ConfiguredPath)
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Repo "target\release\zentor_local_core.exe"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release local-core binary is missing: $candidate. Run cargo build --release --manifest-path core\zentor_local_core\Cargo.toml first."
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  if ([System.IO.Path]::GetFileName($resolved) -ne "zentor_local_core.exe") {
    throw "Release trust-mutation binding smoke expects zentor_local_core.exe, got: $resolved"
  }
  return $resolved
}

function Invoke-LocalCoreBinaryJson {
  param(
    [hashtable]$Command,
    [string]$Repo,
    [string]$Binary,
    [int]$Timeout
  )

  $process = $null
  try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Binary
    $startInfo.WorkingDirectory = $Repo
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $requestJson = $Command | ConvertTo-Json -Compress -Depth 8
    $previousInputEncoding = [Console]::InputEncoding
    try {
      [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
      $process = [System.Diagnostics.Process]::Start($startInfo)
      $stdoutTask = $process.StandardOutput.ReadToEndAsync()
      $stderrTask = $process.StandardError.ReadToEndAsync()
      $process.StandardInput.WriteLine($requestJson)
      $process.StandardInput.Close()
    } finally {
      [Console]::InputEncoding = $previousInputEncoding
    }

    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill()
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "release trust-mutation binding smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release trust-mutation binding smoke timed out after ${Timeout}s."
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
      throw "release local-core exited with $($process.ExitCode): $(Get-BoundedText $stderr)"
    }
    $responses = @()
    foreach ($line in ($stdout -split "`r?`n")) {
      $trimmed = $line.Trim()
      if ($trimmed.Length -eq 0) { continue }
      try {
        $body = $trimmed | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "release local-core emitted non-JSON stdout during trust-mutation binding smoke: $(Get-BoundedText $trimmed)"
      }
      if ($body.type -eq "scan_progress" -or $body.type -eq "progress") { continue }
      $responses += $body
    }
    if ($responses.Count -ne 1) {
      throw "release local-core produced $($responses.Count) action responses; expected exactly one. stderr: $(Get-BoundedText $stderr)"
    }
    return $responses[0]
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill()
      if (-not $process.WaitForExit(5000)) {
        throw "release trust-mutation binding smoke killed local-core but could not reap it within 5000 ms."
      }
    }
  }
}

function Get-FileSha256Hex {
  param([string]$Path)
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Assert-Rejected {
  param(
    [AllowNull()][object]$Response,
    [string]$ExpectedError,
    [string]$Label
  )
  if ($null -eq $Response -or $Response.ok -ne $false) {
    throw "$Label did not fail closed: $(Get-BoundedText ($Response | ConvertTo-Json -Compress -Depth 8))"
  }
  if ([string]$Response.error -notlike "*$ExpectedError*") {
    throw "$Label did not report '$ExpectedError': $(Get-BoundedText ($Response | ConvertTo-Json -Compress -Depth 8))"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-trust-binding-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$changedFixture = Join-Path $tempRoot "changed-review.bin"
$matchingFixture = Join-Path $tempRoot "matching-review.bin"
$labelsFile = Join-Path $dataRoot "training_labels.jsonl"

$previousDataDir = $env:AVORAX_DATA_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  [System.IO.File]::WriteAllText($allowlistFile, "[]`r`n", [System.Text.UTF8Encoding]::new($false))
  $initialAllowlistHash = Get-FileSha256Hex $allowlistFile
  [System.IO.File]::WriteAllBytes(
    $changedFixture,
    [System.Text.Encoding]::ASCII.GetBytes("harmless scanned trust-mutation bytes")
  )
  $changedExpectedSha256 = Get-FileSha256Hex $changedFixture
  [System.IO.File]::WriteAllBytes(
    $changedFixture,
    [System.Text.Encoding]::ASCII.GetBytes("harmless replacement trust-mutation bytes")
  )
  [System.IO.File]::WriteAllBytes(
    $matchingFixture,
    [System.Text.Encoding]::ASCII.GetBytes("harmless unchanged trust-mutation bytes")
  )
  $matchingSha256 = Get-FileSha256Hex $matchingFixture

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot

  $changedAllowlist = Invoke-LocalCoreBinaryJson @{
    command = "add_allowlist_entry"
    path = $changedFixture
    sha256 = $changedExpectedSha256
    confirmed = $true
  } $repo $binary $TimeoutSeconds
  Assert-Rejected $changedAllowlist "changed after its scan verdict" "Changed allowlist source"

  $changedLabel = Invoke-LocalCoreBinaryJson @{
    command = "label_detection"
    path = $changedFixture
    sha256 = $changedExpectedSha256
    user_label = "falsePositive"
    previous_verdict = "review"
    confirmed = $true
  } $repo $binary $TimeoutSeconds
  Assert-Rejected $changedLabel "changed after its scan verdict" "Changed feedback source"

  $unconfirmedAllowlist = Invoke-LocalCoreBinaryJson @{
    command = "add_allowlist_entry"
    path = $matchingFixture
    sha256 = $matchingSha256
  } $repo $binary $TimeoutSeconds
  Assert-Rejected $unconfirmedAllowlist "requires explicit confirmation" "Unconfirmed allowlist addition"

  $unconfirmedLabel = Invoke-LocalCoreBinaryJson @{
    command = "label_detection"
    path = $matchingFixture
    sha256 = $matchingSha256
    user_label = "falsePositive"
    previous_verdict = "review"
  } $repo $binary $TimeoutSeconds
  Assert-Rejected $unconfirmedLabel "requires explicit confirmation" "Unconfirmed detection feedback"

  if ((Get-FileSha256Hex $allowlistFile) -ne $initialAllowlistHash) {
    throw "Rejected trust mutations changed the isolated allowlist store."
  }
  if (Test-Path -LiteralPath $labelsFile) {
    throw "Rejected trust mutations created an isolated training-label store."
  }

  $allowlist = Invoke-LocalCoreBinaryJson @{
    command = "add_allowlist_entry"
    path = $matchingFixture
    sha256 = $matchingSha256
    confirmed = $true
  } $repo $binary $TimeoutSeconds
  if ($allowlist.ok -ne $true -or
      $allowlist.entry.active -ne $true -or
      [string]$allowlist.entry.path -ne $matchingFixture -or
      [string]$allowlist.entry.sha256 -ne "sha256:$matchingSha256" -or
      [string]::IsNullOrWhiteSpace([string]$allowlist.entry.id)) {
    throw "Matching hash-bound allowlist addition lacked exact success evidence: $(Get-BoundedText ($allowlist | ConvertTo-Json -Compress -Depth 8))"
  }

  $label = Invoke-LocalCoreBinaryJson @{
    command = "label_detection"
    path = $matchingFixture
    sha256 = $matchingSha256
    user_label = "falsePositive"
    previous_verdict = "review"
    confirmed = $true
  } $repo $binary $TimeoutSeconds
  if ($label.ok -ne $true -or
      [string]$label.path -ne $labelsFile -or
      [string]$label.evidence.store_path -ne $labelsFile -or
      [string]$label.evidence.file_sha256 -ne $matchingSha256 -or
      [string]$label.evidence.user_label -ne "falsePositive" -or
      [string]$label.evidence.previous_verdict -ne "review" -or
      [string]::IsNullOrWhiteSpace([string]$label.evidence.label_id)) {
    throw "Matching hash-bound feedback lacked exact persisted success evidence: $(Get-BoundedText ($label | ConvertTo-Json -Compress -Depth 8))"
  }

  $persistedAllowlist = Get-Content -LiteralPath $allowlistFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
  if (@($persistedAllowlist).Count -ne 1 -or
      [string]$persistedAllowlist[0].id -ne [string]$allowlist.entry.id -or
      [string]$persistedAllowlist[0].sha256 -ne "sha256:$matchingSha256") {
    throw "Hash-bound allowlist response did not match isolated persisted state."
  }
  $persistedLabels = @(Get-Content -LiteralPath $labelsFile -ErrorAction Stop | ForEach-Object {
    $_ | ConvertFrom-Json -ErrorAction Stop
  })
  if ($persistedLabels.Count -ne 1 -or
      [string]$persistedLabels[0].label_id -ne [string]$label.evidence.label_id -or
      [string]$persistedLabels[0].file_sha256 -ne $matchingSha256 -or
      [string]$persistedLabels[0].user_label -ne "falsePositive") {
    throw "Hash-bound feedback response did not match isolated persisted state."
  }
  if ((Get-FileSha256Hex $changedFixture) -eq $changedExpectedSha256) {
    throw "Changed benign fixture unexpectedly reverted to the scanned hash."
  }
  if ((Get-FileSha256Hex $matchingFixture) -ne $matchingSha256) {
    throw "Trust-mutation smoke modified the matching benign fixture."
  }
  if (Test-Path -LiteralPath $quarantineRoot) {
    throw "Trust-mutation smoke unexpectedly created quarantine state."
  }

  Write-Host "Avorax release local-core trust-mutation hash-binding smoke passed."
  Write-Host "Binary: $binary"
  Write-Host "Changed-source rejection: allowlist and feedback"
  Write-Host "Server confirmation rejection: allowlist and feedback"
  Write-Host "Persisted matching SHA-256: $matchingSha256"
  Write-Host "Fixture execution: false"
  Write-Host "Live malware/EICAR/Defender changes: false"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "ZENTOR_ALLOWLIST_FILE" $previousAllowlistFile
  Restore-EnvVar "AVORAX_QUARANTINE_DIR" $previousQuarantineDir
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
