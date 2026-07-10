param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [ValidateSet("List", "Add", "Remove")]
  [string]$Action = "List",
  [string]$TargetPath = "",
  [string]$AllowlistId = "",
  [switch]$ConfirmAction,
  [string]$LocalCorePath = "",
  [string]$ReportPath = "",
  [string]$AllowlistFile = "",
  [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

function Get-BoundedText {
  param([AllowNull()][object]$Value, [int]$MaxChars = 4096)
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  $text = $text -replace "[`0-\x1F\x7F]+", " "
  if ($text.Length -le $MaxChars) { return $text }
  return $text.Substring(0, [Math]::Max(0, $MaxChars - 3)) + "..."
}

function Restore-EnvVar {
  param(
    [string]$Name,
    [AllowNull()][object]$Value
  )
  if ($null -eq $Value) {
    if (Test-Path -Path "Env:\$Name") {
      Remove-Item -Path "Env:\$Name" -ErrorAction Stop
    }
  } else {
    Set-Item -Path "Env:\$Name" -Value $Value -ErrorAction Stop
  }
}

function Assert-NotReparsePath {
  param([string]$PathValue, [string]$Description)
  $item = Get-Item -LiteralPath $PathValue -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $PathValue"
  }
}

function Resolve-RepoChildPath {
  param([string]$Repo, [string]$PathValue, [string]$Description)
  $rootFull = [System.IO.Path]::GetFullPath($Repo).TrimEnd('\', '/')
  $candidate = $PathValue
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $rootFull $candidate
  }
  $pathFull = [System.IO.Path]::GetFullPath($candidate)
  $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must be inside the repository: $pathFull"
  }
  if ($pathFull.TrimEnd('\', '/').Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must be a child file, not the repository root."
  }
  return $pathFull
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
    throw "Avorax allowlist expects zentor_local_core.exe, got: $resolved"
  }
  Assert-NotReparsePath $resolved "local-core binary"
  return $resolved
}

function Resolve-TempOrRepoChildFile {
  param([string]$Repo, [string]$PathValue, [string]$Description)
  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    $PathValue = ".workflow\ultracode\avorax-hardening\runtime\allowlist\allowlist.json"
  }
  if ($PathValue.Contains([char]0)) {
    throw "$Description contains a NUL byte."
  }
  if ($PathValue.Length -gt 4096) {
    throw "$Description exceeds 4096 characters."
  }
  if ($PathValue -replace '/', '\' -match '(^|\\)\.\.(\\|$)') {
    throw "$Description must not contain parent traversal."
  }
  $repoFull = [System.IO.Path]::GetFullPath($Repo).TrimEnd('\', '/')
  $candidate = $PathValue
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $repoFull $candidate
  }
  $pathFull = [System.IO.Path]::GetFullPath($candidate)
  $repoPrefix = $repoFull + [System.IO.Path]::DirectorySeparatorChar
  $tempPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  if ((-not $pathFull.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) -and
      (-not $pathFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase))) {
    throw "$Description must be inside the repository or the current user's temp directory: $pathFull"
  }
  if ($pathFull.TrimEnd('\', '/').Equals($repoFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must be a child file, not the repository root."
  }
  if ($pathFull.TrimEnd('\', '/').Equals($tempPrefix.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must be a child file, not the temp root."
  }

  $directory = Split-Path -Parent $pathFull
  if ([string]::IsNullOrWhiteSpace($directory)) {
    throw "$Description must have a parent directory."
  }
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
  Assert-NotReparsePath $directory "$Description directory"
  if (Test-Path -LiteralPath $pathFull) {
    if (-not (Test-Path -LiteralPath $pathFull -PathType Leaf)) {
      throw "$Description is not a regular file: $pathFull"
    }
    Assert-NotReparsePath $pathFull $Description
  } else {
    [System.IO.File]::WriteAllText($pathFull, "[]`r`n", [System.Text.UTF8Encoding]::new($false))
  }
  return $pathFull
}

function Resolve-TargetFile {
  param([string]$PathValue)
  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    throw "Add requires -TargetPath."
  }
  if ($PathValue.Contains([char]0)) {
    throw "TargetPath contains a NUL byte."
  }
  if ($PathValue.Length -gt 4096) {
    throw "TargetPath exceeds 4096 characters."
  }
  if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
    throw "TargetPath must be an existing file: $PathValue"
  }
  $resolved = (Resolve-Path -LiteralPath $PathValue).Path
  Assert-NotReparsePath $resolved "allowlist target file"
  return $resolved
}

function Assert-AllowlistId {
  param([string]$Id)
  if ([string]::IsNullOrWhiteSpace($Id)) {
    throw "Remove requires -AllowlistId."
  }
  if ($Id.Trim() -ne $Id) {
    throw "AllowlistId must not contain leading or trailing whitespace."
  }
  if ($Id.Contains([char]0)) {
    throw "AllowlistId contains a NUL byte."
  }
  if ($Id.Length -gt 128) {
    throw "AllowlistId exceeds maximum length."
  }
  if ($Id -notmatch '^[A-Za-z0-9_-]+$') {
    throw "AllowlistId may contain only ASCII letters, digits, hyphen, and underscore."
  }
}

function Invoke-LocalCoreJson {
  param(
    [object]$Command,
    [string]$Repo,
    [string]$Binary,
    [int]$Timeout
  )

  $json = $Command | ConvertTo-Json -Compress
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

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.WriteLine($json)
    $process.StandardInput.Close()

    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "Avorax allowlist command timed out after ${Timeout}s and failed to stop local-core: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "Avorax allowlist command timed out after ${Timeout}s."
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
      throw "local-core exited with $($process.ExitCode): $(Get-BoundedText $stderr)"
    }

    $responses = @()
    foreach ($line in ($stdout -split "`r?`n")) {
      $trimmed = $line.Trim()
      if ($trimmed.Length -eq 0) { continue }
      try {
        $body = $trimmed | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "local-core emitted non-JSON stdout during Avorax allowlist command: $(Get-BoundedText $trimmed)"
      }
      if ($body.type -eq "scan_progress" -or $body.type -eq "progress") {
        continue
      }
      $responses += $body
    }
    if ($responses.Count -eq 0) {
      throw "local-core produced no JSON allowlist response. stderr: $(Get-BoundedText $stderr)"
    }
    $response = $responses[-1]
    if (($response.PSObject.Properties.Name -contains "ok") -and $response.ok -eq $false) {
      throw "local-core rejected Avorax allowlist command: $(Get-BoundedText $response.error)"
    }
    return [ordered]@{
      response = $response
      stderr = Get-BoundedText $stderr
    }
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function Write-JsonReportAtomic {
  param([string]$PathValue, [object]$Body)
  $directory = Split-Path -Parent $PathValue
  if (-not [string]::IsNullOrWhiteSpace($directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
  }
  $tempPath = Join-Path $directory (".tmp-" + [System.Guid]::NewGuid().ToString("N") + ".json")
  $backupPath = Join-Path $directory (".bak-" + [System.Guid]::NewGuid().ToString("N") + ".json")
  $json = $Body | ConvertTo-Json -Depth 100
  [System.IO.File]::WriteAllText($tempPath, $json + "`r`n", [System.Text.UTF8Encoding]::new($false))
  if (Test-Path -LiteralPath $PathValue -PathType Leaf) {
    [System.IO.File]::Replace($tempPath, $PathValue, $backupPath, $true)
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
      Remove-Item -LiteralPath $backupPath -Force
    }
  } else {
    [System.IO.File]::Move($tempPath, $PathValue)
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath
$allowlistFileFull = Resolve-TempOrRepoChildFile $repo $AllowlistFile "AllowlistFile"

if ($Action -eq "List") {
  if (-not [string]::IsNullOrWhiteSpace($TargetPath)) {
    throw "List action does not accept -TargetPath."
  }
  if (-not [string]::IsNullOrWhiteSpace($AllowlistId)) {
    throw "List action does not accept -AllowlistId."
  }
} elseif ($Action -eq "Add") {
  $targetFull = Resolve-TargetFile $TargetPath
  if (-not [string]::IsNullOrWhiteSpace($AllowlistId)) {
    throw "Add action does not accept -AllowlistId."
  }
  if (-not $ConfirmAction) {
    throw "Add requires -ConfirmAction. Avorax will not trust files without explicit confirmation."
  }
} elseif ($Action -eq "Remove") {
  if (-not [string]::IsNullOrWhiteSpace($TargetPath)) {
    throw "Remove action does not accept -TargetPath."
  }
  Assert-AllowlistId $AllowlistId
  if (-not $ConfirmAction) {
    throw "Remove requires -ConfirmAction. Avorax will not change allowlist entries without explicit confirmation."
  }
}

$command = [ordered]@{ command = "list_allowlist" }
if ($Action -eq "Add") {
  $command = [ordered]@{
    command = "add_allowlist_entry"
    path = $targetFull
  }
} elseif ($Action -eq "Remove") {
  $command = [ordered]@{
    command = "remove_allowlist_entry"
    allowlist_id = $AllowlistId
    confirmed = $true
  }
}

$reportFull = ""
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
  $reportFull = Resolve-RepoChildPath $repo $ReportPath "Avorax allowlist report"
}

$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE

try {
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFileFull
  $result = Invoke-LocalCoreJson $command $repo $binary $TimeoutSeconds
  $response = $result.response
  $entries = if ($Action -eq "List") { @($response.entries) } else { @($response.entry) }
  $activeEntries = @($entries | Where-Object { $_.active -eq $true })

  $summary = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    tool = "avorax-allowlist"
    repository = $repo
    local_core_path = $binary
    action = $Action
    allowlist_file = $allowlistFileFull
    target_path = if ($Action -eq "Add") { $targetFull } else { "" }
    allowlist_id = if ($Action -eq "Remove") { $AllowlistId } else { "" }
    explicit_confirmation = [bool]$ConfirmAction
    entries_count = $entries.Count
    active_entries_count = $activeEntries.Count
    safety = [ordered]@{
      live_malware_used = $false
      standard_eicar_string_written = $false
      defender_exclusion_required = $false
      machine_wide_changes = $false
      service_installation_attempted = $false
      pre_execution_blocking_claimed = $false
      broad_root_allowlist_allowed = $false
      folder_allowlist_supported_by_wrapper = $false
      hash_allowlist_supported_by_wrapper = $false
    }
    raw_response = $response
  }

  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-JsonReportAtomic $reportFull $summary
  }

  Write-Host "Avorax allowlist command completed."
  Write-Host "Action: $Action"
  Write-Host "Entries: $($summary.entries_count)"
  Write-Host "Active entries: $($summary.active_entries_count)"
  if ($Action -eq "Add") {
    Write-Host "Target: $targetFull"
  }
  if ($Action -eq "Remove") {
    Write-Host "Allowlist id: $AllowlistId"
  }
  if (-not [string]::IsNullOrWhiteSpace($reportFull)) {
    Write-Host "Report: $reportFull"
  }
} finally {
  Restore-EnvVar "ZENTOR_ALLOWLIST_FILE" $previousAllowlistFile
}
