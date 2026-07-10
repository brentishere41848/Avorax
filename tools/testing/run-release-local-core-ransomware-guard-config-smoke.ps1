param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
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

function Resolve-LocalCoreBinary {
  param(
    [string]$Repo,
    [string]$ConfiguredPath
  )
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Repo "target\release\zentor_local_core.exe"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release local-core binary is missing: $candidate. Run cargo build --release --manifest-path core\zentor_local_core\Cargo.toml first."
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  if ([System.IO.Path]::GetFileName($resolved) -ne "zentor_local_core.exe") {
    throw "Release local-core ransomware guard config smoke expects zentor_local_core.exe, got: $resolved"
  }
  return $resolved
}

function Invoke-LocalCoreBinaryJson {
  param(
    [hashtable]$Command,
    [string]$InputJsonPath,
    [string]$Repo,
    [string]$Binary,
    [int]$Timeout
  )

  $json = $Command | ConvertTo-Json -Compress -Depth 16
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
    $startInfo.Arguments = "/d /c `"type `"$InputJsonPath`" | `"$Binary`"`""
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    if (-not $process.WaitForExit($Timeout * 1000)) {
      try {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      } catch {
        throw "release local-core ransomware guard config smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core ransomware guard config smoke timed out after ${Timeout}s."
    }

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
      throw "release local-core exited with $($process.ExitCode): $(Get-BoundedText $stderr)"
    }

    $jsonResponses = @()
    foreach ($line in ($stdout -split "`r?`n")) {
      $trimmed = $line.Trim()
      if ($trimmed.Length -eq 0) { continue }
      try {
        $body = $trimmed | ConvertFrom-Json -ErrorAction Stop
      } catch {
        throw "release local-core emitted non-JSON stdout during ransomware guard config smoke: $(Get-BoundedText $trimmed)"
      }
      if ($body.type -eq "scan_progress" -or $body.type -eq "progress") {
        continue
      }
      $jsonResponses += $body
    }
    if ($jsonResponses.Count -eq 0) {
      throw "release local-core produced no JSON response. stderr: $(Get-BoundedText $stderr)"
    }
    return $jsonResponses[-1]
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function Convert-ToConfigPathText {
  param([string]$Path)
  return $Path.Trim().Replace("\", "/")
}

function Assert-SequenceEquals {
  param(
    [object[]]$Actual,
    [string[]]$Expected,
    [string]$Label
  )
  if (@($Actual).Count -ne @($Expected).Count) {
    throw "$Label count mismatch. Expected $(@($Expected).Count), got $(@($Actual).Count): $(Get-BoundedText ($Actual | ConvertTo-Json -Compress -Depth 8))"
  }
  for ($index = 0; $index -lt @($Expected).Count; $index++) {
    if ([string]$Actual[$index] -ne $Expected[$index]) {
      throw "$Label mismatch at index ${index}. Expected '$($Expected[$index])', got '$($Actual[$index])'."
    }
  }
}

function New-ModifiedPathSet {
  param(
    [string]$Root,
    [string]$Prefix,
    [int]$Count
  )
  $paths = @()
  for ($index = 0; $index -lt $Count; $index++) {
    $paths += "$Root/$Prefix-$index.docx"
  }
  return $paths
}

function Assert-Limitation {
  param(
    [object]$Response,
    [string]$Expected
  )
  if (-not (@($Response.limitations) | Where-Object { $_ -eq $Expected })) {
    throw "release local-core ransomware guard activity response missing limitation '$Expected': $(Get-BoundedText ($Response | ConvertTo-Json -Compress -Depth 8))"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-ransomware-guard-config-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$configPath = Join-Path $tempRoot "config\ransomware_guard.json"
$documentsRoot = Join-Path $tempRoot "Documents"
$picturesRoot = Join-Path $tempRoot "Pictures"
$downloadsRoot = Join-Path $tempRoot "Downloads"
$backupRoot = Join-Path $tempRoot "Backup"
$backupExe = Join-Path $backupRoot "backup-sync.exe"
$inputJson = Join-Path $tempRoot "local-core-command.json"

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR
$previousRansomwareConfig = $env:AVORAX_RANSOMWARE_GUARD_CONFIG

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $documentsRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $picturesRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $downloadsRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
  [System.IO.File]::WriteAllText(
    $backupExe,
    "harmless backup/sync process path fixture`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
  $env:AVORAX_RANSOMWARE_GUARD_CONFIG = $configPath

  $default = Invoke-LocalCoreBinaryJson @{
    command = "list_ransomware_guard_config"
  } $inputJson $repo $binary $TimeoutSeconds
  if ($default.ok -ne $true -or $default.config.source -ne "default") {
    throw "release local-core list_ransomware_guard_config did not return a default empty config before persistence: $(Get-BoundedText ($default | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($default.config.protected_roots).Count -ne 0 -or @($default.config.trusted_process_allowlist).Count -ne 0) {
    throw "release local-core default ransomware guard config was not empty: $(Get-BoundedText ($default | ConvertTo-Json -Compress -Depth 8))"
  }

  $configure = Invoke-LocalCoreBinaryJson @{
    command = "configure_ransomware_guard"
    protected_roots = @($documentsRoot, " $documentsRoot ", $picturesRoot)
    trusted_process_allowlist = @($backupExe, "")
  } $inputJson $repo $binary $TimeoutSeconds
  if ($configure.ok -ne $true) {
    throw "release local-core configure_ransomware_guard failed: $(Get-BoundedText ($configure | ConvertTo-Json -Compress -Depth 8))"
  }
  if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "release local-core configure_ransomware_guard did not write the configured isolated config file: $configPath"
  }
  $stagedTempFiles = [System.IO.Directory]::GetFiles((Split-Path -Parent $configPath), "*.tmp-*")
  if ($stagedTempFiles.Count -ne 0) {
    throw "release local-core configure_ransomware_guard left staged temp files beside the active config."
  }

  $expectedDocuments = Convert-ToConfigPathText $documentsRoot
  $expectedPictures = Convert-ToConfigPathText $picturesRoot
  $expectedBackup = Convert-ToConfigPathText $backupExe
  $expectedDownloads = Convert-ToConfigPathText $downloadsRoot
  $badProcess = Convert-ToConfigPathText (Join-Path $tempRoot "Temp\bad.exe")
  $trustedProcessWithSegments = Convert-ToConfigPathText (Join-Path $backupRoot "Tools\..\backup-sync.exe")
  $persisted = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json -ErrorAction Stop
  if ($persisted.source -ne "avorax_local_core") {
    throw "persisted ransomware guard config did not record avorax_local_core source: $(Get-BoundedText ($persisted | ConvertTo-Json -Compress -Depth 8))"
  }
  Assert-SequenceEquals @($persisted.protected_roots) @($expectedDocuments, $expectedPictures) "persisted protected_roots"
  Assert-SequenceEquals @($persisted.trusted_process_allowlist) @($expectedBackup) "persisted trusted_process_allowlist"

  $listed = Invoke-LocalCoreBinaryJson @{
    command = "list_ransomware_guard_config"
  } $inputJson $repo $binary $TimeoutSeconds
  if ($listed.ok -ne $true) {
    throw "release local-core list_ransomware_guard_config failed after persistence: $(Get-BoundedText ($listed | ConvertTo-Json -Compress -Depth 8))"
  }
  Assert-SequenceEquals @($listed.config.protected_roots) @($expectedDocuments, $expectedPictures) "listed protected_roots"
  Assert-SequenceEquals @($listed.config.trusted_process_allowlist) @($expectedBackup) "listed trusted_process_allowlist"

  $goodConfigText = [System.IO.File]::ReadAllText($configPath, [System.Text.UTF8Encoding]::new($false))
  $rejectBroadRoot = Invoke-LocalCoreBinaryJson @{
    command = "configure_ransomware_guard"
    protected_roots = @("C:/")
    trusted_process_allowlist = @()
  } $inputJson $repo $binary $TimeoutSeconds
  if ($rejectBroadRoot.ok -ne $false -or [string]$rejectBroadRoot.error -notlike "*protected root is too broad*") {
    throw "release local-core configure_ransomware_guard did not reject a broad protected root: $(Get-BoundedText ($rejectBroadRoot | ConvertTo-Json -Compress -Depth 8))"
  }
  $afterRejectText = [System.IO.File]::ReadAllText($configPath, [System.Text.UTF8Encoding]::new($false))
  if ($afterRejectText -ne $goodConfigText) {
    throw "release local-core broad-root rejection modified the previously persisted ransomware guard config."
  }

  $protectedActivity = New-ModifiedPathSet $expectedDocuments "protected" 25
  $outsideNoise = New-ModifiedPathSet $expectedDownloads "outside" 25
  $detectedActivity = Invoke-LocalCoreBinaryJson @{
    command = "evaluate_ransomware_activity"
    ransomware_activity = @{
      process_id = 4242
      process_path = $badProcess
      modified_paths = @($protectedActivity + $outsideNoise)
      files_renamed_count = 50
      entropy_change_score = 0.8
      ransom_note_score = 0.0
      backup_tamper_score = 0.0
      time_window_seconds = 60
    }
  } $inputJson $repo $binary $TimeoutSeconds
  if ($detectedActivity.ok -ne $true -or $detectedActivity.detected -ne $true) {
    throw "release local-core evaluate_ransomware_activity did not detect protected mass modification: $(Get-BoundedText ($detectedActivity | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($detectedActivity.config_source -ne "avorax_local_core") {
    throw "release local-core ransomware activity did not use persisted config source: $(Get-BoundedText ($detectedActivity | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($detectedActivity.signal.files_modified_count -ne 25 -or @($detectedActivity.signal.affected_paths).Count -ne 25) {
    throw "release local-core ransomware activity did not count only protected-root paths: $(Get-BoundedText ($detectedActivity.signal | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($detectedActivity.signal.affected_paths) | Where-Object { $_ -like "$expectedDownloads*" }) {
    throw "release local-core ransomware activity included unprotected Downloads paths: $(Get-BoundedText ($detectedActivity.signal | ConvertTo-Json -Compress -Depth 8))"
  }
  if ($detectedActivity.signal.severity -ne "critical" -or $detectedActivity.signal.confidence -ne "medium") {
    throw "release local-core ransomware activity reported unexpected severity/confidence: $(Get-BoundedText ($detectedActivity.signal | ConvertTo-Json -Compress -Depth 8))"
  }
  Assert-Limitation $detectedActivity "caller-supplied-activity-observations-only"
  Assert-Limitation $detectedActivity "post-write-detection-only"
  Assert-Limitation $detectedActivity "no-persistent-service-monitor"
  Assert-Limitation $detectedActivity "no-kernel-pre-execution-blocking"

  $outsideOnly = Invoke-LocalCoreBinaryJson @{
    command = "evaluate_ransomware_activity"
    ransomware_activity = @{
      process_id = 4243
      process_path = $badProcess
      modified_paths = (New-ModifiedPathSet $expectedDownloads "outside-only" 40)
      files_renamed_count = 40
      entropy_change_score = 0.8
      ransom_note_score = 0.0
      backup_tamper_score = 0.0
      time_window_seconds = 60
    }
  } $inputJson $repo $binary $TimeoutSeconds
  if ($outsideOnly.ok -ne $true -or $outsideOnly.detected -ne $false -or $null -ne $outsideOnly.signal) {
    throw "release local-core ransomware activity did not ignore paths outside protected roots: $(Get-BoundedText ($outsideOnly | ConvertTo-Json -Compress -Depth 8))"
  }

  $trustedSuppressed = Invoke-LocalCoreBinaryJson @{
    command = "evaluate_ransomware_activity"
    ransomware_activity = @{
      process_id = 4244
      process_path = $trustedProcessWithSegments
      modified_paths = (New-ModifiedPathSet $expectedDocuments "trusted" 30)
      files_renamed_count = 30
      entropy_change_score = 0.8
      ransom_note_score = 0.0
      backup_tamper_score = 0.0
      time_window_seconds = 60
    }
  } $inputJson $repo $binary $TimeoutSeconds
  if ($trustedSuppressed.ok -ne $true -or $trustedSuppressed.detected -ne $false -or $null -ne $trustedSuppressed.signal) {
    throw "release local-core ransomware activity did not suppress trusted non-critical process activity: $(Get-BoundedText ($trustedSuppressed | ConvertTo-Json -Compress -Depth 8))"
  }

  $criticalOverride = Invoke-LocalCoreBinaryJson @{
    command = "evaluate_ransomware_activity"
    ransomware_activity = @{
      process_id = 4245
      process_path = $trustedProcessWithSegments
      modified_paths = (New-ModifiedPathSet $expectedDocuments "critical" 30)
      files_renamed_count = 30
      entropy_change_score = 0.8
      ransom_note_score = 0.9
      backup_tamper_score = 0.95
      time_window_seconds = 60
    }
  } $inputJson $repo $binary $TimeoutSeconds
  if ($criticalOverride.ok -ne $true -or $criticalOverride.detected -ne $true -or $criticalOverride.signal.confidence -ne "high") {
    throw "release local-core ransomware activity did not let critical ransom-note/backup-tamper activity override trusted process suppression: $(Get-BoundedText ($criticalOverride | ConvertTo-Json -Compress -Depth 8))"
  }

  $missingActivity = Invoke-LocalCoreBinaryJson @{
    command = "evaluate_ransomware_activity"
  } $inputJson $repo $binary $TimeoutSeconds
  if ($missingActivity.ok -ne $false -or [string]$missingActivity.error -notlike "*ransomware_activity is required*") {
    throw "release local-core ransomware activity did not fail visibly for missing request: $(Get-BoundedText ($missingActivity | ConvertTo-Json -Compress -Depth 8))"
  }

  $tooManyPaths = @()
  for ($index = 0; $index -le 64; $index++) {
    $tooManyPaths += "$expectedDocuments/too-many-$index.docx"
  }
  $unboundedActivity = Invoke-LocalCoreBinaryJson @{
    command = "evaluate_ransomware_activity"
    ransomware_activity = @{
      process_id = 4246
      process_path = $badProcess
      modified_paths = $tooManyPaths
      files_renamed_count = 1
      entropy_change_score = 0.8
      ransom_note_score = 0.0
      backup_tamper_score = 0.0
      time_window_seconds = 60
    }
  } $inputJson $repo $binary $TimeoutSeconds
  if ($unboundedActivity.ok -ne $false -or [string]$unboundedActivity.error -notlike "*modified_paths exceeds maximum entry count*") {
    throw "release local-core ransomware activity did not reject unbounded modified_paths: $(Get-BoundedText ($unboundedActivity | ConvertTo-Json -Compress -Depth 8))"
  }

  [System.IO.File]::WriteAllText(
    $configPath,
    '{"protected_roots":["C:/Windows"],"trusted_process_allowlist":[""],"updated_at":"2024-01-01T00:00:00Z","source":"fixture"}',
    [System.Text.UTF8Encoding]::new($false)
  )
  $invalidPersisted = Invoke-LocalCoreBinaryJson @{
    command = "list_ransomware_guard_config"
  } $inputJson $repo $binary $TimeoutSeconds
  if ($invalidPersisted.ok -ne $false -or [string]$invalidPersisted.error -notlike "*invalid ransomware guard config*") {
    throw "release local-core list_ransomware_guard_config did not fail visibly for invalid persisted paths: $(Get-BoundedText ($invalidPersisted | ConvertTo-Json -Compress -Depth 8))"
  }

  [System.IO.File]::WriteAllText(
    $configPath,
    '{"protected_roots":[],"trusted_process_allowlist":[],"updated_at":"2024-01-01T00:00:00Z","source":"fixture","enabled":false}',
    [System.Text.UTF8Encoding]::new($false)
  )
  $unknownField = Invoke-LocalCoreBinaryJson @{
    command = "list_ransomware_guard_config"
  } $inputJson $repo $binary $TimeoutSeconds
  if ($unknownField.ok -ne $false -or [string]$unknownField.error -notlike "*unable to parse ransomware guard config*") {
    throw "release local-core list_ransomware_guard_config did not reject unknown persisted fields: $(Get-BoundedText ($unknownField | ConvertTo-Json -Compress -Depth 8))"
  }

  Write-Host "Avorax release local-core ransomware guard config smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Config: $configPath"
  Write-Host "Protected roots: $(@($listed.config.protected_roots).Count)"
  Write-Host "Trusted processes: $(@($listed.config.trusted_process_allowlist).Count)"
  Write-Host "Broad-root rejected: $($rejectBroadRoot.ok -eq $false)"
  Write-Host "Detected protected activity: $($detectedActivity.detected)"
  Write-Host "Protected paths counted: $($detectedActivity.signal.files_modified_count)"
  Write-Host "Outside-only ignored: $($outsideOnly.detected -eq $false)"
  Write-Host "Trusted non-critical suppressed: $($trustedSuppressed.detected -eq $false)"
  Write-Host "Critical override detected: $($criticalOverride.detected)"
  Write-Host "Missing activity rejected: $($missingActivity.ok -eq $false)"
  Write-Host "Unbounded paths rejected: $($unboundedActivity.ok -eq $false)"
  Write-Host "Invalid persisted config rejected: $($invalidPersisted.ok -eq $false)"
  Write-Host "Unknown persisted field rejected: $($unknownField.ok -eq $false)"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "ZENTOR_LEGACY_DATA_DIR" $previousLegacyDataDir
  Restore-EnvVar "AVORAX_RANSOMWARE_GUARD_CONFIG" $previousRansomwareConfig
  if (Test-Path -LiteralPath $tempRoot) {
    $resolvedTemp = (Resolve-Path -LiteralPath $tempRoot).Path
    $systemTemp = [System.IO.Path]::GetTempPath()
    if (-not $resolvedTemp.StartsWith($systemTemp, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to remove unexpected ransomware guard config temp root: $resolvedTemp"
    }
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction Stop
  }
}
