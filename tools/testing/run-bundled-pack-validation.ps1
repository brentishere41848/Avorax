param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$PythonPath = "",
  [string]$ReportPath = "",
  [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

function Resolve-PythonPath {
  param([string]$ConfiguredPath)

  if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
    if (-not (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf)) {
      throw "Configured PythonPath is not a file: $ConfiguredPath"
    }
    return (Resolve-Path -LiteralPath $ConfiguredPath).Path
  }

  $bundled = "C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
  if (Test-Path -LiteralPath $bundled -PathType Leaf) {
    return (Resolve-Path -LiteralPath $bundled).Path
  }
  return "python"
}

function ConvertTo-ProcessArgument {
  param([string]$Value)
  return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-PackValidator {
  param(
    [string]$Python,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [int]$Timeout,
    [string]$Description
  )

  $argumentText = ($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join " "
  $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $Python
  $startInfo.WorkingDirectory = $WorkingDirectory
  $startInfo.Arguments = $argumentText
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
    } catch {}
    throw "$Description timed out after ${Timeout}s: $argumentText"
  }

  $stdout = $stdoutTask.GetAwaiter().GetResult()
  $stderr = $stderrTask.GetAwaiter().GetResult()
  if ($process.ExitCode -ne 0) {
    throw "$Description failed with exit code $($process.ExitCode). stdout=$stdout stderr=$stderr"
  }

  return $stdout
}

function Assert-ExpectedPackInventory {
  param(
    [object[]]$PackFiles,
    [string[]]$ExpectedNames,
    [string]$Kind
  )

  $foundNames = @{}
  foreach ($pack in $PackFiles) {
    $foundNames[$pack.Name.ToLowerInvariant()] = $true
  }

  foreach ($expected in $ExpectedNames) {
    if (-not $foundNames.ContainsKey($expected.ToLowerInvariant())) {
      throw "Missing expected bundled $Kind pack: $expected"
    }
  }
}

function Resolve-RepoChildReportPath {
  param([string]$Path, [string]$RepositoryRoot)

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return $null
  }

  $candidate = $Path
  if (-not [System.IO.Path]::IsPathRooted($candidate)) {
    $candidate = Join-Path $RepositoryRoot $candidate
  }
  $fullPath = [System.IO.Path]::GetFullPath($candidate)
  $repoPrefix = $RepositoryRoot.TrimEnd("\") + "\"
  if (-not $fullPath.Equals($RepositoryRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
      -not $fullPath.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Bundled pack validation report path must stay inside the repository: $Path"
  }
  if (Test-Path -LiteralPath $fullPath -PathType Container) {
    throw "Bundled pack validation report path is a directory: $fullPath"
  }
  return $fullPath
}

function Write-JsonFileAtomic {
  param([string]$Path, [object]$Value, [int]$Depth)

  $directory = Split-Path -Parent $Path
  if ([string]::IsNullOrWhiteSpace($directory)) {
    throw "Bundled pack validation report path has no parent directory: $Path"
  }
  if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
  }
  if (Test-Path -LiteralPath $Path -PathType Container) {
    throw "Bundled pack validation report path is a directory: $Path"
  }

  $tempPath = Join-Path $directory ("." + (Split-Path -Leaf $Path) + "." + [guid]::NewGuid().ToString("N") + ".tmp")
  $backupPath = Join-Path $directory ("." + (Split-Path -Leaf $Path) + "." + [guid]::NewGuid().ToString("N") + ".bak")
  $encoding = New-Object System.Text.UTF8Encoding($false)
  try {
    [System.IO.File]::WriteAllText($tempPath, ($Value | ConvertTo-Json -Depth $Depth), $encoding)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
      [System.IO.File]::Replace($tempPath, $Path, $backupPath)
    } else {
      [System.IO.File]::Move($tempPath, $Path)
    }
  } finally {
    if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
      Remove-Item -LiteralPath $tempPath -Force
    }
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
      Remove-Item -LiteralPath $backupPath -Force
    }
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$python = Resolve-PythonPath $PythonPath
$report = Resolve-RepoChildReportPath $ReportPath $repo
$validator = Join-Path $repo "tools\zentor_intel\validate_indicator_pack.py"
if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
  throw "Pack validator is missing: $validator"
}

$signatureRoot = Join-Path $repo "assets\zentor_native\signatures"
$ruleRoot = Join-Path $repo "assets\zentor_native\rules"
if (-not (Test-Path -LiteralPath $signatureRoot -PathType Container)) {
  throw "Signature pack directory is missing: $signatureRoot"
}
if (-not (Test-Path -LiteralPath $ruleRoot -PathType Container)) {
  throw "Rule pack directory is missing: $ruleRoot"
}

$expectedSignaturePacks = @(
  "zentor_core.zsig",
  "zentor_github_known_bad.zsig",
  "zentor_infostealer_indicators.zsig",
  "zentor_lab_known_bad.zsig",
  "zentor_miner_pup_indicators.zsig",
  "zentor_ransomware_indicators.zsig",
  "zentor_realworld_hashes.zsig",
  "zentor_script_threats.zsig"
)

$expectedRulePacks = @(
  "zentor_infostealers.zrule",
  "zentor_miners_pup.zrule",
  "zentor_persistence.zrule",
  "zentor_ransomware.zrule",
  "zentor_rules.zrule",
  "zentor_script_threats.zrule"
)

$signaturePacks = @(Get-ChildItem -LiteralPath $signatureRoot -Filter "*.zsig" -File | Sort-Object FullName)
$rulePacks = @(Get-ChildItem -LiteralPath $ruleRoot -Filter "*.zrule" -File | Sort-Object FullName)

if ($signaturePacks.Count -lt 1) {
  throw "No bundled signature packs were found."
}
if ($rulePacks.Count -lt 1) {
  throw "No bundled rule packs were found."
}

Assert-ExpectedPackInventory $signaturePacks $expectedSignaturePacks "signature"
Assert-ExpectedPackInventory $rulePacks $expectedRulePacks "rule"

$packs = @($signaturePacks + $rulePacks) | Sort-Object FullName
$validatedPacks = @()
foreach ($pack in $packs) {
  $relative = $pack.FullName
  $repoPrefix = $repo.TrimEnd("\") + "\"
  if ($pack.FullName.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    $relative = $pack.FullName.Substring($repoPrefix.Length)
  }
  $validatorOutput = Invoke-PackValidator $python @("-B", $validator, "--input", $pack.FullName) $repo $TimeoutSeconds "Bundled pack validation failed for $relative"
  $kind = if ($pack.Extension -eq ".zsig") { "signature" } else { "rule" }
  $validatedPacks += [ordered]@{
    kind = $kind
    name = $pack.Name
    path = $relative
    bytes = $pack.Length
    validator_output = $validatorOutput.Trim()
  }
}

if ($null -ne $report) {
  $reportValue = [ordered]@{
    schema_version = 1
    status = "passed"
    repository = $repo
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    validator = $validator
    expected_signature_packs = $expectedSignaturePacks
    expected_rule_packs = $expectedRulePacks
    signature_pack_count = $signaturePacks.Count
    rule_pack_count = $rulePacks.Count
    total_pack_count = $packs.Count
    packs = $validatedPacks
  }
  Write-JsonFileAtomic $report $reportValue 8
  Write-Host "Bundled pack validation report: $report"
}

Write-Host "PASS bundled pack validation: $($signaturePacks.Count) signature packs, $($rulePacks.Count) rule packs ($($packs.Count) total)"
