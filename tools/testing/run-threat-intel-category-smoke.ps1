param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$PythonPath = "",
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

function Invoke-IntelCommand {
  param(
    [string]$Python,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [int]$Timeout
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
    throw "Threat-intel category command timed out after ${Timeout}s: $argumentText"
  }
  [pscustomobject]@{
    ExitCode = $process.ExitCode
    Stdout = $stdoutTask.GetAwaiter().GetResult()
    Stderr = $stderrTask.GetAwaiter().GetResult()
    Command = "$Python $argumentText"
  }
}

function Assert-Success {
  param([object]$Result, [string]$Description)

  if ($Result.ExitCode -ne 0) {
    throw "$Description failed with exit code $($Result.ExitCode). stdout=$($Result.Stdout) stderr=$($Result.Stderr)"
  }
}

function Assert-FailedCategory {
  param([object]$Result, [string]$Description)

  if ($Result.ExitCode -eq 0) {
    throw "$Description unexpectedly succeeded."
  }
  $combined = "$($Result.Stdout)`n$($Result.Stderr)"
  if ($combined -notmatch "must be one of" -and $combined -notmatch "must use canonical category spelling") {
    throw "$Description did not report an allowlisted-category failure. stdout=$($Result.Stdout) stderr=$($Result.Stderr)"
  }
}

function Read-SingleJsonlObject {
  param([string]$Path, [string]$Description)

  $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8)
  if ($lines.Count -ne 1) {
    throw "$Description expected one JSONL row, found $($lines.Count)."
  }
  $lines[0] | ConvertFrom-Json
}

function Read-JsonFile {
  param([string]$Path, [string]$Description)

  try {
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    throw "$Description is not valid JSON: $($_.Exception.Message)"
  }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$python = Resolve-PythonPath $PythonPath
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$tempRoot = Join-Path $tempBase ("avorax-threat-intel-category-smoke-" + [guid]::NewGuid().ToString("N"))
$tempFull = [System.IO.Path]::GetFullPath($tempRoot)
if (-not $tempFull.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Temporary smoke directory escaped the system temp directory: $tempFull"
}

New-Item -ItemType Directory -Path $tempFull -Force | Out-Null
try {
  $sourcePath = Join-Path $tempFull "source.json"
  $hashFeedPath = Join-Path $tempFull "hash-feed.txt"
  $developerHashPath = Join-Path $tempFull "developer-hashes.txt"
  $hashFeedOutput = Join-Path $tempFull "hash-feed.jsonl"
  $developerOutput = Join-Path $tempFull "developer-hashes.jsonl"
  $invalidOutput = Join-Path $tempFull "invalid.jsonl"
  $manualInput = Join-Path $tempFull "manual-iocs.json"
  $manualInvalidInput = Join-Path $tempFull "manual-iocs-invalid.json"
  $manualOutput = Join-Path $tempFull "manual-iocs.jsonl"
  $signatureInput = Join-Path $tempFull "signature-input.jsonl"
  $signatureInvalidInput = Join-Path $tempFull "signature-invalid.jsonl"
  $signaturePack = Join-Path $tempFull "signature-pack.zsig"
  $signatureInvalidPack = Join-Path $tempFull "signature-invalid-pack.zsig"
  $knownBadInput = Join-Path $tempFull "known-bad-input.jsonl"
  $knownBadInvalidInput = Join-Path $tempFull "known-bad-invalid.jsonl"
  $knownBadPack = Join-Path $tempFull "known-bad.zsig"
  $ruleInputDir = Join-Path $tempFull "rules-valid"
  $ruleInvalidDir = Join-Path $tempFull "rules-invalid"
  $rulePack = Join-Path $tempFull "rules.zrule"
  $ruleInvalidPack = Join-Path $tempFull "rules-invalid-pack.zrule"

  @"
{
  "source_name": "category smoke",
  "source_type": "manual_lab"
}
"@ | Set-Content -LiteralPath $sourcePath -Encoding UTF8
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | Set-Content -LiteralPath $hashFeedPath -Encoding UTF8
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" | Set-Content -LiteralPath $developerHashPath -Encoding UTF8
  @"
{
  "source_name": "manual category smoke",
  "threat_category": "credential-theft-indicator",
  "confidence": "high",
  "false_positive_notes": "Benign category smoke fixture.",
  "action_policy": "review",
  "indicators": [
    {
      "indicator_type": "string_pattern",
      "value": "BENIGN-MANUAL-CATEGORY-SMOKE"
    }
  ]
}
"@ | Set-Content -LiteralPath $manualInput -Encoding UTF8
  @"
{
  "source_name": "manual category smoke",
  "threat_category": "not_real",
  "confidence": "high",
  "false_positive_notes": "Benign category smoke fixture.",
  "action_policy": "review",
  "indicators": [
    {
      "indicator_type": "string_pattern",
      "value": "BENIGN-MANUAL-CATEGORY-SMOKE"
    }
  ]
}
"@ | Set-Content -LiteralPath $manualInvalidInput -Encoding UTF8
  '{"indicator_id":"ZTI-CATEGORY-SIG-0001","source_name":"category smoke","indicator_type":"string_pattern","value":"BENIGN-SIGNATURE-CATEGORY-SMOKE","threat_category":"exploit-dropper","confidence":"medium","false_positive_notes":"Benign category smoke fixture.","action_policy":"review"}' | Set-Content -LiteralPath $signatureInput -Encoding UTF8
  '{"indicator_id":"ZTI-CATEGORY-SIG-0002","source_name":"category smoke","indicator_type":"string_pattern","value":"BENIGN-SIGNATURE-CATEGORY-SMOKE","threat_category":"not_real","confidence":"medium","false_positive_notes":"Benign category smoke fixture.","action_policy":"review"}' | Set-Content -LiteralPath $signatureInvalidInput -Encoding UTF8
  '{"indicator_id":"ZTI-CATEGORY-KNOWN-BAD-0001","source_name":"category smoke","indicator_type":"sha256","value":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","threat_category":"security_tamper_indicator","confidence":"confirmed","false_positive_notes":"Benign category smoke fixture.","action_policy":"quarantine_if_policy_allows"}' | Set-Content -LiteralPath $knownBadInput -Encoding UTF8
  '{"indicator_id":"ZTI-CATEGORY-KNOWN-BAD-0002","source_name":"category smoke","indicator_type":"sha256","value":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","threat_category":"not_real","confidence":"confirmed","false_positive_notes":"Benign category smoke fixture.","action_policy":"quarantine_if_policy_allows"}' | Set-Content -LiteralPath $knownBadInvalidInput -Encoding UTF8
  New-Item -ItemType Directory -Path $ruleInputDir -Force | Out-Null
  New-Item -ItemType Directory -Path $ruleInvalidDir -Force | Out-Null
  @"
{
  "format": "zentor-rule-pack-v1",
  "version": "category-smoke",
  "rules": [
    {
      "id": "ZNE-RULE-CATEGORY-SMOKE",
      "name": "Category smoke rule",
      "description": "Benign category smoke fixture.",
      "category": "persistence-indicator",
      "confidence": "medium",
      "verdict": "suspicious",
      "false_positive_notes": "Benign category smoke fixture.",
      "conditions": [
        {
          "type": "contains_ascii",
          "value": "BENIGN-RULE-CATEGORY-SMOKE"
        }
      ],
      "min_condition_matches": 1,
      "action": "review_only"
    }
  ]
}
"@ | Set-Content -LiteralPath (Join-Path $ruleInputDir "category-smoke.zrule") -Encoding UTF8
  @"
{
  "format": "zentor-rule-pack-v1",
  "version": "category-smoke",
  "rules": [
    {
      "id": "ZNE-RULE-CATEGORY-SMOKE-INVALID",
      "name": "Category smoke invalid rule",
      "description": "Benign category smoke fixture.",
      "category": "not_real",
      "confidence": "medium",
      "verdict": "suspicious",
      "false_positive_notes": "Benign category smoke fixture.",
      "conditions": [
        {
          "type": "contains_ascii",
          "value": "BENIGN-RULE-CATEGORY-SMOKE"
        }
      ],
      "min_condition_matches": 1,
      "action": "review_only"
    }
  ]
}
"@ | Set-Content -LiteralPath (Join-Path $ruleInvalidDir "category-smoke-invalid.zrule") -Encoding UTF8

  $hashFeedImporter = Join-Path $repo "tools\zentor_intel\import_hash_feed.py"
  $developerImporter = Join-Path $repo "tools\zentor_intel\import_github_hashes_only.py"
  $manualImporter = Join-Path $repo "tools\zentor_intel\import_malware_report_iocs.py"
  $signatureCompiler = Join-Path $repo "tools\zentor_intel\compile_zentor_signatures.py"
  $knownBadBuilder = Join-Path $repo "tools\zentor_intel\build_known_bad_from_github.py"
  $ruleCompiler = Join-Path $repo "tools\zentor_intel\compile_zentor_rules.py"
  $packValidator = Join-Path $repo "tools\zentor_intel\validate_indicator_pack.py"

  $hashFeed = Invoke-IntelCommand $python @(
    $hashFeedImporter,
    "--source", $sourcePath,
    "--input", $hashFeedPath,
    "--output", $hashFeedOutput,
    "--category", "suspicious-script"
  ) $repo $TimeoutSeconds
  Assert-Success $hashFeed "hash feed category alias smoke"
  $hashFeedRow = Read-SingleJsonlObject $hashFeedOutput "hash feed category alias smoke"
  if ($hashFeedRow.threat_category -ne "suspiciousScript") {
    throw "hash feed category alias smoke wrote '$($hashFeedRow.threat_category)', expected suspiciousScript."
  }

  $developer = Invoke-IntelCommand $python @(
    $developerImporter,
    "--input", $developerHashPath,
    "--output", $developerOutput,
    "--source-name", "developer category smoke",
    "--category", "rootkit_indicator"
  ) $repo $TimeoutSeconds
  Assert-Success $developer "developer hash category alias smoke"
  $developerRow = Read-SingleJsonlObject $developerOutput "developer hash category alias smoke"
  if ($developerRow.threat_category -ne "rootkitIndicator") {
    throw "developer hash category alias smoke wrote '$($developerRow.threat_category)', expected rootkitIndicator."
  }

  $invalidHashFeed = Invoke-IntelCommand $python @(
    $hashFeedImporter,
    "--source", $sourcePath,
    "--input", $hashFeedPath,
    "--output", $invalidOutput,
    "--category", "made_up_category"
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidHashFeed "hash feed invalid category smoke"

  $invalidDeveloper = Invoke-IntelCommand $python @(
    $developerImporter,
    "--input", $developerHashPath,
    "--output", $invalidOutput,
    "--source-name", "developer category smoke",
    "--category", "not-a-real-category"
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidDeveloper "developer hash invalid category smoke"

  $manual = Invoke-IntelCommand $python @(
    $manualImporter,
    "--input", $manualInput,
    "--output", $manualOutput
  ) $repo $TimeoutSeconds
  Assert-Success $manual "manual IOC category alias smoke"
  $manualRow = Read-SingleJsonlObject $manualOutput "manual IOC category alias smoke"
  if ($manualRow.threat_category -ne "credentialTheftIndicator") {
    throw "manual IOC category alias smoke wrote '$($manualRow.threat_category)', expected credentialTheftIndicator."
  }

  $invalidManual = Invoke-IntelCommand $python @(
    $manualImporter,
    "--input", $manualInvalidInput,
    "--output", $invalidOutput
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidManual "manual IOC invalid category smoke"

  $signature = Invoke-IntelCommand $python @(
    $signatureCompiler,
    "--input", $signatureInput,
    "--output", $signaturePack,
    "--version", "category-smoke"
  ) $repo $TimeoutSeconds
  Assert-Success $signature "signature compiler category alias smoke"
  $signaturePackJson = Read-JsonFile $signaturePack "signature compiler category alias smoke"
  if ($signaturePackJson.signatures[0].category -ne "exploitDropper") {
    throw "signature compiler category alias smoke wrote '$($signaturePackJson.signatures[0].category)', expected exploitDropper."
  }

  $invalidSignature = Invoke-IntelCommand $python @(
    $signatureCompiler,
    "--input", $signatureInvalidInput,
    "--output", $signatureInvalidPack,
    "--version", "category-smoke"
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidSignature "signature compiler invalid category smoke"

  $validSignaturePack = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $signaturePack
  ) $repo $TimeoutSeconds
  Assert-Success $validSignaturePack "signature pack validator category smoke"
  $invalidPackObject = Read-JsonFile $signaturePack "invalid signature pack category smoke"
  $invalidPackObject.signatures[0].category = "exploit-dropper"
  $invalidPackObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $signatureInvalidPack -Encoding UTF8
  $nonCanonicalSignaturePack = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $signatureInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $nonCanonicalSignaturePack "signature pack validator noncanonical category smoke"
  $invalidPackObject = Read-JsonFile $signaturePack "invalid signature pack category smoke"
  $invalidPackObject.signatures[0].category = "not_real"
  $invalidPackObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $signatureInvalidPack -Encoding UTF8
  $invalidSignaturePack = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $signatureInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidSignaturePack "signature pack validator invalid category smoke"
  $invalidPackObject = Read-JsonFile $signaturePack "invalid signature metadata smoke"
  $invalidPackObject.signatures[0].confidence = "certain"
  $invalidPackObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $signatureInvalidPack -Encoding UTF8
  $invalidSignatureConfidence = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $signatureInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidSignatureConfidence "signature pack validator invalid confidence smoke"
  $invalidPackObject = Read-JsonFile $signaturePack "invalid signature metadata smoke"
  $invalidPackObject.signatures[0].severity = "urgent"
  $invalidPackObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $signatureInvalidPack -Encoding UTF8
  $invalidSignatureSeverity = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $signatureInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidSignatureSeverity "signature pack validator invalid severity smoke"
  $invalidPackObject = Read-JsonFile $signaturePack "invalid signature metadata smoke"
  $invalidPackObject.signatures[0].signature_type = "asciiString"
  $invalidPackObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $signatureInvalidPack -Encoding UTF8
  $invalidSignatureType = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $signatureInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidSignatureType "signature pack validator invalid signature_type smoke"
  $invalidPackObject = Read-JsonFile $signaturePack "invalid signature metadata smoke"
  $invalidPackObject.signatures[0].action_policy = "delete_immediately"
  $invalidPackObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $signatureInvalidPack -Encoding UTF8
  $invalidSignatureAction = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $signatureInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidSignatureAction "signature pack validator invalid action_policy smoke"
  $invalidPackObject = Read-JsonFile $signaturePack "invalid signature metadata smoke"
  $invalidPackObject.signatures[0].file_types = @("PE")
  $invalidPackObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $signatureInvalidPack -Encoding UTF8
  $invalidSignatureFileType = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $signatureInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidSignatureFileType "signature pack validator invalid file_type smoke"

  $knownBad = Invoke-IntelCommand $python @(
    $knownBadBuilder,
    "--input", $knownBadInput,
    "--output", $knownBadPack,
    "--version", "category-smoke"
  ) $repo $TimeoutSeconds
  Assert-Success $knownBad "known-bad builder category alias smoke"
  $knownBadPackJson = Read-JsonFile $knownBadPack "known-bad builder category alias smoke"
  if ($knownBadPackJson.signatures[0].category -ne "securityTamperIndicator") {
    throw "known-bad builder category alias smoke wrote '$($knownBadPackJson.signatures[0].category)', expected securityTamperIndicator."
  }

  $invalidKnownBad = Invoke-IntelCommand $python @(
    $knownBadBuilder,
    "--input", $knownBadInvalidInput,
    "--output", $invalidOutput,
    "--version", "category-smoke"
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidKnownBad "known-bad builder invalid category smoke"

  $rule = Invoke-IntelCommand $python @(
    $ruleCompiler,
    "--input", $ruleInputDir,
    "--output", $rulePack,
    "--version", "category-smoke"
  ) $repo $TimeoutSeconds
  Assert-Success $rule "rule compiler category alias smoke"
  $rulePackJson = Read-JsonFile $rulePack "rule compiler category alias smoke"
  if ($rulePackJson.rules[0].category -ne "persistenceIndicator") {
    throw "rule compiler category alias smoke wrote '$($rulePackJson.rules[0].category)', expected persistenceIndicator."
  }

  $validRulePack = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $rulePack
  ) $repo $TimeoutSeconds
  Assert-Success $validRulePack "rule pack validator category smoke"
  $invalidRulePackJson = Read-JsonFile $rulePack "invalid rule pack category smoke"
  $invalidRulePackJson.rules[0].category = "persistence-indicator"
  $invalidRulePackJson | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ruleInvalidPack -Encoding UTF8
  $nonCanonicalRulePack = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $ruleInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $nonCanonicalRulePack "rule pack validator noncanonical category smoke"
  $invalidRulePackJson = Read-JsonFile $rulePack "invalid rule pack metadata smoke"
  $invalidRulePackJson.rules[0].confidence = "certain"
  $invalidRulePackJson | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ruleInvalidPack -Encoding UTF8
  $invalidRuleConfidence = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $ruleInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidRuleConfidence "rule pack validator invalid confidence smoke"
  $invalidRulePackJson = Read-JsonFile $rulePack "invalid rule pack metadata smoke"
  $invalidRulePackJson.rules[0].verdict = "probable_malware"
  $invalidRulePackJson | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ruleInvalidPack -Encoding UTF8
  $invalidRuleVerdict = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $ruleInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidRuleVerdict "rule pack validator invalid verdict smoke"
  $invalidRulePackJson = Read-JsonFile $rulePack "invalid rule pack metadata smoke"
  $invalidRulePackJson.rules[0].action = "delete_immediately"
  $invalidRulePackJson | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ruleInvalidPack -Encoding UTF8
  $invalidRuleAction = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $ruleInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidRuleAction "rule pack validator invalid action smoke"
  $invalidRulePackJson = Read-JsonFile $rulePack "invalid rule pack metadata smoke"
  $invalidRulePackJson.rules[0].conditions[0].type = "containsAscii"
  $invalidRulePackJson | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ruleInvalidPack -Encoding UTF8
  $invalidRuleConditionType = Invoke-IntelCommand $python @(
    $packValidator,
    "--input", $ruleInvalidPack
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidRuleConditionType "rule pack validator invalid condition type smoke"

  $invalidRule = Invoke-IntelCommand $python @(
    $ruleCompiler,
    "--input", $ruleInvalidDir,
    "--output", $invalidOutput,
    "--version", "category-smoke"
  ) $repo $TimeoutSeconds
  Assert-FailedCategory $invalidRule "rule compiler invalid category smoke"

  Write-Host "PASS threat-intel category smoke"
} finally {
  if (Test-Path -LiteralPath $tempFull) {
    $resolvedTemp = [System.IO.Path]::GetFullPath($tempFull)
    if (-not $resolvedTemp.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to remove temporary smoke directory outside temp: $resolvedTemp"
    }
    Remove-Item -LiteralPath $tempFull -Recurse -Force
  }
}
