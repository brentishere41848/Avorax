param(
  [string]$RepoRoot = $(Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [string]$SignerPath = "",
  [int]$TimeoutSeconds = 60
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

function Resolve-ReleaseSigner {
  param(
    [string]$Repo,
    [string]$ConfiguredPath
  )
  $candidate = $ConfiguredPath
  if ([string]::IsNullOrWhiteSpace($candidate)) {
    $candidate = Join-Path $Repo "target\release\avorax_sign_manifest.exe"
  }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    throw "Release update manifest signer is missing: $candidate. Run cargo build --release --manifest-path core\avorax_update_service\Cargo.toml first."
  }
  $resolved = (Resolve-Path -LiteralPath $candidate).Path
  if ([System.IO.Path]::GetFileName($resolved) -ne "avorax_sign_manifest.exe") {
    throw "Release update package builder fail-safe smoke expects avorax_sign_manifest.exe, got: $resolved"
  }
  return $resolved
}

function ConvertTo-CmdArgument {
  param([string]$Value)
  return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-ReleaseCommand {
  param(
    [string]$Binary,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [int]$Timeout
  )

  $process = $null
  try {
    $argumentText = ($Arguments | ForEach-Object { ConvertTo-CmdArgument $_ }) -join " "
    $commandText = ConvertTo-CmdArgument $Binary
    if ($argumentText.Length -gt 0) {
      $commandText = "$commandText $argumentText"
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "cmd.exe"
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.Arguments = "/d /s /c `"$commandText`""
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
        throw "release update package builder fail-safe command timed out after ${Timeout}s and failed to stop: $(Get-BoundedText $_.Exception.Message)"
      }
      throw "release update package builder fail-safe command timed out after ${Timeout}s."
    }

    return [pscustomobject]@{
      ExitCode = $process.ExitCode
      Stdout = $stdoutTask.Result
      Stderr = $stderrTask.Result
    }
  } finally {
    if ($null -ne $process -and -not $process.HasExited) {
      $process.Kill($true)
    }
  }
}

function Get-RepoRelativePath {
  param(
    [string]$Repo,
    [string]$Path
  )
  $root = [System.IO.Path]::GetFullPath($Repo).TrimEnd('\', '/')
  $target = [System.IO.Path]::GetFullPath($Path)
  $prefix = $root + [System.IO.Path]::DirectorySeparatorChar
  if (-not $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "update package builder fail-safe smoke path must stay under the repository: $target"
  }
  return $target.Substring($prefix.Length)
}

function Write-Utf8NoBomFile {
  param([string]$Path, [string]$Text)
  [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Add-MinimalEngineAsset {
  param([string]$PayloadRoot)
  $signatureDir = Join-Path $PayloadRoot "engine\signatures"
  New-Item -ItemType Directory -Path $signatureDir -Force | Out-Null
  Write-Utf8NoBomFile (Join-Path $signatureDir "avorax_builder_failsafe.asig") "{`"format`":`"avorax-builder-failsafe-signature-fixture`",`"safe`":true}`n"
}

function New-ScenarioPayload {
  param(
    [string]$PayloadRoot,
    [string]$Scenario
  )
  New-Item -ItemType Directory -Path $PayloadRoot -Force | Out-Null
  Write-Utf8NoBomFile (Join-Path $PayloadRoot "AvoraxBuilderFailSafe.txt") "benign Avorax update builder fail-safe app payload`n"

  switch ($Scenario) {
    "tools-root" {
      Add-MinimalEngineAsset $PayloadRoot
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "tools") -Force | Out-Null
      Write-Utf8NoBomFile (Join-Path $PayloadRoot "tools\tool.txt") "benign tool fixture`n"
    }
    "migrations-root" {
      Add-MinimalEngineAsset $PayloadRoot
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "migrations") -Force | Out-Null
      Write-Utf8NoBomFile (Join-Path $PayloadRoot "migrations\migration.txt") "benign migration fixture`n"
    }
    "driver-root" {
      Add-MinimalEngineAsset $PayloadRoot
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "driver") -Force | Out-Null
      Write-Utf8NoBomFile (Join-Path $PayloadRoot "driver\driver.txt") "benign driver fixture`n"
    }
    "driver-tools-root" {
      Add-MinimalEngineAsset $PayloadRoot
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "driver-tools") -Force | Out-Null
      Write-Utf8NoBomFile (Join-Path $PayloadRoot "driver-tools\driver-tool.txt") "benign driver tooling fixture`n"
    }
    "unsupported-engine-child" {
      Add-MinimalEngineAsset $PayloadRoot
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "engine\unsupported") -Force | Out-Null
      Write-Utf8NoBomFile (Join-Path $PayloadRoot "engine\unsupported\asset.bin") "benign unsupported engine fixture`n"
    }
    "empty-engine-component" {
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "engine\signatures") -Force | Out-Null
    }
    "update-service-root" {
      Add-MinimalEngineAsset $PayloadRoot
      Write-Utf8NoBomFile (Join-Path $PayloadRoot "avorax_update_service.exe") "benign updater self-update fixture`n"
    }
    "managed-service-directory" {
      Add-MinimalEngineAsset $PayloadRoot
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "avorax_core_service.exe") -Force | Out-Null
      Write-Utf8NoBomFile (Join-Path $PayloadRoot "avorax_core_service.exe\nested.txt") "benign managed service directory fixture`n"
    }
    "docs-non-markdown" {
      Add-MinimalEngineAsset $PayloadRoot
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "docs") -Force | Out-Null
      Write-Utf8NoBomFile (Join-Path $PayloadRoot "docs\not-markdown.txt") "benign docs fixture`n"
    }
    "empty-docs" {
      Add-MinimalEngineAsset $PayloadRoot
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "docs") -Force | Out-Null
    }
    "missing-engine" {
      New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "docs") -Force | Out-Null
      Write-Utf8NoBomFile (Join-Path $PayloadRoot "docs\readme.md") "# Benign docs fixture`n"
    }
    default {
      throw "unknown update package builder fail-safe scenario: $Scenario"
    }
  }
}

function Invoke-FailSafeScenario {
  param(
    [string]$Repo,
    [string]$Builder,
    [string]$TempRoot,
    [string]$Scenario,
    [string]$ExpectedDiagnostic,
    [int]$Timeout
  )

  $scenarioRoot = Join-Path $TempRoot $Scenario
  $payloadRoot = Join-Path $scenarioRoot "payload"
  $outputRoot = Join-Path $scenarioRoot "out"
  New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
  New-ScenarioPayload $payloadRoot $Scenario

  $version = "0.4.$($script:ScenarioCounter)"
  $script:ScenarioCounter += 1
  $payloadRelative = Get-RepoRelativePath $Repo $payloadRoot
  $outputRelative = Get-RepoRelativePath $Repo $outputRoot
  $result = Invoke-ReleaseCommand "powershell.exe" @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $Builder,
    "-Version",
    $version,
    "-Channel",
    "stable",
    "-PayloadRoot",
    $payloadRelative,
    "-OutputDir",
    $outputRelative
  ) $Repo $Timeout

  $diagnostic = "$($result.Stdout) $($result.Stderr)"
  if ($result.ExitCode -eq 0) {
    throw "update package builder unexpectedly accepted fail-safe scenario ${Scenario}: $(Get-BoundedText $diagnostic)"
  }
  if (-not $diagnostic.Contains($ExpectedDiagnostic)) {
    throw "update package builder fail-safe scenario $Scenario diagnostic mismatch. Expected '$ExpectedDiagnostic', got: $(Get-BoundedText $diagnostic)"
  }
  $packages = @(Get-ChildItem -LiteralPath $outputRoot -Filter "*.aup" -File -ErrorAction SilentlyContinue)
  if ($packages.Count -ne 0) {
    throw "update package builder fail-safe scenario $Scenario produced an .aup package"
  }
  if (Test-Path -LiteralPath (Join-Path $outputRoot "update-feed.json") -PathType Leaf) {
    throw "update package builder fail-safe scenario $Scenario produced update-feed.json"
  }
  Write-Host "PASS builder fail-safe scenario ${Scenario}: $(Get-BoundedText $diagnostic 240)"
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$signer = Resolve-ReleaseSigner $repo $SignerPath
$builder = Join-Path $repo "tools\update\avorax-build-update-package.ps1"
if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) {
  throw "update package builder script is missing: $builder"
}

$tempRoot = Join-Path $repo (".workflow\ultracode\avorax-hardening\tmp\release-update-builder-failsafe-" + [System.Guid]::NewGuid().ToString("N"))
$oldSigner = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_SIGNER")
$oldSigningKey = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX")
$oldPublicKeyId = [System.Environment]::GetEnvironmentVariable("AVORAX_UPDATE_PUBLIC_KEY_ID")
$script:ScenarioCounter = 0

try {
  New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
  Set-Item -Path Env:\AVORAX_UPDATE_SIGNER -Value (ConvertTo-CmdArgument $signer) -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX -Value ("07" * 32) -ErrorAction Stop
  Set-Item -Path Env:\AVORAX_UPDATE_PUBLIC_KEY_ID -Value "avorax-release-builder-failsafe-ed25519" -ErrorAction Stop

  $scenarios = @(
    @{ Name = "tools-root"; Diagnostic = "Normal .aup update package must not include tools payloads" },
    @{ Name = "migrations-root"; Diagnostic = "Normal .aup update package must not include migration payloads" },
    @{ Name = "driver-root"; Diagnostic = "Normal .aup update package must not include driver payloads" },
    @{ Name = "driver-tools-root"; Diagnostic = "Normal .aup update package must not include driver-tools payloads" },
    @{ Name = "unsupported-engine-child"; Diagnostic = "Normal .aup update package must not include unsupported engine payload path" },
    @{ Name = "empty-engine-component"; Diagnostic = "Normal .aup update package engine component 'engine\signatures' contains no runtime files" },
    @{ Name = "update-service-root"; Diagnostic = "Normal .aup update package must not include avorax_update_service.exe" },
    @{ Name = "managed-service-directory"; Diagnostic = "app payload directory must not be named managed service" },
    @{ Name = "docs-non-markdown"; Diagnostic = "Normal .aup update package docs payload must contain Markdown files only" },
    @{ Name = "empty-docs"; Diagnostic = "Payload docs source contains no Markdown files for a normal .aup update." },
    @{ Name = "missing-engine"; Diagnostic = "Payload stage is missing engine assets; refusing to create an update package that would leave the engine unavailable." }
  )

  foreach ($scenario in $scenarios) {
    Invoke-FailSafeScenario $repo $builder $tempRoot $scenario.Name $scenario.Diagnostic $TimeoutSeconds
  }

  Write-Host "Avorax release update-package builder restricted-payload fail-safe smoke test passed."
} finally {
  Restore-EnvVar "AVORAX_UPDATE_SIGNER" $oldSigner
  Restore-EnvVar "AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX" $oldSigningKey
  Restore-EnvVar "AVORAX_UPDATE_PUBLIC_KEY_ID" $oldPublicKeyId
  if (Test-Path -LiteralPath $tempRoot) {
    $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
    $repoPrefix = ([System.IO.Path]::GetFullPath($repo).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar)
    if (-not $resolvedTemp.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "refusing to remove update package builder fail-safe temp outside repo: $resolvedTemp"
    }
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction Stop
  }
}
