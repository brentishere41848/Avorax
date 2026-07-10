param(
    [string]$RepoRoot = ".",
    [string]$ReportPath = "",
    [switch]$AllowKnownBlockers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "avorax-security-gate-tools.ps1")
$maxTextFileBytes = 1048576

function Test-LocalWindowsPath {
    param([string]$Path)
    $normalized = $Path -replace '/', '\'
    return $normalized -match '^[A-Za-z]:\\'
}

function Assert-NoReparsePath {
    param(
        [string]$Path,
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Description path is required."
    }
    if (-not (Test-LocalWindowsPath $Path)) {
        throw "$Description must be an absolute local Windows drive path: $Path"
    }
    $current = [System.IO.Path]::GetFullPath($Path)
    while ($true) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Description must not traverse a reparse point: $current"
            }
        }
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        if ($parent.FullName -eq $current) { break }
        $current = $parent.FullName
    }
}

function Resolve-DirectoryPath {
    param(
        [string]$Path,
        [string]$Description
    )

    Assert-NoReparsePath $Path $Description
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not ($item -is [System.IO.DirectoryInfo])) {
        throw "$Description is not a directory: $Path"
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a reparse point: $Path"
    }
    return $item.FullName
}

function Resolve-RegularFilePath {
    param(
        [string]$Path,
        [string]$Description
    )

    Assert-NoReparsePath $Path $Description
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not ($item -is [System.IO.FileInfo])) {
        throw "$Description is not a regular file: $Path"
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a reparse point: $Path"
    }
    return $item.FullName
}

function Assert-PathUnder {
    param(
        [string]$Candidate,
        [string]$Root,
        [string]$Description
    )

    $candidateFull = [System.IO.Path]::GetFullPath($Candidate)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    if (-not $rootFull.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $rootFull = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    }
    if (-not $candidateFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description must stay under repository root: $candidateFull"
    }
    return $candidateFull
}

function Get-RepoPath {
    param(
        [string]$RelativePath
    )

    return Join-Path $script:ResolvedRepoRoot $RelativePath
}

function Test-RepoRelativePresence {
    param(
        [string]$RelativePath
    )

    $candidate = Get-RepoPath $RelativePath
    if ($RelativePath.IndexOfAny([char[]]@('*', '?')) -ge 0) {
        $matches = @(Get-ChildItem -Path $candidate -File -ErrorAction Stop)
        return ($matches.Count -gt 0)
    }
    return (Test-Path -LiteralPath $candidate)
}

function Test-ExactLines {
    param(
        [string]$Path,
        [string[]]$Expected,
        [string]$Description
    )

    $content = Get-Content -LiteralPath $Path -ErrorAction Stop
    $lines = @(
        $content |
            Where-Object { $_ -match '\S' } |
            Where-Object { -not $_.TrimStart().StartsWith("#") }
    )
    $unexpected = @($lines | Where-Object { $_ -notmatch '^[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+_-]+$' })
    $missing = @($Expected | Where-Object { $lines -notcontains $_ })
    $extra = @($lines | Where-Object { $Expected -notcontains $_ })

    [pscustomobject]@{
        name = $Description
        path = $Path
        ok = ($unexpected.Count -eq 0 -and $missing.Count -eq 0 -and $extra.Count -eq 0)
        line_count = $lines.Count
        missing = $missing
        extra = $extra
        unexpected = $unexpected
    }
}

function New-LockfileCheck {
    param(
        [string]$Component,
        [string]$Manifest,
        [string]$Lockfile,
        [bool]$RequiredForRelease = $true
    )

    $manifestPath = Get-RepoPath $Manifest
    $lockPath = Get-RepoPath $Lockfile
    [pscustomobject]@{
        component = $Component
        manifest = $Manifest
        manifest_present = (Test-RepoRelativePresence $Manifest)
        lockfile = $Lockfile
        lockfile_present = (Test-RepoRelativePresence $Lockfile)
        required_for_release = $RequiredForRelease
    }
}

function Count-RegexMatches {
    param(
        [string]$Text,
        [string]$Pattern
    )

    return [System.Text.RegularExpressions.Regex]::Matches(
        $Text,
        $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::Multiline
    ).Count
}

function New-LockfileSummary {
    param(
        [string]$Ecosystem,
        [string]$Lockfile,
        [string]$PackagePattern,
        [string]$IntegrityPattern,
        [string]$IntegrityDescription
    )

    $fullPath = Get-RepoPath $Lockfile
    $present = Test-RepoRelativePresence $Lockfile
    $packageCount = 0
    $integrityCount = 0
    if ($present) {
        $text = Read-AvoraxGateTextFileBounded $fullPath $maxTextFileBytes "$Ecosystem lockfile $Lockfile"
        $packageCount = Count-RegexMatches $text $PackagePattern
        $integrityCount = Count-RegexMatches $text $IntegrityPattern
    }

    [pscustomobject]@{
        ecosystem = $Ecosystem
        lockfile = $Lockfile
        present = $present
        package_count = $packageCount
        integrity_evidence = $IntegrityDescription
        integrity_entry_count = $integrityCount
    }
}

function Write-JsonAtomic {
    param(
        [string]$Path,
        [object]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }
    $fullPath = Assert-PathUnder $Path $script:ResolvedRepoRoot "Report path"
    Assert-NoReparsePath $fullPath "Report path"
    $parent = Split-Path -Parent $fullPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Assert-NoReparsePath $parent "Report directory"
        if (-not (Test-Path -LiteralPath $parent)) {
            [System.IO.Directory]::CreateDirectory($parent) | Out-Null
        }
        [void](Resolve-DirectoryPath $parent "Report directory")
    } else {
        $parent = $script:ResolvedRepoRoot
    }
    if (Test-Path -LiteralPath $fullPath) {
        [void](Resolve-RegularFilePath $fullPath "existing dependency evidence report")
    }
    $tempPath = Join-Path $parent ("." + (Split-Path $fullPath -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".tmp")
    $backupPath = Join-Path $parent ("." + (Split-Path $fullPath -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".bak")
    $json = $Value | ConvertTo-Json -Depth 8
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($tempPath, $json, $encoding)
        [void](Resolve-RegularFilePath $tempPath "temporary dependency evidence report")
        if (Test-Path -LiteralPath $fullPath) {
            [System.IO.File]::Replace($tempPath, $fullPath, $backupPath)
        } else {
            [System.IO.File]::Move($tempPath, $fullPath)
        }
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            [void](Resolve-RegularFilePath $tempPath "temporary dependency evidence report")
            Remove-Item -LiteralPath $tempPath -Force
        }
        if (Test-Path -LiteralPath $backupPath) {
            [void](Resolve-RegularFilePath $backupPath "dependency evidence report backup file")
            Remove-Item -LiteralPath $backupPath -Force
        }
    }
}

$script:ResolvedRepoRoot = Resolve-DirectoryPath ([System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $RepoRoot).Path)) "Repository root"

$directExpected = @(
    "onnx==1.22.0",
    "numpy==2.2.6",
    "jsonschema==4.26.0"
)
$lockExpected = @(
    "attrs==26.1.0",
    "jsonschema==4.26.0",
    "jsonschema-specifications==2025.9.1",
    "ml_dtypes==0.5.4",
    "numpy==2.2.6",
    "onnx==1.22.0",
    "protobuf==7.35.1",
    "referencing==0.37.0",
    "rpds-py==2026.5.1",
    "typing_extensions==4.15.0"
)

$requirementChecks = @(
    $(Test-ExactLines -Path (Get-RepoPath "ml\requirements.txt") -Expected $directExpected -Description "python_direct_requirements"),
    $(Test-ExactLines -Path (Get-RepoPath "ml\requirements.lock.txt") -Expected $lockExpected -Description "python_verification_lock")
)

$lockfileChecks = @(
    $(New-LockfileCheck "Root Rust workspace" "Cargo.toml" "Cargo.lock"),
    $(New-LockfileCheck "Native engine" "core\zentor_native_engine\Cargo.toml" "core\zentor_native_engine\Cargo.lock"),
    $(New-LockfileCheck "Local core" "core\zentor_local_core\Cargo.toml" "core\zentor_local_core\Cargo.lock"),
    $(New-LockfileCheck "Guard service" "core\zentor_guard_service\Cargo.toml" "core\zentor_guard_service\Cargo.lock"),
    $(New-LockfileCheck "Update service (workspace member)" "core\avorax_update_service\Cargo.toml" "Cargo.lock"),
    $(New-LockfileCheck "API service" "services\api\Cargo.toml" "services\api\Cargo.lock"),
    $(New-LockfileCheck "Flutter client" "apps\zentor_client\pubspec.yaml" "apps\zentor_client\pubspec.lock"),
    $(New-LockfileCheck "Zentor protocol package" "packages\zentor_protocol\pubspec.yaml" "packages\zentor_protocol\pubspec.lock"),
    $(New-LockfileCheck "Avorax protocol package" "packages\avorax_protocol\pubspec.yaml" "packages\avorax_protocol\pubspec.lock"),
    $(New-LockfileCheck "Android Gradle dependencies (non-Windows release path)" "apps\zentor_client\android\settings.gradle.kts" "apps\zentor_client\android\gradle.lockfile" $false),
    $(New-LockfileCheck "Archived legacy website" "archive\*_website_old\package.json" "archive\*_website_old\package-lock.json" $false)
)

$wrapperPath = Get-RepoPath "apps\zentor_client\android\gradle\wrapper\gradle-wrapper.properties"
$wrapperText = Read-AvoraxGateTextFileBounded $wrapperPath $maxTextFileBytes "Gradle wrapper properties"
$expectedGradleHash = "b84e04fa845fecba48551f425957641074fcc00a88a84d2aae5808743b35fc85"
$gradleWrapperCheck = [pscustomobject]@{
    name = "android_gradle_wrapper"
    path = "apps\zentor_client\android\gradle\wrapper\gradle-wrapper.properties"
    url_pinned = $wrapperText.Contains("distributionUrl=https\://services.gradle.org/distributions/gradle-9.1.0-all.zip")
    sha256_pinned = $wrapperText.Contains("distributionSha256Sum=$expectedGradleHash")
    expected_sha256 = $expectedGradleHash
}

$lockfileSummaries = @(
    $(New-LockfileSummary "cargo" "Cargo.lock" '^\[\[package\]\]' '^\s*checksum\s*=' "Cargo registry checksum entries"),
    $(New-LockfileSummary "cargo" "core\zentor_native_engine\Cargo.lock" '^\[\[package\]\]' '^\s*checksum\s*=' "Cargo registry checksum entries"),
    $(New-LockfileSummary "cargo" "core\zentor_local_core\Cargo.lock" '^\[\[package\]\]' '^\s*checksum\s*=' "Cargo registry checksum entries"),
    $(New-LockfileSummary "cargo" "core\zentor_guard_service\Cargo.lock" '^\[\[package\]\]' '^\s*checksum\s*=' "Cargo registry checksum entries"),
    $(New-LockfileSummary "cargo" "services\api\Cargo.lock" '^\[\[package\]\]' '^\s*checksum\s*=' "Cargo registry checksum entries"),
    $(New-LockfileSummary "pub" "apps\zentor_client\pubspec.lock" '^\s{2}[A-Za-z0-9_][A-Za-z0-9_-]*:\s*$' '^\s+sha256:\s*' "pub.dev SHA-256 entries"),
    $(New-LockfileSummary "pub" "packages\zentor_protocol\pubspec.lock" '^\s{2}[A-Za-z0-9_][A-Za-z0-9_-]*:\s*$' '^\s+sha256:\s*' "pub.dev SHA-256 entries"),
    $(New-LockfileSummary "pub" "packages\avorax_protocol\pubspec.lock" '^\s{2}[A-Za-z0-9_][A-Za-z0-9_-]*:\s*$' '^\s+sha256:\s*' "pub.dev SHA-256 entries"),
    $(New-LockfileSummary "python" "ml\requirements.lock.txt" '^[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+_-]+$' '^[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+_-]+$' "exact version pins")
)

$licenseInventory = [pscustomobject]@{
    status = "source_level_partial"
    evidence_basis = "lockfiles, exact requirement pins, pinned wrapper hash, and documented license notes only"
    full_release_sbom_required = $true
    machine_wide_dependency_installation = $false
    network_access_required = $false
    documentation = "docs\dependency-license-inventory.md"
    documented_license_notes = @(
        [pscustomobject]@{
            component = "Python ML tooling"
            packages = @("onnx==1.22.0", "numpy==2.2.6", "jsonschema==4.26.0")
            licenses = @("Apache-2.0", "BSD License", "MIT")
            status = "documented metadata verified for pinned direct requirements"
        },
        [pscustomobject]@{
            component = "Rust deflate helper"
            packages = @("flate2 1.1.9", "miniz_oxide 0.8.9", "crc32fast 1.5.0", "adler2 2.0.1")
            licenses = @("MIT OR Apache-2.0", "MIT OR Zlib OR Apache-2.0", "0BSD OR MIT OR Apache-2.0")
            status = "documented local crate metadata checked for bounded OOXML deflate helper"
        }
    )
}

$missingRequiredLocks = @(
    $lockfileChecks |
        Where-Object { $_.required_for_release -and (-not $_.lockfile_present) } |
        ForEach-Object { $_.lockfile }
)
$failedRequirementChecks = @(
    $requirementChecks |
        Where-Object { -not $_.ok } |
        ForEach-Object { $_.name }
)
$wrapperFailures = @()
if (-not $gradleWrapperCheck.url_pinned) { $wrapperFailures += "Gradle wrapper URL is not pinned to 9.1.0-all" }
if (-not $gradleWrapperCheck.sha256_pinned) { $wrapperFailures += "Gradle wrapper distributionSha256Sum is missing or unexpected" }

$releaseBlockers = @()
$releaseBlockers += $missingRequiredLocks
$releaseBlockers += $failedRequirementChecks
$releaseBlockers += $wrapperFailures

$report = [pscustomobject]@{
    generated_utc = (Get-Date).ToUniversalTime().ToString("o")
    repo_root = $script:ResolvedRepoRoot
    allow_known_blockers = [bool]$AllowKnownBlockers
    ok = ($releaseBlockers.Count -eq 0)
    partial = ($releaseBlockers.Count -gt 0 -and [bool]$AllowKnownBlockers)
    requirement_checks = $requirementChecks
    lockfile_checks = $lockfileChecks
    gradle_wrapper = $gradleWrapperCheck
    lockfile_summaries = $lockfileSummaries
    license_inventory = $licenseInventory
    release_blockers = $releaseBlockers
}

Write-JsonAtomic $ReportPath $report

if ($releaseBlockers.Count -gt 0 -and -not $AllowKnownBlockers) {
    Write-Error ("Dependency evidence check failed: " + ($releaseBlockers -join "; "))
    exit 1
}

if ($releaseBlockers.Count -gt 0) {
    Write-Output ("Dependency evidence check completed with known blockers: " + ($releaseBlockers -join "; "))
} else {
    Write-Output "Dependency evidence check passed."
}
