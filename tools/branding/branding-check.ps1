param(
    [string]$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\security\avorax-security-gate-tools.ps1")

$legacy = ("Pa" + "sus")
$terms = @(
    $legacy,
    $legacy.ToUpperInvariant(),
    $legacy.ToLowerInvariant(),
    ("anti" + "-cheat"),
    ("fair" + " play"),
    ("gaming" + " protection"),
    ("game" + " setup"),
    ("player" + " session"),
    ("match" + " telemetry")
)

$migrationNote = "docs/migration-from-" + $legacy.ToLowerInvariant() + ".md"
$exclude = @(
    "!.git/**",
    "!archive/**",
    "!**/target/**",
    "!**/build/**",
    "!**/.dart_tool/**",
    "!**/node_modules/**",
    "!**/dist/**",
    "!$migrationNote"
)

$maxDiagnosticChars = 4096
$maxDiagnosticBytes = 65536

function Get-BoundedDiagnostic {
    param(
        [AllowNull()][object]$Value,
        [int]$MaxLength = $maxDiagnosticChars
    )

    if ($null -eq $Value) {
        return ""
    }

    if ($Value -is [array]) {
        $text = ($Value | ForEach-Object {
            if ($null -eq $_) {
                ""
            } else {
                [string]$_
            }
        }) -join [Environment]::NewLine
    } else {
        $text = [string]$Value
    }

    if ($text.Length -le $MaxLength) {
        return $text
    }

    return $text.Substring(0, $MaxLength) + "...[truncated]"
}

function Get-RipgrepPath {
    try {
        $commands = @(Get-Command -Name "rg" -CommandType Application -ErrorAction Stop)
    } catch [System.Management.Automation.CommandNotFoundException] {
        return $null
    } catch {
        throw
    }

    if ($commands.Count -eq 0) {
        return $null
    }

    $command = $commands[0]
    if ([string]::IsNullOrWhiteSpace($command.Source)) {
        return $null
    }

    return $command.Source
}

function Invoke-RipgrepSearch {
    param(
        [string]$RipgrepPath,
        [string[]]$Arguments
    )

    try {
        $diagnostic = Invoke-AvoraxGateCommandDiagnostic $RipgrepPath $Arguments "ripgrep branding search" $maxDiagnosticBytes
        $matches = @()
        if (-not [string]::IsNullOrWhiteSpace($diagnostic.stdout)) {
            $matches = @($diagnostic.stdout -split "`r?`n")
        }

        return [pscustomobject]@{
            ExitCode = $diagnostic.exit_code
            Matches = @($matches)
            Error = Get-BoundedDiagnostic $diagnostic.stderr
        }
    } catch {
        return [pscustomobject]@{
            ExitCode = 2
            Matches = @()
            Error = Get-BoundedDiagnostic $_.Exception.Message
        }
    }
}

function Test-PathExcluded {
    param([string]$RelativePath)

    $normalized = $RelativePath.Replace("\", "/")
    if ($normalized -eq $migrationNote) {
        return $true
    }

    $excludedPrefixes = @(
        ".git/",
        "archive/"
    )
    foreach ($prefix in $excludedPrefixes) {
        if ($normalized.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    $excludedSegments = @(
        "/target/",
        "/build/",
        "/.dart_tool/",
        "/node_modules/",
        "/dist/"
    )
    foreach ($segment in $excludedSegments) {
        if (("/" + $normalized).Contains($segment)) {
            return $true
        }
    }

    return $false
}

function Test-AllowedHistoricalMatch {
    param(
        [string]$Line,
        [string]$Term
    )

    $legacyRepo = "github.com/brentishere41848/" + $legacy.ToLowerInvariant() + "_anti-virus.git"
    if ($Term -eq $legacy.ToLowerInvariant() -and $Line.Contains($legacyRepo)) {
        return $true
    }

    return $false
}

function Get-RelativePathCompat {
    param(
        [string]$BasePath,
        [string]$FullPath
    )

    if ([System.IO.Path].GetMethod("GetRelativePath", [type[]]@([string], [string]))) {
        return [System.IO.Path]::GetRelativePath($BasePath, $FullPath)
    }

    $base = (Resolve-Path $BasePath).Path.TrimEnd("\") + "\"
    $baseUri = New-Object System.Uri($base)
    $fullUri = New-Object System.Uri($FullPath)
    return [System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($fullUri).ToString()).Replace("/", "\")
}

function Search-WithPowerShell {
    param(
        [string]$Term,
        [string]$SearchRoot
    )

    $rootPath = (Resolve-Path $SearchRoot).Path
    $results = @()

    $excludedDirectoryNames = @(
        ".git",
        "archive",
        "target",
        "build",
        ".dart_tool",
        ".gradle",
        "ephemeral",
        "node_modules",
        "dist"
    )
    $binaryExtensions = @(
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".exe",
        ".dll",
        ".sys",
        ".msi",
        ".zip",
        ".7z",
        ".onnx",
        ".db",
        ".pdb",
        ".obj",
        ".lib",
        ".so",
        ".dylib",
        ".pmodel",
        ".zmodel",
        ".psig",
        ".zsig",
        ".ptrust",
        ".ztrust"
    )

    $directories = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
    $directories.Push((Get-Item -LiteralPath $rootPath))

    while ($directories.Count -gt 0) {
        $directory = $directories.Pop()

        try {
            foreach ($childDirectory in Get-ChildItem -LiteralPath $directory.FullName -Directory -Force -ErrorAction Stop) {
                if ($excludedDirectoryNames -contains $childDirectory.Name) {
                    continue
                }
                $directories.Push($childDirectory)
            }

            foreach ($file in Get-ChildItem -LiteralPath $directory.FullName -File -Force -ErrorAction Stop) {
                if ($binaryExtensions -contains $file.Extension.ToLowerInvariant()) {
                    continue
                }

                $relative = (Get-RelativePathCompat -BasePath $rootPath -FullPath $file.FullName).Replace("\", "/")
                if (Test-PathExcluded $relative) {
                    continue
                }

                try {
                    $fileMatches = Select-String -LiteralPath $file.FullName -SimpleMatch -Pattern $Term -ErrorAction Stop
                    foreach ($match in $fileMatches) {
                        $formattedMatch = "${relative}:$($match.LineNumber):$($match.Line)"
                        if (-not (Test-AllowedHistoricalMatch -Line $formattedMatch -Term $Term)) {
                            $results += $formattedMatch
                        }
                    }
                } catch {
                    Write-Warning "Skipping unreadable fallback branding-scan file '$relative': $($_.Exception.Message)"
                }
            }
        } catch {
            try {
                Write-Warning "Skipping unreadable fallback branding-scan directory '$($directory.FullName)': $($_.Exception.Message)"
            } catch {
                Write-Error "Fallback branding-scan warning emission failed for '$($directory.FullName)': $($_.Exception.Message)" -ErrorAction Continue
            }
        }
    }

    return $results
}

$failures = @()
$rgPath = Get-RipgrepPath
foreach ($term in $terms) {
    if ($null -ne $rgPath) {
        $args = @("-n", "-S", [regex]::Escape($term), $Root)
        foreach ($glob in $exclude) {
            $args += "--glob"
            $args += $glob
        }
        $result = Invoke-RipgrepSearch -RipgrepPath $rgPath -Arguments $args
        if ($result.ExitCode -gt 1) {
            $failures += "Branding search failed for term [$term] with rg exit code $($result.ExitCode):"
            $failures += $result.Error
            continue
        }

        $matches = $result.Matches
        if ($result.ExitCode -eq 0 -and $matches) {
            $matches = @($matches | Where-Object { -not (Test-AllowedHistoricalMatch -Line $_ -Term $term) })
        }
        if ($result.ExitCode -eq 0 -and $matches) {
            $failures += "Forbidden active branding term [$term]:"
            $failures += $matches
        }
    } else {
        $matches = Search-WithPowerShell -Term $term -SearchRoot $Root
        if ($matches) {
            $failures += "Forbidden active branding term [$term]:"
            $failures += $matches
        }
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host $_ }
    exit 1
}

Write-Host "Avorax branding check passed."
