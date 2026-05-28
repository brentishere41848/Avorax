param(
    [string]$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
)

$ErrorActionPreference = "Stop"

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

function Test-CommandAvailable {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
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
                        $results += "${relative}:$($match.LineNumber):$($match.Line)"
                    }
                } catch {
                    # Ignore unreadable or binary-like files; active text assets are covered by normal scans.
                }
            }
        } catch {
            try {
                Write-Warning "Skipping unreadable directory: $($directory.FullName)"
            } catch {
            }
        }
    }

    return $results
}

$failures = @()
foreach ($term in $terms) {
    if (Test-CommandAvailable "rg") {
        $args = @("-n", "-S", [regex]::Escape($term), $Root)
        foreach ($glob in $exclude) {
            $args += "--glob"
            $args += $glob
        }
        $matches = & rg @args 2>$null
        if ($LASTEXITCODE -eq 0 -and $matches) {
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

Write-Host "Zentor branding check passed."
