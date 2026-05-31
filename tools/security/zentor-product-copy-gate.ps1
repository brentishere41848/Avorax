$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$scanRoots = @(
  "apps\zentor_client\lib",
  "apps\zentor_client\test",
  "packages\zentor_protocol\lib",
  "installer\windows",
  "README.md",
  "docs\anti-virus-overview.md",
  "docs\architecture.md",
  "docs\client-ui.md",
  "docs\limitations.md",
  "docs\native-engine.md",
  "docs\real-time-protection.md",
  "docs\quarantine.md",
  "docs\recovery-vault.md"
)

$legacy = ("pa" + "sus")
$forbidden = @(
  $legacy,
  ("zentor" + " anti-virus"),
  ("zentor" + " native"),
  ("zentor" + " cloud"),
  ("zentor" + " guard"),
  ("zentor" + " core"),
  ("zentor" + " recovery"),
  ("zentor" + " quarantine"),
  ("zentor" + " checks"),
  ("zentor" + " scans"),
  ("anti" + "-cheat"),
  ("fair" + " play"),
  ("gaming" + " protection"),
  ("game" + " setup"),
  ("player" + " session"),
  ("match" + " telemetry"),
  ("fake" + " checkout"),
  ("fake" + " license"),
  ("fake" + " reviews"),
  ("fake" + " awards"),
  ("100" + "% protection"),
  ("perfect" + " protection"),
  ("best" + " antivirus"),
  ("guaranteed" + " protection"),
  ("certified" + " by av-test"),
  ("trusted" + " by millions")
)

$textExtensions = @(
  ".dart",
  ".md",
  ".json",
  ".yaml",
  ".yml",
  ".xml",
  ".wxs",
  ".wxl",
  ".ps1",
  ".sh",
  ".txt"
)

$violations = @()
foreach ($relative in $scanRoots) {
  $path = Join-Path $root $relative
  if (-not (Test-Path -LiteralPath $path)) { continue }

  $files = if ((Get-Item -LiteralPath $path).PSIsContainer) {
    Get-ChildItem -LiteralPath $path -Recurse -File |
      Where-Object { $textExtensions -contains $_.Extension.ToLowerInvariant() }
  } else {
    @(Get-Item -LiteralPath $path)
  }

  foreach ($file in $files) {
    $content = (Get-Content -Raw -LiteralPath $file.FullName).ToLowerInvariant()
    foreach ($phrase in $forbidden) {
      if ($content.Contains($phrase)) {
        $violations += "$($file.FullName): forbidden product-copy phrase '$phrase'"
      }
    }
  }
}

if ($violations.Count -gt 0) {
  $violations | ForEach-Object { Write-Error $_ }
  exit 1
}

Write-Host "Avorax product copy gate passed."
