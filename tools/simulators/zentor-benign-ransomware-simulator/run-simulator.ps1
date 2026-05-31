param(
  [string]$Root = $(Join-Path ([System.IO.Path]::GetTempPath()) ("zentor-ransomware-sim-" + [guid]::NewGuid().ToString("N"))),
  [int]$FileCount = 40
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Root | Out-Null

for ($i = 0; $i -lt $FileCount; $i++) {
  $path = Join-Path $Root ("document-$i.txt")
  Set-Content -LiteralPath $path -Value "Avorax safe ransomware simulator fixture $i" -Encoding UTF8
}

for ($i = 0; $i -lt $FileCount; $i++) {
  $path = Join-Path $Root ("document-$i.txt")
  Add-Content -LiteralPath $path -Value "modified quickly by safe simulator"
  Rename-Item -LiteralPath $path -NewName ("document-$i.locked-test") -Force
}

Set-Content -LiteralPath (Join-Path $Root "READ_ME_TEST_ONLY.txt") -Value "Safe Avorax simulator note. This is not a ransom note and contains no demand." -Encoding UTF8

[ordered]@{
  ok = $true
  simulator = "zentor-benign-ransomware-simulator"
  root = $Root
  files_modified = $FileCount
  scope = "temporary test directory only"
  warning = "This simulator is benign and must not be treated as a real malware sample."
} | ConvertTo-Json -Depth 4
