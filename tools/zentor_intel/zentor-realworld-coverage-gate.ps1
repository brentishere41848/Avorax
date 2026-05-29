$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
Push-Location $root
try {
  cargo test --manifest-path core\zentor_native_engine\Cargo.toml
  if ($LASTEXITCODE -ne 0) { throw "Zentor Native Engine tests failed." }
  powershell -ExecutionPolicy Bypass -File tools\branding\branding-check.ps1
  if ($LASTEXITCODE -ne 0) { throw "Branding check failed." }
  $forbidden = Get-ChildItem -Recurse -File |
    Where-Object {
      $_.FullName -notmatch "\\(target|build|archive|dist|\.git|\.dart_tool|node_modules)\\" -and
      $_.Extension.ToLowerInvariant() -in @(".vir", ".malware", ".sample")
    }
  if ($forbidden) {
    $forbidden | ForEach-Object { Write-Error "Forbidden malware-like binary/sample extension: $($_.FullName)" }
    throw "Forbidden malware samples found."
  }
  Write-Host "Zentor real-world coverage gate passed."
} finally {
  Pop-Location
}
