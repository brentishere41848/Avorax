param(
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Channel = "dev",
  [string]$PayloadRoot = "dist\windows-msi\stage",
  [string]$OutputDir = "dist\updates",
  [string]$SignerCommand = $env:AVORAX_UPDATE_SIGNER
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$payloadSource = Join-Path $root $PayloadRoot
if (-not (Test-Path -LiteralPath $payloadSource)) {
  throw "Payload root was not found. Build the app/installer stage first: $payloadSource"
}
if ([string]::IsNullOrWhiteSpace($SignerCommand)) {
  throw "AVORAX_UPDATE_SIGNER is required. Refusing to create an unsigned .aup package."
}

$out = Join-Path $root $OutputDir
$packageId = "avorax-$Version-$Channel"
$publicKeyId = if ([string]::IsNullOrWhiteSpace($env:AVORAX_UPDATE_PUBLIC_KEY_ID)) { "avorax-dev-ed25519" } else { $env:AVORAX_UPDATE_PUBLIC_KEY_ID }
$work = Join-Path $out "work-$packageId"
$payload = Join-Path $work "payload"
if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $payload | Out-Null
$payloadApp = Join-Path $payload "app"
$payloadServices = Join-Path $payload "services"
$payloadEngine = Join-Path $payload "engine"
$payloadDocs = Join-Path $payload "docs"
$payloadTools = Join-Path $payload "tools"
New-Item -ItemType Directory -Force -Path $payloadApp, $payloadServices | Out-Null

$serviceFiles = @("avorax_core_service.exe", "avorax_guard_service.exe", "avorax_update_service.exe")
foreach ($name in $serviceFiles) {
  $source = Join-Path $payloadSource $name
  if (Test-Path -LiteralPath $source) {
    Copy-Item -LiteralPath $source -Destination (Join-Path $payloadServices $name) -Force
  }
}

Get-ChildItem -LiteralPath $payloadSource -File | Where-Object {
  $serviceFiles -notcontains $_.Name
} | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $payloadApp $_.Name) -Force
}

Get-ChildItem -LiteralPath $payloadSource -Directory | Where-Object {
  $_.Name -notin @("engine", "docs", "tools")
} | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $payloadApp $_.Name) -Recurse -Force
}

foreach ($dir in @("engine", "docs", "tools")) {
  $source = Join-Path $payloadSource $dir
  if (Test-Path -LiteralPath $source) {
    $destination = Join-Path $payload $dir
    Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force
  }
}

if (-not (Test-Path -LiteralPath (Join-Path $payloadServices "avorax_update_service.exe"))) {
  throw "Payload stage is missing avorax_update_service.exe; refusing to create an in-app update package."
}
if (-not (Test-Path -LiteralPath $payloadEngine)) {
  throw "Payload stage is missing engine assets; refusing to create an update package that would leave the engine unavailable."
}

$hashes = [ordered]@{}
Get-ChildItem -LiteralPath $payload -Recurse -File | Sort-Object FullName | ForEach-Object {
  $relative = $_.FullName.Substring($payload.Length).TrimStart("\", "/").Replace("\", "/")
  $hashes[$relative] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}

$manifest = [ordered]@{
  product = "Avorax Anti-Virus"
  package_format_version = 1
  version = $Version
  previous_min_version = "0.0.0"
  channel = $Channel
  release_date = (Get-Date).ToUniversalTime().ToString("o")
  package_id = $packageId
  components = [ordered]@{
    app = Test-Path (Join-Path $payloadApp "Avorax.exe")
    core_service = Test-Path (Join-Path $payloadServices "avorax_core_service.exe")
    guard_service = Test-Path (Join-Path $payloadServices "avorax_guard_service.exe")
    update_service = Test-Path (Join-Path $payloadServices "avorax_update_service.exe")
    native_engine_assets = Test-Path $payloadEngine
    signatures = Test-Path (Join-Path $payloadEngine "signatures")
    rules = Test-Path (Join-Path $payloadEngine "rules")
    ml_model = Test-Path (Join-Path $payloadEngine "ml")
    trust_packs = Test-Path (Join-Path $payloadEngine "trust")
    docs = Test-Path $payloadDocs
    driver_tools = $false
  }
  requires_restart = $true
  requires_reboot = $false
  requires_admin = $true
  driver_update_included = $false
  migration_steps = @()
  rollback_supported = $true
  payload_hashes = $hashes
  package_sha256 = ""
  signature_algorithm = "ed25519"
  public_key_id = $publicKeyId
  release_notes_url = $null
}

$manifestPath = Join-Path $work "manifest.json"
$sigPath = Join-Path $work "manifest.sig"
($manifest | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $manifestPath -Encoding UTF8
& $SignerCommand $manifestPath $sigPath
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sigPath)) {
  throw "Update manifest signing failed. No .aup package was produced."
}

$packagePath = Join-Path $out "Avorax-AntiVirus-$Version.aup"
if (Test-Path -LiteralPath $packagePath) { Remove-Item -LiteralPath $packagePath -Force }
Compress-Archive -Path (Join-Path $work "*") -DestinationPath $packagePath -Force
$packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()

$feed = [ordered]@{
  product = "Avorax Anti-Virus"
  channel = $Channel
  latest_version = $Version
  minimum_supported_version = "0.0.0"
  packages = @(
    [ordered]@{
      version = $Version
      package_url = "Avorax-AntiVirus-$Version.aup"
      package_sha256 = $packageHash
      release_notes = "Avorax $Version update package."
      published_at = (Get-Date).ToUniversalTime().ToString("o")
      required = $false
      critical = $false
      rollback_supported = $true
    }
  )
}
($feed | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath (Join-Path $out "update-feed.json") -Encoding UTF8
$feedPath = Join-Path $out "update-feed.json"
Write-Host "Created update package: $packagePath"
Write-Host "Created update feed: $feedPath"
