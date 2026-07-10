param(
  [string]$Version = "0.1.0",
  [string]$Configuration = "Release",
  [switch]$SkipFlutterBuild,
  [switch]$RequireLocalCore,
  [switch]$AllowIncompletePayload,
  [switch]$SkipClamAV,
  [switch]$IncludeClamAVCompatibility,
  [switch]$AllowDevelopmentModel,
  [switch]$RecoveryInstall,
  [switch]$RequireDriverPackage,
  [string]$DriverPackageDir,
  [string]$DotnetPath = $env:AVORAX_DOTNET,
  [string]$CargoPath = $env:CARGO,
  [string]$FlutterPath = $env:AVORAX_FLUTTER,
  [switch]$AllowClamAVDownload
)

$ErrorActionPreference = "Stop"
. (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path "tools\security\avorax-security-gate-tools.ps1")
. (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path "tools\windows\avorax-system32-tools.ps1")
$maxJsonBytes = 1048576
$maxJsonDiagnosticChars = 4096
$maxClamAvDownloadBytes = [int64]400MB
$clamAvDownloadTimeoutSeconds = 300

function Assert-SafeToken([string]$Value, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
    throw "$Description contains unsafe characters: $Value"
  }
}

function Test-LocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Assert-LocalNoReparsePath([string]$Path, [string]$Description) {
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

function Assert-PathUnder([string]$Path, [string]$Base, [string]$Description) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  $pathFull = [System.IO.Path]::GetFullPath($Path)
  $baseTrimmed = $baseFull.TrimEnd('\', '/')
  if ($pathFull.TrimEnd('\', '/').Equals($baseTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
    return
  }
  if (-not $pathFull.StartsWith($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must stay under $Base`: $Path"
  }
}

function Assert-RepoChildPath([string]$Path, [string]$Base, [string]$Description) {
  $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Description must resolve to a child path inside the Avorax repository root, not the repository root itself."
  }
  Assert-PathUnder $pathFull $baseFull $Description
}

function Resolve-InstallerRepoChildPath([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Description path is required."
  }
  $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
    $Path
  } else {
    Join-Path $script:AvoraxRepoRoot $Path
  }
  $full = [System.IO.Path]::GetFullPath($candidate)
  Assert-LocalNoReparsePath $full $Description
  Assert-RepoChildPath $full $script:AvoraxRepoRoot $Description
  return $full
}

function Get-SafeItem([string]$Path, [string]$Description, [string]$Kind) {
  Assert-LocalNoReparsePath $Path $Description
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $Path"
  }
  if ($Kind -eq "file" -and -not ($item -is [System.IO.FileInfo])) {
    throw "$Description is not a regular file: $Path"
  }
  if ($Kind -eq "directory" -and -not ($item -is [System.IO.DirectoryInfo])) {
    throw "$Description is not a directory: $Path"
  }
  return $item
}

function Get-SafeFile([string]$Path, [string]$Description) {
  return Get-SafeItem $Path $Description "file"
}

function Get-SafeDirectory([string]$Path, [string]$Description) {
  return Get-SafeItem $Path $Description "directory"
}

function Get-SafeExistingPath([string]$Path, [string]$Description) {
  Assert-LocalNoReparsePath $Path $Description
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description must not be a reparse point: $Path"
  }
  return $item
}

function Test-SafeFile([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  [void](Get-SafeFile $Path $Description)
  return $true
}

function Test-SafeDirectory([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  [void](Get-SafeDirectory $Path $Description)
  return $true
}

function Get-OptionalSafeFile([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  return (Get-SafeFile $Path $Description).FullName
}

function Get-RequiredToolPath([string]$Path, [string]$Description) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Description path is required. Refusing to launch an ambient command from PATH."
  }
  return (Get-SafeFile $Path $Description).FullName
}

function Get-JsonBooleanProperty([object]$Object, [string]$Name, [string]$Description) {
  if ($null -eq $Object) {
    throw "$Description object is missing."
  }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -eq $property) {
    throw "$Description.$Name is missing."
  }
  if (-not ($property.Value -is [bool])) {
    $type = if ($null -eq $property.Value) { "null" } else { $property.Value.GetType().Name }
    throw "$Description.$Name must be a JSON boolean, got $type."
  }
  return [bool]$property.Value
}

function Get-BoundedJsonDiagnostic([object]$Value) {
  if ($null -eq $Value) { return "" }
  $text = [string]$Value
  if ($text.Length -le $maxJsonDiagnosticChars) { return $text }
  return $text.Substring(0, $maxJsonDiagnosticChars) + "...[truncated]"
}

function Read-JsonFile([string]$Path, [string]$Description) {
  $file = Get-SafeFile $Path $Description
  try {
    $json = Read-AvoraxGateTextFileBounded $file.FullName $maxJsonBytes $Description
    return ConvertFrom-Json -InputObject $json -ErrorAction Stop
  } catch {
    $message = Get-BoundedJsonDiagnostic $_.Exception.Message
    if ($message.StartsWith("$Description exceeds ")) {
      throw $message
    }
    throw "$Description is not valid bounded JSON: $message"
  }
}

function Get-WindowsRuntimeRoot {
  $diagnostics = @()
  foreach ($name in @("SystemRoot", "WINDIR")) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
      $diagnostics += "$name is not set or is empty"
      continue
    }
    $root = $value.Trim()
    if (-not (Test-LocalWindowsPath $root)) {
      $diagnostics += "$name must be a local Windows drive path: $root"
      continue
    }
    try {
      return (Get-SafeDirectory $root "$name Windows runtime root").FullName
    } catch {
      $diagnostics += "$name Windows runtime root rejected: $($_.Exception.Message)"
    }
  }
  throw "Windows runtime root is unavailable: $($diagnostics -join '; ')"
}

function New-SafeDirectory([string]$Path, [string]$Description) {
  Assert-LocalNoReparsePath $Path $Description
  if ($script:AvoraxRepoRoot) {
    Assert-PathUnder $Path $script:AvoraxRepoRoot $Description
  }
  if (-not (Test-Path -LiteralPath $Path)) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }
  return (Get-SafeDirectory $Path $Description).FullName
}

function Remove-SafeDirectoryTree([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $directory = (Get-SafeDirectory $Path $Description).FullName
  if ($script:AvoraxRepoRoot) {
    Assert-PathUnder $directory $script:AvoraxRepoRoot $Description
  }
  Remove-Item -LiteralPath $directory -Recurse -Force
}

function Assert-NoReparseTree([string]$Path, [string]$Description) {
  $rootItem = Get-SafeDirectory $Path $Description
  Get-ChildItem -LiteralPath $rootItem.FullName -Force -Recurse -ErrorAction Stop | ForEach-Object {
    if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Description must not contain reparse points: $($_.FullName)"
    }
  }
}

function Invoke-InstallerCommand([string]$Tool, [string[]]$Arguments, [string]$DisplayName, [string]$WorkingDirectory = $null) {
  if ([string]::IsNullOrWhiteSpace($Tool)) {
    throw "$DisplayName could not run because its executable was unavailable."
  }
  $diagnostic = Invoke-AvoraxGateCommandDiagnostic $Tool $Arguments $DisplayName 32768 $WorkingDirectory
  if ($diagnostic.exit_code -ne 0) {
    throw "$DisplayName failed with exit code $($diagnostic.exit_code): $($diagnostic.output)"
  }
}

function Copy-Tree([string]$Source, [string]$Destination) {
  $sourceDirectory = (Get-SafeDirectory $Source "tree source").FullName
  Assert-NoReparseTree $sourceDirectory "tree source"
  Remove-SafeDirectoryTree $Destination "tree destination"
  $destinationDirectory = New-SafeDirectory $Destination "tree destination"
  Get-ChildItem -LiteralPath $sourceDirectory -Force | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $destinationDirectory -Recurse -Force
  }
}

function Copy-RequiredTree([string]$Source, [string]$Destination, [string]$Name) {
  [void](Get-SafeDirectory $Source "$Name source")
  Copy-Tree $Source $Destination
}

function Find-SafeFileInTree([string]$Root, [string]$Filter, [string]$Description) {
  $rootDirectory = (Get-SafeDirectory $Root "$Description root").FullName
  $matches = @(Get-ChildItem -LiteralPath $rootDirectory -Recurse -File -Filter $Filter -ErrorAction Stop | Sort-Object FullName)
  if ($matches.Count -eq 0) {
    return $null
  }

  return Get-SafeFile $matches[0].FullName $Description
}

function Assert-CompleteDriverPackage([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Required signed driver package directory was not found: $Path"
  }
  $packageDirectory = (Get-SafeDirectory $Path $Description).FullName
  Assert-NoReparseTree $packageDirectory $Description
  $driverSys = Find-SafeFileInTree $packageDirectory "ZentorAvFilter.sys" "signed Windows minifilter driver binary"
  $driverInf = Find-SafeFileInTree $packageDirectory "ZentorAvFilter.inf" "signed Windows minifilter driver INF"
  $driverCat = Find-SafeFileInTree $packageDirectory "*.cat" "signed Windows minifilter driver catalog"
  if (-not ($driverSys -and $driverInf -and $driverCat)) {
    throw "Driver package at $packageDirectory is incomplete. Required: ZentorAvFilter.sys, ZentorAvFilter.inf, and a signed .cat catalog."
  }
  return $packageDirectory
}

function Copy-RequiredFile([string]$Source, [string]$Destination, [string]$Name) {
  $sourceFile = (Get-SafeFile $Source "$Name file").FullName
  $destinationDirectory = New-SafeDirectory (Split-Path $Destination) "$Name destination directory"
  Assert-LocalNoReparsePath $Destination "$Name destination"
  if (Test-Path -LiteralPath $Destination) {
    [void](Get-SafeFile $Destination "$Name destination")
  }
  Copy-Item -LiteralPath $sourceFile -Destination (Join-Path $destinationDirectory (Split-Path $Destination -Leaf)) -Force
}

function Assert-StagePath([string]$RelativePath, [string]$Description) {
  $path = Join-Path $stageDir $RelativePath
  if (-not (Test-Path -LiteralPath $path)) {
    throw "Installer payload is incomplete. Missing $Description at $RelativePath"
  }
  [void](Get-SafeExistingPath $path "installer payload $Description")
}

function Copy-RequiredAlias([string]$Source, [string]$Destination, [string]$Name) {
  Copy-RequiredFile $Source $Destination $Name
}

function Remove-SafeRegularFileIfPresent([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  [void](Get-SafeFile $Path $Description)
  Remove-Item -LiteralPath $Path -Force
}

function Get-TextEncoding([string]$EncodingName) {
  switch ($EncodingName) {
    "ASCII" { return [System.Text.Encoding]::ASCII }
    "UTF8" { return New-Object System.Text.UTF8Encoding($false) }
    default { throw "Unsupported text encoding for installer write: $EncodingName" }
  }
}

function Write-TextFileAtomic([string]$Path, [string]$Value, [string]$EncodingName, [string]$Description) {
  $directory = New-SafeDirectory (Split-Path $Path) "$Description directory"
  Assert-LocalNoReparsePath $Path $Description
  if ($script:AvoraxRepoRoot) {
    Assert-PathUnder $Path $script:AvoraxRepoRoot $Description
  }
  if (Test-Path -LiteralPath $Path) {
    [void](Get-SafeFile $Path $Description)
  }
  $target = [System.IO.Path]::GetFullPath($Path)
  $tempPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".tmp")
  $backupPath = Join-Path $directory ("." + (Split-Path $Path -Leaf) + "." + [System.Guid]::NewGuid().ToString("N") + ".bak")
  $encoding = Get-TextEncoding $EncodingName
  try {
    [System.IO.File]::WriteAllText($tempPath, $Value, $encoding)
    [void](Get-SafeFile $tempPath "$Description temporary file")
    if (Test-Path -LiteralPath $target) {
      [System.IO.File]::Replace($tempPath, $target, $backupPath)
    } else {
      [System.IO.File]::Move($tempPath, $target)
    }
  } finally {
    Remove-SafeRegularFileIfPresent $tempPath "$Description temporary file"
    Remove-SafeRegularFileIfPresent $backupPath "$Description backup file"
  }
}

function Write-JsonFileAtomic([string]$Path, [object]$Value, [int]$Depth, [string]$Description) {
  Write-TextFileAtomic $Path ($Value | ConvertTo-Json -Depth $Depth) "UTF8" $Description
}

function Expand-SafeZip([string]$ZipPath, [string]$Destination, [string]$Description) {
  $zipFile = (Get-SafeFile $ZipPath "$Description archive").FullName
  Remove-SafeDirectoryTree $Destination "$Description extract destination"
  $destinationDirectory = New-SafeDirectory $Destination "$Description extract destination"
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [System.IO.Compression.ZipFile]::OpenRead($zipFile)
  $entryCount = 0
  $totalBytes = [int64]0
  $maxEntries = 5000
  $maxTotalBytes = [int64]350MB
  try {
    foreach ($entry in $archive.Entries) {
      $entryName = $entry.FullName -replace '\\', '/'
      if ([string]::IsNullOrWhiteSpace($entryName) -or $entryName.StartsWith('/') -or $entryName -match '^[A-Za-z]:' -or $entryName -match '(^|/)\.\.(/|$)') {
        throw "$Description archive contains an unsafe entry path: $($entry.FullName)"
      }
      $entryCount++
      if ($entryCount -gt $maxEntries) {
        throw "$Description archive exceeds the entry limit of $maxEntries"
      }
      $totalBytes += [int64]$entry.Length
      if ($totalBytes -gt $maxTotalBytes) {
        throw "$Description archive exceeds the uncompressed size limit of $maxTotalBytes bytes"
      }
      $targetPath = [System.IO.Path]::GetFullPath((Join-Path $destinationDirectory ($entryName -replace '/', [System.IO.Path]::DirectorySeparatorChar)))
      Assert-PathUnder $targetPath $destinationDirectory "$Description archive entry"
      if ($entryName.EndsWith('/')) {
        [System.IO.Directory]::CreateDirectory($targetPath) | Out-Null
        continue
      }
      $parent = [System.IO.Path]::GetDirectoryName($targetPath)
      [System.IO.Directory]::CreateDirectory($parent) | Out-Null
      if (Test-Path -LiteralPath $targetPath) {
        throw "$Description archive contains duplicate output path: $entryName"
      }
      $inputStream = $entry.Open()
      try {
        $outputStream = [System.IO.File]::Open($targetPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
          $inputStream.CopyTo($outputStream)
        } finally {
          $outputStream.Dispose()
        }
      } finally {
        $inputStream.Dispose()
      }
      [void](Get-SafeFile $targetPath "$Description extracted file")
    }
  } finally {
    $archive.Dispose()
  }
}

function Save-HttpsFileWithLimit([System.Uri]$Uri, [string]$Destination, [int64]$MaxBytes, [int]$TimeoutSeconds, [string]$Description) {
  if ($Uri.Scheme -ne "https") {
    throw "$Description URL must use HTTPS: $($Uri.AbsoluteUri)"
  }
  Assert-LocalNoReparsePath $Destination "$Description destination"
  if (Test-Path -LiteralPath $Destination) {
    [void](Get-SafeFile $Destination "$Description destination")
    throw "$Description destination already exists: $Destination"
  }
  $request = [System.Net.HttpWebRequest]::Create($Uri)
  $request.Method = "GET"
  $request.AllowAutoRedirect = $true
  $request.MaximumAutomaticRedirections = 5
  $request.Timeout = $TimeoutSeconds * 1000
  $request.ReadWriteTimeout = $TimeoutSeconds * 1000
  $response = $null
  $inputStream = $null
  $outputStream = $null
  try {
    $response = $request.GetResponse()
    $finalUri = $response.ResponseUri
    if ($null -eq $finalUri -or $finalUri.Scheme -ne "https") {
      throw "$Description final download URI must remain HTTPS."
    }
    if ($response.ContentLength -gt $MaxBytes) {
      throw "$Description content length $($response.ContentLength) exceeds limit $MaxBytes"
    }
    $inputStream = $response.GetResponseStream()
    $outputStream = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $buffer = New-Object byte[] 65536
    $total = [int64]0
    while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $total += [int64]$read
      if ($total -gt $MaxBytes) {
        throw "$Description exceeded limit $MaxBytes bytes during download"
      }
      $outputStream.Write($buffer, 0, $read)
    }
  } finally {
    if ($null -ne $outputStream) { $outputStream.Dispose() }
    if ($null -ne $inputStream) { $inputStream.Dispose() }
    if ($null -ne $response) { $response.Dispose() }
  }
}

function Ensure-ClamAVPackage([string]$ZipPath, [string]$Url, [string]$ExpectedSha256, [bool]$AllowDownload) {
  if ($ExpectedSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
    throw "ClamAV expected SHA-256 is invalid."
  }
  Assert-LocalNoReparsePath $ZipPath "ClamAV package cache"
  if (Test-Path -LiteralPath $ZipPath) {
    $cachedZip = (Get-SafeFile $ZipPath "cached ClamAV package").FullName
    $existingHash = (Get-FileHash -LiteralPath $cachedZip -Algorithm SHA256).Hash
    if ($existingHash -ne $ExpectedSha256.ToUpperInvariant()) {
      throw "Cached ClamAV package hash mismatch. Expected $ExpectedSha256 but found $existingHash at $cachedZip"
    }
    return
  }

  if (-not $AllowDownload) {
    throw "ClamAV compatibility package is not cached at $ZipPath. Pass -AllowClamAVDownload to fetch the pinned HTTPS package, or keep -IncludeClamAVCompatibility disabled."
  }
  $uri = [System.Uri]$Url
  if ($uri.Scheme -ne "https") {
    throw "ClamAV package URL must use HTTPS: $Url"
  }
  $zipDirectory = New-SafeDirectory (Split-Path $ZipPath) "ClamAV package cache directory"
  $tempZipPath = Join-Path $zipDirectory ("clamav-download-" + [System.Guid]::NewGuid().ToString("N") + ".zip.tmp")
  Write-Host "Downloading ClamAV runtime: $Url"
  try {
    Save-HttpsFileWithLimit $uri $tempZipPath $script:maxClamAvDownloadBytes $script:clamAvDownloadTimeoutSeconds "ClamAV package download"
    $downloadedZip = (Get-SafeFile $tempZipPath "downloaded ClamAV package").FullName
    $downloadedHash = (Get-FileHash -LiteralPath $downloadedZip -Algorithm SHA256).Hash
    if ($downloadedHash -ne $ExpectedSha256.ToUpperInvariant()) {
      throw "Downloaded ClamAV package hash mismatch. Expected $ExpectedSha256 but found $downloadedHash"
    }
    [System.IO.File]::Move($downloadedZip, [System.IO.Path]::GetFullPath($ZipPath))
  } finally {
    Remove-SafeRegularFileIfPresent $tempZipPath "temporary ClamAV package download"
  }
}

function Copy-ClamAVRuntime([string]$ZipPath, [string]$ExtractDir, [string]$Destination) {
  Expand-SafeZip $ZipPath $ExtractDir "ClamAV compatibility runtime"
  Remove-SafeDirectoryTree $Destination "ClamAV compatibility destination"
  $destinationDirectory = New-SafeDirectory $Destination "ClamAV compatibility destination"

  $sourceRoot = $ExtractDir
  $candidateRoots = Get-ChildItem -LiteralPath $ExtractDir -Directory
  foreach ($candidateRoot in $candidateRoots) {
    if (Test-SafeFile (Join-Path $candidateRoot.FullName "clamscan.exe") "ClamAV clamscan executable") {
      $sourceRoot = $candidateRoot.FullName
      break
    }
  }

  $runtimeExtensions = @(".exe", ".dll", ".txt", ".md")
  Get-ChildItem -LiteralPath $sourceRoot -File |
    Where-Object { $runtimeExtensions -contains $_.Extension.ToLowerInvariant() } |
    ForEach-Object {
      Copy-RequiredFile $_.FullName (Join-Path $destinationDirectory $_.Name) "ClamAV runtime file"
    }

  foreach ($directoryName in @("certs", "conf_examples", "COPYING")) {
    $sourceDirectory = Join-Path $sourceRoot $directoryName
    if (Test-Path -LiteralPath $sourceDirectory) {
      $sourceItem = Get-SafeExistingPath $sourceDirectory "ClamAV runtime component"
      if ($sourceItem -is [System.IO.DirectoryInfo]) {
        Copy-Tree $sourceDirectory (Join-Path $destinationDirectory $directoryName)
      } else {
        Copy-RequiredFile $sourceDirectory (Join-Path $destinationDirectory $directoryName) "ClamAV runtime component"
      }
    }
  }

  if (-not (Test-SafeFile (Join-Path $destinationDirectory "clamscan.exe") "ClamAV clamscan executable")) {
    throw "ClamAV runtime was expanded, but clamscan.exe was not found."
  }
}

function To-WixId([string]$Value) {
  $id = [regex]::Replace($Value, "[^A-Za-z0-9_]", "_")
  if ($id -match "^[0-9]") {
    $id = "I_$id"
  }
  if ($id.Length -gt 60) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
      $hash = [System.BitConverter]::ToString(
        $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
      ).Replace("-", "").Substring(0, 10)
    } finally {
      $sha.Dispose()
    }
    $id = $id.Substring(0, 45) + "_" + $hash
  }
  return $id
}

function XmlEscape([string]$Value) {
  return [System.Security.SecurityElement]::Escape($Value)
}

function Get-RelativePath([string]$Base, [string]$Path) {
  $baseFull = [IO.Path]::GetFullPath($Base).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $pathFull = [IO.Path]::GetFullPath($Path)
  if ($pathFull.TrimEnd('\', '/').Equals($baseFull.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    return "."
  }
  if ($pathFull.StartsWith($baseFull, [StringComparison]::OrdinalIgnoreCase)) {
    return $pathFull.Substring($baseFull.Length)
  }
  return $pathFull
}

function Get-FlutterBuildNumber([string]$Version) {
  $buildNumber = [regex]::Replace($Version, "[^0-9]", "")
  if ([string]::IsNullOrWhiteSpace($buildNumber)) {
    return "1"
  }
  return $buildNumber
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$script:AvoraxRepoRoot = $root
Assert-SafeToken $Version "Installer version"
Assert-SafeToken $Configuration "Flutter build configuration"
[void](Get-SafeDirectory $root "repository root")
$clientDir = Join-Path $root "apps\zentor_client"
$releaseDir = Join-Path $clientDir "build\windows\x64\runner\$Configuration"
$workspaceTargetDir = Join-Path $root "target\release"
$localCoreExe = Join-Path $root "core\zentor_local_core\target\x86_64-pc-windows-msvc\release\zentor_local_core.exe"
$localCoreExeGnu = Join-Path $root "core\zentor_local_core\target\x86_64-pc-windows-gnu\release\zentor_local_core.exe"
$localCoreExeDefault = Join-Path $root "core\zentor_local_core\target\release\zentor_local_core.exe"
$localCoreExeWorkspace = Join-Path $workspaceTargetDir "zentor_local_core.exe"
$guardServiceExeDefault = Join-Path $root "core\zentor_guard_service\target\release\zentor_guard_service.exe"
$guardServiceExeWorkspace = Join-Path $workspaceTargetDir "zentor_guard_service.exe"
$updateServiceExeDefault = Join-Path $root "core\avorax_update_service\target\release\avorax_update_service.exe"
$updateServiceExeWorkspace = Join-Path $workspaceTargetDir "avorax_update_service.exe"
$distRoot = Join-Path $root "dist"
$stageDir = Join-Path $distRoot "windows-msi\stage"
$wxsPath = Join-Path $distRoot "windows-msi\Avorax.wxs"
$bundleWxsPath = Join-Path $distRoot "windows-msi\Avorax.Bundle.wxs"
$msiPath = Join-Path $distRoot "Avorax-AntiVirus-$Version-x64.msi"
$exeInstallerPath = Join-Path $distRoot "Avorax-AntiVirus-$Version-x64-setup.exe"
$clamAvVersion = "1.5.2"
$clamAvUrl = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$clamAvVersion/clamav-$clamAvVersion.win.x64.zip"
$clamAvSha256 = "6F868ED7A7E5A15ACED82C53A4FA9F3F42FA9D7F7DE14A606BA8DB0756518EED"
$clamAvZipPath = Join-Path $PSScriptRoot "cache\clamav-$clamAvVersion.win.x64.zip"
$clamAvExtractDir = Join-Path $distRoot "windows-msi\clamav-extract"
$modelSourceDir = Join-Path $root "assets\models"
$nativeSourceDir = Join-Path $root "assets\zentor_native"
$yaraSourceDir = Join-Path $root "assets\yara"
$testAssetsSourceDir = Join-Path $root "assets\test"
$trustAssetsSourceDir = Join-Path $root "assets\trust"
$threatAssetsSourceDir = Join-Path $root "assets\threats"
$driverToolsSourceDir = Join-Path $root "core\zentor_windows_minifilter"
$processGuardToolsSourceDir = Join-Path $root "core\zentor_windows_process_guard"
$windowsToolsSourceDir = Join-Path $root "tools\windows"
$securityToolsSourceDir = Join-Path $root "tools\security"
$perfToolsSourceDir = Join-Path $root "tools\perf"
$brandingToolsSourceDir = Join-Path $root "tools\branding"
$zneToolsSourceDir = Join-Path $root "tools\zne"
$intelToolsSourceDir = Join-Path $root "tools\zentor_intel"
$simulatorsSourceDir = Join-Path $root "tools\simulators"
$updateToolsSourceDir = Join-Path $root "tools\update"
$docsSourceDir = Join-Path $root "docs"
$betaNoticeSource = Join-Path $root "installer\common\BETA-NOTICE.txt"
$driverPackageDefaultDir = Join-Path $distRoot "windows-driver\ZentorAvFilter"
$modelFile = Join-Path $modelSourceDir "zentor_static_malware_model.onnx"
$modelMetadataFile = Join-Path $modelSourceDir "zentor_static_malware_model.metadata.json"
$driverPackageInput = if ($DriverPackageDir) { $DriverPackageDir } else { $driverPackageDefaultDir }
$driverPackageSource = Resolve-InstallerRepoChildPath $driverPackageInput "signed Windows minifilter driver package source"
if ($RequireDriverPackage) {
  [void](Assert-CompleteDriverPackage $driverPackageSource "signed Windows minifilter driver package source")
}

$dotnet = Get-RequiredToolPath $DotnetPath ".NET SDK dotnet executable"

if (-not $SkipFlutterBuild) {
  $flutter = Get-RequiredToolPath $FlutterPath "Flutter executable"
  $flutterClientDir = (Get-SafeDirectory $clientDir "Flutter client directory").FullName
  $buildNumber = Get-FlutterBuildNumber $Version
  Invoke-InstallerCommand $flutter @(
    "build",
    "windows",
    "--release",
    "--build-name",
    $Version,
    "--build-number",
    $buildNumber,
    "--dart-define=AVORAX_APP_VERSION=$Version",
    "--dart-define=ZENTOR_APP_VERSION=$Version",
    "--dart-define=AVORAX_UPDATE_FEED_URL=https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json",
    "--dart-define=AVORAX_UPDATE_CHANNEL=dev",
    "--dart-define=AVORAX_UPDATES_REPO_OWNER=brentishere41848",
    "--dart-define=AVORAX_UPDATES_REPO_NAME=Avorax"
  ) "Flutter Windows release build" $flutterClientDir
}

if (-not (Test-SafeFile (Join-Path $releaseDir "Avorax.exe") "Flutter release Avorax.exe")) {
  $buildInstruction = if ($SkipFlutterBuild) {
    "Run the Flutter Windows release build first or omit -SkipFlutterBuild."
  } else {
    "Review the Flutter Windows release build diagnostics above."
  }
  throw "Flutter release output was not found at $releaseDir. $buildInstruction Building Avorax.exe requires Windows symlink support for Flutter plugins plus the Visual Studio Desktop C++ workload/components required by flutter doctor -v; this script will not stage a placeholder app executable."
}

if (-not (Test-SafeFile $localCoreExe "targeted local core executable") -and -not (Test-SafeFile $localCoreExeDefault "default local core executable") -and -not (Test-SafeFile $localCoreExeGnu "GNU local core executable") -and -not (Test-SafeFile $localCoreExeWorkspace "workspace local core executable")) {
  if ($AllowIncompletePayload -and -not $RequireLocalCore -and [string]::IsNullOrWhiteSpace($CargoPath)) {
    Write-Warning "zentor_local_core.exe is missing and Cargo was not invoked because -AllowIncompletePayload is set without an explicit -CargoPath."
  } else {
    $cargo = Get-RequiredToolPath $CargoPath "Cargo executable for zentor_local_core"
    $localCoreCrateDir = (Get-SafeDirectory (Join-Path $root "core\zentor_local_core") "zentor_local_core crate directory").FullName
    Invoke-InstallerCommand $cargo @("build", "--release") "zentor_local_core release build" $localCoreCrateDir
  }
}

if (-not (Test-SafeFile $guardServiceExeDefault "default Guard Service executable") -and -not (Test-SafeFile $guardServiceExeWorkspace "workspace Guard Service executable")) {
  if ($AllowIncompletePayload -and [string]::IsNullOrWhiteSpace($CargoPath)) {
    Write-Warning "zentor_guard_service.exe is missing and Cargo was not invoked because -AllowIncompletePayload is set without an explicit -CargoPath."
  } else {
    $cargo = Get-RequiredToolPath $CargoPath "Cargo executable for zentor_guard_service"
    $guardServiceCrateDir = (Get-SafeDirectory (Join-Path $root "core\zentor_guard_service") "zentor_guard_service crate directory").FullName
    Invoke-InstallerCommand $cargo @("build", "--release") "zentor_guard_service release build" $guardServiceCrateDir
  }
}

if (-not (Test-SafeFile $updateServiceExeDefault "default Update Service executable") -and -not (Test-SafeFile $updateServiceExeWorkspace "workspace Update Service executable")) {
  if ($AllowIncompletePayload -and [string]::IsNullOrWhiteSpace($CargoPath)) {
    Write-Warning "avorax_update_service.exe is missing and Cargo was not invoked because -AllowIncompletePayload is set without an explicit -CargoPath."
  } else {
    $cargo = Get-RequiredToolPath $CargoPath "Cargo executable for avorax_update_service"
    $updateServiceCrateDir = (Get-SafeDirectory (Join-Path $root "core\avorax_update_service") "avorax_update_service crate directory").FullName
    Invoke-InstallerCommand $cargo @("build", "--release") "avorax_update_service release build" $updateServiceCrateDir
  }
}

New-SafeDirectory (Split-Path $wxsPath) "Windows installer output directory" | Out-Null
Copy-Tree $releaseDir $stageDir

if (-not (Test-SafeFile $modelFile "AI model file") -or -not (Test-SafeFile $modelMetadataFile "AI model metadata file")) {
  throw "Avorax AI model assets are required: $modelFile and $modelMetadataFile"
}
$modelMetadata = Read-JsonFile $modelMetadataFile "AI model metadata file"
$modelProductionReady = Get-JsonBooleanProperty $modelMetadata "production_ready" "AI model metadata"
if (-not $modelProductionReady -and -not $AllowDevelopmentModel) {
  throw "The packaged AI model is marked production_ready=false. Provide a validated production model or pass -AllowDevelopmentModel for an explicitly non-production build."
}
$stageModelDir = Join-Path $stageDir "assets\models"
$releaseModelDir = Join-Path $releaseDir "assets\models"
Copy-RequiredTree $modelSourceDir $stageModelDir "AI model assets"
Copy-RequiredTree $modelSourceDir $releaseModelDir "AI model assets"

if (-not (Test-SafeFile (Join-Path $nativeSourceDir "signatures\zentor_core.zsig") "native signature pack") -or -not (Test-SafeFile (Join-Path $nativeSourceDir "rules\zentor_rules.zrule") "native rule pack") -or -not (Test-SafeFile (Join-Path $nativeSourceDir "ml\zentor_native_model.zmodel") "native ML model")) {
  throw "Avorax Native Engine assets are required under $nativeSourceDir"
}
$stageNativeDir = Join-Path $stageDir "assets\zentor_native"
$releaseNativeDir = Join-Path $releaseDir "assets\zentor_native"
Copy-RequiredTree $nativeSourceDir $stageNativeDir "Avorax Native Engine assets"
Copy-RequiredTree $nativeSourceDir $releaseNativeDir "Avorax Native Engine assets"

$stageEngineDir = Join-Path $stageDir "engine"
$releaseEngineDir = Join-Path $releaseDir "engine"
Copy-RequiredTree $nativeSourceDir $stageEngineDir "installed Avorax Native Engine assets"
Copy-RequiredTree $nativeSourceDir $releaseEngineDir "installed Avorax Native Engine assets"
New-SafeDirectory (Join-Path $stageEngineDir "config") "staged engine config directory" | Out-Null
New-SafeDirectory (Join-Path $releaseEngineDir "config") "release engine config directory" | Out-Null
$engineDefaultConfig = @{
  product = "Avorax Anti-Virus"
  engine = "Avorax Native Engine"
  installed_layout_version = 1
  compatibility_engines_enabled = $false
} | ConvertTo-Json -Depth 4
Write-TextFileAtomic (Join-Path $stageEngineDir "config\engine.default.json") $engineDefaultConfig "UTF8" "staged default engine config"
Write-TextFileAtomic (Join-Path $releaseEngineDir "config\engine.default.json") $engineDefaultConfig "UTF8" "release default engine config"
Copy-RequiredAlias (Join-Path $nativeSourceDir "signatures\zentor_core.zsig") (Join-Path $stageEngineDir "signatures\avorax_core.asig") "core native signature alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "signatures\zentor_core.zsig") (Join-Path $releaseEngineDir "signatures\avorax_core.asig") "core native signature alias"
Remove-SafeRegularFileIfPresent (Join-Path $stageEngineDir "signatures\zentor_core.zsig") "duplicate staged legacy core signature pack"
Remove-SafeRegularFileIfPresent (Join-Path $releaseEngineDir "signatures\zentor_core.zsig") "duplicate release legacy core signature pack"
foreach ($signatureAlias in @(
  @("zentor_realworld_hashes.zsig", "avorax_realworld_hashes.asig"),
  @("zentor_script_threats.zsig", "avorax_script_threats.asig"),
  @("zentor_ransomware_indicators.zsig", "avorax_ransomware_indicators.asig"),
  @("zentor_infostealer_indicators.zsig", "avorax_infostealer_indicators.asig"),
  @("zentor_miner_pup_indicators.zsig", "avorax_miner_pup_indicators.asig")
)) {
  $source = Join-Path $nativeSourceDir "signatures\$($signatureAlias[0])"
  if (Test-SafeFile $source "optional native signature alias source") {
    Copy-RequiredAlias $source (Join-Path $stageEngineDir "signatures\$($signatureAlias[1])") "native signature alias"
    Copy-RequiredAlias $source (Join-Path $releaseEngineDir "signatures\$($signatureAlias[1])") "native signature alias"
  }
}
Copy-RequiredAlias (Join-Path $nativeSourceDir "rules\zentor_rules.zrule") (Join-Path $stageEngineDir "rules\avorax_core.arule") "core native rule alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "rules\zentor_rules.zrule") (Join-Path $releaseEngineDir "rules\avorax_core.arule") "core native rule alias"
Remove-SafeRegularFileIfPresent (Join-Path $stageEngineDir "rules\zentor_rules.zrule") "duplicate staged legacy core rule pack"
Remove-SafeRegularFileIfPresent (Join-Path $releaseEngineDir "rules\zentor_rules.zrule") "duplicate release legacy core rule pack"
foreach ($ruleAlias in @(
  @("zentor_script_threats.zrule", "avorax_script_threats.arule"),
  @("zentor_ransomware.zrule", "avorax_ransomware.arule"),
  @("zentor_infostealers.zrule", "avorax_infostealers.arule"),
  @("zentor_persistence.zrule", "avorax_persistence.arule"),
  @("zentor_miners_pup.zrule", "avorax_miners_pup.arule")
)) {
  $source = Join-Path $nativeSourceDir "rules\$($ruleAlias[0])"
  if (Test-SafeFile $source "optional native rule alias source") {
    Copy-RequiredAlias $source (Join-Path $stageEngineDir "rules\$($ruleAlias[1])") "native rule alias"
    Copy-RequiredAlias $source (Join-Path $releaseEngineDir "rules\$($ruleAlias[1])") "native rule alias"
  }
}
Copy-RequiredAlias (Join-Path $nativeSourceDir "ml\zentor_native_model.zmodel") (Join-Path $stageEngineDir "ml\avorax_native_model.amodel") "native ML model alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "ml\zentor_native_model.zmodel") (Join-Path $releaseEngineDir "ml\avorax_native_model.amodel") "native ML model alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "ml\zentor_native_model.metadata.json") (Join-Path $stageEngineDir "ml\avorax_native_model.metadata.json") "native ML metadata alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "ml\zentor_native_model.metadata.json") (Join-Path $releaseEngineDir "ml\avorax_native_model.metadata.json") "native ML metadata alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "trust\zentor_known_good.ztrust") (Join-Path $stageEngineDir "trust\avorax_known_good.atrust") "known-good trust alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "trust\zentor_known_good.ztrust") (Join-Path $releaseEngineDir "trust\avorax_known_good.atrust") "known-good trust alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "trust\zentor_known_bad_test.ztrust") (Join-Path $stageEngineDir "trust\avorax_known_bad_test.atrust") "known-bad test trust alias"
Copy-RequiredAlias (Join-Path $nativeSourceDir "trust\zentor_known_bad_test.ztrust") (Join-Path $releaseEngineDir "trust\avorax_known_bad_test.atrust") "known-bad test trust alias"

if (Test-SafeFile (Join-Path $yaraSourceDir "zentor_core_rules.yar") "optional YARA core rules") {
  $stageYaraDir = Join-Path $stageDir "assets\yara"
  $releaseYaraDir = Join-Path $releaseDir "assets\yara"
  Copy-Tree $yaraSourceDir $stageYaraDir
  Copy-Tree $yaraSourceDir $releaseYaraDir
}

if (-not (Test-SafeFile (Join-Path $testAssetsSourceDir "known_bad_test_hashes.json") "safe known-bad test hash asset")) {
  throw "Known-bad test hash asset is required: $(Join-Path $testAssetsSourceDir "known_bad_test_hashes.json")"
}
$stageTestDir = Join-Path $stageDir "assets\test"
$releaseTestDir = Join-Path $releaseDir "assets\test"
Copy-RequiredTree $testAssetsSourceDir $stageTestDir "safe test assets"
Copy-RequiredTree $testAssetsSourceDir $releaseTestDir "safe test assets"

$stageTrustDir = Join-Path $stageDir "assets\trust"
$releaseTrustDir = Join-Path $releaseDir "assets\trust"
Copy-RequiredTree $trustAssetsSourceDir $stageTrustDir "trust assets"
Copy-RequiredTree $trustAssetsSourceDir $releaseTrustDir "trust assets"

$stageThreatsDir = Join-Path $stageDir "assets\threats"
$releaseThreatsDir = Join-Path $releaseDir "assets\threats"
Copy-RequiredTree $threatAssetsSourceDir $stageThreatsDir "known-bad test threat assets"
Copy-RequiredTree $threatAssetsSourceDir $releaseThreatsDir "known-bad test threat assets"

foreach ($requiredDriverFile in @(
  "driver\ZentorAvFilter.vcxproj",
  "driver\ZentorAvFilter.inf",
  "driver\Driver.c",
  "driver\Communication.c",
  "driver\Filter.c",
  "scripts\build-driver.ps1",
  "scripts\install-test-driver.ps1",
  "scripts\uninstall-test-driver.ps1"
)) {
  $driverFilePath = Join-Path $driverToolsSourceDir $requiredDriverFile
  if (-not (Test-SafeFile $driverFilePath "Windows driver development file")) {
    throw "Avorax Windows driver development file is missing: $driverFilePath"
  }
}
$stageDriverToolsDir = Join-Path $stageDir "driver-tools\zentor_windows_minifilter"
Copy-RequiredTree $driverToolsSourceDir $stageDriverToolsDir "Windows minifilter driver tools"
$stageProcessGuardToolsDir = Join-Path $stageDir "driver-tools\zentor_windows_process_guard"
Copy-RequiredTree $processGuardToolsSourceDir $stageProcessGuardToolsDir "Windows process guard driver tools"

$stageDriverPackageDir = Join-Path $stageDir "driver\ZentorAvFilter"
$releaseDriverPackageDir = Join-Path $releaseDir "driver\ZentorAvFilter"
$driverPackageIncluded = $false
if (Test-SafeDirectory $driverPackageSource "signed Windows minifilter driver package source") {
  Assert-NoReparseTree $driverPackageSource "signed Windows minifilter driver package source"
  $driverSys = Find-SafeFileInTree $driverPackageSource "ZentorAvFilter.sys" "signed Windows minifilter driver binary"
  $driverInf = Find-SafeFileInTree $driverPackageSource "ZentorAvFilter.inf" "signed Windows minifilter driver INF"
  $driverCat = Find-SafeFileInTree $driverPackageSource "*.cat" "signed Windows minifilter driver catalog"
  if ($driverSys -and $driverInf -and $driverCat) {
    Copy-RequiredTree $driverPackageSource $stageDriverPackageDir "signed Windows minifilter driver package"
    Copy-RequiredTree $driverPackageSource $releaseDriverPackageDir "signed Windows minifilter driver package"
    $driverPackageIncluded = $true
  } elseif ($RequireDriverPackage) {
    throw "Driver package at $driverPackageSource is incomplete. Required: ZentorAvFilter.sys, ZentorAvFilter.inf, and a signed .cat catalog."
  }
} elseif ($RequireDriverPackage) {
  throw "Required signed driver package directory was not found: $driverPackageSource"
}
$driverInstallScript = Join-Path $stageDir "tools\windows\avorax-install-driver.ps1"

$stageToolsDir = Join-Path $stageDir "tools"
Copy-RequiredTree $windowsToolsSourceDir (Join-Path $stageToolsDir "windows") "Windows validation tools"
Copy-RequiredTree $securityToolsSourceDir (Join-Path $stageToolsDir "security") "security release gates"
Copy-RequiredTree $perfToolsSourceDir (Join-Path $stageToolsDir "perf") "performance release gate"
Copy-RequiredTree $brandingToolsSourceDir (Join-Path $stageToolsDir "branding") "branding release gate"
Copy-RequiredTree $zneToolsSourceDir (Join-Path $stageToolsDir "zne") "ZNE self-test tools"
Copy-RequiredTree $intelToolsSourceDir (Join-Path $stageToolsDir "zentor_intel") "safe threat-intel tools"
Copy-RequiredTree $simulatorsSourceDir (Join-Path $stageToolsDir "simulators") "safe simulator tools"
Copy-RequiredTree $updateToolsSourceDir (Join-Path $stageToolsDir "update") "update package tools"
New-SafeDirectory (Split-Path $driverInstallScript) "driver install helper directory" | Out-Null
@'
param(
  [string]$DriverInf,
  [string]$ReportPath
)
$ErrorActionPreference = "Stop"

function Test-LocalWindowsPath([string]$Path) {
  $normalized = $Path -replace '/', '\'
  return $normalized -match '^[A-Za-z]:\\'
}

function Assert-NoReparsePath([string]$Path, [string]$Description) {
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

function Get-SafeFile([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "$Description is missing or uninspectable: $Path"
  }
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not ($item -is [System.IO.FileInfo])) {
    throw "$Description is not a regular non-reparse file: $Path"
  }
  return $item.FullName
}

function Get-SafeDirectory([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "$Description is missing or uninspectable: $Path"
  }
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not ($item -is [System.IO.DirectoryInfo])) {
    throw "$Description is not a directory: $Path"
  }
  return $item
}

function Remove-SafeRegularFileIfPresent([string]$Path, [string]$Description) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  [void](Get-SafeFile $Path $Description)
  Remove-Item -LiteralPath $Path -Force
}

function New-SafeDirectory([string]$Path, [string]$Description) {
  Assert-NoReparsePath $Path $Description
  if (-not (Test-Path -LiteralPath $Path)) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not ($item -is [System.IO.DirectoryInfo])) {
    throw "$Description is not a directory: $Path"
  }
  return $item.FullName
}

function Get-CheckedEnvironmentRoot([string[]]$Names, [string]$Description) {
  $diagnostics = @()
  foreach ($name in $Names) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
      $diagnostics += "$name is not set or is empty"
      continue
    }
    $root = $value.Trim()
    if (-not (Test-LocalWindowsPath $root)) {
      $diagnostics += "$name must be a local Windows drive path: $root"
      continue
    }
    Assert-NoReparsePath $root "$Description root"
    return [System.IO.Path]::GetFullPath($root)
  }
  throw "$Description root is unavailable: $($diagnostics -join '; ')"
}

function Get-AvoraxReportRoot {
  $programDataRoot = Get-CheckedEnvironmentRoot @("ProgramData", "PROGRAMDATA") "ProgramData"
  Join-Path (Join-Path $programDataRoot "Avorax") "reports"
}

function Assert-DriverReportPath([string]$Path, [string]$ReportRoot) {
  Assert-NoReparsePath $Path "driver install report"
  $reportRootFull = [System.IO.Path]::GetFullPath($ReportRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  if ($pathFull.Equals($reportRootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "driver install report must resolve to a child file path under Avorax ProgramData reports, not the reports directory itself."
  }
  $reportRootPrefix = $reportRootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($reportRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "driver install report must resolve under Avorax ProgramData reports: $pathFull"
  }
}

function Resolve-InstalledAvoraxRootFromScript {
  $toolsRoot = Split-Path -Parent $PSScriptRoot
  $installRoot = Split-Path -Parent $toolsRoot
  Assert-NoReparsePath $installRoot "installed Avorax root"
  [System.IO.Path]::GetFullPath($installRoot)
}

function Get-InstalledDriverPackageRoot {
  $driverRoot = Join-Path (Resolve-InstalledAvoraxRootFromScript) "driver\ZentorAvFilter"
  (Get-SafeDirectory $driverRoot "installed Avorax driver package").FullName
}

function Assert-DriverInfPath([string]$Path, [string]$DriverRoot) {
  Assert-NoReparsePath $Path "driver INF"
  $driverRootFull = [System.IO.Path]::GetFullPath($DriverRoot).TrimEnd('\', '/')
  $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $driverRootPrefix = $driverRootFull + [System.IO.Path]::DirectorySeparatorChar
  if (-not $pathFull.StartsWith($driverRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "driver INF must resolve under the installed Avorax driver package: $pathFull"
  }
  if ((Split-Path $pathFull -Leaf) -ne "ZentorAvFilter.inf") {
    throw "driver INF must be the installed ZentorAvFilter.inf file: $pathFull"
  }
}

function Resolve-DriverInfPath([AllowNull()][string]$Path) {
  $driverRoot = Get-InstalledDriverPackageRoot
  if (-not [string]::IsNullOrWhiteSpace($Path)) {
    Assert-DriverInfPath $Path $driverRoot
    return [System.IO.Path]::GetFullPath($Path)
  }
  Join-Path $driverRoot "ZentorAvFilter.inf"
}

function Resolve-DriverReportPath([AllowNull()][string]$Path) {
  $reportRoot = Get-AvoraxReportRoot
  if (-not [string]::IsNullOrWhiteSpace($Path)) {
    Assert-DriverReportPath $Path $reportRoot
    return [System.IO.Path]::GetFullPath($Path)
  }
  Join-Path $reportRoot "driver_install_report.json"
}

$DriverInf = Resolve-DriverInfPath $DriverInf
$ReportPath = Resolve-DriverReportPath $ReportPath

function Get-BoundedDiagnostic([object]$Value, [int]$MaxLength = 4096) {
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return "" }
  $text = $text.Trim()
  if ($text.Length -le $MaxLength) { return $text }
  return $text.Substring(0, $MaxLength) + "...<truncated>"
}

function Get-WindowsToolRoot {
  $diagnostics = @()
  foreach ($name in @("SystemRoot", "WINDIR")) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
      $diagnostics += "$name is not set or is empty"
      continue
    }
    $root = $value.Trim()
    if (-not (Test-LocalWindowsPath $root)) {
      $diagnostics += "$name must be a local Windows drive path: $root"
      continue
    }
    try {
      Assert-NoReparsePath $root "$name Windows System32 tool root"
      return [System.IO.Path]::GetFullPath($root)
    } catch {
      $diagnostics += "$name Windows System32 tool root rejected: $($_.Exception.Message)"
      continue
    }
  }
  throw "Windows System32 tool root is unavailable: $($diagnostics -join '; ')"
}

function Get-SystemTool([string]$Name) {
  $systemRoot = Get-WindowsToolRoot
  return Get-SafeFile (Join-Path $systemRoot "System32\$Name") "$Name system tool"
}

function Write-JsonReport([object]$Report) {
  $reportDirectory = New-SafeDirectory (Split-Path $ReportPath) "driver install report directory"
  Assert-NoReparsePath $ReportPath "driver install report"
  if (Test-Path -LiteralPath $ReportPath) {
    [void](Get-SafeFile $ReportPath "driver install report")
  }
  $target = [System.IO.Path]::GetFullPath($ReportPath)
  $tempPath = Join-Path $reportDirectory ("driver-install-report-" + [System.Guid]::NewGuid().ToString("N") + ".tmp")
  $backupPath = Join-Path $reportDirectory ("driver-install-report-" + [System.Guid]::NewGuid().ToString("N") + ".bak")
  try {
    $json = $Report | ConvertTo-Json -Depth 5
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempPath, $json, $encoding)
    [void](Get-SafeFile $tempPath "temporary driver install report")
    if (Test-Path -LiteralPath $target) {
      [System.IO.File]::Replace($tempPath, $target, $backupPath)
    } else {
      [System.IO.File]::Move($tempPath, $target)
    }
  } finally {
    if (Test-Path -LiteralPath $tempPath) {
      [void](Get-SafeFile $tempPath "temporary driver install report")
      Remove-Item -LiteralPath $tempPath -Force
    }
    Remove-SafeRegularFileIfPresent $backupPath "driver install report backup file"
  }
}

$errors = New-Object System.Collections.Generic.List[string]
$testSigningRequired = $false
$rebootRequired = $false
$testSigningProbeError = $null
$filterLoadError = $null
$filterQueryError = $null
$driverInstallError = $null
$serviceConfigError = $null
$certificateImportErrors = New-Object System.Collections.Generic.List[string]
try {
  $driverInfPath = Get-SafeFile $DriverInf "driver INF"
  $certutil = Get-SystemTool "certutil.exe"
  $bcdedit = Get-SystemTool "bcdedit.exe"
  $pnputil = Get-SystemTool "pnputil.exe"
  $sc = Get-SystemTool "sc.exe"
  $fltmc = Get-SystemTool "fltmc.exe"
  $driverDir = Split-Path $driverInfPath
  $certPath = Join-Path $driverDir "ZentorAvFilter.cer"
  if (Test-Path -LiteralPath $certPath) {
    $certPath = Get-SafeFile $certPath "driver test certificate"
    $certRootDiagnostic = Invoke-AvoraxCommandDiagnostic $certutil @("-addstore", "-f", "Root", $certPath) "certutil -addstore Root" 4096
    $certRootExitCode = $certRootDiagnostic.exit_code
    if ($certRootExitCode -ne 0) {
      $certRootText = $certRootDiagnostic.output
      $certRootError = Get-BoundedDiagnostic "certutil Root import failed with exit code $certRootExitCode`: $certRootText"
      $certificateImportErrors.Add($certRootError)
      $errors.Add($certRootError)
    }
    $certPublisherDiagnostic = Invoke-AvoraxCommandDiagnostic $certutil @("-addstore", "-f", "TrustedPublisher", $certPath) "certutil -addstore TrustedPublisher" 4096
    $certPublisherExitCode = $certPublisherDiagnostic.exit_code
    if ($certPublisherExitCode -ne 0) {
      $certPublisherText = $certPublisherDiagnostic.output
      $certPublisherError = Get-BoundedDiagnostic "certutil TrustedPublisher import failed with exit code $certPublisherExitCode`: $certPublisherText"
      $certificateImportErrors.Add($certPublisherError)
      $errors.Add($certPublisherError)
    }
  }
  $bcdeditDiagnostic = Invoke-AvoraxCommandDiagnostic $bcdedit @("/enum") "bcdedit /enum" 32768
  $bcdeditExitCode = $bcdeditDiagnostic.exit_code
  $testSigningText = $bcdeditDiagnostic.output
  if ($bcdeditExitCode -ne 0) {
    $testSigningProbeError = Get-BoundedDiagnostic "bcdedit /enum failed with exit code $bcdeditExitCode`: $testSigningText"
    throw "TESTSIGNING status could not be verified: $testSigningProbeError"
  }
  $testSigningOn = $testSigningText -match "(?im)^\s*testsigning\s+Yes\s*$"
  if (-not $testSigningOn) {
    $testSigningRequired = $true
    $rebootRequired = $true
    throw "Windows TESTSIGNING is off. Avorax will not enable TESTSIGNING silently. Run 'bcdedit /set testsigning on' from an elevated terminal, reboot, then rerun this driver installer."
  }
  $driverInstallDiagnostic = Invoke-AvoraxCommandDiagnostic $pnputil @("/add-driver", $driverInfPath, "/install") "pnputil /add-driver ZentorAvFilter" 4096
  $driverInstallExitCode = $driverInstallDiagnostic.exit_code
  if ($driverInstallExitCode -ne 0) {
    $driverInstallText = $driverInstallDiagnostic.output
    $driverInstallError = Get-BoundedDiagnostic "pnputil failed to install ZentorAvFilter. Exit code: $driverInstallExitCode. Output: $driverInstallText"
    throw $driverInstallError
  }
  $serviceConfigDiagnostic = Invoke-AvoraxCommandDiagnostic $sc @("config", "ZentorAvFilter", "start=", "auto") "sc config ZentorAvFilter start= auto" 4096
  $serviceConfigExitCode = $serviceConfigDiagnostic.exit_code
  if ($serviceConfigExitCode -ne 0) {
    $serviceConfigText = $serviceConfigDiagnostic.output
    $serviceConfigError = Get-BoundedDiagnostic "sc config ZentorAvFilter start=auto failed. Exit code: $serviceConfigExitCode. Output: $serviceConfigText"
    $errors.Add($serviceConfigError)
  }
  $loaded = $false
  $loadDiagnostic = Invoke-AvoraxCommandDiagnostic $fltmc @("load", "ZentorAvFilter") "fltmc load ZentorAvFilter" 4096
  $loadExitCode = $loadDiagnostic.exit_code
  $loadText = $loadDiagnostic.output
  if ($loadExitCode -ne 0) {
    $filterLoadError = Get-BoundedDiagnostic "fltmc failed to load ZentorAvFilter. Exit code: $loadExitCode. Output: $loadText"
    $errors.Add($filterLoadError)
  }
  $filterQueryDiagnostic = Invoke-AvoraxCommandDiagnostic $fltmc @("filters") "fltmc filters" 4096
  $filterQueryExitCode = $filterQueryDiagnostic.exit_code
  if ($filterQueryExitCode -ne 0) {
    $filterQueryText = $filterQueryDiagnostic.output
    $filterQueryError = Get-BoundedDiagnostic "fltmc filters failed after load attempt. Exit code: $filterQueryExitCode. Output: $filterQueryText"
    $errors.Add($filterQueryError)
  } else {
    $loaded = $filterQueryDiagnostic.output -match "ZentorAvFilter"
  }
  Write-JsonReport ([ordered]@{
    installed = $true
    running = $loaded
    reboot_required = $false
    testsigning_required = $false
    driver_inf = $driverInfPath
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    testsigning_probe_error = $testSigningProbeError
    filter_load_error = $filterLoadError
    filter_query_error = $filterQueryError
    driver_install_error = $driverInstallError
    service_config_error = $serviceConfigError
    certificate_import_errors = @($certificateImportErrors)
    errors = @($errors)
  })
} catch {
  $errors.Add($_.Exception.Message)
  Write-JsonReport ([ordered]@{
    installed = $false
    running = $false
    reboot_required = $rebootRequired
    testsigning_required = $testSigningRequired
    driver_inf = $DriverInf
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    testsigning_probe_error = $testSigningProbeError
    filter_load_error = $filterLoadError
    filter_query_error = $filterQueryError
    driver_install_error = $driverInstallError
    service_config_error = $serviceConfigError
    certificate_import_errors = @($certificateImportErrors)
    errors = @($errors)
  })
  throw
}
'@ | ForEach-Object { Write-TextFileAtomic $driverInstallScript $_ "UTF8" "driver install helper" }
New-SafeDirectory (Join-Path $releaseDir "tools\windows") "release Windows tools directory" | Out-Null
Copy-RequiredFile $driverInstallScript (Join-Path $releaseDir "tools\windows\avorax-install-driver.ps1") "driver install helper"
foreach ($windowsTool in @("avorax-enable-test-signing.ps1", "avorax-open-firmware-settings.ps1")) {
  $windowsToolSource = Join-Path $root "tools\windows\$windowsTool"
  if (Test-SafeFile $windowsToolSource "optional Windows helper") {
    New-SafeDirectory (Join-Path $stageDir "tools\windows") "staged Windows tools directory" | Out-Null
    New-SafeDirectory (Join-Path $releaseDir "tools\windows") "release Windows tools directory" | Out-Null
    Copy-RequiredFile $windowsToolSource (Join-Path $stageDir "tools\windows\$windowsTool") "optional Windows helper"
    Copy-RequiredFile $windowsToolSource (Join-Path $releaseDir "tools\windows\$windowsTool") "optional Windows helper"
  }
}
Assert-StagePath "tools\windows\avorax-enable-test-signing.ps1" "explicit TESTSIGNING enablement helper"
Assert-StagePath "tools\windows\avorax-open-firmware-settings.ps1" "Secure Boot firmware remediation helper"
Assert-StagePath "tools\update\avorax-dev-sign-manifest.py" "development update manifest signer"

$coreSource = $null
$coreSource = Get-OptionalSafeFile $localCoreExe "targeted local core executable"
if (-not $coreSource) {
  $coreSource = Get-OptionalSafeFile $localCoreExeDefault "default local core executable"
}
if (-not $coreSource) {
  $coreSource = Get-OptionalSafeFile $localCoreExeGnu "GNU local core executable"
}
if (-not $coreSource) {
  $coreSource = Get-OptionalSafeFile $localCoreExeWorkspace "workspace local core executable"
}

if ($coreSource) {
  Copy-RequiredFile $coreSource (Join-Path $stageDir "avorax_core_service.exe") "Avorax Core Service executable"
  Copy-RequiredFile $coreSource (Join-Path $releaseDir "avorax_core_service.exe") "Avorax Core Service executable"
  Copy-RequiredFile $coreSource (Join-Path $stageDir "zentor_local_core.exe") "legacy local core executable"
  Copy-RequiredFile $coreSource (Join-Path $releaseDir "zentor_local_core.exe") "legacy local core executable"
} elseif ($RequireLocalCore -or -not $AllowIncompletePayload) {
  throw "zentor_local_core.exe was not found. Avorax installers must include the local core and Avorax Native Engine runtime. Build it for Windows first or pass -AllowIncompletePayload only for local packaging diagnostics."
} else {
  Write-Warning "zentor_local_core.exe was not found. This diagnostic package will install the app, but local malware scanning will show Engine Unavailable until the core is deployed."
}

$guardSource = Get-OptionalSafeFile $guardServiceExeDefault "default Guard Service executable"
if (-not $guardSource) {
  $guardSource = Get-OptionalSafeFile $guardServiceExeWorkspace "workspace Guard Service executable"
}
if ($guardSource) {
  Copy-RequiredFile $guardSource (Join-Path $stageDir "avorax_guard_service.exe") "Avorax Guard Service executable"
  Copy-RequiredFile $guardSource (Join-Path $releaseDir "avorax_guard_service.exe") "Avorax Guard Service executable"
  Copy-RequiredFile $guardSource (Join-Path $stageDir "zentor_guard_service.exe") "legacy Guard Service executable"
  Copy-RequiredFile $guardSource (Join-Path $releaseDir "zentor_guard_service.exe") "legacy Guard Service executable"
} elseif (-not $AllowIncompletePayload) {
  throw "zentor_guard_service.exe was not found. Avorax installers must include and register the Guard Service. Build it for Windows first or pass -AllowIncompletePayload only for local packaging diagnostics."
} else {
  Write-Warning "zentor_guard_service.exe was not found. This diagnostic package will not include the real-time Guard helper."
}

$updateSource = Get-OptionalSafeFile $updateServiceExeDefault "default Update Service executable"
if (-not $updateSource) {
  $updateSource = Get-OptionalSafeFile $updateServiceExeWorkspace "workspace Update Service executable"
}
if ($updateSource) {
  Copy-RequiredFile $updateSource (Join-Path $stageDir "avorax_update_service.exe") "Avorax Update Service executable"
  Copy-RequiredFile $updateSource (Join-Path $releaseDir "avorax_update_service.exe") "Avorax Update Service executable"
} elseif (-not $AllowIncompletePayload) {
  throw "avorax_update_service.exe was not found. Avorax installers must include and register the Update Service. Build it for Windows first or pass -AllowIncompletePayload only for local packaging diagnostics."
} else {
  Write-Warning "avorax_update_service.exe was not found. This diagnostic package cannot apply in-app .aup updates."
}

if ($IncludeClamAVCompatibility -and -not $SkipClamAV) {
  Ensure-ClamAVPackage $clamAvZipPath $clamAvUrl $clamAvSha256 ([bool]$AllowClamAVDownload)
  Copy-ClamAVRuntime $clamAvZipPath $clamAvExtractDir (Join-Path $stageDir "ClamAV")
  Copy-ClamAVRuntime $clamAvZipPath $clamAvExtractDir (Join-Path $releaseDir "ClamAV")
  Write-Host "Bundled optional ClamAV compatibility runtime $clamAvVersion in the MSI."
} else {
  Write-Host "Skipping ClamAV compatibility runtime. Avorax Native Engine is the primary scanner."
}

$runtimeDllNames = @(
  "vcruntime140.dll",
  "vcruntime140_1.dll",
  "msvcp140.dll"
)
$runtimeSystem32 = Join-Path (Get-WindowsRuntimeRoot) "System32"
foreach ($dllName in $runtimeDllNames) {
  $dll = Join-Path $runtimeSystem32 $dllName
  if (Test-SafeFile $dll "Visual C++ runtime file") {
    Copy-RequiredFile $dll (Join-Path $stageDir (Split-Path $dll -Leaf)) "Visual C++ runtime file"
  } else {
    Write-Warning "Visual C++ runtime file missing on this machine: $dll"
  }
}

$docsStage = Join-Path $stageDir "docs"
Copy-RequiredTree $docsSourceDir $docsStage "documentation"
Copy-RequiredFile (Join-Path $root "README.md") (Join-Path $docsStage "README.md") "README"
Copy-RequiredFile $betaNoticeSource (Join-Path $stageDir "BETA-NOTICE.txt") "beta safety notice"
Copy-RequiredFile $betaNoticeSource (Join-Path $releaseDir "BETA-NOTICE.txt") "beta safety notice"

$manifest = [ordered]@{
  product = "Avorax Anti-Virus"
  version = $Version
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  includes = [ordered]@{
    flutter_client = Test-SafeFile (Join-Path $stageDir "Avorax.exe") "staged Flutter client"
    local_core = Test-SafeFile (Join-Path $stageDir "avorax_core_service.exe") "staged Core Service"
    guard_service = Test-SafeFile (Join-Path $stageDir "avorax_guard_service.exe") "staged Guard Service"
    update_service = Test-SafeFile (Join-Path $stageDir "avorax_update_service.exe") "staged Update Service"
    native_engine_assets = Test-SafeDirectory (Join-Path $stageDir "engine") "staged engine assets"
    ai_model_assets = Test-SafeDirectory (Join-Path $stageDir "assets\models") "staged AI model assets"
    trust_assets = Test-SafeDirectory (Join-Path $stageDir "assets\trust") "staged trust assets"
    known_bad_test_assets = Test-SafeDirectory (Join-Path $stageDir "assets\threats") "staged known-bad test assets"
    windows_driver_tools = Test-SafeDirectory (Join-Path $stageDir "driver-tools") "staged Windows driver tools"
    windows_minifilter_driver_package = $driverPackageIncluded
    validation_tools = Test-SafeFile (Join-Path $stageDir "tools\windows\zentor-protection-selftest.ps1") "staged protection self-test"
    release_gates = Test-SafeFile (Join-Path $stageDir "tools\windows\zentor-release-gate.ps1") "staged release gate"
    safe_simulators = Test-SafeDirectory (Join-Path $stageDir "tools\simulators") "staged safe simulators"
    docs = Test-SafeFile (Join-Path $stageDir "docs\windows-driver.md") "staged Windows driver documentation"
    clamav_compatibility = Test-SafeDirectory (Join-Path $stageDir "ClamAV") "staged ClamAV compatibility runtime"
  }
  service_install = [ordered]@{
    core_service = "installed and started by MSI"
    guard_service = "installed and started by MSI"
    update_service = "installed by MSI as manual-demand updater"
  }
  driver_status = if ($driverPackageIncluded) { "signed driver package is included and installer will install/load ZentorAvFilter" } else { "driver package not included; build with -RequireDriverPackage for release builds" }
}
$manifestPath = Join-Path $stageDir "install-manifest.json"
Write-JsonFileAtomic $manifestPath $manifest 8 "installer payload manifest"
Copy-RequiredFile $manifestPath (Join-Path $releaseDir "install-manifest.json") "installer payload manifest"

$releaseManifestPath = Join-Path $stageEngineDir "trust\avorax_release_manifest.json"
$releaseFiles = Get-ChildItem -LiteralPath $stageDir -Recurse -File |
  Where-Object { $_.FullName -ne $releaseManifestPath } |
  Sort-Object FullName |
  ForEach-Object {
    [ordered]@{
      path = Get-RelativePath $stageDir $_.FullName
      sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      bytes = $_.Length
    }
  }
$releaseManifest = [ordered]@{
  product = "Avorax Anti-Virus"
  version = $Version
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  files = $releaseFiles
}
Write-JsonFileAtomic $releaseManifestPath $releaseManifest 8 "release self-trust manifest"
Copy-RequiredFile $releaseManifestPath (Join-Path $releaseEngineDir "trust\avorax_release_manifest.json") "release self-trust manifest"

foreach ($requiredPayload in @(
  @("Avorax.exe", "Flutter desktop client"),
  @("avorax_core_service.exe", "Avorax Core Service"),
  @("avorax_guard_service.exe", "Avorax Guard Service"),
  @("avorax_update_service.exe", "Avorax Update Service"),
  @("zentor_local_core.exe", "local core scanner helper"),
  @("zentor_guard_service.exe", "Guard Service"),
  @("engine\config\engine.default.json", "installed engine config"),
  @("engine\signatures\avorax_core.asig", "installed native signature pack"),
  @("engine\rules\avorax_core.arule", "installed native rule pack"),
  @("engine\ml\avorax_native_model.amodel", "installed native ML model"),
  @("engine\ml\zentor_native_model.zmodel", "installed native ML source model"),
  @("engine\trust\avorax_known_good.atrust", "installed trust store"),
  @("engine\trust\avorax_release_manifest.json", "Avorax release self-trust manifest"),
  @("assets\zentor_native\signatures\zentor_core.zsig", "native signature pack"),
  @("assets\zentor_native\rules\zentor_rules.zrule", "native rule pack"),
  @("assets\zentor_native\ml\zentor_native_model.zmodel", "native ML model"),
  @("assets\models\zentor_static_malware_model.onnx", "AI compatibility model"),
  @("assets\test\known_bad_test_hashes.json", "safe known-bad test hashes"),
  @("assets\trust\zentor_known_good.db", "trust store"),
  @("assets\threats\zentor_known_bad_test_hashes.json", "known-bad test threat asset"),
  @("driver-tools\zentor_windows_minifilter\scripts\run-driver-self-test.ps1", "minifilter driver self-test"),
  @("driver-tools\zentor_windows_process_guard\scripts\run-process-guard-self-test.ps1", "process guard self-test"),
  @("tools\windows\zentor-protection-selftest.ps1", "protection self-test"),
  @("tools\windows\avorax-install-driver.ps1", "driver install custom action script"),
  @("tools\windows\zentor-release-gate.ps1", "Windows release gate"),
  @("tools\windows\avorax-installed-smoke-test.ps1", "installed smoke test"),
  @("tools\windows\avorax-installer-stage-test.ps1", "installer stage test"),
  @("tools\security\zentor-false-positive-gate.ps1", "false-positive gate"),
  @("tools\perf\zentor-performance-gate.ps1", "performance gate"),
  @("tools\branding\branding-check.ps1", "branding gate"),
  @("tools\zne\zne-release-gate.ps1", "ZNE release gate"),
  @("tools\simulators", "safe simulators"),
  @("tools\zentor_intel", "safe threat-intel tools"),
  @("tools\update\avorax-build-update-package.ps1", "update package builder"),
  @("docs\README.md", "installed README"),
  @("docs\windows-driver.md", "driver documentation"),
  @("docs\safe-malware-testing.md", "safe malware testing documentation"),
  @("BETA-NOTICE.txt", "beta safety notice"),
  @("install-manifest.json", "installed payload manifest")
)) {
  Assert-StagePath $requiredPayload[0] $requiredPayload[1]
}

$files = Get-ChildItem -LiteralPath $stageDir -Recurse -File |
  Where-Object { $_.Extension -ne ".pdb" } |
  Sort-Object FullName

$directories = @{}
foreach ($file in $files) {
  $relativeDir = Get-RelativePath $stageDir $file.DirectoryName
  if ($relativeDir -eq ".") { continue }
  $parts = $relativeDir -split "[/\\]"
  $current = ""
  foreach ($part in $parts) {
    $current = if ($current) { Join-Path $current $part } else { $part }
    if (-not $directories.ContainsKey($current)) {
      $parent = [IO.Path]::GetDirectoryName($current)
      $directories[$current] = [ordered]@{
        Id = "DIR_" + (To-WixId $current)
        Name = $part
        Parent = if ($parent) { "DIR_" + (To-WixId $parent) } else { "INSTALLFOLDER" }
      }
    }
  }
}

$directoryXml = New-Object System.Text.StringBuilder
foreach ($dir in $directories.GetEnumerator() | Sort-Object { $_.Key.Split('\').Count }) {
  [void]$directoryXml.AppendLine("    <DirectoryRef Id=`"$($dir.Value.Parent)`">")
  [void]$directoryXml.AppendLine("      <Directory Id=`"$($dir.Value.Id)`" Name=`"$(XmlEscape $dir.Value.Name)`" />")
  [void]$directoryXml.AppendLine("    </DirectoryRef>")
}

$componentsXml = New-Object System.Text.StringBuilder
$componentRefsXml = New-Object System.Text.StringBuilder
$index = 0
foreach ($file in $files) {
  $index++
  $relativePath = Get-RelativePath $stageDir $file.FullName
  $relativeDir = [IO.Path]::GetDirectoryName($relativePath)
  $directoryId = if ([string]::IsNullOrEmpty($relativeDir)) { "INSTALLFOLDER" } else { "DIR_" + (To-WixId $relativeDir) }
  $componentId = "CMP_$index"
  $fileId = "FIL_$index"
  [void]$componentsXml.AppendLine("    <DirectoryRef Id=`"$directoryId`">")
  [void]$componentsXml.AppendLine("      <Component Id=`"$componentId`" Guid=`"*`">")
  [void]$componentsXml.AppendLine("        <File Id=`"$fileId`" Source=`"$(XmlEscape $file.FullName)`" KeyPath=`"yes`" />")
  if ($relativePath -eq "zentor_local_core.exe") {
    [void]$componentsXml.AppendLine("        <ServiceInstall Id=`"AvoraxCoreServiceInstall`" Type=`"ownProcess`" Vital=`"yes`" Name=`"avorax_core_service`" DisplayName=`"Avorax Core Service`" Description=`"Provides local scanning, native engine loading, quarantine, scan jobs, and local protection state for Avorax Anti-Virus.`" Start=`"auto`" Account=`"LocalSystem`" ErrorControl=`"normal`" Arguments=`"--service`" />")
    [void]$componentsXml.AppendLine("        <ServiceControl Id=`"AvoraxCoreServiceControl`" Name=`"avorax_core_service`" Start=`"install`" Stop=`"both`" Remove=`"uninstall`" Wait=`"yes`" />")
  }
  if ($relativePath -eq "avorax_guard_service.exe") {
    [void]$componentsXml.AppendLine("        <ServiceInstall Id=`"AvoraxGuardServiceInstall`" Type=`"ownProcess`" Vital=`"yes`" Name=`"avorax_guard_service`" DisplayName=`"Avorax Guard Service`" Description=`"Provides real-time protection, process monitoring, driver communication, and threat response for Avorax Anti-Virus.`" Start=`"auto`" Account=`"LocalSystem`" ErrorControl=`"normal`" Arguments=`"--service`" />")
    [void]$componentsXml.AppendLine("        <ServiceControl Id=`"AvoraxGuardServiceControl`" Name=`"avorax_guard_service`" Start=`"install`" Stop=`"both`" Remove=`"uninstall`" Wait=`"yes`" />")
  }
  if ($relativePath -eq "avorax_update_service.exe") {
    [void]$componentsXml.AppendLine("        <ServiceInstall Id=`"AvoraxUpdateServiceInstall`" Type=`"ownProcess`" Vital=`"yes`" Name=`"avorax_update_service`" DisplayName=`"Avorax Update Service`" Description=`"Applies verified Avorax updates, manages rollback, and updates Avorax components safely.`" Start=`"demand`" Account=`"LocalSystem`" ErrorControl=`"normal`" Arguments=`"--service`" />")
    [void]$componentsXml.AppendLine("        <ServiceControl Id=`"AvoraxUpdateServiceControl`" Name=`"avorax_update_service`" Stop=`"both`" Remove=`"uninstall`" Wait=`"yes`" />")
  }
  [void]$componentsXml.AppendLine("      </Component>")
  [void]$componentsXml.AppendLine("    </DirectoryRef>")
  [void]$componentRefsXml.AppendLine("      <ComponentRef Id=`"$componentId`" />")
}

$installReportSource = Join-Path $distRoot "windows-msi\install_report.template.json"
$licenseRtfPath = Join-Path $distRoot "windows-msi\avorax-installer-license.rtf"
$licenseRtf = @'
{\rtf1\ansi\deff0
{\b Avorax Anti-Virus Preview Installer}\par
This installer deploys the Avorax desktop client, visible Avorax services, local Avorax Native Engine assets, documentation, and validation tools.\par
Preview builds are for defensive local testing. Keep Microsoft Defender or your existing antivirus enabled unless you are deliberately testing Avorax in a controlled environment.\par
}
'@
Write-TextFileAtomic $licenseRtfPath $licenseRtf "ASCII" "installer license RTF"
$installReport = [ordered]@{
  version = $Version
  install_path = $null
  install_path_status = "not_recorded_by_static_msi_template"
  app_installed = $true
  core_service_installed = $true
  core_service_running = $false
  guard_service_installed = $true
  guard_service_running = $false
  update_service_installed = $true
  update_service_running = $false
  native_engine_assets_present = $true
  signature_pack_count = (Get-ChildItem -LiteralPath (Join-Path $stageEngineDir "signatures") -File -Filter "*.asig").Count
  rule_pack_count = (Get-ChildItem -LiteralPath (Join-Path $stageEngineDir "rules") -File -Filter "*.arule").Count
  model_present = Test-SafeFile (Join-Path $stageEngineDir "ml\avorax_native_model.amodel") "staged installed native model"
  trust_pack_present = Test-SafeFile (Join-Path $stageEngineDir "trust\avorax_known_good.atrust") "staged installed trust pack"
  engine_self_test_result = "pending_post_install_validation"
  driver_package_included = $driverPackageIncluded
  driver_install_result = if ($driverPackageIncluded) { "pending_msi_custom_action" } else { "not_included" }
  errors = @()
}
Write-JsonFileAtomic $installReportSource $installReport 6 "installer report template"

$programDataSubdirs = @("config", "logs", "events", "Quarantine", "scans", "cache", "reports", "migration", "updates")
$updateDataSubdirs = @("staging", "rollback", "logs")
$programDataXml = New-Object System.Text.StringBuilder
$programDataRefsXml = New-Object System.Text.StringBuilder
[void]$programDataXml.AppendLine("    <StandardDirectory Id=`"CommonAppDataFolder`">")
[void]$programDataXml.AppendLine("      <Directory Id=`"AvoraxProgramDataFolder`" Name=`"Avorax`">")
foreach ($dir in $programDataSubdirs) {
  if ($dir -eq "updates") {
    [void]$programDataXml.AppendLine("        <Directory Id=`"AvoraxData_updates`" Name=`"updates`">")
    [void]$programDataXml.AppendLine("          <Directory Id=`"AvoraxData_updates_staging`" Name=`"staging`" />")
    [void]$programDataXml.AppendLine("          <Directory Id=`"AvoraxData_updates_rollback`" Name=`"rollback`" />")
    [void]$programDataXml.AppendLine("          <Directory Id=`"AvoraxData_updates_logs`" Name=`"logs`" />")
    [void]$programDataXml.AppendLine("        </Directory>")
  } else {
    [void]$programDataXml.AppendLine("        <Directory Id=`"AvoraxData_$dir`" Name=`"$dir`" />")
  }
}
[void]$programDataXml.AppendLine("      </Directory>")
[void]$programDataXml.AppendLine("    </StandardDirectory>")
foreach ($dir in $programDataSubdirs) {
  $componentId = "AvoraxCreateData_$dir"
  [void]$programDataXml.AppendLine("    <DirectoryRef Id=`"AvoraxData_$dir`">")
  [void]$programDataXml.AppendLine("      <Component Id=`"$componentId`" Guid=`"*`">")
  [void]$programDataXml.AppendLine("        <CreateFolder />")
  if ($dir -eq "reports") {
    [void]$programDataXml.AppendLine("        <File Id=`"AvoraxInstallReportFile`" Source=`"$(XmlEscape $installReportSource)`" Name=`"install_report.json`" KeyPath=`"yes`" />")
  } else {
    [void]$programDataXml.AppendLine("        <RegistryValue Root=`"HKLM`" Key=`"Software\Avorax\ProgramData`" Name=`"$dir`" Type=`"integer`" Value=`"1`" KeyPath=`"yes`" />")
  }
  [void]$programDataXml.AppendLine("      </Component>")
  [void]$programDataXml.AppendLine("    </DirectoryRef>")
  [void]$programDataRefsXml.AppendLine("      <ComponentRef Id=`"$componentId`" />")
}
foreach ($dir in $updateDataSubdirs) {
  $componentId = "AvoraxCreateData_updates_$dir"
  [void]$programDataXml.AppendLine("    <DirectoryRef Id=`"AvoraxData_updates_$dir`">")
  [void]$programDataXml.AppendLine("      <Component Id=`"$componentId`" Guid=`"*`">")
  [void]$programDataXml.AppendLine("        <CreateFolder />")
  [void]$programDataXml.AppendLine("        <RegistryValue Root=`"HKLM`" Key=`"Software\Avorax\ProgramData\updates`" Name=`"$dir`" Type=`"integer`" Value=`"1`" KeyPath=`"yes`" />")
  [void]$programDataXml.AppendLine("      </Component>")
  [void]$programDataXml.AppendLine("    </DirectoryRef>")
  [void]$programDataRefsXml.AppendLine("      <ComponentRef Id=`"$componentId`" />")
}


$driverCustomActionXml = ""
if ($driverPackageIncluded) {
  $driverCustomActionXml = @'
    <CustomAction Id="InstallAvoraxMinifilterDriver" Directory="INSTALLFOLDER" Execute="deferred" Impersonate="no" ExeCommand="&quot;[SystemFolder]WindowsPowerShell\v1.0\powershell.exe&quot; -NoProfile -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER]tools\windows\avorax-install-driver.ps1&quot;" Return="check" />
    <InstallExecuteSequence>
      <Custom Action="InstallAvoraxMinifilterDriver" After="InstallFiles" Condition="NOT Installed" />
    </InstallExecuteSequence>
'@
}

$upgradeCode = "35E0D125-9699-4CFB-8E93-588D0E83F517"
$majorUpgradeXml = '    <MajorUpgrade DowngradeErrorMessage="A newer version of Avorax is already installed." />'
if ($RecoveryInstall) {
  # Broken pre-0.2.24 installers start avorax_core_service during the related-product
  # uninstall after deleting its binary. Use a recovery UpgradeCode so Windows Installer
  # does not invoke the stale product uninstall path; the new MSI lays down files and
  # re-registers services in-place instead.
  $upgradeCode = "8F98C732-0D84-42E0-9C77-9438992D2786"
  $majorUpgradeXml = ''
}
$wxs = @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"
     xmlns:ui="http://wixtoolset.org/schemas/v4/wxs/ui">
  <Package
    Name="Avorax Anti-Virus"
    Manufacturer="Avorax Security"
    Version="$Version"
    UpgradeCode="$upgradeCode"
    Scope="perMachine">
$majorUpgradeXml
    <MediaTemplate EmbedCab="yes" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="Avorax" />
    </StandardDirectory>
    <StandardDirectory Id="ProgramMenuFolder">
      <Directory Id="ApplicationProgramsFolder" Name="Avorax Anti-Virus" />
    </StandardDirectory>
$programDataXml

$directoryXml
$componentsXml
$driverCustomActionXml
    <DirectoryRef Id="ApplicationProgramsFolder">
      <Component Id="StartMenuShortcut" Guid="*">
        <Shortcut Id="ZentorStartMenuShortcut" Name="Avorax Anti-Virus" Target="[INSTALLFOLDER]Avorax.exe" WorkingDirectory="INSTALLFOLDER" />
        <RemoveFolder Id="RemoveApplicationProgramsFolder" On="uninstall" />
        <RegistryValue Root="HKCU" Key="Software\Avorax\Client" Name="installed" Type="integer" Value="1" KeyPath="yes" />
      </Component>
    </DirectoryRef>

    <Feature Id="MainFeature" Title="Avorax Anti-Virus" Level="1">
$componentRefsXml
$programDataRefsXml
      <ComponentRef Id="StartMenuShortcut" />
    </Feature>

    <ui:WixUI Id="WixUI_Minimal" />
    <WixVariable Id="WixUILicenseRtf" Value="$(XmlEscape $licenseRtfPath)" />
  </Package>
</Wix>
"@

Write-TextFileAtomic $wxsPath $wxs "UTF8" "MSI WiX source"

Invoke-InstallerCommand $dotnet @("tool", "restore") "WiX tool restore" $root
Invoke-InstallerCommand $dotnet @("wix", "extension", "add", "WixToolset.UI.wixext/6.0.2") "WiX UI extension restore" $root
Invoke-InstallerCommand $dotnet @("wix", "build", $wxsPath, "-arch", "x64", "-ext", "WixToolset.UI.wixext", "-o", $msiPath) "MSI build" $root

if (-not (Test-SafeFile $msiPath "MSI installer artifact")) {
  throw "MSI build did not produce the expected package: $msiPath"
}

$bundleUpgradeCode = "9D6FE1FD-B9F4-4C80-9D03-CF7F453D00B9"
$bundleWxs = @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"
     xmlns:bal="http://wixtoolset.org/schemas/v4/wxs/bal">
  <Bundle
    Name="Avorax Anti-Virus"
    Manufacturer="Avorax Security"
    Version="$Version"
    UpgradeCode="$bundleUpgradeCode">
    <BootstrapperApplication>
      <bal:WixStandardBootstrapperApplication
        Theme="hyperlinkLicense"
        LicenseUrl="https://github.com/brentishere41848/Avorax/blob/main/docs/privacy.md"
        LaunchTarget="[ProgramFiles64Folder]Avorax\Avorax.exe"
        LaunchWorkingFolder="[ProgramFiles64Folder]Avorax" />
    </BootstrapperApplication>
    <Chain>
      <MsiPackage SourceFile="$(XmlEscape $msiPath)" Compressed="yes" Visible="yes" Vital="yes" />
    </Chain>
  </Bundle>
</Wix>
"@

Write-TextFileAtomic $bundleWxsPath $bundleWxs "UTF8" "EXE bundle WiX source"
Invoke-InstallerCommand $dotnet @("wix", "extension", "add", "WixToolset.BootstrapperApplications.wixext/6.0.2") "WiX bootstrapper extension restore" $root
Invoke-InstallerCommand $dotnet @("wix", "build", $bundleWxsPath, "-arch", "x64", "-ext", "WixToolset.BootstrapperApplications.wixext", "-o", $exeInstallerPath) "EXE installer build" $root

if (-not (Test-SafeFile $exeInstallerPath "EXE installer artifact")) {
  throw "EXE build did not produce the expected package: $exeInstallerPath"
}

Write-Host "Created MSI: $msiPath"
Write-Host "Created EXE installer: $exeInstallerPath"
