$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Administrator rights are required to uninstall the Pasus test driver."
}

fltmc unload PasusAvFilter 2>$null
sc.exe delete PasusAvFilter | Out-Host

Write-Host "PasusAvFilter test driver was stopped/removed if it was installed. User quarantine data was not deleted."
