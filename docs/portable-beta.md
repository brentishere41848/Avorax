# Avorax Portable Scanner Beta

## Beta Safety Disclaimer

**Avorax Portable Scanner Beta is experimental, limited security software. Do
not rely on it as your only antivirus.** It is intended for manual scanning of
common, locally detectable threats covered by its current signatures, rules,
static analysis, and conservative heuristics. It may fail to detect or stop
advanced, novel, targeted, polymorphic, fileless, kernel-level, or large-scale
malware and ransomware attacks.

This beta does not provide continuous background protection or guaranteed
before-execution blocking. Keep Microsoft Defender or another supported,
up-to-date antivirus enabled. Back up important files and keep Windows and
applications patched. No antivirus can guarantee detection of every threat.

The portable beta is a local, user-mode manual scanner built from the verified
release local core and bundled Avorax Native Engine packs. It is an interim
testing artifact for hosts where the Flutter Windows/MSI toolchain is not yet
available.

It does not install a Windows service or driver, start with Windows, provide
persistent background protection, replace Microsoft Defender, or block files
before execution. The finite `Watch` action observes only explicit folders for
at most ten seconds per invocation.

## Start

After extracting the local bundle, double-click `Avorax-Status.cmd` to verify
the engine or `Avorax-Quick-Scan.cmd` to run a detect-only Quick Scan. Reports,
configuration, allowlist state, and quarantine data are stored under:

```text
%LOCALAPPDATA%\Avorax\PortableBeta
```

Do not disable Defender. Avorax uses harmless local validation fixtures; the
portable package contains no live malware.

## PowerShell Actions

```powershell
# Ready-state check
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Avorax-Portable.ps1 -Action Status

# Detect-only Quick or Full Scan
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Avorax-Portable.ps1 -Action QuickScan
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Avorax-Portable.ps1 -Action FullScan

# Scan one file; confirmed signatures may be quarantined only with this switch
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Avorax-Portable.ps1 -Action FileScan `
  -Path C:\path\to\file.exe -AutoQuarantineConfirmed

# Finite best-effort user-mode observation of one explicit folder
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Avorax-Portable.ps1 -Action Watch `
  -Path C:\Users\you\Downloads -DurationSeconds 8

# List quarantine records
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Avorax-Portable.ps1 -Action QuarantineList

# Restore or delete requires the exact ID and explicit confirmation
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Avorax-Portable.ps1 -Action QuarantineRestore `
  -QuarantineId ID_FROM_LIST -ConfirmAction
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Avorax-Portable.ps1 -Action QuarantineDelete `
  -QuarantineId ID_FROM_LIST -ConfirmAction
```

The launcher refuses reports outside its selected data root. It also preserves
wrapper failure semantics: invalid paths, unconfirmed trust/destructive actions,
engine failures, malformed output, timeouts, and scan errors fail visibly.

## Verification

The bundle builder must pass all of these before writing a successful build
report:

- canonical executable SHA-256 inventory;
- native engine ready state;
- positive signature and rule counts;
- native self-test;
- local stdio and no-network boundary;
- harmless scan/quarantine/list/restore/delete lifecycle through the packaged
  wrappers;
- generated file manifest and final ZIP SHA-256.

The local ZIP is not code-signed and is not a production release artifact. MSI,
service, packaged UI, driver, pre-execution, persistent-monitoring, and
production false-positive evidence remain separate requirements.
