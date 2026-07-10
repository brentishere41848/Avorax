# Testing With EICAR

Avorax uses EICAR for safe antivirus test coverage, but the default local MVP
verifier uses Avorax's internal simulator fixture to avoid repeated Microsoft
Defender `DOS/EICAR_Test_File` alerts on development machines.

The EICAR test file is not real malware. Avorax treats it as a confirmed test signature so scanner, Guard, quarantine, and release gates can be tested without real malware samples.

Expected behavior:

- Scanner detects EICAR offline.
- Auto-quarantine confirmed mode moves it to quarantine.
- Guard can stop/quarantine an EICAR process or known bad test hash in user-mode fallback.
- Driver validation can use EICAR to prove the minifilter/Guard verdict path returns a block decision.

Non-admin local smoke test:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-safe-eicar-smoke.ps1
```

This creates a temporary `ZENTOR-SAFE-EICAR-SIMULATOR-FILE` fixture, scans it through local-core IPC in detect-only mode, verifies a confirmed test threat is reported, and removes the temporary fixture. It does not install drivers, change machine-wide settings, quarantine/delete files, download content, or use live malware.

Default MVP verification:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1
```

The default verifier does not create the standard EICAR file. It verifies Avorax
scan/quarantine behavior with `ZENTOR-SAFE-EICAR-SIMULATOR-FILE`, plus a unit
fixture proving Windows anti-malware blocked-read errors are surfaced as
confirmed detections when Defender or another Windows anti-malware provider
intercepts content before Avorax can read it.

Standard EICAR host integration is opt-in:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -IncludeDefenderEicar
```

Use this only when you intentionally want to exercise the real EICAR test-file
path on the current host. Microsoft Defender may block it first; that is expected
host behavior, not live malware.

Non-admin quarantine/restore smoke test:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-safe-quarantine-restore-smoke.ps1
```

This creates the same harmless simulator fixture under a temporary directory, points `AVORAX_QUARANTINE_DIR` at a temporary quarantine root for that process only, scans in `autoQuarantineConfirmedOnly` mode, verifies the local core moved the confirmed simulator into `.avoraxq` quarantine storage, lists the quarantine record, restores it with explicit confirmation, verifies the restored bytes, and removes the temporary root. It does not install drivers, change machine-wide settings, delete quarantine payloads permanently, download content, or use live malware.

Driver validation command:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\zentor-protection-selftest.ps1 -BuildDriver -InstallDriver -CargoPath C:\Path\To\cargo.exe
```

Avorax must never include real malware samples in this repository.
