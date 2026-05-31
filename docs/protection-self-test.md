# Protection Self-Test

Avorax protection self-test is a Windows development validation workflow. It uses EICAR and harmless test binaries only. It does not use real malware.

## One-Command Workflow

Run this from the repository root on a disposable Windows driver-development VM:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\zentor-protection-selftest.ps1 -BuildDriver -InstallDriver
```

The workflow writes:

```text
dist\windows-driver-validation\selftest_report.json
```

## What It Verifies

- Guard Service can run.
- Minifilter driver is installed and running.
- Driver-service communication is available.
- EICAR/safe EICAR simulator returns a confirmed block verdict.
- Harmless known-bad test executable returns a block verdict by test hash.
- Post-launch fallback remains available.
- Local AI model status is reported honestly.

If the driver is missing or not running, the report must fail and Avorax must show post-launch fallback instead of pre-execution blocking.

## Test Signing

Avorax does not enable TESTSIGNING automatically. For a development VM only:

```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

Disable it after testing:

```powershell
bcdedit /set testsigning off
shutdown /r /t 0
```

Production driver distribution requires Microsoft driver signing.
