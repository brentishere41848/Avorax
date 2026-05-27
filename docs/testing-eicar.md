# Testing With EICAR

Pasus uses EICAR for safe antivirus test coverage.

The EICAR test file is not real malware. Pasus treats it as a confirmed test signature so scanner, Guard, quarantine, and release gates can be tested without real malware samples.

Expected behavior:

- Scanner detects EICAR offline.
- Auto-quarantine confirmed mode moves it to quarantine.
- Guard can stop/quarantine an EICAR process or known bad test hash in user-mode fallback.
- Driver validation can use EICAR to prove the minifilter/Guard verdict path returns a block decision.

Driver validation command:

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\pasus-protection-selftest.ps1 -BuildDriver -InstallDriver
```

Pasus must never include real malware samples in this repository.
