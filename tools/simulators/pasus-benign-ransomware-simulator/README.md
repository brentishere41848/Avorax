# Pasus Benign Ransomware Simulator

This simulator is safe test code for Pasus Ransomware Guard.

It only operates inside a temporary directory it creates. It does not touch user documents, system folders, backups, browsers, credentials, or real data.

Run:

```powershell
powershell -ExecutionPolicy Bypass -File tools\simulators\pasus-benign-ransomware-simulator\run-simulator.ps1
```

Expected Pasus behavior when Ransomware Guard is watching the temp test directory:

- Detect rapid modifications/renames.
- Record affected test files.
- Stop or flag the simulator process if Guard enforcement is active.
- Restore from Recovery Vault only if protected test copies exist.

This is not malware and must not be used to claim real-world ransomware certification.
