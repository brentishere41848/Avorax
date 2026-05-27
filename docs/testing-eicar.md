# Testing With EICAR

Pasus uses EICAR for safe antivirus test coverage.

The EICAR test file is not real malware. Pasus treats it as a confirmed test signature so scanner, Guard, quarantine, and release gates can be tested without real malware samples.

Expected behavior:

- Scanner detects EICAR offline.
- Auto-quarantine confirmed mode moves it to quarantine.
- Guard can stop/quarantine an EICAR process or known bad test hash in user-mode fallback.

Pasus must never include real malware samples in this repository.
