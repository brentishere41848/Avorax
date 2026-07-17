# Reviewed Feed Source Validation

Checkpoint: 2165
Date: 2026-07-17
Scope: local SHA-256 feed provenance metadata and ingestion bounds

## Verified

- Direct metadata and registry-template modes have exact, mutually exclusive schemas.
- Unknown top-level/template fields and malformed registry container types fail before output.
- Optional provenance URLs require absolute HTTPS with valid DNS labels and without credentials, fragments, or backslashes.
- Canonically equivalent duplicate SHA-256 rows fail with both line numbers.
- Active feed output is bounded to 100,000 rows and remains atomically written by the shared JSONL writer.
- Rejected metadata and duplicate feeds preserve an existing output byte-for-byte.
- Valid direct and registry fixtures retain their selected source identity.

## Partial

- The row-limit branch is source-enforced and covered by the default source-contract suite; this checkpoint did not allocate a 100,001-row runtime fixture.
- Production publisher identity, feed review, false-positive handling, and signing-key custody remain release-process responsibilities.

## Disabled or Blocked

- Requested GitHub malware repositories remain disabled metadata-only sources.
- Git tree/blob metadata is not accepted as canonical SHA-256 evidence.
- No sample acquisition, network fetch, package apply, or Defender change occurred.

## Technical Limits

- Provenance validation proves data shape, not that a source is honest or a hash is correctly classified.
- Exact hashes detect only byte-identical files.

## Commands and Results

```powershell
C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m py_compile tools\zentor_intel\import_hash_feed.py tests\test_hash_intel_update.py
# exit 0

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py tests\test_hash_intel_update.py
# python source-contract run passed: 10 tests

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py
# python source-contract run passed: 604 tests

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-hash-intel-update-package-smoke.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
# signed definitions-only package smoke passed; exit 0

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\zentor-no-malware-binaries-gate.ps1 -RepoRoot . -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
# exit 0

git diff --check
# exit 0
```
