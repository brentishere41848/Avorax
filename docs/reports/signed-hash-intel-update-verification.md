# Signed Hash-Intelligence Update Verification

Checkpoint: 2164
Date: 2026-07-17
Scope: strict reviewed SHA-256 packs and definitions-only signed update packaging

## Verified

- `known-bad-sha256` requires a non-empty signature pack.
- Every active row must be a unique lowercase 64-character SHA-256 `exact_hash` with `confirmed` confidence, `critical` severity, a production category, `file_types: ["*"]`, empty context, null partial-pattern fields, and `quarantine_if_policy_allows`. The pack digest must also be canonical lowercase SHA-256.
- Empty, duplicate-ID, duplicate-hash, uppercase item/pack digest, partial-hash, lower-confidence, wrong-severity, unknown/test-category, narrowed-file-type, contextual, masked, and wrong-policy fixtures fail visibly.
- Hash pack compilation validates a unique temporary pack and atomically activates it only after success. A failed empty-feed build preserves the previous output and removes both temporary JSONL and pack files.
- The signed wrapper accepts only bounded version/channel path tokens, requires an absolute checked Python executable, stages exactly one signature pack, performs no network operation, and removes both of its checked work trees.
- The release-binary smoke used one SHA-256 computed from benign text and a temporary generated Ed25519 key. The resulting `.aup` contained exactly `manifest.json`, `manifest.sig`, and `payload/engine/signatures/zentor_reviewed_known_bad.zsig`.
- Update Service `--verify` accepted the signed package at current version `0.3.0`; the manifest declared only native engine signatures. No package was applied or installed.
- Runtime adversarial probes rejected a traversal version and relative Python executable before any feed processing. Temporary smoke, wrapper, and package-builder directories were removed after execution.

## Partial

- The normal signed updater has atomic staging and rollback tests, but this checkpoint did not apply the hash-only package to a real installed service.
- Production feed review, false-positive ownership, signing-key custody, HTTPS publication, release retention, and installed rollback evidence remain external release responsibilities.

## Disabled or Blocked

- The requested GitHub malware repositories remain disabled metadata-only sources. Their tree APIs do not provide a reviewed canonical file SHA-256 feed.
- `zentor_github_known_bad.zsig` remains empty. No Git blob SHA, filename, path, size, or repository label is promoted to a blocking signature.
- No sample download, clone, execution, unpacking, or retention path was added.

## Technical Limits

- Exact hashes detect only byte-identical files and do not generalize to variants.
- User-mode scanning and monitoring do not provide demonstrated kernel or pre-execution blocking.
- Production package authenticity ultimately depends on trusted release-host integrity, protected Ed25519 private keys, embedded/configured public-key correctness, and installed binary ACLs.

## Commands and Results

```powershell
C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m py_compile tools\zentor_intel\validate_indicator_pack.py tools\zentor_intel\build_realworld_detection_pack.py tests\test_hash_intel_update.py
# exit 0

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py tests\test_hash_intel_update.py
# python source-contract run passed: 7 tests

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py
# python source-contract run passed: 601 tests

cargo build --release --manifest-path core\avorax_update_service\Cargo.toml --bin avorax_update_service --bin avorax_sign_manifest --bin avorax_generate_update_key
# Finished release profile; exit 0; 59.44s

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-hash-intel-update-package-smoke.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
# traversal/relative-tool rejection and signed package verification passed; exit 0

cargo test --manifest-path core\avorax_update_service\Cargo.toml
# 4 key-generator + 0 signer + 201 update-service tests passed; 0 failed

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-update-package-builder-smoke.ps1
# signed package builder verify smoke passed; exit 0

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-release-update-package-builder-failsafe-smoke.ps1
# 11 restricted/invalid payload scenarios rejected; exit 0

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m unittest discover -s tests -p test_packaging_tools.py -v
# 22 tests passed; 3 Windows symlink-privilege cases skipped as expected

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\zentor-no-malware-binaries-gate.ps1 -RepoRoot . -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
# exit 0

git diff --check
# exit 0
```

The first smoke attempt exposed a real definitions-only builder defect: the
component-evidence `docs` directory was not created when no docs payload existed.
The builder now creates that empty checked staging directory, a source-contract
asserts the invariant, and the repeated end-to-end smoke passed.
