# Hash-Intelligence Activation and Rollback Verification

Checkpoint: 2166
Date: 2026-07-17
Scope: atomic engine component revocation and isolated signed definitions lifecycle

## Verified

- A signed signature-only `.aup` verifies through the release Update Service.
- Apply uses only checked temporary install/data roots and fake service control.
- The new reviewed pack becomes active while a pack absent from the signed component is removed.
- The old signature component is retained in the pre-apply rollback snapshot.
- Rollback restores the old pack byte-for-byte and removes the newly activated pack.
- App, service, rules, model, trust, and docs fixtures remain unchanged during a signature-only update.
- Successful apply leaves no files under the update staging root.
- Atomic replacement rejects a non-directory destination without mutating it and leaves no staging/backup sibling behind.

## Partial

- Real installed service stop/start, installed ACLs, elevation, production keys, and production publication were not exercised.
- Repository-wide strict Clippy remains partial: Rust 1.96 reports eleven pre-existing lint findings outside the new replacement implementation. They are style/maintainability findings, not failed functional tests; the exact categories are listed below and remain visible rather than suppressed in the default gate.

## Disabled or Blocked

- No machine-wide install or service mutation was performed.
- Requested GitHub malware repositories remain disabled metadata-only sources.
- No malware/feed/sample was downloaded, executed, unpacked, or retained.

## Technical Limits

- The fake service-control smoke proves updater orchestration, not Windows Service Control Manager behavior.
- User-mode scanning still does not provide demonstrated kernel or pre-execution blocking.

## Commands and Results

```powershell
cargo test --manifest-path core\avorax_update_service\Cargo.toml -- --test-threads=1
# 4 key-generator + 0 signer + 203 update-service tests passed; 0 failed

cargo build --release --manifest-path core\avorax_update_service\Cargo.toml --bin avorax_update_service --bin avorax_sign_manifest --bin avorax_generate_update_key
# release build passed

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\run-hash-intel-update-package-smoke.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
# Avorax signed hash-intel verify/apply/rollback smoke test passed

C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py
# python source-contract run passed: 606 tests

cargo clippy --manifest-path core\avorax_update_service\Cargo.toml --all-targets -- -D warnings
# failed on 11 existing findings: useless_conversion, needless_borrow,
# unnecessary_sort_by, too_many_arguments, never_loop,
# items_after_test_module, and useless_vec; none points into file_replacer.rs

cargo clippy --manifest-path core\avorax_update_service\Cargo.toml --all-targets -- -D warnings -A clippy::useless_conversion -A clippy::needless_borrow -A clippy::unnecessary_sort_by -A clippy::too_many_arguments -A clippy::never_loop -A clippy::items_after_test_module -A clippy::useless_vec
# passed; no additional warning category was emitted

cargo fmt --manifest-path core\avorax_update_service\Cargo.toml -- --check
# exit 0

git diff --check
# exit 0
```

The first extended smoke failed because the previous implementation merged the
new signature files into the existing component and left the old pack active.
The atomic component replacement fix and repeated end-to-end smoke close that
revocation defect.
