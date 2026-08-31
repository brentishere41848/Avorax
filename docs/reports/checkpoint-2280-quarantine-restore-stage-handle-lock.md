# Checkpoint 2280: Quarantine Restore Stage Handle Lock

## Status

Implementation, harmless platform/runtime tests, Source contract 712, existing
cross-platform CI coverage, exact-304 verifier/validator scope, dependency
review, and audit/operational documentation were scripted before execution.
No checkpoint-2280 test ran during the scripting phase. Post-freeze verification
now passes locally. Hosted exact-head, integration, synchronized-destination,
and closure evidence remain pending.

The complete antivirus-hardening goal remains active. This checkpoint does not
claim production antivirus completion, Defender replacement, installed-service
identity, kernel mediation, pre-execution blocking, secure erasure, production
detection accuracy, or power-loss-proof transactionality.

## Threat And Control

Checkpoint 2279 retained one stage handle from empty creation through identity
authentication and payload copy, but standard Windows `OpenOptions` permitted
read, write, and delete sharing. Same-principal code could therefore request a
competing write/delete handle or rename/delete the live stage while Avorax was
still using it.

The shared platform-security crate now owns
`open_new_restore_staging_file`. It atomically creates an absent read/write
stage and returns the same handle used by Local Core. On Windows it permits only
`FILE_SHARE_READ`, so read-only path-identity probes continue to work while
competing write opens, delete opens, rename, and removal must fail for the
handle lifetime. On Unix it creates mode `0600` with `O_NOFOLLOW`. Every
platform preserves an existing competing path because creation remains
`create_new(true)`.

Local Core no longer constructs its own generic `OpenOptions`. It uses the
shared protected handle before hardening, empty-file inspection, stable identity
capture, path rebinding, synchronization, authenticated `RestoreReserved`
transition, and bounded payload copy.

## Harmless Regression Scope

Only temporary ASCII fixtures are used and no fixture is executed. Tests cover:

- preserving a pre-existing stage byte-for-byte on exclusive-create failure;
- Windows read-only reopen while the reservation is live;
- Windows rejection of competing write-open, rename, and delete;
- successful rename after all live fixture handles close;
- Unix owner-only creation and symlink-target rejection; and
- Local Core source wiring before stable identity binding.

The existing Windows, Ubuntu 24.04, and macOS 15 CI paths already run the full
locked platform-security crate. The definitive verifier's existing `platform
quarantine permission regressions` step therefore expands without increasing
the exact 304-step schema.

## Technical Limits

The Windows lock lasts only while the reservation/copy handle is open. Current
path-based atomic no-replace activation requires that handle to close first, so
the short post-close preactivation interval still relies on ancestor, path,
stable identity, single-link, size, SHA-256, and no-replace checks. Read sharing
is intentional for path binding. The lock does not defeat every hard-link or ACL
mutation, a privileged handle, administrators, SYSTEM/root, hostile filesystems
or storage, or kernel compromise.

Unix `O_NOFOLLOW` and mode `0600` protect final-component creation and default
access; they are not a mandatory namespace lock. Journal and directory updates
remain a bounded user-mode recovery protocol rather than one durable multi-file
transaction. Ambiguous evidence remains fail-visible and preserved for manual
review.

## Planned Post-Freeze Verification

```powershell
cargo fmt --all -- --check
cargo test --locked --manifest-path core\avorax_platform_security\Cargo.toml restore_staging -- --test-threads=1
cargo test --locked --manifest-path core\zentor_local_core\Cargo.toml quarantine::quarantine_store::tests::restore_reservation_uses_the_platform_handle_lock_before_identity_binding -- --exact --test-threads=1
python -m pytest tests\test_custom_driver_contract.py -q
cargo test --locked --manifest-path core\avorax_platform_security\Cargo.toml -- --test-threads=1
cargo test --locked --manifest-path core\zentor_local_core\Cargo.toml quarantine -- --test-threads=1
cargo test --locked --workspace -- --test-threads=1
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --workspace --release
flutter test
powershell -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\checkpoint-2280-quarantine-restore-stage-handle-lock-report.json
```

The report validator must accept the authentic report under Windows PowerShell
5.1 and PowerShell 7 and reject every scripted hostile mutation. Exact commands,
counts, durations, report hashes, hosted run IDs, integration, and destination
evidence will be appended only after they exist.

## Local Verification After Freeze

Focused and broad execution now passes: Source `712/712`, restore-stage platform
`2/2`, complete platform security `33/33`, exact Local Core wiring `1/1`, all
quarantine-related Local Core tests `182/182`, and complete Local Core `625/625`.
The locked standard workspace, all-feature workspace, and all-target/all-feature
workspace pass with zero failures; strict all-target/all-feature Clippy and the
locked all-target/all-feature release build also pass.

Flutter analysis reports no issues and the client passes `852/852`. Zentor and
Avorax protocol analysis/tests pass `14/14 + 6/6`. The definitive no-skip,
no-Defender verifier passes exactly `304/304` in `706.4s`, with zero failed,
skipped, or error-bearing steps. Its 238,710-byte report SHA-256 is
`49701948f989f942902fbffad5a1221ae34f26b3811c18427b2aab1dbe6a6bcb`.
Windows PowerShell 5.1 and PowerShell 7 accept the authentic report and reject
all `34/34` hostile results across 17 mutations. The 36,198-byte adversarial
result SHA-256 is
`1235e51aa65ecf7718a37ab56dc5a8513aff6aa68efc7da6def6f7aeedc0952d`.

Failures were not converted to success. Initial format checking found only the
new Rust layout and passed after `cargo fmt --all`. Neither the system Python
3.14 nor bundled Python provides `pytest`, so no package was installed; the
repository fallback runner was used. Its first run found two stale pre-2280
source markers, then passed `712/712` after repair. The first exact Local Core
filter selected zero tests because the module path was incomplete; the corrected
exact path passed `1/1`. The first quarantine run passed `181/182` and exposed
one stale source marker; the clean rerun passed `182/182`. The first adversarial
audit correctly failed because one optional explanatory phrase was not a
validator requirement; the mutations were narrowed to required claims and the
clean dual-host rerun rejected `34/34`. All failed attempts remain in the local
record.

Hosted Windows/Ubuntu/macOS execution, normal PR integration, merged-main
evidence, guarded destination synchronization, and destination regression are
still required. The complete antivirus-hardening goal remains active.

## Safety And Vault

No live malware, malware repository, downloaded sample, Defender change,
machine-wide install, service/driver start, artifact execution, release, or
publication is authorized. The protected
`C:\ProgramData\Avorax\Quarantine` invariant remains read-only: 16,072 files,
zero directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
`.metadata_auth_key`, and zero pending.
