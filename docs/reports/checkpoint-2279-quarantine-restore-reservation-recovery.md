# Checkpoint 2279: Quarantine Restore Reservation Recovery

## Status

Implementation, harmless tests, Source contract 711, existing Ubuntu/macOS CI
filters, exact-304 verifier/validator scope, and audit/operational documentation
were scripted before execution. No checkpoint-2279 test ran during the scripting
phase. Focused, broad, release, Flutter/protocol, definitive, and adversarial
local verification now passes. Exact implementation-head CI and desktop package
evidence also passes. Normal integration, merged-main, destination, and closure
evidence remains pending.

The complete antivirus-hardening goal remains active.

## Risk

Checkpoint 2278 authenticated the completed restore-stage identity only after
the payload copy. A crash after exclusive stage creation or during copy could
therefore leave an artifact while the journal remained `Prepared`. Recovery
correctly preserved any such artifact for manual review, but product-created
partial state was not boundedly recoverable.

The security objective is to authenticate the exact empty stage identity before
copying any payload byte and to recover only states whose ownership, metadata,
payload, destination, and file identity remain exact. Unknown state must never
be guessed clean or successful.

## Scripted Design

The restore lifecycle now has exactly three adjacent phases:

1. `Prepared` authenticates confirmation, exact previous/terminal JSON/HMAC,
   and the controlled adjacent staging path.
2. Local Core exclusively creates and hardens an empty regular single-link
   stage, captures its Windows volume/file ID or Unix device/inode, and advances
   atomically to `RestoreReserved` with that identity.
3. Only after `RestoreReserved` is durable enough to reread and validate does
   Local Core copy through the same open stage handle under the existing 1 GiB
   cap, synchronize it, rewind, hash, and recheck path, stable identity, link
   count, size, and SHA-256. It then advances to `RestoreStaged`.
4. Existing no-replace activation, terminal metadata replay, verified payload
   removal, destination revalidation, and journal cleanup remain in order.

`replace_action_journal` accepts only exact adjacent `Prepared ->
RestoreReserved` and `RestoreReserved -> RestoreStaged` changes. The latter must
retain the same authenticated stable identity. A direct phase skip, changed
identity, changed record pair, action, ID, or staging path fails visibly.

## Recovery Matrix

| Phase/state | Scripted result |
|---|---|
| `Prepared`, no stage/destination | Remove untouched intent after exact old metadata/payload checks |
| `Prepared`, exact empty ordinary single-link stage | Remove the narrow unbound reservation, then the journal |
| `Prepared`, non-empty/linked/unavailable stage | Preserve state for manual review |
| `Prepared`, destination present | Preserve state and fail visibly |
| `RestoreReserved`, stage missing | Retain exact old record/payload and remove the no-effect journal |
| `RestoreReserved`, exact identity but empty/incomplete | Remove the identity-bound partial stage and journal |
| `RestoreReserved`, exact identity and same size but wrong SHA-256 | Remove the identity-bound invalid stage and journal |
| `RestoreReserved`, exact completed copy | Advance to `RestoreStaged` and resume existing recovery |
| `RestoreReserved`, identity mismatch/hard link/early destination | Preserve evidence and fail visibly |
| `RestoreStaged` | Existing exactly-one-stage-or-destination replay remains unchanged |

Automatic cleanup never follows a symlink/reparse point, never accepts a hard
link count other than one, and never removes a competing restore destination.

## Harmless Fixtures

The action-recovery filter adds fixtures for:

- empty unbound reservation cleanup;
- hard-linked empty pre-bind stage rejection;
- identity-bound empty, partial, and same-size hash-mismatched cleanup;
- exact completed-copy promotion and restore completion;
- stable-identity substitution rejection;
- early destination rejection; and
- direct `Prepared -> RestoreStaged` phase-skip rejection plus delete-phase
  rejection.

Fixtures contain only benign text, use isolated temporary directories, and are
never executed. No live malware or downloaded sample is used or retained.

## Contracts And Verification

Source contract 711 requires:

- enum order `Prepared`, `RestoreReserved`, `RestoreStaged`;
- journal-before-reservation, identity-before-copy, copy-before-staged-phase,
  and staged-phase-before-no-replace activation ordering;
- exclusive read/write `create_new`, hardening, zero-length and stable-identity
  reservation checks;
- same-handle bounded copy, sync, rewind, SHA-256, link/path/identity checks;
- only exact adjacent journal transitions;
- bounded prepared/reserved recovery and identity-bound cleanup;
- all harmless adversarial fixtures;
- unchanged fail-fast Ubuntu/macOS action filters;
- exact 304 verifier steps and validator scope; and
- documentation, vault, dependency, and limitation statements.

The existing verifier step remains:

```powershell
cargo test --workspace quarantine_lifecycle_action_recovery_ -- --test-threads=1
```

The batch must be frozen before running, in order:

```powershell
python tools\testing\run-python-source-contracts.py
cargo fmt --all -- --check
cargo test --locked --manifest-path core\zentor_local_core\Cargo.toml quarantine_lifecycle_action_recovery_ -- --test-threads=1
cargo test --locked --manifest-path core\zentor_local_core\Cargo.toml quarantine_ -- --test-threads=1
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace -- --test-threads=1
cargo test --locked --workspace --all-targets --all-features -- --test-threads=1
cargo build --locked --workspace --all-targets --all-features --release
flutter analyze
flutter test --reporter compact
$env:CARGO_PROFILE_TEST_DEBUG='0'
$env:CARGO_INCREMENTAL='0'
$env:CARGO_PROFILE_TEST_CODEGEN_UNITS='1'
$env:CARGO_PROFILE_TEST_STRIP='symbols'
powershell -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .workflow\ultracode\avorax-hardening\results\checkpoint-2279-quarantine-restore-reservation-recovery-report.json
```

Both Windows PowerShell 5.1 and PowerShell 7 must accept the authentic report
and reject the generated adversarial report set. Exact commands, counts,
elapsed times, report hashes, any failed attempt, hosted run IDs, artifact
metadata, PR/merge IDs, guarded synchronization, and final audits must be added
after execution. No failure may be converted to success or omitted.

The first post-freeze source-contract run executed all 711 contracts and failed
one documentation assertion: the dependency inventory described the unchanged
dependency boundary but omitted the literal `RestoreReserved`/`restore-reserved`
phase name. Fail-fast stopped before Rust execution. The inventory was corrected
without changing dependencies or locks; this failed run is retained as failed
and a clean full Source rerun is required.

## Local Verification After Freeze

The corrected frozen source passes Source `711/711`, PowerShell parser and diff
checks, platform identity `1/1`, action recovery `25/25`, all quarantine-related
Local Core tests `167/167`, complete Local Core `624/624`, crate and workspace
strict Clippy, and the locked all-target/all-feature release build. Both locked
workspace variants pass with `1,850` executed Rust tests, `21` intentional
isolated child-fixture ignores, and zero failures.

Flutter analysis reports no issues and the client passes `852/852`. Zentor and
Avorax protocol analysis/tests pass `14/14 + 6/6`. UI inventory accounts for
all `61` controls. Package-source contracts pass `24` tests with three
documented Windows symlink-privilege skips. Branding, product-copy,
no-malware-binaries, and dependency evidence gates pass; all nine tracked
lockfiles remain unchanged.

The exact no-skip/no-Defender verifier passes `304/304` in `673.5s`, with zero
failed, skipped, or non-null-error steps. Its 237,555-byte report SHA-256 is
`e5792c4caf7b77c8462536a0407d74f956983e68b95ab2439d02dba83ea94552`.
Windows PowerShell 5.1 and PowerShell 7 both accept that authentic report and
reject all `34/34` hostile results across 17 checkpoint mutations. The
35,813-byte adversarial result SHA-256 is
`8cddc794cd1520a0d0172345fd0297c416ab70aec0d624f3b0e7db2289bf3aa7`.

Failures were retained rather than converted to success. The first broad
workspace invocation reached Local Core `624/624`, then Defender blocked the
generated Native test executable before execution with Windows error 225. No
Defender setting or exclusion changed; the documented test-only no-debug,
non-incremental, single-codegen-unit, symbol-stripped profile rebuilt a distinct
harness and both complete variants passed. Two no-malware gate attempts were
rejected before scanning because the Python path was non-absolute and then a
WindowsApps reparse point; the concrete non-reparse bundled Python path passed.
Two initial PowerShell 7 parser-wrapper command strings failed from caller
quoting, while PowerShell 5.1 already parsed the harness; the corrected
environment-bound PowerShell 7 parser invocation passed before the adversarial
audit ran.

One post-documentation format command used the invalid form `cargo fmt
--locked --all -- --check`; Cargo rejected the unsupported `--locked` argument
before formatting. The corrected `cargo fmt --all -- --check` passed. The final
read-only audit passes 14 tracked modifications plus this one untracked report,
zero deletions, nine unchanged lockfiles, zero product processes, zero
repository pending files, and zero matching temporary roots. The protected
vault remains exact at 16,072 files, zero directories, 4,522,733 bytes, 5,357
each `.avoraxq`/`.json`/`.auth`, one key, zero pending, and zero reparse points.
The 2,977-byte audit SHA-256 is
`feae0e51f9bcea9314394a9c0e3c98a075ef28e7defbf72654225f69b0609cd5`.

## Hosted Implementation-Head Evidence

Commit `c4c21e5fb243554fa2a426a2d6c7b37aa7fa6dab` is the exact head of
PR `#167`, based on `a49e62ae048e8b8afff27b084080d4b08b22eb13`.
The PR is mergeable and clean. Avorax CI run `33355915264` passes all six
jobs, including the actual Ubuntu and macOS action-recovery filters. Desktop
Packages PR run `33355915194` passes package contracts, Windows x64 MSI/setup
EXE, Linux x64 DEB/tar, macOS arm64/x64 DMGs, and consolidation. The prerelease
publication job is skipped as required.

Hosted artifact metadata for that exact package run is:

| Artifact | ID | Bytes | Hosted SHA-256 digest |
|---|---:|---:|---|
| consolidated desktop evidence | `9745412188` | 133,166,414 | `ea7c9393afa4d3db7cfb124e4226e7ae02bdb44d202c62d697e464bbf48d6a97` |
| Windows package evidence | `9745282306` | 37,602,611 | `483bf5e6fda7836abd08ed25c28ac5729e75e5af21cf9ff7390920a09d1ccdb0` |
| Linux package evidence | `9745199889` | 33,175,459 | `b76d8afa3e236f22ff43c03fe3f47e9de7260d67777323d0055f00e0f7b6830d` |
| macOS arm64 package evidence | `9745210418` | 30,511,790 | `e66d66ab8ab3bb255aecd38cbf7680827eae69dac921f2b6f01dc60138edfa35` |
| macOS x64 package evidence | `9745405529` | 31,903,955 | `51ead5e8709f07bfc2ef2405db945773e5e5415f4bd0213ec72f8d750e699277` |

Consolidation logs prove exactly six platform release files, seven checksum
targets, one CycloneDX lockfile SBOM with 569 components, and eight uploaded
evidence files. The seven recorded target hashes are:

- Linux DEB: `68d745656f98d6004d962ae1e2b8ec8cfa036eac54f06231c9ff85c07d1fd574`;
- Linux tar: `5902d31a46a7c85377583563e5f4f1c0fe105da6e24901896f2f4da0acc2e713`;
- lockfile SBOM: `3a669e82404811fdf43c495e39acc893ec513dad1505d681d4a2b5836216cc91`;
- macOS arm64 DMG: `40cf5ec7ccbd66d6389ef582753ef2819b1e266be481e412e474da81db210003`;
- macOS x64 DMG: `ab05244238be07bbfaa90ac1f6f38fefa73aefff6e32048583befe5aecd3dc76`;
- Windows setup EXE: `42045bc1dd631b84b413708013d69f89178309c03bdf2db90ff94106cebe9239`;
- Windows MSI: `2acf6c45c2ed75bac9cf2841dc23a75f1a73b3071b75bfd35457e8425d6597a9`.

Only GitHub job logs and artifact metadata were inspected. No artifact was
downloaded, extracted, installed, executed, released, or published. Normal PR
merge, merged-main CI/packages, guarded destination synchronization, and
destination verification remain required before checkpoint closure.

## Dependency And Vault Boundaries

Checkpoint 2279 adds no dependency, feature, external tool, action, license, or
lockfile change. All nine lockfiles must remain exact. The protected vault is
not a fixture and must remain exactly:

- 16,072 files;
- zero directories;
- 4,522,733 bytes;
- 5,357 each `.avoraxq`, `.json`, and `.auth`;
- one `.metadata_auth_key`; and
- zero pending artifacts.

No service/driver start, machine-wide install, Defender weakening, artifact
download/extraction/execution, release, publication, or direct-main push is
authorized.

## Residual Limits

- The narrow creation-to-identity-journal gap permits automatic cleanup only
  when the authenticated controlled path still names an empty ordinary
  single-link file. Non-empty, linked, unavailable, or otherwise ambiguous
  unbound state remains preserved for manual review.
- JSON/HMAC, action journal, quarantine payload, restore destination, and their
  directory entries are not one power-loss-proof filesystem transaction.
- Journal removal and directory durability depend on truthful local storage;
  Windows replacement ambiguity can preserve adjacent backup evidence.
- Stable identity, path, ancestor, link, size, hash, and ACL checks are
  point-in-time user-mode evidence. They cannot defeat administrators,
  SYSTEM/root, hostile filesystems/storage, or kernel compromise.
- This is bounded confirmed-intent replay, not secure erase, installed identity,
  production signing or detection accuracy, signed-driver mediation,
  pre-execution blocking, Defender replacement, or completion of the antivirus-
  hardening goal.
