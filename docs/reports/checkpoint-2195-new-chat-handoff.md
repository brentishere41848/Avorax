# Checkpoint 2195 New-Chat Handoff

Date: 2026-08-22 (Europe/Brussels)

## User Direction

Continue the full Avorax antivirus goal in a new chat. For the next checkpoint,
finish scripting the implementation, tests, verifier changes, and documentation
first. Do not start running tests until that scripting batch is complete. Once
the batch is complete, execute focused checks first and then the full regression
and hosted evidence sequence.

This sequencing request does not relax any quality or safety gate. Nothing may
be described as verified before the later execution phase proves it.

## Authoritative Workspace State

- Working repository:
  `C:\Users\Brent\Documents\Codex\2026-06-23\goal-use-ultracode-to-make-the\.publish\Avorax-beta-a9769947f80c42ac945b1704111804dc`
- Original synchronized tree (do not use as the editing worktree):
  `C:\Users\Brent\Documents\Avorax-main`
- Current branch:
  `agent/checkpoint-2195-native-direct-authenticode`
- Branch base / current committed HEAD:
  `1b2904a9a0e3b0a902271f041b25169d1716a50f`
- The branch tracks `origin/main` and has no checkpoint-2195 commit yet.
- `.verification/` is pre-existing untracked evidence. Never stage, delete, move,
  clean, or rewrite it.

At handoff, the only new implementation file is untracked:

- `core/zentor_native_engine/src/windows_authenticode.rs`
- 411 lines
- SHA-256:
  `4DE1708C3B5AA94E060A1C7BF3F4CA64F8139799A23AAF5791BDDF794815DDE2`

This module was deliberately left **partial and unverified** at the user's
handoff request. It has not been compiled, formatted, linted, or run. Do not
infer correctness from its presence. Inspect and repair it while completing the
implementation batch.

## Last Closed Checkpoint

Checkpoint 2194 hardened Native Engine Windows-root handling and was fully
closed before checkpoint 2195 began.

- Implementation commit: `7cdf7caf5fa0c0e0d66fb66dc9fa397128b74dcb`
- Honesty correction: `1dee3e25d5131d9b999cce7580e5df0f59a82f47`
- Evidence/docs commit: `d92ac67a052b1b40ad183fe5b7441f29dc6b72db`
- PR: <https://github.com/brentishere41848/Avorax/pull/46>
- Merged main commit: `1b2904a9a0e3b0a902271f041b25169d1716a50f`

Definitive local checkpoint-2194 verification passed `223/223` with zero
failed/skipped steps in 522.3 seconds. Native tests passed 448 tests, the Rust
workspace passed `1,486/1,486`, Flutter passed `838/838`, and source contracts
passed `626/626`. Strict Clippy, rustfmt, parsers, standalone locked/offline
build, exact implementation/evidence-head CI, package workflows, and
merged-main CI/package workflows passed. Publication jobs were intentionally
skipped. No package was installed or released.

After merge, the 17 synchronized checkpoint files in the original tree matched
the evidence head byte-for-byte. Original-tree rechecks passed Authenticode
`2/2`, Windows ACL/SID `4/4`, strict Native Clippy, and standalone
`cargo check --all-targets --locked --offline`.

## Protected Quarantine Invariant

Never modify or delete `C:\ProgramData\Avorax\Quarantine`. The last read-only
inventory after checkpoint 2194 was exactly:

- 16,072 files, 0 directories, 4,522,733 bytes
- 5,357 `.avoraxq`
- 5,357 `.json`
- 5,357 `.auth`
- one `.metadata_auth_key`
- zero pending files

Re-inventory read-only before and after any relevant verification. A mismatch is
a blocker and must not be "fixed" by deleting or rewriting vault content.

## Checkpoint 2195 Objective

Replace Native Engine's external WindowsPowerShell Authenticode probe with a
direct, isolated Windows API boundary while preserving the two-part trust rule:

1. The file must have a valid Windows Authenticode trust verdict.
2. The verified leaf signer must identify Microsoft under the existing exact
   organization/common-name policy.

Do not weaken the rule to "located under Windows" or "any valid signature".
Do not claim catalog-signature coverage, revocation completeness, hard API
deadlines, or atomicity beyond what is actually implemented and demonstrated.

The partial module currently attempts to:

- require an absolute, bounded, NUL-free UTF-16 path;
- open the candidate with read access, `FILE_FLAG_OPEN_REPARSE_POINT`, no
  write/delete sharing, and post-open regular/non-reparse validation;
- pass the still-open handle to `WinVerifyTrust` with no UI;
- use only locally cached revocation data, check the chain excluding the root,
  and disable MD2/MD4;
- retain WinTrust state, retrieve the exact primary signer and leaf certificate,
  read bounded organization/common-name attributes, then close WinTrust state;
- return `false` only for explicitly classified invalid/untrusted statuses and
  surface inconclusive/operational statuses as errors;
- test exact publisher matching, status classification, rename denial while the
  handle is open, and path bounds.

## Implementation Batch Still Required

Complete all of the following before starting the requested test-execution
phase:

1. Audit and repair `windows_authenticode.rs`. Pay special attention to
   `windows-sys` type signatures, unused imports, WinTrust close behavior,
   status classification, pointer lifetimes, file sharing, UTF-16 bounds, and
   whether helper APIs require dynamic loading on supported Windows versions.
2. Wire `#[cfg(windows)] mod windows_authenticode;` into
   `core/zentor_native_engine/src/lib.rs`.
3. Rewrite `trust/microsoft_trust.rs` to call the native module on Windows and
   return conservative `false` on non-Windows. Remove the obsolete PowerShell
   launch, encoded script, environment-variable transport, module discovery,
   JSON parsing, bounded child runner, and their dead tests/imports. Preserve
   checked Windows system-root/path behavior and generic non-following candidate
   checks.
4. Expand the target-Windows `windows-sys 0.61` feature list in Native Engine's
   `Cargo.toml` for the exact Foundation, Storage/FileSystem, Security,
   Cryptography, Catalog, SIP, WinTrust, and existing SystemInformation bindings
   actually used. Do not add a second Windows binding crate.
5. Keep both root and standalone lockfiles pinned. Regenerate only if Cargo
   proves a lock metadata change is required; no new registry package should be
   necessary because `windows-sys 0.61.2` is already locked.
6. Replace the PowerShell-specific Rust and Python source-contract tests with
   direct-WinTrust contracts. Add `NATIVE_WINDOWS_AUTHENTICODE` to
   `tests/test_custom_driver_contract.py`. Assert closed-state cleanup, open
   handle use, no UI, cache-only network policy, bounded signer extraction,
   explicit inconclusive errors, and absence of `Command`, PowerShell,
   `EncodedCommand`, `PSModulePath`, and JSON helper parsing in production trust
   code.
7. Add adversarial benign tests for unsigned input, malformed/non-PE input,
   relative/NUL/oversized paths, final reparse targets where privilege permits,
   rename/replace denial while the handle is open, signer-name lookalikes,
   inconclusive status classification, and a real Microsoft-signed Windows
   system binary. Never execute a fixture.
8. Decide and document embedded-versus-catalog signature behavior and primary
   versus secondary signature behavior. Preserve conservative failure if full
   support is not implemented; do not make unsupported coverage claims.
9. Add a mandatory central-verifier step and independent report-validator
   contract for checkpoint 2195. A stale 223-step checkpoint-2194 report must be
   rejected after the expected step count changes.
10. Update `RUN_LOG.md`, `STATUS.md`, the engine/control matrix, known blockers,
    threat model, dependency evidence if affected, and a final checkpoint-2195
    report. Clearly separate verified, partial, disabled/blocked, and technically
    limited behavior.

## Deferred Test-Execution Phase

Only after the entire implementation/test/verifier/documentation batch above is
scripted, execute in this order:

1. PowerShell parser checks and `cargo fmt --check`.
2. Focused direct-Authenticode tests on Windows, including unsigned and real
   Microsoft-signed fixtures.
3. Full Native Engine tests, strict all-target/all-feature Clippy, and standalone
   `--locked --offline` all-target check.
4. Rust workspace, Flutter, source contracts, no-malware-binaries gate, update,
   quarantine, restore, logging, resource, and regression suites.
5. The one-command definitive verifier and its independent validator. Preserve
   exact commands, timestamps, duration, pass/fail/skip counts, and errors.
6. Read-only quarantine inventory and exact diff/lock/dependency review.
7. Commit the implementation checkpoint, push the branch, run exact-head CI and
   desktop-package workflows with publishing skipped, then add evidence docs in
   a separate commit and repeat exact-head checks before PR/merge.
8. Merge only after all required checks pass. Synchronize only the explicit
   checkpoint file list into `C:\Users\Brent\Documents\Avorax-main` after
   byte/hash preconditions and reverify there.

## Security and Repository Boundaries

- Never download, clone, open, unpack, execute, or retain live malware. Use only
  EICAR text and benign fixtures/mocks.
- Never weaken or disable Microsoft Defender, add exclusions, install/start a
  driver or service, install machine-wide components, or claim pre-execution
  blocking.
- Never force-reset, clean the repository, delete untracked evidence, push to
  `main` directly, publish a release/package, or install an artifact.
- Preserve unrelated changes and all working behavior.
- Use small reversible commits. Push/PR work is authorized, but release/publish
  remains unauthorized.
- Production Native Engine remains detection-only. Local Core remains the sole
  production owner of quarantine, authenticated metadata, restore, rescan, and
  deletion.
- Keep the full antivirus goal active. Checkpoint 2195 completion is not project
  completion.

## Microsoft API References Consulted

- <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust>
- <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data>
- <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info>
- <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelperprovdatafromstatedata>
- <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain>
- <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovcertfromchain>
- <https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringw>
- <https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Security/CodeSigning/cpp/codesigning.cpp>

Use official Microsoft documentation as the primary source for any remaining
Win32 ambiguity.
