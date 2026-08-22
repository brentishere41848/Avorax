# Checkpoint 2197 Native Secondary Authenticode

Date: 2026-08-22

## Scope

Checkpoint 2197 adds bounded secondary embedded Authenticode evaluation to the
Native Engine. It preserves the existing trust conjunction: Windows must accept
the selected signature, its verified leaf must match the exact Microsoft
organization/common-name policy, and scan-path trust must bind to the SHA-256
already computed by the detection engine.

This checkpoint does not add secondary catalog-signature support, authorize
execution, install or start software, change Defender, publish a release, or
claim pre-execution blocking or production detection accuracy.

## Implementation

For `WTD_CHOICE_FILE`, the verifier now:

1. supplies `WINTRUST_SIGNATURE_SETTINGS` with secondary-count and exact-index
   flags while requesting primary index zero;
2. initializes `dwVerifiedSigIndex` to a sentinel before each call, accepts only
   zero or the untouched sentinel for primary index zero, and requires every
   secondary output to equal its requested index exactly;
3. closes and resets WinTrust provider state before the next signature;
4. rejects a total above 16 signatures, arithmetic overflow, or count drift;
5. returns trust immediately for a valid exact-Microsoft primary;
6. searches secondaries in index order only after a valid non-Microsoft primary;
7. ignores only definitive invalid secondary verdicts and aborts on every
   inconclusive/API/I/O/policy/identity/hash/cleanup error; and
8. does not let a definitively invalid primary reach secondary aggregation,
   while retaining checkpoint 2196's bounded catalog fallback.

No exception is swallowed and no clean result is synthesized.

## Safe Fixtures

Pure tests exercise ordering, early success, no-match, callback failure, and
the 16-total limit. The Windows runtime test examines at most 64 direct entries
under installed Microsoft Edge, considers eight fixed known benign DLL names,
rejects reparse paths, and requires a real bounded secondary-signature set.
It verifies a valid primary outside the exact Microsoft allowlist,
provider-aware primary output, every exact secondary returned index, stable
count, closed/reset state, and at least one exact-Microsoft secondary. The DLL
is opened read-only and never
executed, copied, unpacked, or retained.

## Verification

The complete implementation, test, verifier, validator, source-contract, and
documentation batch was scripted before running tests. Execution order:

1. diff review, formatting, parser, and focused source contracts;
2. pure and benign runtime secondary Authenticode tests;
3. direct/catalog regression filters and strict Native Clippy;
4. complete Native Engine, locked/all-feature workspace, Flutter, dependency,
   security, packaging, and release-build gates;
5. definitive 226-step verifier and independent report validator;
6. exact-head hosted CI/packages, normal PR merge, and merged-main checks; and
7. preconditioned original-tree synchronization plus final read-only vault audit.

Local steps 1 through 5 passed. `cargo fmt --check`, PowerShell parser checks,
Python AST parsing, `git diff --check`, strict Native Clippy, and the following
runtime suites passed:

- `cargo test --locked --manifest-path core/zentor_native_engine/Cargo.toml
  windows_authenticode::tests -- --test-threads=1`: `14/14`;
- secondary/direct/catalog Authenticode filters: `3/3`, `5/5`, and `3/3`;
- complete Native Engine: `448` library plus `6` compiler tests;
- complete locked Rust workspace and all-features workspace: passed;
- Flutter analyzer: no issues; Flutter tests: `838/838`;
- dependency-free Python source contracts: `626/626`.

The definitive verifier command was:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot . -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .verification\checkpoint-2197-small-threat-mvp-full-report.json
```

It passed exactly `226/226` steps with zero failed, skipped, or error steps from
`2026-08-22T18:27:29Z` through `2026-08-22T18:35:30Z` (`480.8s`). Independent
`validate-small-threat-mvp-report.ps1 -RequireFullSuite` validation passed. The
same validator rejected checkpoint 2196's stale 225-step report with exit code
1, proving the new step cannot be omitted.

Three first-pass issues were kept visible and repaired: a generic test needed an
explicit result type; the Windows provider left the primary returned-index field
at its initialized sentinel; and the real Edge fixture's exact-Microsoft signer
was a later secondary rather than index one. Production now permits the sentinel
only for requested primary zero and demands exact returned indices for all
secondaries; the runtime test checks every bounded secondary. No test was muted,
skipped, or converted into a fake pass. Global/bundled `pytest` was unavailable,
so the repository's dependency-free source-contract runner was used without
installing anything.

The protected vault remained exactly 16,072 files, zero directories, 4,522,733
bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending files.

Implementation head `e4dcb89e9b6fe487713d07283a719ad41317af22` is
pushed on draft PR `#49`. Exact-head Avorax CI `32591435260` passed all five
jobs. Desktop Packages push/PR runs `32591426228`/`32591435262` passed package
contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS x64/arm64 DMGs,
six-artifact consolidation, checksums, and lockfile SBOM generation. Publish
jobs `97077392409` and `97077262064` were intentionally skipped. No artifact
was installed, published, or released. Evidence head
`137ee29052a10696956256629f8d729ec561ba40` passed Avorax CI `32592153314`
and Desktop Packages `32592153266`, with publication skipped. PR `#49` merged
normally as `736a9f6ccdb6f7512c854aa816361fc322489222`. Merged-main CI
`32593102355` and packages `32593102373` passed with publication skipped. All
12 explicit files synchronized to the original tree after exact old/new blob
preconditions matched; destination hashes and focused secondary `3/3`, strict
Clippy, rustfmt, parser, and source-contract `626/626` checks passed. The vault
invariant remained unchanged.

## Remaining Limits

- Secondary catalog signatures are not enumerated.
- An invalid primary cannot be rescued by an otherwise valid secondary.
- One in-process WinTrust call has no hard cancellation deadline.
- Earlier writable/memory-mapped handles and post-verdict mutation remain
  user-mode TOCTOU limits.
- Windows trust stores, providers, WinTrust semantics, and protected installed
  fixture state remain trusted boundaries.
- Installed LocalSystem/service/UI behavior, production signing, signed-driver
  IPC, pre-execution enforcement, Defender coexistence, and production accuracy
  require separate evidence.
