# Checkpoint 2212: Authenticode Private Desktop

## Status

Implementation, local verification, hosted evidence, normal integration, guarded
destination synchronization, and destination verification are complete. The
definitive report passes exactly `242/242` checks in `473.5s`, and the independent
validator accepts it. No candidate fixture was executed.

## Implemented Boundary

- Release Local Core and Guard create one uniquely named, bounded private desktop
  with `CreateDesktopW` in the current process window station for every isolated
  Authenticode helper launch.
- Creation temporarily applies a `SecurityImpersonation` token duplicated from the
  exact read-back-verified low-integrity child primary token. The applied token is
  read back and revalidated; successful `RevertToSelf` is mandatory before process
  creation continues. This avoids broadening the desktop DACL after the initial real
  child exposed loader failure `0xC0000142` for a medium-integrity-created desktop.
- The desktop uses a non-inheritable `SECURITY_ATTRIBUTES` contract and only the
  requested `DESKTOP_CREATEWINDOW`, `DESKTOP_READOBJECTS`, and
  `DESKTOP_WRITEOBJECTS` access flags. The parent reads back the exact name byte
  count, exact generated name, `UOI_FLAGS`, exact returned structure size, zero
  inheritance, and zero hook flags.
- `STARTUPINFOEXW.lpDesktop` receives the exact retained name. The desktop handle
  remains alive until the helper exits, then `CloseDesktop` success is checked;
  RAII remains a failure-path fallback.
- Before primary-token validation, mitigation validation, restricted-thread-token
  entry, request parsing, or candidate open, the child gets its startup desktop
  name and requires an exact match with the name queried from
  `GetThreadDesktop(GetCurrentThreadId())`.
- Token duplication/application/read-back/revert, creation, encoding, name/flag/size
  read-back, process attachment, child binding, or cleanup failure is diagnostic.
  There is no default-desktop retry.

## Local Evidence

- Real benign child fixture verifies the actual desktop attachment and emits only
  `AVORAX_PRIVATE_DESKTOP_OK`; the focused private-desktop filter passes `2/2`.
- Pure adversarial tests reject absent/default, uppercase, non-hex, shortened,
  backslash-containing, mismatched, inheritable, reserved, or hook-enabled state.
- The definitive verifier adds exact step 242:
  `native-engine Authenticode helper private-desktop regressions`.
- The independent validator requires exactly 242 steps, the exact step, parent and
  child verified-scope language, fail-visible language, and technical-limit text.
- Source contracts require the Windows features, API calls, read-back, ordering,
  handle lifetime, tests, verifier, validator, and this documentation matrix and
  pass `642/642`.
- Complete Authenticode passes `45` tests with `9` intentional child-fixture
  ignores. Both locked workspace variants pass with Native Engine `481` passed/
  `9` ignored and signature compiler `6/6`.
- Strict Native/Local Core/Guard Clippy, locked release Local Core/Guard builds,
  both release-host trust smokes, Flutter analyze and `838/838`, no-malware, and
  dependency evidence pass.
- Final review found that the initial passing implementation left `CloseDesktop`
  result handling only in `Drop`. Explicit checked close after confirmed child exit
  and its source contract were added, so the earlier report is not final evidence.
- `.verification/checkpoint-2212-private-desktop-definitive-retry2-report.json`
  passes `242/242` from `2026-08-23T19:03:30.5313301Z` through
  `2026-08-23T19:11:24.0609659Z` (`473.5s`). Fresh stale-count, renamed-step,
  missing-scope, missing-limit, and skipped-required-step copies are all rejected.
- Cargo and Flutter lockfiles remain exact at Git blobs `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`
  and `51fa085a41168aa1deadace8b5395614db43649e`. The protected vault remains
  exactly `16,072` files, zero directories, `4,522,733` bytes, `5,357` each
  `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.
- Exact implementation head `2612b7af77700a47558a638b017f3b5dac9fd0ce`
  passes Avorax CI pull-request run `32660616609` and Desktop Packages push/PR
  runs `32660604610`/`32660616617`. Both package runs build and upload Windows
  x64 MSI/setup EXE, Linux x64 DEB/tar, and macOS x64/arm64 DMGs, then require
  all six artifacts, dependency/license evidence, checksums, and lockfile SBOM.
  Windows administrative MSI extraction passes without installation. Prerelease
  publication is skipped.

## Integration Closure

Evidence head `e73a56df16ba9922deaa1515880454ebf4525a9e` passes exact-head
Avorax CI `32661792977` and Desktop Packages pull-request run `32661792980`.
Every required CI job, Windows x64 MSI/setup EXE, Linux x64 DEB/tar, macOS
x64/arm64 DMGs, administrative MSI extraction, six-artifact consolidation,
checksums, lockfile SBOM, dependency/license evidence, and upload pass.
Publication is skipped. A separate evidence-head push package run was not
expected because that commit changed documentation only.

PR `#64` normally merges as `744c4926bbb68782fb5bcc8a7bcce1bbd4bbd1c4`.
Exact merged-main Avorax CI `32662681992` and Desktop Packages `32662682077`
pass the same required evidence, again with publication skipped.

The merge changes exactly `13` paths from prior main
`33cafa59953d507cd17649f15e83489e67c32e71`: the 12 checkpoint-2212 paths plus
the checkpoint-2211 report closure carried by normal integration. Every existing
destination path first matched its prior-main Git-filtered blob, while the new
checkpoint-2212 report was absent. A bounded in-memory `git cat-file` export
wrote only those validated blobs through same-directory temporary files and
atomic replacement. All 13 destination raw blob hashes then matched merge
`744c492` exactly.

In `C:\Users\Brent\Documents\Avorax-main`, source contracts pass `642/642`,
private-desktop checks pass `2/2`, and complete Authenticode passes `45` with
`9` intentional child-fixture ignores. Strict Native/Local Core/Guard Clippy,
locked Local Core/Guard release builds, the two-host release trust smoke, the
no-malware gate, and both locked workspace variants pass. Native reports `481`
passed with `9` ignored and the signature compiler passes `6/6` in each variant.

The native Cargo and Flutter lockfiles match merge blobs
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d` and
`51fa085a41168aa1deadace8b5395614db43649e`; the root workspace Cargo lock also
matches merge blob `7ab38f4820b08029c64872360fac7141e2512ac4`.
The protected vault remains exactly `16,072` files, zero directories,
`4,522,733` bytes, `5,357` each `.avoraxq`/`.json`/`.auth`, one
`.metadata_auth_key`, and zero pending. Checkpoint 2212 is closed; the complete
antivirus goal remains active.

## Technical Limits

The private desktop isolates windows, hooks, menus, and desktop objects only within
the current process window station. It inherits that station's security descriptor;
it is not a private window station and does not isolate the station-wide clipboard
or global atom table, SID, profile, registry namespace, filesystem/network/read
access, or named kernel objects. Per-helper desktop heap consumption is bounded by
existing scan concurrency and helper lifetime but is not a Windows Job memory
accounting claim. This is not AppContainer, authenticated cross-identity IPC,
installed LocalSystem proof, driver enforcement, or pre-execution blocking.

## Remaining Program Work

Checkpoint 2212 has no remaining integration work. The larger antivirus program
still lacks installed LocalSystem and authenticated cross-identity IPC evidence,
production signing, a signed kernel driver, demonstrated pre-execution blocking,
and production false-positive/detection-rate evidence. Those limits remain tracked
as partial, blocked, or technically limited and are not implied by this closure.
