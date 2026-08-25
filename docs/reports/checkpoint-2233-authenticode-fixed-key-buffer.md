# Checkpoint 2233 - Authenticode Fixed Launch-Key Buffer

## Objective

Reduce avoidable Authenticode per-launch HMAC-key representations without
changing the exact 36-byte wire protocol or overstating user-mode secrecy.
Checkpoint 2232 provided best-effort cleanup but retained four displayable,
heap-owning `Zeroizing<String>` values and created a second owned child key after
the pipe read.

## Scripted Implementation

- Define one `AuthenticodeLaunchKey` alias as `Zeroizing<[u8; 37]>`.
- Reserve bytes 0..36 for canonical lowercase RFC-4122-v4 UUID text and byte 36
  as a zero overflow guard.
- Generate the parent key directly into the fixed buffer with UUID's bounded
  encoder; retain no owned launch-key `String`.
- Keep pipe delivery exact: parent `WriteFile` sends only 36 bytes. Child
  `ReadFile` accepts at most 37, requires exactly 36 transferred bytes, and
  requires the overflow guard to remain zero.
- Move that same child buffer into pending and completed handshake state. Remove
  the prior UTF-8 slice plus `to_owned()` key duplication.
- Validate guard, exact lowercase UUID byte shape, UTF-8, RFC-4122 variant, and
  random UUID version before returning a borrowed 36-byte HMAC key slice.
- Preserve best-effort RAII zeroization and absence of `Debug` derives on all
  key-bearing protocol containers.

## Scripted Verification

- Update the existing explicit-zeroization regression for fixed all-zero
  storage and post-scrub canonical-key rejection.
- Add
  `native_authenticode_launch_key_fixed_buffer_is_guarded_and_fail_visible`, a
  benign pure regression for exact buffer length, canonical generation, zero
  overflow guard, changed-guard rejection, all-zero scrub, and post-scrub
  failure. It reads or executes no candidate fixture.
- Add source contract 663 for the alias, four owners, direct encoding, exact
  36-byte parent write, guarded 37-byte child read, move-only child ownership,
  absent production `Zeroizing<String>`/`to_owned()`, verifier, validator, and
  documentation contracts.
- Add exactly one mandatory verifier target,
  `native-engine Authenticode fixed launch-key buffer regressions`. The strict
  validator requires exactly 263 steps; stale 262-step evidence must fail.
- Script eight adversarial report mutations covering status, Defender inclusion,
  Rust skip, stale step count, renamed mandatory step, removed verified scope,
  removed technical-limit scope, and failed final step.

No checkpoint-2233 passing result is claimed during scripting. Parser,
formatting, compilation, focused tests, full regression, definitive verifier,
strict validators, adversarial report checks, hosted evidence, integration,
synchronization, and destination verification begin only after this complete
batch is scripted.

## Security Boundary

This removes avoidable owned `String` key forms and a child-owned copy. It does
not make the key encrypted, durable, or inaccessible while live. Best-effort
zeroization of `Zeroizing<[u8; 37]>` cannot guarantee erasure of UUID/HMAC
internals, compiler temporaries, stack or register spills, allocator/OS/pipe
copies, process dumps, paging, same-user or privileged reads, or forensic
remnants. It is not secure erasure, cross-identity authentication,
AppContainer/LPAC, installed LocalSystem, signed-driver, kernel, or pre-execution
protection.

## Dependencies And Safety

Checkpoint 2233 reuses pinned `zeroize 1.9.0`, `uuid`, `hmac`, and `sha2` and
adds no crate, package, feature, or lockfile change. It adds no executable,
network source, installer, service, driver, machine-wide component, release, or
publication. Only benign protocol bytes and EICAR-safe existing test policy are
allowed; no live malware or candidate fixture is executed, Defender is not
weakened, and the protected quarantine vault is untouched.

## Broad Local Evidence

- Parsers and formatting pass; dependency-free source contracts pass `663/663`.
- Fixed-buffer `1/1`, zeroization `1/1`, key-confirmation `2/2`, pipe-delivery
  `1/1`, and complete Authenticode `81/81` pass with 19 intentional isolated
  child-entrypoint ignores.
- Native passes `517/517` plus signature compiler `6/6`; Local passes `536/536`;
  Guard passes `248/248` and all-features `249/249`; both locked root workspace
  modes pass.
- Strict Native/Local/Guard lint, locked/offline Native, Local/Guard/Update
  release builds, and corrected absolute-path PS7/PS5.1 Authenticode helper
  smoke pass. Two earlier invocation errors stopped before helper execution and
  are not counted.
- Flutter analyze passes and Flutter tests pass `838/838`. Root, standalone
  Native, and Flutter lockfiles remain unchanged; Flutter raw SHA-256 is
  `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`
  and Git blob is `51fa085a41168aa1deadace8b5395614db43649e`.

The exact 263-step verifier, embedded and independent validators, eight
adversarial reports, exact-head hosted CI/packages, integration, synchronization,
and destination proof remain pending. This local pass does not change the
`Zeroizing<[u8; 37]>` overflow-guard, removed owned `String`, secure-erasure, or
pre-execution boundaries above.

## Definitive Local Evidence

- The full verifier starts at `2026-08-25T15:09:40.0697976Z`, completes at
  `2026-08-25T15:17:21.5029589Z`, and passes exact `263/263` with zero failed or
  skipped steps in `461.4s`. Defender EICAR integration is false and Rust/
  Flutter skips are false. The mandatory fixed-buffer target passes in `0.2s`.
- The embedded and separately invoked Windows PowerShell 5.1 strict validators
  accept the same atomic report. The adversarial script rejects all `8/8`
  mutated reports, including stale 262-step, removed mandatory target, and
  missing verified or technically limited fixed-buffer scope.
- An extra non-required PS7 validator invocation fails before evidence evaluation
  because PowerShell 7 converts ISO timestamp strings to `DateTime`. It is not
  counted. Both PS7 and PS5.1 release Authenticode smokes remain independently
  green.
- Root, standalone Native, and Flutter locks remain exact. No test process is
  left. The protected vault remains 16,072 files, zero directories, 4,522,733
  bytes, 5,357 each payload/JSON/auth, one metadata key, and zero pending/temp/
  reparse. It was read only.

Hosted exact-head CI/packages, normal PR integration, guarded synchronization,
and destination verification remain pending. The verified
`Zeroizing<[u8; 37]>` overflow guard and removed owned `String` copy still do
not prove secure erasure, cross-identity authentication, signed-driver behavior,
or pre-execution enforcement.

## Exact Implementation-Head Hosted Evidence

Implementation commit `00e9f3c3f0f03c5bf4596c7bdc8bad1ef091ddd6` was pushed
only to the checkpoint branch and is PR `#85`'s exact head. Avorax CI run
`32865480443` passes all five jobs: branding/copy, Flutter client/protocol,
security/protection/performance, Rust Local Core/Native/Guard/Update/backend,
and Unix quarantine permissions.

Desktop Packages push run `32865302082` and PR run `32865480497` pass package
contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS x64/arm64 DMGs, and
consolidation/checksums. Publication jobs `97866405363` and `97864507631` are
explicitly skipped. No release or prerelease was created.

Consolidated artifacts `9570689038` and `9570466353` are 131,516,444 and
131,671,922 bytes. Their downloaded SHA-256 values exactly match GitHub digests
`10ed03fd553b98687955b63dc58bc6b25795e231918447ad09682eeb63809ed5` and
`b0d96529086e4422eba504d096990d090c7acda7e44ab2b434b46b50d7797cf7`.
Without extracting or executing either artifact, bounded in-stream validation
passes exactly eight unique regular root entries, six platform release files,
seven checksum targets with matching internal SHA-256, clean ZIP reads, and one
CycloneDX 1.6 lockfile SBOM with exactly 569 components. Evidence-head hosted
checks, normal merge, synchronization, and destination proof remain pending.

## Integration And Destination Closure

Evidence commit `646000bf64565ff16af19231275ddefecdcb21b8` passes all five
Avorax CI jobs in run `32868120569` and all Desktop Packages jobs in run
`32868120588`; publication job `97876653526` is skipped. Consolidated artifact
`9571887670` is 131,521,867 bytes and its downloaded SHA-256 exactly matches
GitHub at `40b0dcaa8a32c6d283c7b4d6649177f213b7a3cb29b0611ddd8e80a95996db66`.
Its bounded non-extracting validation passes exact 8/6/7 inventory and one
CycloneDX 1.6 lockfile SBOM with 569 components.

PR `#85` merged normally as
`7467bfd61a077a8783f3c333ef2488a9d00433f2`, with exact parents
`6de2a8f3bd48c5c45ee3281a90828d8b0796ded5` and
`646000bf64565ff16af19231275ddefecdcb21b8`. Merged-main CI
`32870805497` and Desktop Packages `32870805371` pass; publication job
`97884457320` is skipped. Consolidated artifact `9572796463` is 131,671,586
bytes with matching GitHub/download SHA-256
`d7a9a0627c5032541712ed4d93cb51bd1000a2b8e8a9266615777ebebc1ab3f3`
and passes the same non-extracting 8/6/7/CycloneDX 1.6/569-component review.
The first local ZIP check was attempted while the visible `gh` process was
still writing and failed as incomplete; after that process completed at the
exact GitHub byte count, the credited validation passed.

Guarded preconditions accepted seven checkpoint-2232 closure-document blobs,
four merged-main source/test blobs, and one absent new report. Root containment,
reparse rejection, checked staging, temporary hash verification, and atomic
replacement synchronized exactly 12 paths and 6,773,798 bytes with zero delete
or residue. The stage was removed only after its exact 12-file inventory and
merge hashes were revalidated.

Destination parsers, formatting, source contracts `663/663`, fixed buffer
`1/1`, Native `517/517` with 19 intentional child-entrypoint ignores plus
compiler `6/6`, Local `536/536`, Guard `248/248 + 249/249`, both locked
workspaces, strict Native/Local/Guard Clippy, offline Native, three release
builds, PS7/PS5.1 Authenticode smoke, Flutter analyze, and Flutter `838/838`
pass. The first verifier invocation used the WindowsApps Python reparse alias
and failed visibly at the signed hash-intelligence smoke; it is not credited.
The corrected explicit Python-binary run passes exact `263/263` from
`2026-08-25T16:50:12.2323462Z` through `2026-08-25T16:57:46.3305093Z` in
`454.1s`, with the fixed-buffer target at `0.2s` and zero failed/skipped steps.
Embedded and independent PS5.1 validation pass, and `8/8` destination report
mutations are rejected.

All 12 synchronized paths and root/Native/Flutter locks remain exact; lock
SHA-256 values are `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
No process, sync temp, or stage remains. The protected vault remains 16,072
files, zero directories, 4,522,733 bytes, 5,357 each payload/JSON/auth, one
metadata key, and zero pending/temp/reparse. Nothing was installed, released,
published, executed as candidate content, or changed in Defender. Checkpoint
2233 is closed; the complete antivirus project remains active.
