# Checkpoint 2232 - Authenticode Launch-Key Best-Effort Zeroization

## Objective

Reduce post-protocol retention of the random Authenticode launch/HMAC key in
Avorax-owned memory without weakening the exact same-user pipe, token, process,
HMAC, response-binding, cancellation, or error-reporting boundaries established
through checkpoint 2231.

## Scripted Implementation

- Pin `zeroize 1.9.0` as a Windows-only direct Native Engine dependency.
- Hold the parent launch key, authenticated response key, pending child key, and
  completed child key in `Zeroizing<String>`.
- Hold the bounded 37-byte child pipe-read buffer in
  `Zeroizing<[u8; 37]>` so success and every early-return path scrub it on drop.
- Return borrowed validated UUID bytes from `authenticode_response_mac_key`
  instead of creating the obsolete raw 36-byte derived-key array.
- Keep key-bearing containers free of `Debug` derives and key-valued errors.
- Preserve exact HMAC domains, canonical UUID validation, constant-time MAC
  verification, bounded I/O, process cleanup, and fail-visible errors.

## Scripted Regression And Verification Contracts

- `native_authenticode_launch_key_zeroization_is_explicit_and_fail_visible`
  explicitly zeroizes a benign test key and pipe buffer, requires empty/all-zero
  storage, and requires prior handshake-HMAC and response-MAC evidence to fail.
- The source contract 662 checks the exact dependency, owned key wrappers, borrowed
  key API, absence of raw key fields and Debug derives, regression markers,
  lock entries, audit text, verifier step, and validator scope.
- The definitive verifier adds exactly one mandatory target,
  `native-engine Authenticode launch-key zeroization regressions`, and the strict
  report validator requires exactly 262 steps. Stale 261-step reports fail.
- No checkpoint-2232 passing result is claimed during scripting. Parsers,
  formatting, compilation, focused/full tests, verifier/validator, hosted CI,
  packages, merge, synchronization, and destination proof remain pending until
  all scripting and lock work is complete.

## Dependency And License

`zeroize 1.9.0` is a RustCrypto crate licensed `Apache-2.0 OR MIT` and requiring
Rust 1.85 or newer. It is a Windows-only direct dependency for Native Engine.
The root graph already pins this version transitively; the root Native edge and
standalone Native exact package/edge were resolved offline after all source and
documentation scripting. Root lock SHA-256 is
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`;
standalone Native is
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`;
unchanged Flutter is
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
It adds no executable, network service, script host, installer, service, driver,
or machine-wide component.

## Threat And Technical Limits

This is best-effort cleanup of Avorax-owned buffers. It cannot guarantee removal
of compiler temporaries, HMAC internals, allocator or OS copies, process dumps,
paging, or forensic remnants and cannot prevent same-user or privileged memory
reads while the key is live. It is not secure erasure, encryption, durable
secret storage, cross-identity authentication, AppContainer/LPAC, installed
LocalSystem, signed-driver, or pre-execution enforcement.

## Local Execution Evidence

- Corrected PowerShell 7 and Windows PowerShell 5.1 parsers, `cargo fmt --check`,
  `git diff --check`, and exact source contracts `662/662` pass. Earlier source
  contract mismatches, the first PS5 parser wrapper, and a relative-path PS5
  release-smoke invocation failed visibly, were corrected, and are not credited.
- The new zeroization target passes `1/1`; handshake HMAC `2/2`, pipe delivery
  `1/1`, and wrong response-key MAC `1/1` also pass. Complete Native passes
  `516/516` with 19 intentional ignored child entrypoints plus signature compiler
  `6/6`; Local Core passes `536/536`; Guard passes `248/248` and all-features
  `249/249`; both serial locked workspace variants pass.
- Strict all-target/all-feature Clippy passes for Native, Local Core, and Guard.
  Standalone Native locked/offline checking, all three locked release builds, and
  PowerShell 7/5.1 release Authenticode smoke pass. The smoke verifies embedded
  and catalog Microsoft trust, unsigned rejection, and hash-mismatch failure
  without executing fixture content.
- Flutter analysis reports no issues and the complete client suite passes
  `838/838`.

The no-skip, no-Defender-integration verifier ran from
`2026-08-25T12:41:36.2627306Z` through
`2026-08-25T12:49:16.0230861Z` and passed exact `262/262`, zero failed or
report-level skipped steps, in `459.7s`. The new zeroization target passed in
`0.2s`; embedded and independently repeated Windows PowerShell 5.1
`-RequireFullSuite` validation accept the report. Eight isolated mutations are
rejected `8/8`: failed status, Defender enabled, Rust skipped, stale 261-step
evidence, renamed zeroization step, missing verified scope, missing technical-
limit scope, and a failed final step. All variants remain untracked in
`.verification`.

Root, Native, and Flutter lock blobs are
`80a97940019c722f29e6852504b430cf97ca906e`,
`876c6627fe0584976778ad26e88149e9e2c51be1`, and
`51fa085a41168aa1deadace8b5395614db43649e`. No checkpoint process remains. The
protected vault remains 16,072 files, zero directories, 4,522,733 bytes, 5,357
each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending,
temporary, or reparse entries. Nothing was installed, released, published,
executed as candidate content, or changed in Defender. Exact-head hosted,
integration, synchronization, and destination evidence remain pending.

## Exact Implementation-Head Hosted Evidence

Implementation commit `eac61e6706aa7e56a9349ef78d31d588e7aea2ca` was pushed only
to the checkpoint branch and is PR `#84`'s exact head. Avorax CI run
`32850233405` passes all five jobs: branding/copy, Flutter client/protocol,
security/protection/performance, Rust Local Core/Native/Guard/Update/backend,
and Unix quarantine permissions.

Desktop Packages push run `32850194350` and PR run `32850233494` pass package
contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS x64/arm64 DMGs, and
consolidation/checksums. Publication jobs `97813669850` and `97815214301` are
explicitly skipped. An immediately superseded duplicate push run `32850193325`
was canceled by workflow concurrency before meaningful execution and is not
credited. No release or prerelease was created.

Consolidated artifacts `9564478764` and `9564663349` are 131,654,335 and
131,510,762 bytes. Their downloaded SHA-256 values exactly match GitHub digests
`4695b44bbd25bc66207ecc8198b3dc9a868a445023b6427db496f86e67c18447` and
`897af2445d84b8ab18b6893b4e527ecddb05d7f716e7d2aa08acd4020209427e`.
Without extracting or executing either artifact, in-stream validation passes
exactly eight unique regular root entries, six platform release files, seven
checksum targets with matching internal SHA-256, clean ZIP reads, and one
CycloneDX 1.6 lockfile SBOM with exactly 569 components. Evidence-head hosted
checks, normal merge, synchronization, and destination proof remain pending.

## Integration And Destination Closure

Evidence commit `183d1d6217b897ef8ca88d98397c4138f854cb00` passes all five
Avorax CI jobs in run `32852690962` and all Desktop Packages jobs in PR run
`32852690969`; publication job `97820931936` is skipped. Consolidated artifact
`9565334960` is 131,650,795 bytes and its downloaded SHA-256 exactly matches
GitHub at `e8ae76ababb3a2ee297e1822302689e06f7dd7ccf5a75b438755007a29b02847`.
In-stream validation, without extraction or execution, passes exact eight root
entries, six platform files, seven matching checksum rows, and one CycloneDX
1.6 lockfile SBOM with 569 components.

PR `#84` merged normally as
`6de2a8f3bd48c5c45ee3281a90828d8b0796ded5`, with exact parents
`b678027bf4b6522fdf12c2eebc2df2fd15c14684` and
`183d1d6217b897ef8ca88d98397c4138f854cb00`. Merged-main CI
`32854127768` and Desktop Packages `32854130974` pass; publication job
`97825750752` is skipped and no release is created. Consolidated artifact
`9565904414` is 131,559,530 bytes with matching GitHub/downloaded SHA-256
`e69dcc6a698404fd98fd1d647eb94da7c0b954acc9959c5537bafb0213d1cba9`.
The same non-extracting validation passes its exact 8/6/7 inventory and
CycloneDX 1.6 SBOM with 569 components.

The first guarded destination attempt stopped before staging because
`RUN_LOG.md` did not match merged main `b678027`; it exactly matched the known
checkpoint-2231 closure commit `c5d7a2f`. Corrected per-path preconditions
accepted six exact closure-document blobs, eight exact merged-main blobs, and
one absent new report. Root containment, reparse rejection, checked staging,
temporary hash verification, and atomic replacement then synchronized exactly
15 paths and 6,845,406 bytes with zero delete or unrelated-path change.

Destination PS7/PS5 parsers, formatting, source contracts `662/662`, focused
zeroization `1/1`, Native `516/516` with 19 intentional child-entrypoint ignores
plus compiler `6/6`, Local `536/536`, Guard `248/248 + 249/249`, both serial
locked workspace variants, strict Native/Local/Guard Clippy, standalone offline
Native, locked release builds, PS7/PS5 Authenticode smoke, Flutter analyze, and
Flutter `838/838` pass. One combined Clippy wrapper used root-relative manifests
from the Flutter subdirectory and failed before compilation; corrected root
invocations pass and only those are credited.

The destination no-skip/no-Defender verifier ran from
`2026-08-25T13:51:12.7681591Z` through `2026-08-25T14:00:28.1197160Z` and
passed exact `262/262`, zero failed or skipped steps, in `555.3s`; zeroization
took `0.2s`. Embedded and independent Windows PowerShell 5.1 strict validation
pass, and eight isolated adversarial destination reports are rejected `8/8`.

Post-test all 15 synchronized paths match merge blobs. Root, Native, and Flutter
lock SHA-256 values are exact at `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
Flutter rewrote only destination lockfile line endings during testing; exact
semantic blob preconditions permitted atomic restoration to the unchanged
source bytes. No checkpoint process, sync temporary, or external stage remains.
The protected vault remains 16,072 files, zero directories, 4,522,733 bytes,
5,357 each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero
pending/temp/reparse. Nothing was installed, released, published, executed as
candidate content, or changed in Defender. Checkpoint 2232 is closed; the
complete antivirus project remains active.

## Safety

The regression uses protocol bytes and fixed benign UUID keys only. It does not
open or execute candidate content. No live malware is downloaded or retained;
Defender is not weakened; no protected quarantine content, machine-wide
component, release, or publication is touched.
