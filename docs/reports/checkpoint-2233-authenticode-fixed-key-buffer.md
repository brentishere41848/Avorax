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
