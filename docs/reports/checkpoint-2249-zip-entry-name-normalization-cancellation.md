# Checkpoint 2249: ZIP Entry-Name Normalization Cancellation

## Status

Implementation-first source, four benign regressions, verifier, validator,
Source contract 679, and documentation scripting is complete. No checkpoint-2249
test has run during this scripting phase. Execution starts only after this full
batch is frozen. Checkpoint 2249 and the complete antivirus hardening goal remain
active.

## Prior Checkpoint Finalization

Checkpoint-2248 closure documentation commit
`2951aa63b6987445571f0a9bd5dab7b1940f489d` passed PR `#106` CI
`33033734816` and merged normally as
`5024093e76950151b89790ed6875373268a83022`. Merged-main CI `33034186873`
passed; docs-only path policy started no package or publication workflow. Guarded
destination synchronization changed exactly four documentation paths with zero
additions or deletes and exact `4/4` target-blob comparison.

Destination Source `678/678`, focused `5/5`, and formatting checks passed. One
final definitive attempt stopped at the broad Authenticode filter with exit 101
and no captured test name; that report remains uncredited and preserved. The
exact focused rerun passed 83 active tests with 21 documented child fixtures
ignored. A clean full rerun passed exact `277/277`, zero failed or skipped, from
`2026-08-27T02:55:39.8239038Z` through `2026-08-27T03:04:30.4287614Z` in
`530.6s`. Independent PS5 and PS7 validators accepted report SHA-256
`8441abf09ffa7405f83bbdc0afd8b3ee7f84c157639b8c054a6d1c16f79a8a31`.
All locks and the protected vault invariant remained exact. Checkpoint 2248 is
fully finalized; the whole goal remains active.

## Objective

Remove the remaining uncheckpointed ZIP entry-name normalization intervals in
local-header sampling, local-header static analysis, central-directory parsing,
and local/central name consistency checks. Preserve malformed-ZIP fallback,
lossy UTF-8 replacement, ASCII-only lowercase, path inspection, body selection,
sample collection, evidence, and verdict behavior. Never convert a cancellation
or arbitrary callback failure into malformed, limited, no-match, or clean
success.

## Scripted Implementation

- Both local-header paths normalize each validated nonempty name through the
  shared `ascii_lowercase_lossy_with_cancellation` helper before constructing an
  entry view, collecting a sample, or inspecting archive evidence.
- Central-directory parsing separates structural `Option` failure from fallible
  name normalization. Malformed or inconsistent metadata remains `Ok(None)`;
  callback failure remains `Err`.
- Local-header body lookup keeps all existing flag, method, size, offset, and
  exact normalized-name checks. Its name conversion is now fallible, so body
  trust cannot proceed after cancellation.
- Entry names remain format-bounded by their unsigned 16-bit length fields to at
  most 65,535 bytes. The shared helper checkpoints before the bounded input chunk
  and after final input. No archive is extracted and no candidate content is
  executed.

## Scripted Evidence

- Four ordinary in-memory fixtures inject errors in local sample collection,
  local static analysis, central entry parsing, and local/central comparison.
  Each requires the exact error to remain visible before its downstream result.
- Mandatory verifier step `native-engine ZIP entry-name normalization
  cancellation regressions` selects exact prefix `zip_name_normalization_`.
- Strict validation requires exactly 278 passing, non-skipped steps and pins the
  verified and technically limited scope under both supported PowerShell hosts.
- Source contract 679 rejects raw lossy/lowercase ZIP name conversion, missing
  `Result<Option<...>>` boundaries, fixtures, verifier/validator wiring, or
  incomplete audit documentation.

## Local Execution Evidence

- Rustfmt, diff whitespace, and PS5/PS7 parser checks pass. Source contracts
  pass exact `679/679`.
- The first focused compile exposed only a test-harness constraint:
  `Result::expect_err` required the private success type to implement `Debug`.
  The fixture now reads `.err().expect(...)` rather than changing production
  traits. The exact rerun passes `4/4`.
- Complete ZIP tests pass `42/42`; workspace cooperative archive cancellation
  passes `4/4`; static archive cancellation passes `4/4`; adjacent static text
  normalization passes `5/5`.
- Complete Native passes `609` active tests with 21 documented child fixtures
  ignored plus compiler `6/6`. Local Core passes `546/546`; Flutter analyze has
  no issues and Flutter passes `847/847`.
- Locked workspace tests, strict Native and Local Core Clippy, formatting, and
  the locked release workspace build pass.
- Packaging source tests pass 21 with three optional Windows symlink-privilege
  fixtures skipped. Branding, product-copy, no-malware-binaries, false-positive,
  and bundled-pack safety gates pass; the pack inventory is exact at eight
  signature and six rule packs. Initial no-malware and pack commands supplied a
  non-absolute `python` name and stopped in path preflight; corrected commands
  used the existing bundled absolute Python path without installation.
- Root Cargo, Native Cargo, and Flutter lock SHA-256 values remain exact. The
  protected vault remains read-only and exact at 16,072 files, zero directories,
  4,522,733 bytes, 5,357 each payload/metadata/auth, one key, zero pending/temp,
  and zero reparse points.

Definitive verification passes exact `278/278`, zero failed and zero skipped,
from `2026-08-27T03:25:34.3535933Z` through
`2026-08-27T03:33:43.7249408Z` in `489.3s`. Embedded and independently invoked
PS5 and PS7 validators accept report SHA-256
`fd3e977d91b72cd217da10df0b43b11cae23b828e12390a12157102142e80a78`.
Both hosts reject a missing new step and a missing ZIP technical-scope phrase
with exit code `1`. Hosted CI/packages, normal integration, guarded
synchronization, and destination evidence remain pending. Checkpoint 2249 and
the complete antivirus goal remain active.

## Safety

Fixtures contain only ordinary benign text and byte arrays in memory. This
checkpoint downloads, unpacks, retains, or executes no malware; creates no live
EICAR file; changes no Defender setting; and installs or starts no service,
driver, installer, or machine-wide component. The protected
`C:\ProgramData\Avorax\Quarantine` vault remains read-only.

## Limits And Honest Claims

Cancellation remains cooperative rather than hard preemption. One validated ZIP
entry name of at most 65,535 bytes can complete once its normalization callback
has admitted that chunk. An already-entered filesystem/system call, one archive
inflate read, one static/provider text or search chunk, one UTF-16 interval,
bounded ML sorting, or one Windows trust call may also complete before its next
checkpoint.

This is bounded user-mode post-start analysis, not constant-memory proof,
installed cross-identity service ownership, authenticated service IPC,
driver/kernel mediation, production detection-accuracy evidence, pre-execution
blocking, or Defender replacement. Reputation and correlation-dependent
providers remain disabled with their documented backend and trusted-telemetry
prerequisites.

## Required Verification Sequence

1. Freeze the complete checkpoint-2249 scripting batch before any test.
2. Run formatting and parser checks, Source contract 679, the four focused ZIP
   name regressions, and adjacent ZIP/archive cancellation suites.
3. Run complete Native, Local Core, Flutter, locked workspace/release, strict
   affected lint, dependency, safety, and clean-diff checks.
4. Run the definitive verifier and require exact `278/278`, zero failures and
   zero skips. Independently validate under PS5 and PS7 and prove missing-step
   and missing-scope reports are rejected.
5. Obtain exact-head hosted CI/package evidence with publication skipped, merge
   through a normal PR, verify merged main, guarded-sync with zero deletes, and
   repeat focused and definitive destination verification before closure.
