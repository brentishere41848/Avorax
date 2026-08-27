# Checkpoint 2249: ZIP Entry-Name Normalization Cancellation

## Status

Implementation, local/full verification, exact-head hosted evidence, normal PR
integration, merged-main evidence, guarded destination synchronization, and
destination verification are complete. Checkpoint 2249 is closed. The complete
antivirus hardening goal remains active.

Historical scripting-phase record: No checkpoint-2249 test has run during this
scripting phase. The verification evidence below was collected only after the
complete implementation, test, verifier, validator, contract, and documentation
batch had been scripted.

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
with exit code `1`.

## Hosted, Integration, And Destination Evidence

- Exact implementation head `4c5f73ad2251231c8bcb1f60035519552f0c35f5`
  passes package push `33036903447`, PR `#107` CI `33037578015`, and PR
  packages `33037578011`. PR `#107` merges normally as
  `ee8267b16b0c1b88bad86d98e9b81c6a329eadfb` with exact parents
  `5024093e76950151b89790ed6875373268a83022` and the implementation head.
- Merged-main CI `33038527598` and packages `33038527578` pass. Publication is
  skipped in the branch, PR, and merged-main package workflows.
- Consolidated artifacts `9632555316`, `9632919862`, and `9633201962` are
  respectively 132,086,199, 132,095,619, and 132,091,298 bytes. Their SHA-256
  values are
  `617e7d2dd3752f3b8877dc144b4040c68a1e9ceef6a4b6753c510a574ea89bce`,
  `c2c827fa8a3cbbfe4fa72b4c42200e4a9e058a2bb2a5886df848ed84b656c1ea`,
  and `5c53a6e3d626adee6420731f4a05b00fbc6bb57d0e1a88707c5a957054c17aef`.
  Each matches GitHub and passes bounded in-stream validation for exact eight
  root entries, six platform files, seven checksum targets, and a CycloneDX 1.6
  SBOM with 569 components. None is extracted or executed.
- Guarded synchronization from `5024093` to `ee8267b` audits and applies exact
  `11/11` paths: ten modifications, one addition, zero deletes. Independent
  Git-filter-aware comparison passes `11/11`; no staging residue remains.
- Destination focused ZIP name regressions pass `4/4`, Source passes `679/679`,
  and workspace formatting passes. Definitive verification passes exact
  `278/278`, zero failed/skipped, from `2026-08-27T04:26:39.3378418Z` through
  `2026-08-27T04:35:57.8009228Z` in `558.4s`. Independent PS5 and PS7 validators
  accept report SHA-256
  `2fccc4b000f629f2eb7d62412a21cf684fb409e3b2ab34315b1842556d100c58`.
- All three dependency locks remain exact. The protected vault remains read-only
  and exact at 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
  payload/metadata/auth, one key, zero pending/temp, and zero reparse points.
  No release, install, service/driver start, Defender change, or protected-vault
  mutation occurred.

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

## Completed Verification Sequence

1. The complete checkpoint-2249 scripting batch was frozen before any test.
2. Formatting and parser checks, Source contract 679, the four focused ZIP
   name regressions, and adjacent ZIP/archive cancellation suites.
3. Complete Native, Local Core, Flutter, locked workspace/release, strict
   affected lint, dependency, safety, and clean-diff checks.
4. The definitive verifier passed exact `278/278`, zero failures and zero skips;
   PS5 and PS7 accepted it and rejected missing-step/missing-scope mutations.
5. Exact-head hosted CI/package evidence passed with publication skipped; normal
   PR merge, merged-main verification, zero-delete guarded sync, and focused plus
   definitive destination verification all passed before closure.
