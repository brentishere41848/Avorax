# Checkpoint 2252 - Static Structured-Indicator Cancellation

Status: **Scripted / unverified**

The complete antivirus-hardening goal remains active. This checkpoint narrows
cooperative cancellation latency inside the Avorax Native Engine String
Indicator provider. It does not establish production detection accuracy,
installed-service ownership, pre-execution blocking, or Defender replacement.

## Prior Verified Baseline

- Checkpoint 2251 is closed through normal implementation merge `3e58dc15`,
  closure merge `ec75c23`, exact-head and merged-main hosted checks, bounded
  artifact review, and guarded destination synchronization.
- The closure-state destination verifier passed exact `280/280`, zero
  non-passing steps, from `2026-08-27T10:45:53.7371804Z` through
  `2026-08-27T10:55:45.7302451Z` in `592` seconds. Independent Windows
  PowerShell 5.1 and PowerShell 7 validators accepted report SHA-256
  `c12f6d94a2e410b758c7b966f35caa165c64f41104535445dfeac39dd8ff114b`.
- The four closure-document blobs, all three lock hashes, zero test-process or
  sync residue, and the protected-vault read-only invariant remained exact:
  16,072 files, zero directories, 4,522,733 bytes, 5,357 each
  `.avoraxq`/`.json`/`.auth`, one metadata key, and zero pending/temp/reparse
  entries.

## Risk And Objective

Checkpoint 2251 bounded exact marker and reference-body searches. Several
higher String Indicator classifiers still used complete-sample or
complete-segment standard-library traversals after those searches: carrier
recognition, IPv4 candidate splitting, URL query/fragment suffix selection,
UNC/`file://` host parsing, autorun lines and command tokens, optical-image
markers, and email lines/fields. A late cancellation could therefore wait for
one admitted sample or adversarially long line, token, host, or field to finish.

Checkpoint 2252 makes those paths fallible and callback-aware. Every affected
byte or UTF-8 character traversal observes the exact scan-job callback at
at-most-64-KiB intervals. Errors propagate before the complete
`StringIndicators` value or downstream verdict can be published.

## Scripted Implementation

- One 64-KiB structured-traversal boundary now covers ASCII delimiter search,
  CRLF-preserving line/field traversal, Unicode-aware trimming, command-token
  traversal, candidate traversal, and host-prefix traversal.
- RTF, PDF, web-document, MIME, attachment, autorun, and optical-image marker
  probes reuse bounded exact search instead of whole-sample `contains` or
  `windows` predicates.
- IPv4 candidate discovery checkpoints by UTF-8 byte progress; a candidate is
  rejected before octet parsing unless its byte length can represent IPv4.
- URL and command suffix classification finds the first query/fragment byte
  through a bounded helper. Remote UNC and `file://` host/share parsing avoids
  unbounded `trim_start_matches` and `split` traversal.
- Autorun parsing keeps existing comment stripping, CRLF handling, accepted
  command keys, token delimiters, and executable/script suffixes. Email parsing
  keeps existing per-line counting and `filename`/`name` semantics without a
  per-line `Vec` allocation.
- Optical-image and disk autorun paths remain detection-only. No candidate is
  opened, mounted, unpacked, executed, quarantined, deleted, or sent over the
  network by this provider.

## Evidence Scripted First

Nine benign in-memory Rust regressions cover interruption of carrier markers,
IPv4 candidates, autorun lines, command tokens, optical markers, email lines,
query/fragment paths, and network hosts, plus preservation of CRLF, autorun,
email, and conservative URL suffix behavior. They use only repeated ordinary
ASCII, reserved `.invalid` references, and injected errors; no fixture is
executed or written.

The definitive verifier adds exact step 281,
`native-engine static structured-indicator cancellation regressions`, filtered
by `static_structured_indicator_cancellation_`. The strict validator requires
exactly 281 steps, that named step, both verified-scope statements, and the new
technical-limit statement. Source contract 682 pins production helpers,
forbidden legacy traversals, all nine regressions, verifier/validator scope,
documentation, and dependency neutrality.

No checkpoint-2252 test has run during this scripting phase. Formatting,
parser checks, focused tests, Source `682/682`, full local regression,
definitive exact `281/281`, adversarial validator checks, hosted evidence,
normal integration, guarded synchronization, and destination reruns remain
pending.

## Responsibility And Limits

The String Indicator engine performs deterministic, bounded, offline static
classification. It reports explainable weak or carrier evidence to the verdict
aggregator; it does not execute references, perform reputation lookup, block a
process, mutate a source file, or own quarantine actions. Local Core remains the
authenticated quarantine owner.

Cancellation remains cooperative. One admitted carrier, candidate, line,
token, path, host, optical-marker, or email-field chunk of at most 64 KiB can
finish before the next callback. One entered OS/filesystem call, archive read,
ML operation, trust call, or other separately bounded analyzer operation may
also finish first. The existing 64 MiB sample cap is an input bound, not a hard
deadline. Installed cross-identity IPC, driver/kernel mediation, production
calibration, pre-execution blocking, and Defender replacement remain partial,
blocked, technically limited, disabled, or unclaimed as already documented.

## Safety And Dependency Delta

Checkpoint 2252 adds no dependency, feature, build script, downloaded content,
package source, license obligation, or lockfile change. It uses Rust slices,
UTF-8 boundaries, checked/saturating arithmetic, the existing shared search
module, and the already locked `anyhow` error boundary. It does not use live
malware, alter Defender, install machine-wide components, start services or
drivers, publish packages, create a release, or access the protected vault.

## Local Verification Progress

The complete scripted batch was frozen before testing. After that boundary,
PS5 and PS7 parser checks pass `2/2` each and Source contracts pass exact
`682/682`. The nine new structured-indicator cancellation regressions pass
`9/9`; all String Indicator tests pass `54/54`; adjacent reference-search tests
pass `8/8`. Rust formatting passes.

The first strict Native Clippy run failed visibly on a test-and-production
callback parameter that exceeded `clippy::type-complexity`. The segment visitor
was repaired as a generic `FnMut` helper without changing behavior; the focused
`9/9` rerun and strict Native all-target/all-feature/locked Clippy then pass.
Strict Local Core and Guard Clippy also pass.

The first real Source-contract run then executed all 682 tests and failed one
stale marker that still expected the pre-repair non-generic function spelling.
The contract now pins the exact generic `<F>` signature; the complete rerun
passes `682/682`. Two earlier `unittest` invocations discovered zero tests and
are explicitly uncredited.

Complete Native verification passes 632 active tests plus signature compiler
`6/6`, with 21 documented child-process fixtures ignored. Local Core passes
`546/546`; the locked all-feature workspace run, standalone locked/offline
Native check, and locked release workspace build pass. Flutter analyze is clean,
Flutter passes `847/847`, and Dart protocol passes `14/14`.

Root Cargo, Native Cargo, and Flutter lock SHA-256 values remain exactly
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`, and
`4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
The read-only protected-vault invariant remains exact at 16,072 files, zero
directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
metadata key, and zero pending/temp/reparse entries. Definitive exact `281/281`,
adversarial report validation, hosted exact-head evidence, integration, guarded
synchronization, and destination reruns remain pending.

## Definitive Local Verification

The first definitive attempt stopped before step completion when active
Microsoft Defender removed a generated Native debug test binary as
`Trojan:Win32/Wacatac.C!ml` (`DidThreatExecute=False`). An exact retry then
failed because the removed file no longer existed. Neither attempt is credited;
Defender was not weakened and the binary was not restored or allowlisted.

The exact blocked archive-cancellation filter passes `4/4` after compiling test
binaries with `CARGO_PROFILE_TEST_DEBUG=0` and `CARGO_INCREMENTAL=0`. These
variables remove test debuginformation/incremental metadata; they do not change
source, dependencies, detection policy, Defender, or release-binary settings.
The definitive verifier reran from the beginning under the same explicit test
profile and passed exact `281/281`, with zero non-passing steps, from
`2026-08-27T11:37:10.9264725Z` through `2026-08-27T11:50:17.8063350Z` in
`786.9` seconds.

The final report is
`.workflow/ultracode/avorax-hardening/results/checkpoint-2252-local-verification-report-final.json`
with SHA-256
`039f30500f4a842f7f9785653df8a49b4b01f22963ecb1c340cb7265a2815153`.
Independent Windows PowerShell 5.1 and PowerShell 7 full-suite validation accepts
the exact report. Both hosts reject a 280-step copy missing the new step and a
separate 281-step copy missing the structured-indicator verified-scope sentence;
all four negative runs exit 1 with the expected diagnostic. The two exact
temporary JSON files and their empty owned directory were removed after bounded
path and content checks; pre-existing `.verification` content was untouched.

Post-verifier locks, zero residual test processes, and the read-only protected-
vault invariant remain exact. Hosted exact-head CI/packages, normal PR
integration, guarded destination synchronization, and destination verification
remain required. No package was published and no release was created.

## Hosted Branch Package Evidence

Implementation commit `09d84239c69288d1193e5ce8ca815c7023f83fed` passes
Desktop Packages push run `33069608149`. Package contracts, Linux x64,
Windows x64, macOS arm64, macOS x64, and consolidation all succeed. The
prerelease publication job is explicitly skipped; no release or package is
published.

GitHub reports consolidated artifact `9645762246`,
`avorax-desktop-release-0.1.15`, as 132,039,189 bytes with digest
`sha256:cd1bbb28059d1be2a64f181e399a8869e7598c8568aafafdd37ac96784d9a7ca`.
A bounded non-extracting review downloads only that Actions artifact archive,
confirms the same byte count and SHA-256, and inspects its ZIP central directory
without installing or executing content. It contains exactly eight safe root
entries: six platform packages, one checksum file, and one lockfile SBOM; there
are no duplicate, encrypted, link, absolute, traversal, or backslash entries.
All seven checksum targets verify. The SBOM is CycloneDX 1.6 with 569 components
and 569 unique component references. The exact 132-MiB temporary archive and
its empty owned directory were removed after review.

Normal PR exact-head CI/packages, merge, merged-main CI/packages, guarded
destination synchronization, and destination verification remain pending.
