# Checkpoint 2244 - Static Archive Analysis Cancellation

Date: 2026-08-26

## Trigger

Checkpoint 2242 made bounded ZIP entry-content collection cooperatively
cancellable, but the earlier Native static ZIP metadata pass still traversed up
to 256 local or central-directory entries and copied or inflated bounded OOXML
relationship and autorun bodies synchronously. A cancellation arriving during
that substep was observed only after the complete static analysis returned.

## Scripted Repair

- Existing `analyze_path`, `analyze_path_with_size`, and `analyze_zip` callers
  remain compatible wrappers using a fallible no-op checkpoint.
- The scan engine uses `analyze_path_with_size_and_cancellation` and maps every
  static archive checkpoint through the existing typed scan-cancellation
  boundary.
- Static ZIP analysis checks before parser traversal, before every local or
  central-directory metadata entry, around stored OOXML relationship and
  autorun copies, and before each at-most-64-KiB deflate output read.
- Callback errors propagate unchanged. Cancellation cannot become
  `limit_exceeded`, and a broken cancellation probe cannot become cancellation,
  clean evidence, or a partial `StaticAnalysis`/file verdict.
- Benign regressions cover metadata traversal, OOXML relationship inflate, and
  arbitrary checkpoint-probe failure. No fixture is executed.

## Verification Contract

Mandatory verifier step 273 is `native-engine static archive analysis
cancellation regressions`. The strict validator requires exact cardinality 273
and verified scope for parser/entry/copy/inflate checkpoints, fail-visible error
propagation, and absence of partial analysis or verdict publication.

Source contract 674 binds the analyzer and engine wiring, benign regressions,
verifier command, validator cardinality/scopes, and all checkpoint documents.
No checkpoint-2244 passing result is claimed during scripting.

## Limits And Status

This is cooperative user-mode cancellation, not thread termination or hard
preemption. One already-running `flate2` decoder read can complete before the
next checkpoint. ZIP metadata remains bounded to 256 entries; relationship and
autorun body sizes retain their existing limits. Non-archive static analysis,
synchronous rule/ML work, Windows trust calls, kernel mediation, installed
service identity, and pre-execution blocking are outside this repair.

## Local Verification

- Focused static archive cancellation passes `4/4`; the complete ZIP analyzer
  area passes `36/36`; adjacent archive collection cancellation passes `4/4`.
- Native passes `559` active tests with `21` intentional child-fixture ignores,
  plus signature compiler `6/6`. Local Core passes `546/546`; Flutter analyzer
  is clean and Flutter passes `847/847`.
- Source contracts pass `674/674`. Strict Native and Local Core Clippy, rustfmt,
  diff check, locked workspace release build, and Windows PowerShell
  5.1/PowerShell 7 parser checks pass.
- The first two attempted `pytest` invocations are uncredited because neither
  available Python runtime included pytest and no test executed. The repository's
  dependency-free runner then exposed two wording mismatches; the corrected full
  source-contract run passes.
- Exact lock hashes remain unchanged: root
  `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
  Native `7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
  Flutter `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
- The protected vault remains exactly `16072` files, zero directories,
  `4522733` bytes, `5357` each payload/JSON/auth, one metadata key, zero pending,
  and zero reparse points.

## Definitive Local Verification

- Definitive verification passes exact `273/273` from
  `2026-08-26T15:07:07.5888297Z` through
  `2026-08-26T15:15:58.7193871Z` in `531.1s`, with Defender integration
  disabled and no Rust or Flutter skips.
- Embedded and independent Windows PowerShell 5.1 and PowerShell 7 validators
  accept the exact report. Its SHA-256 is
  `2547454f20895864be9727dd545e0625d39b0b761732032f886c004ff5de2216`.
- An adversarial `272`-step copy is rejected by both independent validators.
  A second `273`-step copy missing the required parser-traversal cancellation
  scope is also rejected by both; all four expected-negative invocations exit
  `1`.
- Root, Native, and Flutter lock hashes and the protected-vault invariant remain
  exact after the verifier and adversarial checks.

Hosted exact-head CI/package evidence, normal PR/merge, guarded integration,
and destination verification are recorded separately below. They do not expand
the cooperative user-mode scope of these definitive local results.

## Hosted Verification Recovery

GitHub Actions entered an official `major_outage` at
`2026-08-26T15:11:58.254Z`, before this checkpoint's hosted attempts. The
status incident identifies a database-primary failure and an immediate replica
failover at `2026-08-26T15:23:10.599Z`.

- Push package run `32984814869` for local-evidence head `2518612` was
  transiently reported as a startup failure while the incident was active, but
  ultimately completed successfully across Windows, Linux, both macOS
  architectures, and consolidation. Publication job `98231721596` is skipped.
  Consolidated artifact `9613011717` is `132034442` bytes with matching GitHub
  and downloaded SHA-256
  `81cd3cf0f7ef2069ee1af1db53676eb0a6c57485361d75aac38d1848f164398e`.
  Bounded in-stream validation passes exact 8-root/6-platform/7-checksum and
  CycloneDX 1.6/569-component evidence without extraction or execution.
- An empty, source-preserving retrigger commit and the outage-evidence commit
  produced hosted head `3237d49e3df2d6355968882cddf57f0c171e3827`;
  PR `#96` remains open and mergeable.
- Exact-head Avorax CI run `32985138375` remained queued with zero jobs. Manual
  Desktop Packages run `32985149344`, explicitly dispatched with
  `publish_prerelease=false`, reached `startup_failure` with zero jobs. These
  outage attempts remain uncredited.
- After GitHub began restoring traffic, exact-head Avorax CI runs `32987569318`
  and `32987888207` both pass all five jobs. The first exact-head manual package
  run `32986620660` is uncredited: its macOS arm64 build, packaged-core smoke,
  and manifest checks passed, but all five `hdiutil verify` attempts returned
  `Resource temporarily unavailable` and consolidation was skipped.
- Independent exact-head PR package run `32987888192` passes contracts,
  Windows, Linux, both macOS architectures, and consolidation; publication job
  `98244620437` is skipped. Consolidated artifact `9614177410` is `132043669`
  bytes with matching GitHub/download SHA-256
  `2649ce251aa91688097357298e23d28790d09424b6865d8b81d965f36c5af030`.
  The same bounded non-extracting 8/6/7/CycloneDX-1.6/569 validation passes.

At the time this recovery evidence was committed, no release, publication,
merge, or synchronization was claimed. The later exact-head, merge, main,
guarded-sync, and destination evidence below supersedes that pending status.

## Exact-Head And Main Evidence

- Evidence head `0b566a4ce45e9818db840b09156fbf4a2d0b25f0` passes Avorax CI
  runs `32990951715` and `32991018757`, manual Desktop Packages run
  `32990331126`, and PR package run `32991019029`. Publication job
  `98252248675` is skipped. Consolidated PR artifact `9615033566` is
  `132038280` bytes with matching GitHub/download SHA-256
  `dbdf405392a269545b23da7202c86c5fb0e06781a2eab85cc1bda9deec653323`.
  Bounded non-extracting validation passes exact 8-root/6-platform/7-checksum,
  CycloneDX 1.6, and 569-component evidence.
- PR `#96` merged normally as
  `c0cd92f7f10e6205ad209435c24367f54f8cd8b0`; no direct-main push was used.
  Merged-main CI run `32993065989` and automatic package run `32993065971`
  pass on that exact merge. Publication job `98261977747` is skipped.
  Consolidated artifact `9616123602` is `132044279` bytes with matching
  GitHub/download SHA-256
  `697bcf7a12ee557e14768fbb762c35b01960b6ec6fa7e30eca323a7e4a0166a0`.
  It passes the same bounded non-extracting 8/6/7/CycloneDX-1.6/569 checks.
- Superseded delayed package run `32990951779` and manual-main fallback
  `32992945261` were canceled by workflow concurrency. They are retained as
  uncredited attempts, not presented as passing evidence.

## Guarded Integration And Destination Verification

- The guarded sync used base
  `24c383cfc111df66ad6b8b7c4047d78481730a19` and exact target
  `c0cd92f7f10e6205ad209435c24367f54f8cd8b0`. Preflight proved all 13 modified
  destination files matched the base blobs and the one new report was absent.
  Atomic application and independent canonical-blob verification pass `14/14`,
  with zero deletes and zero staging residue.
- Destination focused evidence passes static archive cancellation `4/4`, ZIP
  analyzer `36/36`, adjacent archive cancellation `4/4`, and source contracts
  `674/674`. Complete Native passes `559` active with `21` intentional fixture
  ignores plus compiler `6/6`; Local Core passes `546/546`; Flutter analyze is
  clean and Flutter passes `847/847`. Strict Native/Local Clippy, rustfmt,
  dual-host parser checks, and the locked workspace release build pass.
- Destination definitive verification passes exact `273/273` from
  `2026-08-26T17:43:51.7105344Z` through
  `2026-08-26T17:52:13.7327773Z` in `502s`, with Defender integration disabled
  and no Rust or Flutter skips. Embedded and independent Windows PowerShell 5.1
  and PowerShell 7 validators accept the report. Its SHA-256 is
  `b5c403d2795bbbd9ff544a6ba431b45c14c2620ec6b99557afb93fed1079a405`.
- A first post-run raw-file hash diagnostic compared CRLF worktree bytes with
  Git-normalized blob IDs and was rejected as invalid evidence. The corrected
  `.gitattributes`-aware canonical check passes all `14/14` target blobs.
- Root, Native, and Flutter lock hashes remain exact. The protected vault remains
  `16072` files, zero directories, `4522733` bytes, `5357` each payload/JSON/auth,
  one metadata key, zero pending, and zero reparse points.

Checkpoint 2244 is closed. This closes only the static archive cancellation
checkpoint; the complete antivirus hardening goal remains active. One running
decoder read, non-archive static analysis, synchronous rule/ML and trust calls,
installed-service identity, driver mediation, and pre-execution blocking retain
the limitations documented above.
