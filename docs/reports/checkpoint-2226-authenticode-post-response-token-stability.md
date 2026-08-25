# Checkpoint 2226 - Authenticode Post-Response Token Stability

Date: 2026-08-24 (Europe/Brussels)

## Objective

Extend checkpoint 2225's launch-primary and exact child process-token stability
evidence through candidate trust work and flushed response production. The same
duplex handshake remains open after the initial ACK. The child writes and
flushes its bounded stdout response, sends an exact one-byte response-ready
marker, and blocks for a distinct final ACK.

Before the final ACK, the parent revalidates the same parent-held launch
`TokenId`/`ModifiedId`, reopens the exact still-live child process token with
`TOKEN_QUERY`, repeats the complete launch identity and restricted security
profile, and requires the child token's captured `TokenId`/`ModifiedId` to
remain exact. Trust output cannot be accepted if that post-response evidence
or protocol settlement fails.

## Scripted Implementation

- `AuthenticodeParentChildHandshake` survives the initial nonce/ACK exchange
  and is retained with the exact launch token and process handles.
- The child retains its verified pipe endpoint through request parsing,
  WinTrust/catalog work, bounded JSON response writing, and an explicit stdout
  flush. It then sends only the distinct exact response-ready byte and waits.
- The parent uses bounded overlapped read/write with the existing process-exit,
  timeout, `CancelIoEx`, settlement, terminate, reap, desktop, and worker
  diagnostics. It validates the response-ready marker before any final ACK.
- The parent repeats launch-token stability and full child process-token
  identity/profile/stability validation after response flush and before the
  final ACK. Only then may the child exit and its nonce-bound response be
  interpreted.
- Missing, malformed, duplicate-length, incomplete, timed-out, early-exit,
  query, profile, token-drift, cancellation, or final-ACK failure is diagnostic
  and cannot become publisher trust. There is no weaker retry.
- Every benign isolated child fixture participates in both phases. The timeout
  fixture intentionally never reaches response-ready so bounded terminate/reap
  remains exercised.

## Tests And Evidence Contract

Three benign/adversarial Rust regressions cover the full production process path,
exact marker/ACK values, empty/wrong/oversized protocol values, distinct phase
bytes, missing/malformed response-ready child behavior, cleanup, empty parent
thread-token state, and response output. Source contract 656
requires protocol ordering, retained handles, cleanup, verifier scope, audit
coverage, and limitations. The definitive verifier adds one mandatory target
and the independent validator requires exactly 256 successful steps.

No checkpoint-2226 passing result is claimed during scripting. Production code,
Rust regressions, source contract 656, exact 256-step verifier/validator
contracts, and documentation are being completed before any checkpoint-2226
parser, formatter, build, lint, test, smoke, or verifier execution.

## Security Boundary

This closes the simple post-initial-ACK gap by taking a third launch/child token
snapshot after response flush while the child is alive and blocked. It is still
point-in-time user-mode evidence. It does not bind the distinct named-pipe
impersonation token object to either primary token, cryptographically bind
response bytes to token snapshots, detect every transient between snapshots,
or prevent mutation after the final ACK, same-session process injection, or
privileged handle duplication. The response-ready marker and final ACK are flow
control, not secrets or encryption.

Cross-identity authenticated IPC, AppContainer/LPAC, installed LocalSystem
isolation, production signing, signed-driver enforcement, and demonstrated
pre-execution blocking remain technical or external prerequisites. This batch
uses benign fixtures only, never executes candidate content, and adds no crate,
package, feature, binary, network source, or lockfile change.

## Scripting-Phase Status

Implementation, tests, source/verifier/validator contracts, and the audit,
threat-model, blocker, dependency, status, and run-log records are scripted.
Verification, exact-head hosting, package evidence, normal PR integration,
guarded synchronization, and destination proof remain pending. The complete
antivirus goal remains active.

## Initial Focused Execution

Parsers, formatting, and diff checks pass. The first source-contract run
executed all 656 contracts and failed four stale source-slice assumptions after
the intentional handshake method/child-session split; the runtime target itself
passed `3/3`. The four contract slices were updated without weakening the
production boundary, and the complete source-contract runner then passed
`656/656` while post-response `3/3` and prior child-binding `2/2` remained green.

The first complete Authenticode filter passed 54 tests and failed one legacy
timeout assertion because bounded overlapped waiting reports the remaining
integer millisecond count, which can be `99` for a configured `100ms` deadline.
The failure is retained and is not counted as a pass. The assertion now requires
the exact response-ready timeout phase plus successful terminate/reap evidence
without requiring an inaccurate rounded display value; the bound remains
enforced and no timeout or cleanup behavior was relaxed.

## Full Local Regression

After the timeout assertion repair, the exact timeout regression passes `1/1`
and the complete Authenticode selection passes `55/55`. Native Engine passes
`506` tests with `15` intentional ignored child fixtures, and the signature
compiler passes `6/6`. Local Core passes `536/536`; Guard passes `248/248`.

Both locked root-workspace variants pass with the same Native `506/15` and
compiler `6/6` result. Strict all-target/all-feature Clippy passes for Native,
Local Core, and Guard. Standalone locked/offline Native all-target/all-feature
checking passes. Locked release Local Core and Guard builds and the benign
two-host Authenticode helper smoke pass embedded/catalog Microsoft trust,
mandatory hash-bound nonce IPC, unsigned rejection, and hash-mismatch failure
without executing candidate content.

Flutter analysis reports no issues and all `838/838` tests pass. Source
contracts pass `656/656`; both PowerShell scripts parse; `cargo fmt --all --
--check` and `git diff --check` pass. No dependency or lockfile changed.

The definitive 256-step verifier, strict report validation, adversarial report
rejection, exact-head hosted checks, package evidence, normal PR integration,
guarded destination synchronization, and destination proof remain pending.
The complete antivirus goal remains active.

## Definitive Local Evidence

The definitive verifier ran from `2026-08-24T21:25:06.3091111Z` through
`2026-08-24T21:32:45.9605883Z` and passed exactly `256/256` steps, with zero
failed or skipped, in `459.6s`. The mandatory post-response token-stability
target passed in `0.3s`. Both the verifier-embedded and an independently
repeated Windows PowerShell 5.1 strict validator pass.

Ten isolated malformed report copies were rejected with exit code 1: wrong
schema, failed overall status, enabled Defender/EICAR option, both skip options,
missing post-response target, missing verified scope, missing technical-limit
scope, a failed final step, and stale 255-step evidence. Only exact temporary
files were removed; `.verification` remains untracked and unstaged.

Root Cargo, Native Cargo, and Flutter lock blobs remain exactly
`7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. Read-only protected-vault
inventory remains 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
payload/metadata/auth, one metadata key, and zero pending/temp.

Exact-head hosted CI/package evidence, normal PR integration, guarded original-
tree synchronization, and destination verification remain pending. Nothing was
installed, executed as candidate content, released, or published.

## Implementation-Head Hosted Evidence

Exact implementation `74d7d96313402fe313a6c2bc9f7d6e9ab7020849`
passes all five Avorax CI jobs in run `32780511368`. Desktop Packages push/PR
runs `32780474053`/`32780511318` pass package contracts, Windows MSI/EXE,
Linux DEB/tar, macOS arm64/x64 DMG, and consolidation; both publication jobs
are skipped.

Consolidated artifacts `9539926286` and `9540008859` were retained as untouched
ZIP streams with SHA-256
`66884bbe57321548699b91597ccbf1794f9cba1e1a76879836d9f795c945c520` and
`41edbc1601896374bd5a1ceb5ffb561de3bc7f050b0471999243e687a39d62ce`.
In-stream checks prove exactly six platform files, seven matching checksum rows,
and one CycloneDX 1.6 lockfile SBOM with 569 components in each ZIP, without
extracting or executing candidate installers.

The first artifact inspection correctly rejected a stale expectation that the
Windows names contained `windows-x64`; current package-contract names are
`x64.msi` and `x64-setup.exe`. The corrected exact-name check passes both
streams. The failed attempt is not credited as evidence and changed no product
or artifact bytes.

The implementation-head runs are supporting evidence only; complete integration
and destination closure is recorded below.

## Integration And Destination Closure

Evidence commit `bacf1ccb8f0f47020ee0798522a01f6a3ca0ffca` passes all five
Avorax CI jobs in run `32782113876`. Desktop Packages PR run `32782113878`
passes package contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, both macOS
DMGs, and consolidation after a failed-job-only retry; publication is skipped.
Attempt 1 failed only the macOS arm64 job because the hosted Flutter toolcache
tried to execute a darwin-x64 `impellerc` on arm64 and returned `Illegal byte
sequence`. The unchanged failed job passed on attempt 2. The failed attempt is
retained and is not credited as a pass.

Untouched evidence artifact `9540950441` has SHA-256
`14e45afec7639b698cc3b0d6733bf43e633c0a970731a5cf5776783226dbadcf`
and passes exact eight-entry, six-platform-file, seven-checksum, and CycloneDX
1.6/569-component in-stream validation without extraction or execution.

PR `#78` was made ready, clean, and head-locked to the evidence commit, then
merged normally without a direct-main push as
`bab872d50daf5bbcc775a53e3c0788c51770ca33`, with parent
`5792c22f3815f4eccbc97a78d5ae9e01873193f5`. Merged-main CI `32784751719`
and Desktop Packages `32784751652` pass all required jobs; publication is
skipped. Untouched merged artifact `9541445838` has SHA-256
`c10e9e0cd43798431d9b398fea1bbec8b7d78b12e8b872f49f0598e2cea0ba40`
and independently passes the same exact in-stream checks.

The merge changed exactly 12 paths from its parent, with zero deletes. All 11
existing destination paths first matched the parent and the new report was
absent. Exactly those paths synchronized atomically to
`C:\Users\Brent\Documents\Avorax-main`; normalized blobs and raw SHA-256 values
match merge/source, with no unrelated destination overwrite.

Destination PowerShell parsers `2/2`, source contracts `656/656`, focused
post-response `3/3`, complete Authenticode `70` passed/`15` intentionally
ignored fixtures, Native `506/15` plus compiler `6/6`, Local Core `536/536`,
Guard `248/248`, both locked workspaces, strict Native/Local/Guard Clippy,
standalone locked/offline Native, formatting, release Local Core/Guard,
two-host Authenticode smoke, Flutter analysis, and Flutter `838/838` pass.
Definitive destination verification ran from
`2026-08-24T22:54:38.3164086Z` through `2026-08-24T23:01:56.7274772Z` and
passed exact `256/256`, zero failed or skipped, in `438.4s`; target `0.3s` and
both embedded and independent Windows PowerShell 5.1 validators pass.

Support failures remain retained and uncredited: the first artifact validator
assumed stale Windows filenames; one JavaScript/PowerShell wrapper failed to
parse before validation; one guarded sync wrapper was rejected by command
policy before copying; and one destination Cargo helper used PowerShell's
automatic `$args`, printed help, and returned a false exit-zero. Corrected exact
wrappers performed the real checks and passed. None of those failures changed
product behavior, copied files, or counts as evidence.

During closure-document validation, `python -m unittest` discovered zero tests,
both available Python runtimes lacked optional `pytest`, and the no-malware gate
correctly refused an ambient `PATH` interpreter. Those attempts are not
credited. The repository's dependency-free source-contract runner passed
`656/656`, and the no-malware gate passed with the explicit bundled Python path;
branding, product-copy, formatting, and diff gates also pass.

Final read-only checks retain the exact three lock blobs and protected-vault
invariant above. `.verification` remains untracked and unstaged. No service or
driver was installed or started, Defender was not weakened, candidate content
or installers were not executed, and no release or publication occurred.
Checkpoint 2226 is closed; its point-in-time, impersonation-token, identity,
isolation, signed-driver, and pre-execution limitations and the complete
antivirus goal remain active.
