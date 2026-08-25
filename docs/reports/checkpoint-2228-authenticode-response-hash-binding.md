# Checkpoint 2228 - Authenticode Response Hash Binding

## Objective

Bind the exact bounded stdout bytes later interpreted as an Authenticode helper
verdict to the already retained and freshly reauthenticated response-ready pipe
boundary. Checkpoint 2227 proves which connected process and token profile sent
the ready signal, but its one-byte marker does not carry the response length or
content digest. A response-stream mutation after the helper flushes stdout must
fail visibly before strict JSON parsing or publisher trust.

## Implemented Control

The child response writer now returns the exact bytes it wrote, including the
single JSON newline, after enforcing the existing 16 KiB stdout ceiling. Before
signaling readiness, the child computes SHA-256 over:

1. the fixed domain `avorax-authenticode-response-binding-v1\0`;
2. the exact response length as unsigned little-endian `u64`; and
3. every exact stdout response byte.

The child sends one fixed 41-byte frame over the retained duplex pipe: the
existing one-byte response-ready marker, eight-byte length, and 32-byte SHA-256.
It then blocks for the existing distinct final ACK.

The parent reads at most one extra byte, requires the exact 41-byte frame and a
canonical response length from 1 through 16,384 bytes, then performs checkpoint
2227's exact child-PID binding and fresh connected-client token reauthentication.
It repeats launch/child token evidence before final ACK. After confirmed helper
exit, bounded stdout collection must match both authenticated length and digest
before an `AuthenticodeHelperOutput` can reach strict JSON parsing.

Empty, oversized, truncated, extended, malformed-marker, out-of-range-length,
length-mismatch, or digest-mismatch evidence is diagnostic. A pre-ACK frame,
client, token, timeout, cancellation, or cleanup failure enters existing bounded
terminate/reap handling. A post-exit stdout mismatch remains a hard error and
cannot become publisher trust.

## Scripted Verification

Three Windows Rust regressions are scripted:

- `native_authenticode_response_hash_binding_spans_authenticated_boundary`
  exercises a benign real restricted child and requires exact stdout;
- `native_authenticode_response_hash_binding_contract_is_fail_visible` checks
  exact frame round-trip plus empty, oversized, truncated, extended, marker,
  length, same-length mutation, and digest rejection; and
- `native_authenticode_response_hash_binding_rejects_mutated_stdout` runs a
  benign child that intentionally binds different same-length bytes and requires
  a visible SHA-256 mismatch.

The malformed child never executes candidate content. Existing helper fixtures
now bind the exact literal line they write. Source contract 658 verifies child,
parent, runner, test, verifier, validator, documentation, and ordering contracts.
The central verifier adds mandatory step 258, and strict report validation
requires exactly 258 steps plus the new verified and technically-limited scope.
Stale 257-step evidence cannot satisfy this source revision.

No checkpoint-2228 passing result is claimed during scripting. Production code,
benign/adversarial Rust tests, source contract 658, exact 258-step verifier and
validator contracts, and all required documentation are completed before any
checkpoint-2228 parser, formatter, build, lint, test, smoke, or verifier run.

## Security Limits

The SHA-256 frame is an unkeyed content-integrity digest transported over the
existing same-user pipe endpoint whose process and token profile are freshly
validated. It is not a secret MAC, encryption, cross-identity message
authentication, or durable token-object binding. It does not change the helper
identity, sandbox, access rights, or privilege boundary.

The control detects stdout changes after the frame is captured, but a
sufficiently privileged same-session attacker able to inject the helper,
duplicate its handles, or modify both stdout and the frame before authentication
remains inside the existing trust boundary. Separate impersonation calls may
still produce distinct token objects. Transient mutation between snapshots,
post-ACK token mutation, compromised parent/kernel, AppContainer/LPAC, installed
LocalSystem, production signing, signed-driver enforcement, and demonstrated
pre-execution blocking remain outside this checkpoint.

## Dependency And Safety Boundary

The implementation reuses the Native Engine's pinned `sha2` dependency and the
existing named-pipe, token, process, bounded-I/O, and cleanup code. It adds no
crate, package, feature, or lockfile change. The frame is fixed at 41 bytes and
the response remains capped at 16 KiB, so no new unbounded CPU, RAM, I/O, archive,
or network work is introduced.

No live malware, malware repository, downloaded candidate, executable fixture,
Defender change, machine-wide installation, service/driver start, release, or
publication is involved. Only benign child-test text is written and never used
as executable candidate content. The protected quarantine remains read-only and
`.verification` remains outside staging.

## Scripting-Phase Status

Implementation, regressions, source/verifier/validator contracts, and report,
status, run-log, control-matrix, threat-model, blocker, and dependency records
are scripted. Execution and all local, hosted, integration, synchronization,
and destination evidence remain pending. The complete antivirus goal remains
active.

## Initial Focused Execution

Both PowerShell parsers and `git diff --check` pass. The Rust target compiles;
two of its three tests pass. The first formatter check reports four mechanical
layout differences. The source runner executes all 658 contracts and rejects
one historical checkpoint-2226 assertion that still looks for the retired
one-byte response parser. The third Rust test reaches the intended forged-
digest failure but inspects only the outer `anyhow` context, hiding the inner
SHA-256 diagnostic from its second assertion.

None of these failed checks is credited. Canonical layout, the historical
contract's current frame-parser name, and chain-aware diagnostic formatting are
repaired without weakening production behavior or evidence scope. The entire
focused set must pass on a fresh rerun.

## Corrected Focused Execution

After the exact repairs, both PowerShell parsers, `cargo fmt --check`,
`git diff --check`, source contracts `658/658`, and all three response
hash-binding Rust regressions pass. The real restricted child reaches the
authenticated boundary, exact frame and content mutations fail as designed,
and a same-length stdout/digest mismatch remains a visible SHA-256 failure.

This is focused evidence only. Complete Authenticode/Native/Local/Guard,
workspace, lint, release, Flutter, definitive, hosted, integration,
synchronization, and destination evidence remain pending.

## Workspace, Lint, And Release Build Execution

Both standard and all-feature locked workspace suites pass. Strict all-target/
all-feature Clippy passes for Native, Local Core, and Guard, and standalone
Native locked/offline all-target/all-feature checking passes. Locked Local Core
and Guard release builds pass.

The first release-smoke wrapper call is correctly rejected because its binary
arguments are relative while the safety contract requires absolute paths. That
support invocation is retained and uncredited. The corrected absolute-path run
passes for both release hosts. It verifies mandatory nonce/hash-bound helper
IPC, embedded and catalog Microsoft trust, unsigned rejection, and wrong-hash
failure without executing candidate content.

## Initial Broad Execution

Complete Authenticode reaches `74` passed with `16` intentional child fixtures
ignored, then one historical malformed-ready assertion rejects the new exact
`response-binding frame length` diagnostic because it still requires only the
old `response-ready` wording. The failure is retained and uncredited. Guard
passes `248/248`; concurrently launched Native and Local commands exited but
their complete outputs were not retained by the orchestration wrapper, so they
are not credited.

The test now distinguishes a missing frame's `response-ready read` diagnostic
from a malformed frame's `response-binding frame length` diagnostic and still
requires bounded post-response cleanup for both. Production behavior is
unchanged. Authenticode, Native, and Local must be explicitly rerun.

The first explicit rerun proves the missing-frame path retains the stable
`response-ready` diagnostic prefix but does not guarantee the narrower `read`
word. Authenticode again reaches `74/16`, Native reaches `510/16`, and both stop
only on that assertion; neither run is credited. Local passes `536/536`. The
missing path now requires the stable prefix while the malformed path still
requires exact frame-length wording, and both require cleanup.

## Corrected Broad Rust Execution

The repaired missing/malformed diagnostic regression passes. Source contracts
remain `658/658` and formatting is exact. Complete Authenticode passes `75`
tests with `16` intentional child fixtures ignored. Native passes `511/16` plus
signature compiler `6/6`; Local Core passes `536/536`; Guard passes `248/248`.

The failed broad attempts remain retained and uncredited. Locked workspace,
lint/offline, release/smoke, Flutter, definitive, hosted, integration,
synchronization, and destination evidence remain pending.

## Corrected Workspace, Smoke, And Flutter Execution

Both standard and all-feature locked Rust workspace suites pass. Strict all-
target/all-feature Clippy passes for Native, Local Core, and Guard; standalone
Native locked/offline all-target/all-feature checking passes. Locked release
Local Core and Guard builds pass, followed by the corrected absolute-path two-
host Authenticode smoke described above.

Flutter analysis reports no issues. The complete client suite passes
`838/838`. The analyzer also reports 33 newer package versions that are
incompatible with the current pinned constraints; this is informational and no
unreviewed dependency or lockfile upgrade is made in this checkpoint.

Definitive, malformed-report, hosted, integration, synchronization, and
destination evidence remain pending. The complete antivirus goal remains
active.

## Definitive Local Evidence

The no-skip, no-Defender/EICAR verifier runs from
`2026-08-25T02:20:43.6274754Z` through
`2026-08-25T02:28:47.9121375Z` and passes exact `258/258`, with zero failed or
skipped steps, in `484.2s`. The new response hash-binding target passes in
`0.3s`. Both the verifier's embedded strict validator and an independent
Windows PowerShell 5.1 `-RequireFullSuite` invocation accept the report.

Fifteen isolated adversarial report copies are rejected with exit 1: changed
schema, failed top-level status, enabled Defender/EICAR, either Flutter or Rust
skip, renamed mandatory target, each of five new verified-scope statements,
each of two new technical-limit statements, a failed final step, and stale 257-
step evidence. All copies remain untracked below `.verification` and are never
staged.

The root Cargo, Native Cargo, and Flutter lock blobs remain exactly
`7ab38f4820b08029c64872360fac7141e2512ac4`,
`277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
`51fa085a41168aa1deadace8b5395614db43649e`. The protected quarantine remains
read-only and exact: 16,072 files, zero directories, 4,522,733 bytes, 5,357
each `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending or
temporary files.

Three additional support-command failures are retained and uncredited. A
`unittest` invocation discovered zero pytest-style source tests before the
dependency-free runner passed `658/658`; one nested PowerShell parser wrapper
lost variables to outer-shell quoting before literal quoting passed both
parsers; and the first adversarial harness was rejected at parse time by an
invalid inline closure expression before the corrected harness rejected all
15 cases. None changed product behavior or evidence requirements.

Hosted, integration, synchronization, and destination evidence remain pending.
The complete antivirus goal remains active.

## Implementation-Head Hosted Evidence

The verified tree is unchanged by the non-destructive merge of current
`origin/main`; exact implementation head
`7531850d6fa79033f159f799d5c37b55c5ee80b8` passes all five Avorax CI jobs in
run `32802501559` without retry. Desktop Packages push and draft-PR runs
`32802476664` and `32802501516` pass contracts, Windows x64 MSI/EXE (including
administrative extraction without installation), Linux x64 DEB/tar, macOS
arm64/x64 DMG, and consolidation. Prerelease publication is skipped in both.

Untouched consolidated artifacts `9547257904` and `9547368311` are retained
below untracked `.verification`; they are not extracted or executed. Their
outer ZIP sizes/SHA-256 values are respectively
`131283935`/`95a3f1d2c07672a1cb1947ffda19245f1ad9ce43eab2df0a143b54ae0a3dadff`
and
`131433875`/`302bf947c141a7977c821308269d9e16b4956150e51170999c31140a8b323ae3`.
Bounded in-stream validation proves each contains exactly eight regular root
entries: six platform artifacts, one seven-row checksum file matching all six
artifacts plus the SBOM, and one CycloneDX 1.6 lockfile SBOM with 569
components.

Draft PR `#80` remains unmerged. Evidence-head checks, normal merge, merged-main
evidence, guarded synchronization, and destination proof remain pending. The
complete antivirus goal remains active.
