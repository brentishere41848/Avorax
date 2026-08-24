# Checkpoint 2218: Authenticode Client Pipe Security Read-Back

Date: 2026-08-24

## Status

Implementation, benign runtime test, verifier step 248, exact validator contract,
source contract 648, and audit documentation are scripted as one batch before
execution. No checkpoint-2218 passing result is claimed during that scripting
phase. Corrected focused, broad, and definitive local verification pass. Exact
implementation-head CI and package evidence pass. Evidence-head verification,
merge, synchronization, and destination evidence remain pending.

## Threat

Checkpoint 2217 verifies the applied handshake descriptor on the parent's server
handle immediately after creation. It does not independently prove that the
low-integrity child sees the same exact protected DACL and mandatory label on the
client handle it opens later. Descriptor drift between server creation and client
connection must fail before the launch token or publisher-trust work.

## Scripted Control

- The child opens the one expected local handshake path with exactly
  `GENERIC_WRITE | READ_CONTROL`, no sharing, and no fallback. `READ_CONTROL` is
  the documented access needed to query both `DACL_SECURITY_INFORMATION` and
  `LABEL_SECURITY_INFORMATION`; it adds no write-DAC, ownership, full-SACL, or
  privilege-enabling request.
- After client endpoint validation and exact parent server-PID binding, the child
  resolves the SID from its current process token. Before `WriteFile` can transfer
  any launch-token byte, it calls the same bounded
  `GetSecurityInfo(SE_KERNEL_OBJECT)` descriptor reader used by the parent.
- Exact evidence remains a protected, present, nondefault DACL containing only
  ordered zero-flag full-control ACEs for SYSTEM and the current user, plus one
  present nondefault low-integrity no-write-up mandatory-label ACE. Generic pipe
  rights are normalized before comparison.
- Open/access, SID, query, null descriptor, ACL bound/count, ACE type/size/flag/
  mask/SID, principal/order, policy, label, or context failure is diagnostic and
  cannot reach token exchange, request parsing, candidate access, or publisher
  trust. There is no write-only or weaker retry.

## Scripted Evidence

- A real restricted helper child traverses the production client open, endpoint
  check, parent-PID binding, process-token SID query, client descriptor read-back,
  and token transfer. It executes only the Rust test binary and never opens or
  executes a candidate fixture.
- Existing pure adversarial descriptor evidence rejects changed protection,
  DACL/label presence/default state, ACE count/order/type/flags/masks/SIDs,
  principals, integrity level, and no-write-up policy. Source ordering contracts
  require the client read-back after peer binding and before `WriteFile`.
- The central verifier adds step 248,
  `native-engine Authenticode handshake client security read-back regressions`.
  The independent validator requires exactly 248 successful steps, that exact
  step, all three verified-scope clauses, and the point-in-time technical limit.
- Python source contract 648 pins exact access, ordering, production call, real
  child test, verifier, validator, dependency status, and all audit documents.

## Technical Limit

The child check narrows creation-to-connect descriptor drift and verifies the
actually opened client handle, but it remains point-in-time same-user evidence.
The current account owns or controls the same user-mode namespace; sufficiently
privileged same-user code, injected trusted code, SYSTEM, process-memory access,
or kernel compromise remains outside this boundary. The random token is process
binding evidence, not a durable secret against such actors.

The query reads only DACL and mandatory-label evidence. It does not request the
full SACL, `ACCESS_SYSTEM_SECURITY`, `SeSecurityPrivilege`, `WRITE_DAC`, or
`WRITE_OWNER`; add encryption or cross-identity authentication; create
AppContainer/LPAC; demonstrate an installed LocalSystem service; prove production
signing; add a driver; or provide pre-execution blocking.

No live malware, EICAR creation, candidate execution, network, installation,
service/driver start, Defender change, release/publication, or protected-vault
access is scripted for this checkpoint.

## Planned Verification

After this complete scripting batch, run parser and formatting checks, source
contracts, the focused client read-back and complete Authenticode suites, strict
Native/Local Core/Guard Clippy, both locked workspaces, release Local Core/Guard
builds and two-host benign trust smoke, Flutter analyze and `838/838`, safety and
dependency gates, exact-248 definitive verifier plus independent validator,
malformed-report rejection, lock review, and read-only protected-vault inventory.

## Initial Execution Finding

PowerShell parsers `2/2`, Python compilation, Rust formatting, and diff checks
passed. The first source-contract run executed all `648` tests but failed 17
tests because older Authenticode contracts still pinned the previous central
validator count of 247. No failed contract is counted as success. Those stale
current-count assertions were updated mechanically to 248 before any runtime
test. A second run then exposed 16 matching stale validator-message assertions;
those were likewise updated to 248. Neither failed run is success evidence;
corrected source-contract execution remains pending.

## Corrected Local Verification

- Corrected source contracts pass `648/648`; PowerShell parsers `2/2`, Python
  compilation, Rust formatting, and diff checks remain green.
- The new real child client read-back passes `1/1`; parent read-back passes
  `1/1`; adjacent parent-child handshake passes `2/2`; complete Authenticode
  passes `63` with `13` intentional isolated-child ignores.
- Strict Native, Local Core, and Guard Clippy pass. Standard and all-feature
  locked workspaces pass with Native `491/13`, signature compiler `6/6`, Local
  Core `536`, and Guard `248` standard/`249` all-feature; all other crates pass.
- Flutter analyze reports no issues and the full client suite passes `838/838`.
- Locked release Local Core and Guard builds plus the two-host benign Authenticode
  smoke pass embedded/catalog Microsoft trust, exact hash binding, unsigned
  rejection, and wrong-hash failure without candidate execution.
- Branding, product-copy, no-malware-binaries, and dependency evidence gates pass.
  The definitive verifier ran from `2026-08-24T05:36:38.7395267Z` through
  `2026-08-24T05:44:28.8973301Z` and passed exact `248/248`, zero failed/skipped,
  in `470.1s`; embedded and independent strict validation pass.
- Eight isolated malformed reports are rejected: missing step/count, renamed
  step, each of three verified-scope clauses, missing technical-limit scope, and
  failed or skipped target status.
- Root Cargo, Native Cargo, and filtered Flutter lock blobs remain
  `7ab38f4820b08029c64872360fac7141e2512ac4`,
  `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
  `51fa085a41168aa1deadace8b5395614db43649e`. The raw Windows Flutter checkout
  bytes differ only through Git line-ending filtering and have no Git diff.
- Read-only protected-vault evidence remains exactly 16,072 files, zero
  directories, 4,522,733 bytes, 5,357 each `.avoraxq`/`.json`/`.auth`, one
  `.metadata_auth_key`, and zero pending. At the end of local verification,
  commit and hosted evidence had not yet run; the next section records them.

## Hosted Implementation Evidence

- Exact implementation `54dbb5812e10aeb149a7f9da2031f9caf570ab92` is pushed
  only on `agent/checkpoint-2218-authenticode-client-pipe-security-readback` and
  is the head of draft PR `#70`.
- Avorax CI `32695037132` passes all five jobs at that exact head: branding/copy,
  Rust Local Core/Native/Guard/update/API tests and lint, Unix quarantine
  permissions, Flutter/protocol, and security/protection/performance gates.
- Desktop Packages push `32694996063` and PR `32695037192` pass package
  contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG,
  dependency/license evidence, administrative MSI extraction, and consolidated
  checksums.
- The downloaded exact push artifact contains all six platform packages and one
  CycloneDX 1.6 lockfile SBOM with `569` components. Every one of the seven
  package/SBOM entries matches `SHA256SUMS.txt`.
- Both `Publish desktop beta prerelease` jobs are `skipped`. No package was
  installed, released, or published. Evidence-head CI/packages, normal merge,
  merged-main evidence, guarded original-tree synchronization, and destination
  verification remain pending.
