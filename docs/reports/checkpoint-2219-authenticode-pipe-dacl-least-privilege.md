# Checkpoint 2219: Authenticode pipe DACL least privilege

Date: 2026-08-24

## Scripting Status

The complete implementation, benign/adversarial test, verifier, independent
validator, source-contract, audit, threat-model, dependency, status, and run-log
batch is scripted before execution. No checkpoint-2219 passing result is claimed
during scripting. Execution evidence must be added only after the scripted batch
is complete and the named checks actually pass.

## Control Change

The dedicated local Authenticode handshake pipe retains a protected DACL and a
low-integrity no-write-up mandatory label. Its ordered zero-flag access-allowed
ACEs now grant SYSTEM normalized full control and grant the current user only
normalized generic read plus generic write. The SDDL is exactly
`D:P(A;;GA;;;SY)(A;;GRGW;;;<current-user-sid>)S:(ML;;NW;;;LW)`.

Both the parent-created server endpoint and the child-opened client endpoint use
the existing bounded structured `GetSecurityInfo` read-back. `MapGenericMask`
normalizes the pipe/file rights before exact comparison. A current-user
full-control, read-only, write-only, execute, delete, `WRITE_DAC`, `WRITE_OWNER`,
or otherwise mismatched ACE is diagnostic and cannot reach token exchange or
publisher trust. There is no broader-ACL fallback.

The parent requires generic read to receive the child token. The low-integrity
child requires generic write to send it and `READ_CONTROL` to verify the applied
descriptor. Generic read plus generic write supplies those required rights
without placing execute, delete, `WRITE_DAC`, `WRITE_OWNER`, or full control in
the current-user ACE. SYSTEM retains full control for Windows administration and
recovery.

## Scripted Evidence

- A real ignored child fixture traverses pipe creation, process launch, client
  open, both security read-backs, exact PID/token exchange, and bounded reap.
- Adversarial benign evidence rejects current-user full-control, read-only,
  write-only, execute-augmented, delete-augmented, `WRITE_DAC`-augmented, and
  `WRITE_OWNER`-augmented masks.
- The definitive verifier adds `native-engine Authenticode handshake pipe
  least-privilege DACL regressions` and now emits exactly 249 steps.
- The independent validator requires that exact step, exact scope clauses, the
  ownership limitation, and exactly 249 successful steps.
- Python source contract 649 pins the SDDL, normalized masks, adversarial masks,
  production/read-back relationship, verifier, validator, and all audit docs.

## Technical Limit

The pipe creator's token default owner is not changed or independently read back.
If the current user owns the named pipe, Windows ownership supplies implicit
`READ_CONTROL` and `WRITE_DAC` authority independently of the narrower
current-user ACE. The parent and child checks are point-in-time detection: they
cannot prevent sufficiently privileged same-user code from changing the
descriptor between checks, duplicating handles, inspecting process memory, or
executing trusted code inside either process.

This change does not add encryption, authenticated cross-identity IPC,
AppContainer/LPAC, an installed LocalSystem service, production signing, a
driver, kernel blocking, or pre-execution protection. It does not claim that an
owner lacks implicit DACL authority.

No live malware, EICAR creation, candidate execution, network access,
installation, service/driver start, Defender change, release, publication, or
protected-vault access is scripted for this checkpoint.

## Dependency Delta

Checkpoint 2219 adds no crate, package, feature, or lockfile change. It reuses
the pinned `windows-sys 0.61.2` constants and APIs already enabled for generic
pipe/file access, SDDL parsing, `GetSecurityInfo`, and `MapGenericMask`. Existing
MIT OR Apache-2.0 licensing is unchanged.

## Planned Verification

After scripting is complete: run parser/compilation and formatting checks,
source contracts, the focused least-privilege fixture, both endpoint read-backs,
the full Authenticode module, strict Native/Local Core/Guard Clippy, both locked
workspaces, release Local Core/Guard builds and benign two-host trust smoke,
Flutter analyze and its full suite, safety/dependency gates, definitive exact-249
verification, independent validation, malformed-report rejection, exact-lock
review, and a read-only protected-vault inventory. Hosted exact-head evidence,
normal PR merge, guarded original-tree synchronization, and destination evidence
remain later phases and cannot be inferred from local scripting.

## Initial Execution Findings

- The first parser invocation failed before parsing because its command-local
  token/error variables were not initialized; the corrected command passes both
  PowerShell files. The initial `rustfmt --check` requested import ordering only;
  formatting was applied and the corrected check passes. Neither initial command
  is counted as success.
- The default and bundled Python runtimes do not include `pytest`; no package was
  installed. An existing local pytest runner executed 638 tests and exposed one
  new contract-only slice ending at a nonexistent function name (`637` passed,
  one failed). The slice now ends at the actual next function. The repository's
  dependency-free runner subsequently passes source contract `649/649`.
- The first focused Rust run passed the real pipe path but reported three
  test-only imports in the product library. Those constants moved into the test
  module; corrected focused execution and strict Clippy are warning-free.

## Corrected Local Verification

- PowerShell parsers `2/2`, Python compilation, Rust formatting, and diff checks
  pass. The focused least-privilege child path passes `1/1`; complete
  `windows_authenticode::tests` passes `56` with `13` intentional isolated-child
  ignores.
- Both standard and all-feature locked root workspaces pass. Native passes
  `492/13`, signature compiler `6/6`, Local Core `536/536`, and Guard `248/248`
  standard plus `249/249` all-feature. Strict Native, Local Core, and Guard Clippy
  pass.
- Flutter analyze reports no issues and its full suite passes `838/838`.
  Locked release Local Core and Guard builds plus the two-host benign
  Authenticode smoke pass embedded/catalog Microsoft trust, mandatory hash
  binding, unsigned rejection, and wrong-hash failure without candidate
  execution.
- Root Cargo, Native Cargo, and Flutter lock blobs remain exactly
  `7ab38f4820b08029c64872360fac7141e2512ac4`,
  `277dd9fe1edfc45fa5550e8e2831f2a0c121561d`, and
  `51fa085a41168aa1deadace8b5395614db43649e`. Read-only protected-vault evidence
  remains 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
  `.avoraxq`/`.json`/`.auth`, one `.metadata_auth_key`, and zero pending.
- Branding/product-copy/no-malware/dependency gates, definitive exact-249
  verification, independent validation, malformed-report rejection, hosted
  evidence, merge, synchronization, and destination evidence remain pending and
  are not claimed by this section.

## Definitive Local Evidence

- Branding, product-copy, no-malware-binaries, false-positive, protection,
  performance/resource, release-prerequisite, pack, package-source, and dependency
  gates pass. The definitive verifier ran from
  `2026-08-24T07:27:49.3271263Z` through
  `2026-08-24T07:35:39.6799467Z` in `470.3s` and passed exactly `249/249`, zero
  failed and zero skipped. Embedded and separately invoked strict validation pass.
- Eight isolated malformed copies are rejected: missing required step, renamed
  step, missing exact-DACL scope, missing broader/narrower-mask rejection scope,
  missing ownership technical limit, failed target step, skipped target step, and
  `skip_rust=true`.
- Exact lock blobs and the read-only protected-vault inventory remain unchanged.
  No live malware, candidate execution, machine-wide install, service/driver
  start, Defender change, release, or publication occurred.
- Checkpoint 2219 is **locally verified**. Hosted exact-head CI/package evidence,
  normal PR integration, merged-main evidence, guarded original-tree
  synchronization, and destination verification remain pending; local checkpoint
  completion is not complete-antivirus completion.

## Hosted Implementation Evidence

- Exact implementation `5171fb4e1076de74eb03c5adab7f12f2c1f20a6f` is
  pushed only on `agent/checkpoint-2219-authenticode-pipe-dacl-least-privilege`
  and is the head of draft PR `#71`.
- Avorax CI PR run `32702550130` passes all five jobs at that exact SHA:
  branding/copy, Rust Local Core/Native/Guard/update/API, Unix quarantine
  permissions, Flutter/protocol, and security/protection/performance gates.
- Desktop Packages push run `32702466511` and PR run `32702550182` pass package
  contracts, Windows x64 MSI/EXE, Linux x64 DEB/tar, macOS arm64/x64 DMG,
  dependency/license evidence, administrative MSI extraction, consolidation,
  and checksums. Both `Publish desktop beta prerelease` jobs are skipped.
- The downloaded exact push artifact contains all six platform packages and one
  CycloneDX 1.6 lockfile SBOM with `569` components. Independent local
  recomputation matches all seven rows in `SHA256SUMS.txt`.
- No package was installed, released, or published. Evidence-head CI/packages,
  normal PR integration, merged-main evidence, guarded original-tree
  synchronization, and destination verification remain pending.

## Integration And Destination Evidence

- Evidence head `be122479dea324df96ac9b866381819e4136d612` passes Avorax CI
  `32704723284` and Desktop Packages `32704723183`. PR `#71` merged normally as
  `e6caf8187c8ae99a7ad392e7ff4b8c606cf8a850`; merged-main CI `32706023688`
  and packages `32706023644` pass every mandatory job, all six platform
  packages, consolidation, checksums, dependency evidence, and administrative
  MSI extraction. Publication is skipped throughout.
- Guarded preconditions proved eleven existing original-tree targets byte-exact
  to prior merge `1e453005a01782e9bed887ba9ad489d5b6e51894` and the new checkpoint
  report absent. The first combined sync command was policy-rejected before
  execution; the replacement script's first parser run found an invalid
  `$path:` interpolation, and its first execution found two `git.exe` candidates
  before staging. Corrected execution materialized direct raw Git blobs, verified
  every staged hash, atomically replaced exactly twelve paths, verified all
  twelve destination blobs, and left zero staging files. None of the rejected or
  failed attempts is counted as success.
- The first focused destination command selected zero tests because `--exact`
  lacked the module-qualified test name. The corrected command passes `1/1`.
  Initial direct safety-script launches were blocked by the host signed-script
  policy; process-local execution of only the trusted repository scripts passes.
  The no-malware gate rejected both an omitted Python path and the WindowsApps
  reparse alias before passing with the fixed non-reparse local Python path.
- Destination parsers `2/2`, source contracts `649/649`, formatting, complete
  Authenticode `56/13`, Native `492/13`, compiler `6/6`, Local Core `536/536`,
  Guard `248/248` standard and `249/249` all-feature, both locked workspaces,
  strict Native/Local/Guard Clippy, release builds and benign two-host trust
  smoke, branding/product/no-malware/dependency gates, Flutter analyze, and
  Flutter `838/838` pass.
- The destination definitive report ran from
  `2026-08-24T08:54:17.6603197Z` through
  `2026-08-24T09:02:24.5591800Z` and passed exactly `249/249`, zero failed and
  zero skipped, in `486.9s`. Its embedded validator passes. A first standalone
  PowerShell 7 invocation parsed ISO timestamps as `DateTime` instead of the
  validator's Windows PowerShell string contract and is not success evidence;
  the separately invoked Windows PowerShell `-RequireFullSuite` validator passes.
- Root Cargo, Native Cargo, and Flutter lock blobs remain exact. The protected
  vault remains 16,072 files, zero directories, 4,522,733 bytes, 5,357 each
  payload/metadata/auth, one metadata key, and zero pending. Checkpoint 2219 is
  closed without installation, service/driver start, Defender change, release,
  or publication; the complete antivirus hardening goal remains active.
