# Checkpoint 2238 - Protection Loop Generation Binding

## Objective

Prevent an app-lifetime process snapshot or finite watch-poll operation that
started under an old protection lifecycle from publishing stale status or event
evidence after protection stops or a loop is replaced. Preserve honest
best-effort behavior without claiming hard cancellation of already-started
operating-system or Local Core work.

## Scripted Implementation

- Process-snapshot and watch-poll loops each own a monotonically increasing
  controller-lifetime generation. Every stop invalidates the prior generation
  before cancelling its timer and clearing routine-event state.
- A successful start captures the post-stop generation in its timer callback.
  Timer entry, post-await success, exception handling, and outer unawaited-error
  handling require that exact generation, an active current timer, a mounted
  controller, and a still-running protection state.
- App-detection snapshots remain outside the active-protection generation
  contract. Their existing single-flight guard is retained; the generation
  boundary applies only when an active loop owns the request.
- Starting a watch-poll loop now invalidates the previous loop before checking
  whether the new watched-path set is empty. An empty replacement therefore
  cannot leave an older timer or watched-path lease active.
- The change does not terminate a PowerShell/CIM collector, Local Core process,
  or finite watch-poll request that already started. Its late completion is
  ignored after lifecycle invalidation and cannot rewrite `off` state or append
  a stale active-loop result event.

## Scripted Coverage

Two Flutter controller regressions use benign temporary directories and
manually fired timers. One holds a process-snapshot response until protection is
fully stopped, then returns a suspicious fixture and requires state to remain
off with no late suspicious event. The other holds a watch-poll request until
stop, then completes with an exception and requires no stale failure event or
limited-state overwrite. No candidate file is created or executed.

The definitive verifier adds mandatory step `Flutter protection-loop stale-
generation tests`. Its strict validator requires exactly 267 steps and three
generation/cancellation-honesty scope clauses. Source contract 668 binds the
runtime guards, empty-path invalidation ordering, both race fixtures,
verifier/validator, documentation, and unchanged dependency scope.

No checkpoint-2238 passing result is claimed during scripting. No live malware,
EICAR file, Defender change, machine-wide install, service/driver start,
dependency, feature, lockfile, release, publication, candidate execution, or
protected-vault mutation is involved.

## Local Verification

- Dart format, PowerShell 5.1/7 parser checks, `git diff --check`, and Flutter
  analyze pass. The focused stale-generation tests pass `2/2`; adjacent process
  snapshot, watch-poll, and protection filters pass `9/9`, `5/5`, and `50/50`.
- The complete Flutter suite passes `840/840`. Source contracts pass exact
  `668/668`.
- The explicit no-skip/no-Defender verifier passes exactly `267/267` with zero
  failed or skipped steps from `2026-08-26T02:23:51.6920894Z` through
  `2026-08-26T02:31:41.5036223Z` in `469.8s`. Its report SHA-256 is
  `c219c9b35c74988471fc5dfa1ac2c2808488873fd79706876f51f5c2eaff8236`.
  Embedded and independent strict validation passes under checked Windows
  PowerShell 5.1 and PowerShell 7 hosts.
- Eight isolated mutations under both validator hosts reject `16/16`, covering
  enabled Defender/EICAR, failed status/step, renamed mandatory target, both
  required generation/cancellation-honesty clauses, skipped Flutter, and stale
  266-step evidence.
- Root, Native, and Flutter lock SHA-256 values remain exactly
  `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
  `7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
  and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
  No repository test process remains. Read-only inventory confirms the protected
  vault is unchanged at 16,072 files, zero directories, 4,522,733 bytes, 5,357
  each payload/JSON/auth, one metadata key, and zero pending/temp/reparse.

## Exact Implementation-Head Hosted Evidence

Commit `5944e97063c59f9d703c0a1915950b6f884c7e5e` is PR `#90`'s exact
implementation head. Avorax CI run `32923573250` passes all five mandatory jobs.
Desktop Packages push `32923527726` and PR run `32923573229` pass package
contracts, Windows MSI/EXE, Linux DEB/tar, both macOS DMGs, consolidation, and
evidence upload. Publication jobs `98045073302` and `98044630756` are skipped;
no release or prerelease is created.

Consolidated artifacts `9591053604` and `9590999961` are 131,695,821 and
131,731,372 bytes with SHA-256
`99ccb5ac02eac63c2031d5b8a66af4d578474cf65ff3e8a02a67e86dcfe949c7` and
`b376f8412261dafa5e688d9cc226d30d3463c111cb6a4e0d172f5dfd675edbbc`.
Both match GitHub's digests and pass bounded in-stream validation without
extraction or execution: exact eight root entries, six platform release files,
seven matching checksum rows, and CycloneDX 1.6 lockfile SBOM evidence with 569
components.

Evidence-head CI/packages, normal merge, merged-main evidence, guarded
synchronization, and destination verification remain pending. No install,
service/driver start, Defender change, release, publication, candidate
execution, or protected-vault mutation occurred.

## Limits

Generation binding prevents stale publication; it is not cooperative or forced
cancellation of the underlying request. A stopped request may consume bounded
resources until its existing timeout/reap path completes. Monitoring remains
app-lifetime polling and can miss short-lived processes or file activity between
polls. No installed durable service, cross-identity isolation, process mutation,
driver/kernel interception, or pre-execution blocking claim is added.
