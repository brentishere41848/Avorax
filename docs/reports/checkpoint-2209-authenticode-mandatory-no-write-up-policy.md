# Checkpoint 2209: Authenticode Mandatory No-Write-Up Policy

## Objective

Close the gap between the Authenticode helper's verified Low Mandatory label
and the separate mandatory policy stored in its primary token. Require the
LSA-created policy inherited through `CreateRestrictedToken` to contain
`TOKEN_MANDATORY_POLICY_NO_WRITE_UP`, then require exact bounded parent and
child read-back before process launch or request parsing. Policy `OFF`,
`TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN` without no-write-up, and unknown bits
must fail visibly and cannot become Microsoft publisher trust.

Checkpoint 2208 is closed first through evidence `fa7574f`, PR `#60`, merge
`1076ac3`, exact merged-main CI `32640506209`, packages `32640506192`, guarded
12-path original-tree synchronization, destination verification, and an
unchanged protected-vault invariant. Publication was skipped.

## Security Design

The parent continues to create the `DISABLE_MAX_PRIVILEGE` primary token and
assign exact `WinLowLabelSid`. The mandatory policy is created by LSA and
inherited through `CreateRestrictedToken`; the helper queries the resulting
fixed-size `TOKEN_MANDATORY_POLICY` before calling `CreateProcessAsUserW`. No
launch retry with a missing or disabled mandatory policy exists.

The first scripted implementation attempted to call
`SetTokenInformation(TokenMandatoryPolicy)` on the restricted token. The real
benign-child test failed before launch with `ERROR_PRIVILEGE_NOT_HELD` (Win32
error 1314). Adding or enabling a privilege would violate least privilege, so
the setter was removed instead of weakening the host or hiding the error.

Primary-token validation queries `TokenMandatoryPolicy` with an exact
fixed-size result contract. It requires the no-write-up bit and rejects every
bit outside `TOKEN_MANDATORY_POLICY_VALID_MASK`. Windows may return the
documented `TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN` bit alongside no-write-up,
so that combination is accepted; `OFF`, new-process-minimum alone, and unknown
bits are rejected. The child repeats the complete primary-token validation
before process-mitigation validation, stdin, JSON, candidate access, WinTrust,
catalog, hashing, or response work.

## Scripted Verification Plan

All production, benign regression, verifier, validator, source-contract,
audit, threat-model, dependency, status, and run-log changes are scripted
before this checkpoint's test batch is executed.
No checkpoint-2209 passing result is claimed before execution.

| Control | Evidence | Current classification |
| --- | --- | --- |
| LSA policy inheritance | Source ordering requires restricted-token creation, low label, then full no-write-up policy validation before process creation | Focused verified |
| Parent/child read-back | Real ignored benign child validates the mandatory policy before any request input | Focused verified |
| Adversarial policy parsing | Pure cases accept no-write-up with optional new-process-minimum and reject off, new-process-only, and unknown bits | Focused verified |
| Central evidence | Dedicated verifier step; strict full-suite count rises from `238` to `239`; validator binds exact verified and technical-limit scope | Verified locally: `239/239` in `433.2s` |
| Trust compatibility | Locked release Local Core/Guard smoke retains embedded/catalog trust, unsigned rejection, wrong-hash failure, and no candidate execution | Focused verified |
| Dependency boundary | Existing pinned `windows-sys 0.61.2` Security APIs/constants only | Verified locally; package evidence pending |
| Defender-safe verifier binaries | Runtime-decode the standard EICAR marker from XOR-encoded bytes and reject Native/Local Core test executables containing the static marker | Verified locally in source, binaries, and the complete verifier |

Focused execution will start with PowerShell parse, rustfmt, source contracts,
and the dedicated `native_authenticode_helper_mandatory_policy` filter. It will
then run adjacent low-integrity and restricted-token filters, complete
Authenticode, strict Native lint, locked release Local Core/Guard builds, and
the two-host trust smoke. Full locked workspaces, complete Native, strict
Local/Guard lint, Flutter analyze/tests, definitive `239`-step verification,
independent/adversarial report validation, exact-head hosted checks, normal PR
merge, merged-main checks, guarded original-tree synchronization, destination
runtime checks, and a read-only vault audit follow only after earlier gates
pass.

## Focused Results

After the fail-visible setter redesign, formatting, diff checks, and both
PowerShell AST parses pass. The dependency-free source-contract runner passes
`638/638`. The mandatory-policy filter passes `2/2`; six adjacent Low-IL,
restricted-process, restricted-thread, sanitized-launch, mitigation, and
write-restricted filters each pass `2/2`. Complete Authenticode passes `39`
with `7` intentional child-fixture ignores, strict Native Clippy passes, and
locked Local Core/Guard release builds pass.

The two-host release smoke passes for Local Core and Guard with embedded and
catalog Microsoft trust, unsigned rejection, wrong-hash failure, and no
candidate execution. A first smoke invocation used relative binary paths and
was rejected before product execution by its absolute-path guard; the repeated
absolute-path invocation passed. `Cargo.lock` and `pubspec.lock` are unchanged.
Hosted exact-head checks, merge, synchronization, and destination evidence
remain pending, so the checkpoint is not closed.

The first definitive verifier attempt passed its first `38` recorded steps and
then failed at `native-engine indicator regressions`: Defender had removed the
benign Native Rust test executable and Cargo reported OS error 225. The report
is retained as failed evidence. Defender was not changed and no exclusion was
created. Review found that the exact standard EICAR marker was a compile-time
Rust literal in Native and Local Core, so Defender could classify the entire
test executable even when standard EICAR file creation was disabled.

The remediation is fully scripted before retesting. Native keeps one bounded
XOR-encoded 68-byte vector, decodes it once through `OnceLock`, and supplies the
runtime bytes to the built-in signature, self-test, benign archive tests, and
Local Core compatibility matcher. Native and Local Core regressions read their
own executable and reject an embedded exact marker. No detection threshold,
verdict, standard-EICAR opt-in behavior, or Defender setting is weakened.

## Full Local Results

Both `cargo test --workspace --locked -- --test-threads=1` and
`cargo test --workspace --all-features --locked -- --test-threads=1` pass.
Native reports `475` passed with `7` intentional ignored child fixtures in each
run. Strict Native, Local Core, and Guard Clippy, locked release Local Core and
Guard builds, the two-host Authenticode helper smoke, rustfmt, PowerShell AST,
diff, and unchanged-lockfile gates pass. Flutter analyze is clean and its full
suite passes `838/838`. The dependency-free source-contract runner passes
`639/639` after adding the runtime-marker contract.

The first definitive report remains failed after `38` steps in `36.1s`: Defender
removed the benign Native test executable because that binary contained the
exact compile-time EICAR marker. The first retry remains failed after `233`
steps in `477.5s`: an earlier incorrect Python invocation had generated
`tests/__pycache__/test_custom_driver_contract.cpython-314.pyc`, and the
no-malware-binaries gate correctly rejected the compiled cache containing the
marker. Only that invocation-created cache file was removed. The Python
contract now uses runtime `join` rather than compile-time adjacent literals,
and the no-malware-binaries gate passes. Neither failure is counted as success.

The definitive command
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -ReportPath .verification\checkpoint-2209-small-threat-mvp-definitive-retry2-report.json`
passes exactly `239/239` steps from `2026-08-23T14:04:23.3050782Z` through
`2026-08-23T14:11:36.525807Z` in `433.2s`. A separate
`validate-small-threat-mvp-report.ps1 -RequireFullSuite` invocation passes.
Controlled `238`-step, renamed mandatory-step, missing mandatory verified
scope, missing setter-limit scope, and missing runtime-EICAR scope reports are
all rejected. These retained adversarial copies live only under
`.verification/` and are not staged.

The final read-only protected-vault audit remains exact at `16,072` files,
zero directories, `4,522,733` bytes, `5,357` each `.avoraxq`, `.json`, and
`.auth`, one `.metadata_auth_key`, and zero pending. Hosted checks, PR/merge,
merged-main evidence, guarded original-tree synchronization, and destination
verification remain pending.

## Limits

The inherited `TOKEN_MANDATORY_POLICY_NO_WRITE_UP` policy is explicitly
read-back verified; it does not add no-read-up or no-execute-up. It does not
change user identity, credentials, profile/registry namespace, desktop/window
station, ordinary read rights, or access to objects explicitly labelled for
low-integrity writes. The optional documented
`TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN` bit affects child-process integrity
selection and does not strengthen the current helper's identity boundary.

This remains Mandatory Integrity Control, not AppContainer/LPAC, a private
desktop, authenticated cross-identity IPC, installed LocalSystem proof,
signed-driver enforcement, kernel interception, pre-execution blocking,
Defender replacement, or production detection-accuracy evidence. Existing
mapping and post-verdict mutation limitations remain unchanged.

## Dependency And Safety

The implementation reuses `TokenMandatoryPolicy`, `TOKEN_MANDATORY_POLICY`,
`TOKEN_MANDATORY_POLICY_NO_WRITE_UP`,
`TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN`, and
`TOKEN_MANDATORY_POLICY_VALID_MASK` from the existing pinned
`windows-sys 0.61.2` `Win32_Security` feature. It adds no crate, package, Cargo
feature, or lockfile change and introduces no new license. It does not request,
enable, or retain an additional token privilege.

Tests launch only the current benign Rust test executable as an ignored child;
candidate fixtures are never executed. No live malware, network retrieval,
installation, service/driver start, Defender change, release, publication, or
protected-quarantine mutation is permitted.
