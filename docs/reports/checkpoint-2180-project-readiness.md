# Checkpoint 2180 Project Readiness Analysis

Date: 2026-08-19

## Executive Assessment

Avorax is a functional, defensively designed user-mode antivirus beta for small
threats and suspicious-file review. The current checkout has real scan,
quarantine, restore, delete, allowlist, logging, update, and UI wiring. It is not
yet a production replacement for Microsoft Defender because persistent
installed monitoring, signed-driver enforcement, installed package/service E2E,
production detection-rate evidence, and release signing remain incomplete.

The following percentages are weighted engineering estimates, not test-pass or
detection-rate claims:

| Target | Readiness estimate | Basis |
| --- | ---: | --- |
| Small-threat user-mode beta | 88% | Core scan and response flows are verified in unit, integration, Flutter, and release-binary fixtures. Installed click-through, service, and filesystem E2E remain partial. |
| Production-grade Windows antivirus | 60% | The modular engine and safety boundaries are substantial, but production signing, a disposable elevated Windows test matrix, persistent monitoring, driver proof, independent accuracy studies, and operational key custody remain open. |

No unmitigated critical or high-severity defect was found in the changed
dependency-evidence surface or the verified small-threat user-mode paths during
this checkpoint. High-risk production gaps are listed below as explicit
blockers; they are not treated as working features.

## Current Architecture

| Layer | Responsibility | Current boundary |
| --- | --- | --- |
| Flutter desktop client | Routes, controls, progress, cancellation, status, history, confirmations, and visible failures | Uses typed controller and subprocess boundaries; packaged click-through and OS-dialog E2E are partial. |
| Local Core | Quick/full/custom orchestration, scan reports, cancellation, quarantine lifecycle, allowlist, finite watcher, process snapshots, and ransomware activity policy | Release binary and isolated lifecycle fixtures verified; installed authenticated service mutation remains disabled/partial. |
| Avorax Native Engine | SHA-256, native signatures, deterministic rules, static analysis, bounded archives, trust controls, heuristics, and explainable verdict fusion | Primary offline detection path; no production detection-rate claim. |
| Guard Service | User-mode process observation, driver health/IPC boundary, known-bad cache, and quarantine support | Runtime fixtures verified; persistent installed service and signed-driver E2E are blocked. |
| Update Service | Ed25519-signed `.aup` verification, staging, atomic component activation, rollback, and failure reports | Release-binary tamper/apply/rollback fixtures verified; installed service/network/key-ceremony E2E is partial. |
| Optional drivers | Minifilter and process-guard development paths | Inert in normal packages; activation requires a separate confirmed elevated workflow. Production signing and pre-execution proof are blocked. |

## Custom Engine Matrix

| Engine or control | Real responsibility | Status | Evidence or blocker |
| --- | --- | --- | --- |
| Native hash/signature engine | Stream full SHA-256 and match strict local signature packs | Verified | Exact-hash, EICAR simulator, packaged signature, malformed-pack, and release-binary fixtures pass. |
| Native deterministic rule VM | Evaluate bounded local `.zrule` content and return explainable rule evidence | Verified | Rule pack, script-rule, malformed-rule fail-safe, and archive-entry rule fixtures pass. |
| Static file/PE/script/carrier analysis | Classify file content and inspect PE, script, document, shortcut, installer, and web-carrier signals | Verified with production calibration partial | Positive and benign negative fixtures pass; representative real-world false-positive/false-negative rates are not established. |
| Bounded archive/package analyzer | Inspect ZIP/JAR/APK/XPI/VSIX/NUPKG/APPX/MSIX and nested entries without extraction to disk | Verified | Entry, byte, count, total, depth, encryption, truncation, unsupported-method, and traversal limits fail visibly. |
| Native heuristics | Add conservative entropy, script, downloader, persistence, macro, and family signals | Verified with calibration partial | Runtime fixtures and benign false-positive gate pass; heuristics alone do not become confirmed malware or force quarantine. |
| Explainable risk fusion | Combine independent weighted signals into verdict, category, score, and reasons | Verified | Risk-fusion tests pass, including zero-weight diagnostic category isolation and normal-executable negative coverage. |
| Trust, allowlist, exclusions, and cache | Apply exact bounded trust decisions without broad path or prefix trust | Verified in runtime fixtures | Known-good/bad, allowlist persistence/removal, corrupt allowlist fail-closed, and trust-root boundary tests pass; installed ACL E2E is partial. |
| Native ML advisory | Load strictly validated local native model metadata and bounded scores | Development-only | Runtime/schema/fail-safe fixtures pass. It has no production dataset or approved metrics and cannot independently auto-quarantine. |
| Local ONNX compatibility model | Optional offline advisory compatibility path | Development-only | Metadata/model/static-feature fixtures pass. Production training, independent evaluation, and packaged-runtime validation remain incomplete. |
| YARA compatibility provider | Optional bounded compatibility rule parsing/scanning | Disabled by default | Runtime compatibility fixtures pass; it is not required for core scans and is not advertised as production YARA parity. |
| ClamAV compatibility provider | Optional local compatibility integration | Disabled by default | Compatibility fixtures pass; no ambient daemon or machine-wide dependency is installed or assumed. |
| Cloud reputation | Optional remote metadata/reputation concept | Disabled/unavailable | Local scanning remains functional without it. No cloud detection success or privacy claim is made. |
| Suspicious-process observation | Evaluate bounded app-lifetime process snapshots and show review findings | Partial | IPC/controller/release fixtures pass; no persistent service loop, process termination, kernel action, or pre-execution claim. |
| User-mode realtime watcher | Finite app-lifetime polling and post-write scan/quarantine | Partial | Planner, IPC, controller, honesty, cache, and release-binary fixtures pass; no OS notification or pre-write block. |
| Ransomware activity guard | Detect bounded suspicious activity windows under configured roots | Partial | Policy/config/runtime fixtures pass; this is best-effort post-activity user mode, not guaranteed rollback or kernel blocking. |
| Quarantine engine | Opaque payload names, authenticated metadata, integrity verification, conflict-safe restore, and confirmed delete | Verified in isolated and release-binary fixtures | Tamper, restore, delete, path, and lifecycle fixtures pass. Installed location ACL/DPAPI/service E2E is still partial. |
| Signed definition/update engine | Verify signed packages, reject tampering, activate components atomically, and roll back | Verified in isolated release-binary fixtures | Ed25519 verify, tamper, failure, activation, revocation, and rollback fixtures pass. Production key custody and installed updater E2E remain partial. |
| Windows minifilter | Candidate filesystem pre-execution enforcement | Blocked/guarded | No normal installer activation. Requires production signing, WDK/VS, explicit approval, and a disposable elevated Windows VM. |
| Windows process guard | Candidate process-start enforcement | Blocked/guarded | Same signing/elevated-host prerequisites; no current pre-execution claim. |

## UI Inventory Result

`docs/client-ui.md` contains 11 routes, 65 documented control/setting rows,
9 desktop destinations, and 4 primary mobile shortcuts. The dependency-free UI
gate checks 61 high-risk controls directly against Flutter source markers.

| Surface | Current status | Remaining E2E gap |
| --- | --- | --- |
| Home | Widget/controller verified | Packaged click-through and installed status sources partial. |
| Scan and result actions | Quick/full/custom, progress, cancel, quarantine, ignore, feedback, and allowlist paths verified | Installed OS picker and installed service IPC partial. |
| Protection | Start/stop, self-test, status honesty, watcher/process/ransomware state verified | Persistent service and signed-driver behavior blocked/partial. |
| Quarantine | Refresh, manual quarantine, rescan, restore, and delete verified | Installed ACL/location and OS picker E2E partial. |
| Allowlist | Refresh, add, remove, and busy-state behavior verified | Installed service mutation E2E partial. |
| Security Events | Structured history, export, support bundle, and credential redaction verified | Installed filesystem dialog and Windows notification rendering partial. |
| Updates | Check, download/verify/install confirmation, busy states, and rollback UI verified | Real installed updater/service/network activation partial. |
| Settings and Device | Config validation, scheduling, ransomware settings, health, engine details, and failure visibility verified | Installed host/elevation dialogs partial. |
| Protected Apps | Picker adapters, scope mutation, hash, process evidence, and busy states verified | Optional legacy feature; installed picker/process loop E2E partial. |
| Onboarding and Privacy | Route, persistence, and limitation copy verified | Packaged navigation/layout E2E partial. |

No control may report success from a bare `ok=true`: high-risk mutation paths
require action-specific typed evidence. Unsupported or unproven controls remain
disabled, guarded, partial, or visibly limited with a reason.

## Checkpoint 2180 Findings And Repairs

The full verifier exposed an evidence-integrity bug: Python requirement counts
were zero on CRLF input because duplicated multiline regex helpers did not
normalize line endings. The generator still exited successfully, while the
final report validator caught the invalid count. The repair:

- centralizes regex counting in `Get-AvoraxGateRegexMatchCount`;
- normalizes CRLF and lone CR to LF;
- applies a finite two-second regex timeout;
- makes missing or zero package/integrity summaries release blockers;
- uses the same helper in generation and validation;
- runs the dependency evidence gate in CI; and
- explicitly documents that a full SBOM from exact final artifacts remains a
  production release requirement.

This is evidence hardening, not a new detection capability. It prevents a false
dependency-completeness success.

The unfiltered Rust workspace suite then exposed a separate environmental
failure in the Windows Authenticode probe. WindowsPowerShell 5.1 could discover
an incompatible `Microsoft.PowerShell.Security` module through the parent
process `PSModulePath`, causing both signed and unsigned runtime probes to fail.
The repair derives the exact built-in module manifest from the already checked
`System32\WindowsPowerShell\v1.0\powershell.exe` location, rejects linked or
reparse-point module paths, gives the child process a checked module root,
imports the exact manifest with terminating errors, and invokes the Security
and Utility commands by module-qualified name. Focused probes also pass when
the parent process has an intentionally invalid `PSModulePath`.

This removes ambient module discovery from publisher-trust evidence. It does
not prove the signature identity of future packaged Avorax artifacts or replace
the installed/signing E2E gate.

## Verification Evidence

Passed on this Windows host:

```powershell
C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe tools\testing\run-python-source-contracts.py
# python source-contract run passed: 617 tests

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\security\avorax-dependency-evidence.ps1 -RepoRoot . -ReportPath .verification\2180-dependency-evidence.json
# Dependency evidence check passed.

C:\Users\Brent\.cargo\bin\cargo.exe test --workspace --all-targets -- --test-threads=1
# 1,408 tests passed; 0 failed.

C:\Users\Brent\develop\flutter\bin\flutter.bat test
# 838 tests passed; 0 failed.

C:\Users\Brent\.cargo\bin\cargo.exe build --workspace --release
# Finished release build successfully in 2m 32s.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -RepoRoot . -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat
# 217/217 steps passed in 961.5s; full report validator passed.
```

Canonical report:
`.workflow/ultracode/avorax-hardening/results/small-threat-mvp-verification-report.json`
(`2026-08-19T14:53:47.1862495Z` through
`2026-08-19T15:09:48.6822576Z`). Standard EICAR/Defender integration was
intentionally not run; harmless simulators and exact-hash fixtures were used.

An intermediate direct report-validator call correctly failed after the full
workspace release build replaced `target/release/zentor_local_core.exe`: the
previous lifecycle report hash no longer matched the current executable. This
failure was not ignored. The final one-command verifier rebuilt Local Core,
regenerated its lifecycle evidence, and passed the full report validator. No
subsequent build replaced the final verified artifact.

## Remaining High-Value Work

1. Build and test the signed Windows app, MSI/EXE, Core/Guard services, ACLs,
   quarantine location, repair, update, rollback, and UI flows in a disposable
   elevated Windows VM.
2. Obtain and operate Microsoft code/driver signing, then prove driver install,
   unload/rollback, authenticated IPC, latency, and pre-execution behavior.
3. Establish production update-signing key custody, rotation, revocation, HTTPS
   endpoint operations, and installed failure-recovery drills.
4. Run representative benign-corpus and independently governed malicious-corpus
   evaluation outside this repository. Do not import live malware into the
   source tree or developer workstation.
5. Produce a full final-artifact SBOM and license/copyright review on each
   release host; complete Windows signing, macOS signing/notarization, and Linux
   package-install smoke evidence.
6. Replace or keep disabled the development ML paths until datasets, metrics,
   drift monitoring, and release approval are reproducible.

Until those items are complete, Avorax should coexist with Microsoft Defender.
It must not disable Defender, add Defender exclusions, or claim complete
pre-execution protection.
