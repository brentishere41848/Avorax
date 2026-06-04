# Avorax Security Model

Avorax is a defensive antivirus / anti-malware / endpoint protection product. The security model prioritizes user safety, explicit user control, reversibility, least privilege, auditable decisions, and honest product states.

## Security goals

- Detect known malicious files using local signatures, deterministic rules, heuristics, and trust data.
- Provide useful offline scans without requiring an account, cloud service, or internet access.
- Keep UI responsive and show actionable protection, scan, update, quarantine, and error states.
- Quarantine confirmed threats safely and reversibly.
- Verify update packages before applying them.
- Avoid unsupported claims about kernel, pre-execution, cloud, AI, or ransomware recovery capabilities.

## Non-goals and hard boundaries

- Avorax must not implement malware, credential theft, stealth, evasion, destructive payloads, offensive exploit chains, or hidden persistence.
- Avorax must not disable third-party security tools or Windows protections without explicit user intent and documentation.
- Avorax must not include real malware binaries. Tests must use EICAR, synthetic hashes, harmless fixtures, or temporary-file simulations only.
- Avorax must not claim guaranteed protection, certification, production AI detection, kernel enforcement, or ransomware decryption unless those capabilities are implemented, verified, and documented.
- Avorax must not execute downloaded update code without signature/checksum verification.

## Trust boundaries

### Flutter UI

The UI is not a security boundary. It is a local controller and display surface. Any local process or user can potentially influence UI state. Security decisions must be enforced by the local core, guard service, update service, and OS permissions.

### Local core IPC

The Flutter app communicates with the local core over stdin/stdout JSON commands. This channel is local and not network-exposed, but requests must still treat paths and JSON fields as untrusted input.

Requirements:

- Validate command names and required fields.
- Canonicalize and validate paths before scanning, allowlisting, quarantining, restoring, or deleting.
- Return structured errors instead of panics.
- Avoid logging sensitive file contents.

### Native engine assets

Signatures, rules, trust stores, and ML assets influence verdicts and actions. Engine assets are resolved from installed paths, environment overrides, or repository assets during development.

Requirements:

- Validate pack metadata and hashes where supported.
- Reject unsafe broad signatures/rules in compiler/gates.
- Treat development ML assets as development-only unless metadata says `production_ready=true` and release gates approve.
- Do not let heuristic-only weak evidence trigger destructive action automatically.

### Guard service and driver IPC

Pre-execution and real-time blocking are high-trust paths. The user-mode guard service can provide best-effort monitoring and post-launch action. True pre-execution blocking requires the signed Windows driver path.

Requirements:

- Do not trust caller-provided publisher/signature strings unless they come from a trusted, authenticated driver/service path or are verified by the service.
- Fail open for critical OS/Avorax runtime paths unless a confirmed known-bad result exists and policy explicitly allows blocking.
- Document user-mode fallback limitations.
- Do not claim kernel/pre-execution protection unless the driver is installed, running, communicating, and passing self-test.

### Update packages

`.aup` update packages are untrusted until fully verified.

Requirements:

- Verify product identity, format version, target version/channel, package hash, manifest signature, and per-file payload hashes.
- Reject path traversal, absolute paths, driver updates through normal app update flow, unsigned packages, or packages signed with development keys under production policy.
- Normal update-service CLI verification/apply paths use production policy by default. Development-signed packages must be explicitly enabled with `--allow-development-key` or `AVORAX_ALLOW_DEVELOPMENT_UPDATES=1`.
- Stage updates before applying.
- Roll back on failure where possible. If payload copying fails after a rollback snapshot exists, the update service now attempts to restore that snapshot, restart services, and write a structured failed update report containing rollback status.
- Do not execute downloaded installers or scripts as a normal in-app update path.

## Scan safety model

### Quick Scan

Quick Scan should inspect high-risk locations first and avoid whole-disk traversal:

- Downloads, Desktop, temp directories.
- Browser download folders where discoverable.
- Startup/autostart locations.
- Suspicious running-process paths.
- Recently modified executable/script/installer/archive/macro-capable files.

It should report progress, current file, elapsed time, scanned count, detection count, skipped count, and errors. Permission and locked-file failures should be non-fatal scan errors/skips.

### Full Scan

Full Scan may traverse drives or home filesystem areas but must avoid unsafe traversal:

- Do not follow symlink/junction loops.
- Skip quarantine, app caches, generated build outputs, and explicitly excluded directories unless configured otherwise.
- Bound memory use; stream large files where possible. Current native file scans stream full-file hashing and analyze a bounded 64 MiB sample with explicit sample-limit metadata. Guard pre-execution hashing also uses buffered streaming I/O, and the optional compatibility YARA fallback reads only a bounded 1 MiB sample.
- Handle denied/locked/huge/unusual paths gracefully.
- Support cancellation and progress reporting.
- Real-time monitor duplicate suppression must not rely on size alone; the cache must include file modified time (or stronger content identity) so same-size payload replacements are scanned again.

### Detection and action policy

Verdicts should include evidence, reason codes, confidence, and recommended action. Action policy must remain conservative:

- Clean/unknown/low-signal observations: no automatic action.
- Suspicious/probable findings: user review unless stronger independent evidence and explicit policy allow action.
- Confirmed signature/test-threat findings: may quarantine only when scan mode permits, path is not allowlisted/trusted, and quarantine succeeds safely.
- Strong probable-malware findings with independent evidence must be evaluated before stale local trust records such as known-good hashes, exact user approvals, or trusted-publisher allow decisions; in Lockdown they block pending review, and in less strict modes they are allowed only with monitoring/review.
- ML-only detections from development models must not auto-quarantine.
- User training labels may suppress only exact-hash false-positive/trusted-app review outcomes; suppression resolution must use the newest valid label for that hash so later confirmed-malicious/unsure labels can revoke stale suppression.

Allowlist decisions must not reduce protection through path-only trust for mutable files:

- Explicit hash entries may trust the same SHA-256 at any path.
- File, app, and executable entries must record the current file SHA-256 at creation time and require both the normalized path and hash to match at evaluation time.
- Legacy/path-only file, app, and executable entries must fail closed instead of trusting mutable paths.
- File, app, and executable allowlist creation must fail closed when the target cannot be hashed.
- Folder entries are path-scoped and should remain reserved for explicit user-controlled folder trust decisions.

## Quarantine safety model

- Quarantine should move files rather than delete them.
- Quarantine records must store original path, normalized safe quarantine path, detection/evidence, timestamp, hash, and size where available. The copy fallback verifies the quarantined payload hash before removing the original.
- Restore must require explicit confirmation.
- Restore must reject path traversal and unsafe destinations.
- Restore must verify quarantined payload size and SHA-256 before moving the payload back to the original path, so tampered quarantine files cannot be restored.
- Restore must not overwrite existing files without explicit separate handling.
- Permanent delete must require explicit confirmation.
- Corrupted metadata should produce an actionable error and should not cause data loss.

## Settings and configuration model

Settings are local user preferences, not authoritative security proof. They must be validated before persistence:

- Real-time protection enabled/disabled.
- Ransomware protection enabled/disabled.
- Scan exclusions.
- Protected folders for ransomware monitoring.
- Trusted backup/sync process allowlists for ransomware-policy suppression.
- Allowlist entries.
- Scan sensitivity.
- Automatic update preference.
- Notifications.
- Cloud/developer overrides.

Unsafe broad allowlist/exclusion/protected-root values such as drive roots, system directories, `/`, `/usr`, `/bin`, `/sbin`, and `/etc` should be rejected or require exceptional explicit handling. Current ransomware protected-root IPC rejects broad root-style protected folders before persistence.

## Logging and privacy

Avorax logs structured security/protection events and operational errors without leaking file contents. Local events include type, timestamp, message, optional details, category, and severity; user-initiated export serializes those fields as JSON.

Allowed logging:

- Event type, timestamp, status, path metadata where relevant, hashes, counts, reason codes, scan IDs, update IDs, and actionable errors.

Avoid logging:

- File contents.
- Secrets, tokens, private keys, or update signing secrets.
- Excessive user document data beyond paths necessary for local event history.

Exports should be user-initiated and should clearly identify what data is included.

## Known limitations

- The Windows driver path is developmental unless a signed driver is installed, running, communicating with the guard service, and passing self-test.
- User-mode monitoring cannot prevent all execution or file writes before they happen.
- The bundled native ML model is currently a development model and cannot support production AI claims or automatic quarantine by itself.
- Cloud reputation is optional/disabled unless a real backend is configured; disabled/unavailable provider states must be represented honestly and must not contribute evidence or imply cloud coverage.
- Some Windows service and update tests require elevation.
- Driver validation requires Microsoft signing and a real self-test report.

## Safe development rules

- Use TDD for new behavior where feasible.
- Use harmless synthetic fixtures only.
- Prefer conservative fail-safe behavior over destructive automation.
- Add tests for hostile inputs: corrupted JSON, path traversal, permission errors, symlink loops, malformed update packages, corrupted quarantine metadata, and locked files.
- Update `RUN_LOG.md` and `TODO.md` whenever assumptions, blockers, or major decisions change.

### Guard metadata trust boundary

Guard pre-execution decisions must not trust caller-provided publisher, signature, or hash metadata unless that metadata names a trusted verifier source such as the Avorax kernel driver, Avorax guard service, Windows Code Integrity, or Windows WinTrust. When a file is readable, the guard computes its own SHA-256 with streaming I/O and prefers that over supplied metadata. Supplied hashes are accepted only as a fallback for unreadable race-window files and only with trusted verifier provenance. The guard caches one native engine instance behind a mutex for repeated pre-execution verdicts; this improves latency without changing the fail-open policy for critical OS/Avorax runtime paths.

### Ransomware protected roots

Ransomware evaluation supports explicit protected roots and trusted process allowlists. If protected roots are configured, only activity inside those roots contributes to modification thresholds. Trusted backup/sync processes can be suppressed by exact normalized path for ordinary mass-modification signals, but trusted-process suppression must not hide critical ransom-note or backup-tamper signals because trusted software can be compromised. Flutter settings persist these lists, local core IPC writes the shared policy config, protected roots are included in user-mode watch planning, and local event history records protection/ransomware settings changes with category/severity metadata. Tests use harmless temporary/path-only fixtures and do not encrypt or damage files.
