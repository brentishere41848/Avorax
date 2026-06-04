# Avorax Product Hardening Backlog

This backlog is the working plan for the long-horizon Avorax hardening sprint. It is intentionally product-focused and test-oriented. Claims must remain limited to behavior backed by code, self-tests, or explicit documentation.

## P0 - Buildability, correctness, and safety

- [x] Inspect repository structure, active runtimes, build systems, docs, scripts, UI, Rust engine/service crates, and tests.
- [x] Establish authoritative sprint documents: `TODO.md`, `RUN_LOG.md`, `ARCHITECTURE.md`, and `SECURITY_MODEL.md`.
- [x] Keep the repo buildable and testable after every change.
- [x] Fix stale scan error state after a successful scan.
- [x] Harden local event loading so corrupt event logs cannot crash startup/log screens.
- [x] Add tests for corrupt local logs and scan error clearing.
- [x] Preserve cancellation support in UI/local scan orchestration and document remaining pause/resume limits.
- [x] Add basic scan report invariants for quick/full/custom scans.
- [x] Add quarantine lifecycle tests for metadata, restore confirmation, duplicate restore names, delete, and corrupted metadata.
- [x] Remove or hide UI controls that imply unsupported behavior, especially disabled pause/resume controls until they are implemented.
- [x] Ensure UI product states never claim kernel/pre-execution protection unless the signed driver path is installed, running, and self-tested.

## P1 - Core product quality

- [x] Improve Quick Scan target planning with testable platform abstraction for Windows/macOS/Linux high-risk locations.
- [x] Improve Full Scan traversal exclusions for quarantine/cache/generated folders and symlink/junction loops.
- [x] Add structured scan reports with elapsed time, current file, scanned count, detections, skipped files, and errors.
- [x] Stream native engine file hashing while limiting detection sample reads to 64 MiB and reporting full hash/size/sample-limit metadata.
- [x] Verify quarantine copy-fallback payload hash before deleting the original file and persist file size metadata.
- [x] Add progress/cancellation tests for target selection and local core scan orchestration.
- [x] Improve local core IPC diagnostics: preserve timeout, stderr, malformed JSON, and executable-missing context.
- [x] Improve settings persistence and validation, including safe developer override disable flow.
- [x] Add confirmation dialog for reset configuration and destructive quarantine actions.
- [x] Improve logs/history UI with export result feedback and mojibake cleanup.
- [x] Add `TESTING.md` and `CHANGELOG.md` for verification and release-history tracking.
- [x] Update README/engineering docs for current `.aup`, protection, and repo-relative verification expectations. Remaining release-tag choice is tracked outside P0/P1 hardening.

## P2 - Protection modules

- [x] Wire best-effort user-mode real-time folder monitoring into local core `start_watch` / `stop_watch` instead of returning a stopped state.
- [x] Add debounce, stable-file retry, unchanged-file cache, and event-evaluation tests for real-time monitoring.
- [x] Wire Flutter protection startup/shutdown to call `start_watch` / `stop_watch` for selected protected folders and show `userModeBestEffort` honestly in the Protection UI.
- [x] Harden guard-service IPC trust boundary so caller-provided publisher/signature/hash fields cannot bypass policy unless verified by a trusted driver/service path.
- [x] Harden file/app/executable allowlist entries so approvals are hash-bound and replaced payloads at the same path are not silently trusted.
- [x] Harden quarantine restore so payload size and SHA-256 are verified before moving a quarantined file back to its original path.
- [x] Add ransomware protected-folder settings, allowlist validation, and harmless simulation tests in core policy.
- [x] Add recent ransomware/protection events to UI and logs, wired to protected-root/trusted-process policy metadata.

## P3 - Production hardening

- [x] Cache native engine instance in guard pre-execution path instead of initializing per request.
- [x] Replace native engine scan-file full-memory reads with streaming hashing and bounded scan samples; guard pre-execution hashing now streams too.
- [x] Bound optional compatibility YARA fallback reads in the guard pre-execution path to avoid whole-file memory spikes.
- [x] Make update apply more atomic with rollback on mid-copy failures and service recovery attempts.
- [x] Add production update-key policy that rejects development keys unless explicitly enabled.
- [x] Expand CI to run product-copy, no-malware-binaries, false-positive, protection, and performance gates where feasible.
- [x] Add `packages/avorax_protocol` test dependencies and real update-manifest schema tests.

## P4 - Stretch goals

- [ ] Rule-provider plugin interface for future YARA/native/cloud-reputation sources without coupling UI to providers.
- [ ] Disabled-by-default cloud reputation provider interface with honest unavailable states when no backend is configured.
- [x] Add explicit desktop/mobile navigation semantics and make the desktop sidebar scroll safely on constrained heights.
- [ ] Broader accessibility pass for keyboard traversal audits, contrast review, screen-reader coverage across all feature pages, and localization-ready text extraction.
- [x] Export local event logs with structured category/severity metadata and without file contents; broader support bundles remain optional.
- [x] Add safe benchmark harness for synthetic scan traversal/hashing, native signature test timing, guard decision timing, and non-elevated update-copy simulation.
- [ ] Add elevated/provisioned benchmarks for real update apply latency and signed-driver pre-execution latency.

## Current P0/P1 status

- No known remaining P0/P1 hardening gaps are currently tracked after the latest verification pass. Remaining open work is elevated/provisioned benchmarks, broader accessibility/localization readiness, support bundles, and optional provider/plugin architecture.

## Operating rules

- Use harmless synthetic fixtures only; never add real malware binaries.
- Do not execute downloaded code unless it is verified by the update package verifier.
- Do not destroy quarantined user files without explicit user confirmation.
- Keep marketing/product copy aligned with implemented capabilities.
- Update this file and `RUN_LOG.md` before stopping any hardening session.
