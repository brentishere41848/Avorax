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
- [ ] Update README and installer docs for v0.2.14, `.aup` updates, and repo-relative commands.

## P2 - Protection modules

- [x] Wire best-effort user-mode real-time folder monitoring into local core `start_watch` / `stop_watch` instead of returning a stopped state.
- [x] Add debounce, stable-file retry, unchanged-file cache, and event-evaluation tests for real-time monitoring.
- [x] Wire Flutter protection startup/shutdown to call `start_watch` / `stop_watch` for selected protected folders and show `userModeBestEffort` honestly in the Protection UI.
- [ ] Harden guard-service IPC trust boundary so caller-provided publisher/signature fields cannot bypass policy unless verified by a trusted driver/service path.
- [ ] Add ransomware protected-folder settings, allowlist validation, and harmless simulation tests.
- [ ] Add recent ransomware/protection events to UI and logs.

## P3 - Production hardening

- [ ] Cache native engine instance in guard pre-execution path instead of initializing per request.
- [x] Replace native engine scan-file full-memory reads with streaming hashing and bounded scan samples; pre-execution guard streaming remains a follow-up.
- [ ] Make update apply more atomic with rollback on mid-copy failures and service recovery attempts.
- [ ] Add production update-key policy that rejects development keys unless explicitly enabled.
- [ ] Expand CI to run product-copy, no-malware-binaries, false-positive, protection, and performance gates where feasible.
- [ ] Add `packages/avorax_protocol` test dependencies or remove stale `dart test` expectations for that package.

## P4 - Stretch goals

- [ ] Rule-provider plugin interface for future YARA/native/cloud-reputation sources without coupling UI to providers.
- [ ] Disabled-by-default cloud reputation provider interface with honest unavailable states when no backend is configured.
- [ ] Accessibility pass for keyboard navigation, contrast, semantics labels, and localization-ready text.
- [ ] Exportable report bundles for support/debugging that exclude file contents and sensitive user data.
- [ ] Benchmarks for scan traversal, hashing, native signature matching, guard pre-execution latency, and update apply latency.

## Operating rules

- Use harmless synthetic fixtures only; never add real malware binaries.
- Do not execute downloaded code unless it is verified by the update package verifier.
- Do not destroy quarantined user files without explicit user confirmation.
- Keep marketing/product copy aligned with implemented capabilities.
- Update this file and `RUN_LOG.md` before stopping any hardening session.
