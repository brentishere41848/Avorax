# Avorax Anti-Virus Long-Running Plan

Avorax is a privacy-first anti-virus and anti-malware desktop product. Active work must focus on the Flutter desktop app, Avorax Native Engine, Avorax Core Service, Avorax Guard Service, scanning, quarantine, recovery, real-time protection, driver validation, installer quality, and honest release gates.

## Phases

- **Phase 0: Repository audit and cleanup** - inventory active apps, core crates, services, drivers, installer scripts, CI, archived material, legacy naming, optional compatibility engines, fake claims, missing tests, and failing tests. Output audit docs under `docs/audit/`.
- **Phase 1: Branding and unrelated-product removal verification** - enforce active Avorax Anti-Virus naming, archive inactive website material, and keep product-copy gates passing.
- **Phase 2: Avorax Native Engine v1 hardening** - keep ANE as the primary offline engine with native signatures, rules, self-test, scan API, and compatibility engines disabled by default.
- **Phase 3: Real-world indicator detection** - import safe indicators and malware-report IOCs without storing or downloading malware binaries.
- **Phase 4: Static analyzers** - harden safe parsers for file types, PE/ELF/Mach-O metadata, scripts, documents, archives, entropy, and strings without executing content.
- **Phase 5: Heuristics and false-positive control** - maintain conservative scoring where weak signals alone cannot create malware verdicts or auto-quarantine.
- **Phase 6: Native ML model runtime** - keep deterministic `.zmodel` inference explainable and development-only unless production metadata and gates pass.
- **Phase 7: Risk fusion and verdict policy** - combine signatures, rules, heuristics, ML, behavior, trust, allowlists, and false-positive labels into auditable verdicts.
- **Phase 8: Fast Quick Scan** - prioritize high-risk locations, startup/autostart, running process paths, recent risky files, cache hits, cancellation, and ETA without scanning the whole PC.
- **Phase 9: Full Scan reliability** - scan accessible local files safely with permission handling, loop avoidance, cancellation, progress, archive limits, and detect-only defaults.
- **Phase 10: Core Service hardening** - own engine state, scan jobs, caches, quarantine, allowlist, event store, and local IPC without public network listeners.
- **Phase 11: Guard Service hardening** - integrate real-time protection with ANE verdicts and honest fallback when drivers are missing.
- **Phase 12: Driver validation workflow** - provide WDK/EWDK setup, build, signing, install, uninstall, self-test, and log scripts that fail clearly when prerequisites are missing.
- **Phase 13: Ransomware Guard and Recovery Vault** - detect safe simulator behavior in temp folders, record incidents, and restore only from local vault/snapshot data that exists.
- **Phase 14: Quarantine and allowlist hardening** - use reversible `.zentorq` quarantine, metadata, explicit confirmations, blocked root allowlists, migration readability, and audit logs.
- **Phase 15: UI polish for anti-virus product** - keep the Flutter UI anti-virus focused, flat-background, honest about unavailable drivers and development ML, and free of unrelated product-domain copy.
- **Phase 16: Installer and release pipeline** - package Avorax Anti-Virus artifacts with services, native assets, docs, self-test assets, and no legacy/unrelated product language.
- **Phase 17: Performance and quality gates** - measure engine/load/scan latency, false-positive fixtures, UI responsiveness, and release thresholds.
- **Phase 18: Documentation** - document architecture, native formats, scans, real-time protection, drivers, quarantine, recovery, false positives, safe testing, and limitations.
- **Phase 19: Final verification** - run mandatory gates, create `docs/reports/final-verification-<version>.md`, and tag a release candidate only if mandatory gates pass.

## Current Priority

Phase 0 and Phase 1 are the current active phases. Complete the audit documents, keep active branding/product gates stable, and use the newly added Rust workspace entry point for baseline tests before continuing deeper implementation work.
