# Zentor Anti-Virus Plan

Zentor is a privacy-first anti-virus and anti-malware client. The active product is not a website, unrelated enforcement system, game integration, or hidden surveillance tool.

## Phases

0. Repository audit: inventory active code, archived legacy material, build files, safety boundaries, and current blockers.
1. Project scaffold and rebrand: keep Zentor naming in active files, archive legacy website code, and maintain control files.
2. Zentor Native Engine foundation: deterministic offline scanning API, status reporting, and self-test.
3. Native signature format: `.zsig` validation, indexing, integrity checks, and EICAR test signature.
4. Native rule engine: bounded deterministic `.zrule` evaluation with false-positive controls.
5. Static analyzers: safe file, script, archive, PE, Mach-O, ELF, and metadata analyzers without executing samples.
6. Heuristic scoring and false-positive control: auditable evidence and review-only handling for weak signals.
7. Native ML runtime: development `.zmodel` inference that cannot auto-quarantine by itself.
8. Risk fusion: combine signatures, rules, heuristics, trust, and ML into honest verdicts.
9. Quick Scan: offline high-risk-location scan with cache, progress, cancel, and ETA.
10. Full Scan: accessible local file scan with permission handling and loop avoidance.
11. Core Service: local IPC, scan job ownership, quarantine store, allowlist, and event store.
12. Guard Service: process/file activity monitoring with driver-aware and fallback modes.
13. Windows driver validation: WDK scripts, honest self-test, and no pre-execution claims without passing driver checks.
14. Quarantine and allowlist: reversible quarantine, metadata, blocked root allowlist paths, and audit logs.
15. Ransomware Guard and Recovery Vault: temp-folder simulator, bounded recovery, and honest no-backup cases.
16. Flutter UI: desktop client with real local state, empty/loading/error states, and no fake metrics.
17. Installer and release pipeline: Windows packaging, service install/uninstall, and release gates.
18. Performance and false-positive gates: deterministic fixtures and measurable local targets.
19. Documentation: architecture, safety testing, limitations, driver setup, and integration details.
20. Final verification: run gates, record limitations, tag only when release criteria are satisfied.

## Current Priority

Keep the active repository honest and buildable, remove legacy active terminology, and run the local gates before publishing.
