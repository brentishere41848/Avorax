# Pasus Native Engine

Pasus Native Engine (PNE) is the primary offline anti-malware engine. It does not require ClamAV, YARA, cloud access, an account, or internet connectivity to scan files.

PNE v1 includes:

- Pasus native signatures (`.psig`)
- Pasus native rules (`.prule`)
- Static analyzers for file type, strings, entropy, PE metadata, scripts, and ZIP archives
- Conservative heuristic scoring
- Pure Rust native ML model runtime (`.pmodel`)
- Trust stores for known-good, known-bad test hashes, allowlist, and false-positive controls
- Risk fusion and action policy
- Quarantine integration

Compatibility engines such as ClamAV and YARA are optional compatibility paths only. They are disabled by default and are not required for Quick Scan, Full Scan, Custom Scan, EICAR detection, quarantine, or Guard verdicts.

PNE never executes suspicious files, detonates samples, uploads files, or disables other security software.
