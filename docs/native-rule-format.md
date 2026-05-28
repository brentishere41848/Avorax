# Pasus Native Rule Format

Native rules use the `.prule` extension and replace YARA as Pasus-owned deterministic rules.

Rules support:

- metadata
- file type conditions
- ASCII and UTF-16 string conditions
- entropy thresholds
- PE import thresholds
- script indicators
- archive indicators
- bounded boolean-style condition counts

The rule VM is deterministic and does not execute arbitrary code. Medium-confidence rules are review-only. Rules can contribute to risk fusion, but broad rules cannot auto-quarantine by themselves.
