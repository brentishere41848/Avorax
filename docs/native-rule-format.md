# Avorax Native Rule Format

Native rules use the `.zrule` extension and replace YARA as Avorax-owned deterministic rules.

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

Rule-pack compilation validates source `.zrule` packs before merge: unsupported formats, missing `rules`, unknown rule or condition fields, empty conditions, and impossible `min_condition_matches` fail before output.

Indicator-pack validation applies the same strict checks to bundled or generated `.zrule` packs before release/tooling success: pack, rule, and condition schemas are exact; rule entries must be objects; `rules` must be an explicit list; non-empty packs need a valid self-hash; and empty or impossible condition counts fail visibly.

Generated rule packs require an explicit non-empty `--version`. Missing or empty version metadata fails before output, and canonical self-hashing uses the actual compiled rule list.
