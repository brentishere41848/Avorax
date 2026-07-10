# Threat Intel Import

Avorax threat-intel importers convert safe metadata indicators into native Avorax packs.

Supported inputs:

- SHA-256 hash lists.
- Manual IOC JSON.
- Metadata-only report exports.
- String, script, byte-pattern, import-combo, and behavior indicators when curated manually.

Manual IOC JSON imports require a non-empty bounded `source_name`, an `indicators` list, and non-empty bounded text `indicator_type` plus `value` for every row. Threat category, confidence, false-positive notes, and action policy must be present on the indicator or explicitly inherited from report-level fields; malformed or unsupported active metadata fails before pack generation.

SHA-256 hash-feed imports require bounded text source metadata and an explicit `--category` before confirmed indicators are emitted. The importer still accepts only valid SHA-256 values for confirmed hash signatures.

Developer hash-only JSON imports require string hash entries and an explicit `--category`. JSON numbers, objects, or booleans are not converted to text before validation, and omitted category metadata fails before confirmed SHA-256 rows are emitted.

Compiled signature packs require explicit indicator metadata and an explicit non-empty `--version`. Missing category, confidence, action policy, false-positive notes, source, ID, type, pattern, or pack version fields fail before `.zsig` output.

Known-bad packs are stricter: only explicit confirmed SHA-256 indicators with `quarantine_if_policy_allows` become active known-bad signatures, and the pack build must provide a non-empty `--version`. SHA-1, MD5, repository metadata, and lower-confidence rows are not promoted to active known-bad signatures.

Example:

```powershell
python tools\zentor_intel\import_hash_feed.py --source assets\zentor_native\threat_intel\sources.example.json --input hashes.txt --output indicators.jsonl --category trojan
python tools\zentor_intel\compile_zentor_signatures.py --input indicators.jsonl --output assets\zentor_native\signatures\zentor_realworld_hashes.zsig --version 0.2.1
```

The hash-feed wrapper performs import, compilation, and validation as one local metadata-only workflow. It requires explicit `--category` and `--version`, invokes checked local helper scripts with streaming bounded stdout/stderr tails and a fixed timeout, and removes its temporary JSONL on success or failure:

```powershell
python tools\zentor_intel\build_realworld_detection_pack.py --source assets\zentor_native\threat_intel\sources.example.json --hashes hashes.txt --output assets\zentor_native\signatures\zentor_realworld_hashes.zsig --category trojan --version 0.2.1
```

The importers do not download malware samples, run files, detonate payloads, or upload user files.
