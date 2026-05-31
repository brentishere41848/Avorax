# Threat Intel Import

Avorax threat-intel importers convert safe metadata indicators into native Avorax packs.

Supported inputs:

- SHA-256 hash lists.
- Manual IOC JSON.
- Metadata-only report exports.
- String, script, byte-pattern, import-combo, and behavior indicators when curated manually.

Example:

```powershell
python tools\zentor_intel\import_hash_feed.py --source assets\zentor_native\threat_intel\sources.example.json --input hashes.txt --output indicators.jsonl --category trojan
python tools\zentor_intel\compile_zentor_signatures.py --input indicators.jsonl --output assets\zentor_native\signatures\zentor_realworld_hashes.zsig
```

The importers do not download malware samples, run files, detonate payloads, or upload user files.
