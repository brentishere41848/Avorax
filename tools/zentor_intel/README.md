# Avorax Threat Intel Tools

These tools import safe indicators into Avorax Native Engine packs. They do not download malware, execute samples, detonate files, or upload user files.

External malware repositories must be handled in metadata-only or hash-only mode by default. Do not clone malware repositories into this repo and do not download samples unless an isolated lab workflow is explicitly enabled outside the repo.

Example:

```powershell
python tools\zentor_intel\import_hash_feed.py --source assets\zentor_native\threat_intel\sources.example.json --input hashes.txt --output indicators.jsonl --category trojan
python tools\zentor_intel\compile_zentor_signatures.py --input indicators.jsonl --output assets\zentor_native\signatures\zentor_realworld_hashes.zsig --version 0.2.1
python tools\zentor_intel\validate_indicator_pack.py --input assets\zentor_native\signatures\zentor_realworld_hashes.zsig
```

GitHub malware-repository metadata import:

```powershell
python tools\zentor_intel\import_github_malware_metadata.py --config assets\zentor_native\threat_intel\sources.example.json --include-disabled --output assets\zentor_native\threat_intel\imported_github_metadata.jsonl
```

Developer-provided hash-only import:

```powershell
python tools\zentor_intel\import_github_hashes_only.py --input hashes.txt --output imported_hashes.jsonl --source-name "curated GitHub malware hash list" --category trojan
python tools\zentor_intel\build_known_bad_from_github.py --input imported_hashes.jsonl --output assets\zentor_native\signatures\zentor_github_known_bad.zsig --version 0.2.5
```

Use only metadata indicators such as hashes, strings, import combinations, and behavior patterns. Real malware binaries do not belong in this repository.
