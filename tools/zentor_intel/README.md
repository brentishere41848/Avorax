# Zentor Threat Intel Tools

These tools import safe indicators into Zentor Native Engine packs. They do not download malware, execute samples, detonate files, or upload user files.

Example:

```powershell
python tools\zentor_intel\import_hash_feed.py --source assets\zentor_native\threat_intel\sources.example.json --input hashes.txt --output indicators.jsonl --category trojan
python tools\zentor_intel\compile_zentor_signatures.py --input indicators.jsonl --output assets\zentor_native\signatures\zentor_realworld_hashes.zsig --version 0.2.1
python tools\zentor_intel\validate_indicator_pack.py --input assets\zentor_native\signatures\zentor_realworld_hashes.zsig
```

Use only metadata indicators such as hashes, strings, import combinations, and behavior patterns. Real malware binaries do not belong in this repository.
