# Avorax Threat Intel Tools

These tools import safe indicators into Avorax Native Engine packs. They do not download malware, execute samples, detonate files, or upload user files.

External malware repositories must be handled in metadata-only or hash-only mode by default. Do not clone malware repositories into this repo and do not download samples unless an isolated lab workflow is explicitly enabled outside the repo.

Hash-only imports require an explicit `--category` and only accept supported Avorax threat categories. Manual IOC import, signature compilation, known-bad pack building, rule compilation, and pack validation use the same allowlist. CamelCase, snake_case, kebab-case, and compact aliases are normalized before JSONL or pack output; unsupported text fails instead of being written into or accepted from a pack. Pack validation of already-built `.zsig` and `.zrule` files is stricter: the file must contain canonical output spelling, not an alias. Supported canonical output values are `trojan`, `ransomware`, `spyware`, `infostealer`, `adware`, `worm`, `keylogger`, `miner`, `rootkitIndicator`, `potentiallyUnwantedApp`, `suspiciousDownloader`, `suspiciousScript`, `maliciousMacro`, `exploitDropper`, `credentialTheftIndicator`, `persistenceIndicator`, `securityTamperIndicator`, `testThreat`, and `unknown`.

Action-policy input also normalizes common aliases before JSONL or pack output. For example, `review` becomes `review_only` and `observation_only` becomes `observe`. Pack validation requires canonical action-policy, confidence, signature type, severity, rule verdict/action, file-type, condition-type, and PE import-category values.

Example:

```powershell
python tools\zentor_intel\import_hash_feed.py --source assets\zentor_native\threat_intel\sources.example.json --input hashes.txt --output indicators.jsonl --category trojan
python tools\zentor_intel\compile_zentor_signatures.py --input indicators.jsonl --output assets\zentor_native\signatures\zentor_realworld_hashes.zsig --version 0.2.1
python tools\zentor_intel\validate_indicator_pack.py --input assets\zentor_native\signatures\zentor_realworld_hashes.zsig
```

The wrapper version of that local hash-only workflow requires explicit release metadata and cleans its temporary JSONL after success or failure:

```powershell
python tools\zentor_intel\build_realworld_detection_pack.py --source assets\zentor_native\threat_intel\sources.example.json --hashes hashes.txt --output assets\zentor_native\signatures\zentor_realworld_hashes.zsig --category trojan --version 0.2.1
```

GitHub malware-repository metadata import:

```powershell
python tools\zentor_intel\import_github_malware_metadata.py --config assets\zentor_native\threat_intel\sources.example.json --include-disabled --output assets\zentor_native\threat_intel\imported_github_metadata.jsonl
```

The example registry includes the external sample repositories reviewed for
metadata-only compatibility. Every entry remains disabled and cannot create an
active signature, confirmed verdict, or quarantine action. Do not reinterpret a
Git blob SHA, filename, extension, or repository path as a file SHA-256.

Developer-provided hash-only import:

```powershell
python tools\zentor_intel\import_github_hashes_only.py --input hashes.txt --output imported_hashes.jsonl --source-name "curated GitHub malware hash list" --category trojan
python tools\zentor_intel\build_known_bad_from_github.py --input imported_hashes.jsonl --output assets\zentor_native\signatures\zentor_github_known_bad.zsig --version 0.2.5
```

Use only metadata indicators such as hashes, strings, import combinations, and behavior patterns. Real malware binaries do not belong in this repository.
