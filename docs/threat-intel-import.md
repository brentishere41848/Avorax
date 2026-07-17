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

The hash-feed wrapper performs import, compilation, and validation as one local metadata-only workflow. It requires explicit `--category` and `--version`, invokes checked local helper scripts with streaming bounded stdout/stderr tails and a fixed timeout, and removes its temporary JSONL and temporary signature pack on success or failure. It validates the strict `known-bad-sha256` profile before atomically replacing the output, so an empty or malformed feed cannot replace a previous pack.

```powershell
python tools\zentor_intel\build_realworld_detection_pack.py --source assets\zentor_native\threat_intel\sources.example.json --hashes hashes.txt --output assets\zentor_native\signatures\zentor_realworld_hashes.zsig --category trojan --version 0.2.1
```

The strict profile requires at least one unique lowercase 64-character SHA-256, `exact_hash`, `confirmed` confidence, `critical` severity, a production threat category, the exact `quarantine_if_policy_allows` policy, global file matching, empty required context, and no partial-hash fields. It rejects repository metadata, Git blob identifiers, test/unknown categories, duplicate IDs/hashes, and lower-confidence indicators.

Hash-feed source JSON is also fail-closed. A direct source object may contain only `source_name`, `source_url`, `source_type`, and `malware_family`. A registry object may contain only `sources` and `manual_hash_source_template`, and the selected template has the same exact source schema. Unknown or mixed fields, non-list `sources`, non-object templates, non-HTTPS URLs, embedded credentials, fragments, backslashes, duplicate hashes, and more than 100,000 active rows are rejected before output. This validates provenance shape, not the truth of a third-party classification.

To turn a reviewed local SHA-256 feed into a definitions-only signed update, use the production signing environment and the dedicated wrapper:

```powershell
$env:AVORAX_UPDATE_SIGNER = '"C:\secure\avorax_sign_manifest.exe"'
$env:AVORAX_UPDATE_PUBLIC_KEY_ID = "avorax-prod-ed25519"
powershell -NoProfile -ExecutionPolicy Bypass -File tools\update\avorax-build-hash-intel-update.ps1 `
  -Version 0.3.1 `
  -Channel stable `
  -Category trojan `
  -SourceMetadata reviewed-source.json `
  -HashFeed reviewed-sha256.txt `
  -PythonPath C:\path\to\python.exe `
  -OutputDir dist\updates
```

The resulting `.aup` contains only the reviewed signature pack under `payload/engine/signatures`. The normal update verifier still enforces the Ed25519 manifest signature, package and payload SHA-256 values, version/channel policy, bounded archive shape, atomic staging, rollback, and failure-safe behavior. The wrapper does not fetch feeds or samples; feed acquisition and maintainer review remain separate trusted release-host responsibilities.

The importers do not download malware samples, run files, detonate payloads, or upload user files.
