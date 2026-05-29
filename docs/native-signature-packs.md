# Native Signature Packs

Zentor Native Engine uses `.zsig` packs.

Active packs:

- `zentor_core.zsig`: EICAR and safe internal validation signatures.
- `zentor_realworld_hashes.zsig`: metadata-only known-bad hash fixtures and imported hashes.
- `zentor_script_threats.zsig`: downloader and encoded script indicators.
- `zentor_ransomware_indicators.zsig`: ransom-note and backup deletion indicators.
- `zentor_infostealer_indicators.zsig`: credential-store and wallet access indicators.
- `zentor_miner_pup_indicators.zsig`: miner and potentially unwanted app indicators.

Broad string indicators are low or medium confidence and do not auto-quarantine by themselves. Exact trusted SHA-256 indicators can produce confirmed malware verdicts when the source metadata is valid.
