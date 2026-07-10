# Avorax Native Signature Format

Native signature packs use the `.zsig` extension. The current v1 pack is JSON for auditability and validation; the compiler path can emit a compact binary pack later without changing runtime policy.

Default pack:

- `assets/zentor_native/signatures/zentor_core.zsig`
- `assets/zentor_native/signatures/zentor_core.metadata.json`

Compiler:

```powershell
cargo run --manifest-path core\zentor_native_engine\Cargo.toml --bin zentor-signature-compiler -- `
  --input assets\zentor_native\signatures\zentor_core.zsig `
  --output assets\zentor_native\signatures\zentor_core.zsig `
  --metadata assets\zentor_native\signatures\zentor_core.metadata.json `
  --version 0.1.1
```

The compiler validates human-readable signature JSON, sorts signatures deterministically, writes a compiled `.zsig` pack, and emits metadata with a canonical pack hash. Since checkpoint 858, compiler source JSON is inspected as a regular non-link/non-reparse file and capped at 2 MiB before parsing. Pack and metadata outputs are staged through exclusive UUID temporary files, synced, preflighted against unsafe existing targets, and activated by rename. Runtime loading verifies the pack format and the hash when present.

Signature types include:

- `exact_hash`
- `partial_hash`
- `byte_pattern`
- `masked_byte_pattern`
- `ascii_string`
- `utf16_string`
- `pe_import_combo`
- `pe_section_entropy`
- `pe_resource_indicator`
- `script_pattern`
- `powershell_encoded_command`
- `archive_nested_executable`
- `eicar_test_signature`

Every signature requires metadata, confidence, false-positive notes, file type filters, and an action policy. Broad signatures must be review-only unless additional context produces a stronger fused verdict. Confirmed signatures must use an explicit blocking or quarantine policy.

Threat-intel signature compilation enforces those fields before output: imported indicator rows must provide bounded text IDs, source names, indicator types, patterns, categories, confidence, action policies, and false-positive notes, and the pack build must provide a non-empty `--version`. Missing confidence/action/version metadata fails visibly instead of defaulting into an active signature pack.

Known-bad threat-intel pack generation additionally requires SHA-256 hash syntax, `confidence: confirmed`, `action_policy: quarantine_if_policy_allows`, and a non-empty pack `--version` before an indicator can become an active exact-hash known-bad signature in a generated pack.

Indicator-pack validation rejects unknown pack or signature fields, non-object signature entries, missing `signatures` lists, and malformed `pack_sha256` values before reporting a `.zsig` pack as valid. Empty compatibility packs may remain hashless because they activate no signatures.

ANE detects the EICAR safe anti-malware test string internally, without ClamAV or YARA.
