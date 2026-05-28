# Pasus Native Signature Format

Native signature packs use the `.psig` extension. The current v1 pack is JSON for auditability and validation; the compiler path can emit a compact binary pack later without changing runtime policy.

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

Every signature requires metadata, confidence, false-positive notes, and an action policy. Broad signatures must be review-only unless additional context produces a stronger fused verdict.

PNE detects the EICAR safe anti-malware test string internally, without ClamAV or YARA.
