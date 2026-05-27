# YARA Rules

Pasus packages conservative local rules in `assets/yara/pasus_core_rules.yar`.

Rule policy:

- Rules must include category, confidence, description, source, and false-positive notes.
- Confirmed rules can contribute to automatic quarantine when scan mode allows it.
- Review/medium rules must not auto-quarantine by themselves.
- Normal executables are not threats because of extension or location alone.

The current rule pack includes:

- EICAR test signature: confirmed test detection.
- Obfuscated PowerShell review rule.
- Ransom-note text review rule.
