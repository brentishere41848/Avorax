/*
  Avorax core YARA rules.

  These rules are intentionally conservative. Only the EICAR test signature is
  marked confirmed. Script and obfuscation rules are review signals and must not
  auto-quarantine by themselves.
*/

rule Zentor_EICAR_Test_File
{
  meta:
    name = "Avorax EICAR Test File"
    category = "unknown"
    confidence = "confirmed"
    description = "Matches the standard EICAR antivirus test signature."
    source = "EICAR standard test string"
    false_positive_notes = "This is a safe antivirus test file, not real malware."
  strings:
    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    any of them
}

rule Zentor_Obfuscated_PowerShell_Review
{
  meta:
    name = "Avorax Obfuscated PowerShell Review"
    category = "spyware"
    confidence = "medium"
    description = "PowerShell content contains common obfuscation indicators."
    source = "Avorax local rule"
    false_positive_notes = "Administration tools can use encoded commands; review context before action."
  strings:
    $s1 = "FromBase64String"
    $s2 = "-EncodedCommand"
    $s3 = "Invoke-Expression"
  condition:
    any of them
}

rule Zentor_Ransom_Note_Text_Review
{
  meta:
    name = "Avorax Ransom Note Text Review"
    category = "ransomware"
    confidence = "medium"
    description = "Text resembles a ransom note and should be reviewed with behavior context."
    source = "Avorax local rule"
    false_positive_notes = "Training material or documentation can contain these words."
  strings:
    $r1 = "your files have been encrypted"
    $r2 = "pay the ransom"
    $r3 = "decrypt your files"
  condition:
    any of them
}
