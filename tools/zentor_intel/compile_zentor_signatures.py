#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

from github_intel_common import read_jsonl_objects, required_action_policy, required_category, write_json


TYPE_MAP = {
    "sha256": "exact_hash",
    "string_pattern": "ascii_string",
    "script_pattern": "script_pattern",
    "byte_pattern": "byte_pattern",
    "import_combo": "pe_import_combo",
}
MAX_SIGNATURE_TEXT_BYTES = 4096
ALLOWED_CONFIDENCE = {"low", "medium", "high", "confirmed"}


def required_text(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if not text:
        raise SystemExit(f"{description} must not be empty")
    if len(text.encode("utf-8")) > MAX_SIGNATURE_TEXT_BYTES:
        raise SystemExit(f"{description} exceeds {MAX_SIGNATURE_TEXT_BYTES} bytes")
    if any(ord(char) < 32 for char in text) or "\x00" in text:
        raise SystemExit(f"{description} contains control characters")
    return text


def optional_text(value: object, description: str) -> str | None:
    if value is None:
        return None
    return required_text(value, description)


def required_choice(value: object, description: str, allowed: set[str]) -> str:
    text = required_text(value, description)
    if text not in allowed:
        raise SystemExit(f"{description} must be one of: {', '.join(sorted(allowed))}")
    return text


def canonical_signature_pack(pack: dict) -> bytes:
    canonical = {
        "format": pack["format"],
        "version": pack["version"],
        "compiler_version": pack["compiler_version"],
        "created_at": pack["created_at"],
        "signatures": pack["signatures"],
    }
    return json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile Avorax JSONL indicators to a .zsig JSON pack.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    pack_version = required_text(args.version, "signature pack version")
    signatures = []
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    for line_number, indicator in enumerate(read_jsonl_objects(Path(args.input), "indicator JSONL input"), start=1):
        prefix = f"indicator JSONL line {line_number}"
        indicator_id = required_text(indicator.get("indicator_id"), f"{prefix} indicator_id")
        source_name = required_text(indicator.get("source_name"), f"{prefix} source_name")
        indicator_type = required_text(indicator.get("indicator_type"), f"{prefix} indicator_type")
        if indicator_type not in TYPE_MAP:
            raise SystemExit(f"unsupported indicator type for zsig: {indicator_type}")
        pattern = required_text(indicator.get("value"), f"{prefix} value")
        category = required_category(indicator.get("threat_category"), f"{prefix} threat_category")
        confidence = required_choice(indicator.get("confidence"), f"{prefix} confidence", ALLOWED_CONFIDENCE)
        action_policy = required_action_policy(indicator.get("action_policy"), f"{prefix} action_policy")
        false_positive_notes = required_text(indicator.get("false_positive_notes"), f"{prefix} false_positive_notes")
        malware_family = optional_text(indicator.get("malware_family"), f"{prefix} malware_family")
        display_family = malware_family if malware_family is not None else "Threat"
        signatures.append({
            "id": indicator_id,
            "name": f"{display_family} indicator from {source_name}",
            "version": "1",
            "category": category,
            "confidence": confidence,
            "severity": "critical" if confidence == "confirmed" else "medium",
            "signature_type": TYPE_MAP[indicator_type],
            "pattern": pattern,
            "mask": None,
            "offset": None,
            "file_types": ["*"],
            "min_file_size": None,
            "max_file_size": None,
            "required_context": [],
            "false_positive_notes": false_positive_notes,
            "action_policy": action_policy,
            "created_at": now,
            "updated_at": now,
        })
    pack = {
        "format": "zentor-signature-pack-v1",
        "version": pack_version,
        "compiler_version": None,
        "created_at": None,
        "signatures": sorted(signatures, key=lambda item: item["id"]),
    }
    pack["pack_sha256"] = hashlib.sha256(canonical_signature_pack(pack)).hexdigest()
    output_pack = {
        "format": pack["format"],
        "version": pack["version"],
        "compiler_version": pack["compiler_version"],
        "created_at": pack["created_at"],
        "pack_sha256": pack["pack_sha256"],
        "signatures": pack["signatures"],
    }
    write_json(Path(args.output), output_pack, "signature pack output")
    print(f"compiled {len(signatures)} signatures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
