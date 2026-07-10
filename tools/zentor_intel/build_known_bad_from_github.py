#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

from github_intel_common import normalize_hash, read_jsonl_objects, required_category, write_json


TYPE_MAP = {
    "sha256": "exact_hash",
}
MAX_KNOWN_BAD_TEXT_BYTES = 4096


def required_text(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if not text:
        raise SystemExit(f"{description} must not be empty")
    if len(text.encode("utf-8")) > MAX_KNOWN_BAD_TEXT_BYTES:
        raise SystemExit(f"{description} exceeds {MAX_KNOWN_BAD_TEXT_BYTES} bytes")
    if any(ord(char) < 32 for char in text) or "\x00" in text:
        raise SystemExit(f"{description} contains control characters")
    return text


def optional_text(value: object, description: str, default: str) -> str:
    if value is None:
        return default
    return required_text(value, description)


def required_sha256(value: object, description: str) -> str:
    text = required_text(value, description)
    try:
        parsed = normalize_hash(text)
    except ValueError as exc:
        raise SystemExit(f"{description} must be a valid SHA-256 hash") from exc
    if parsed is None or parsed[0] != "sha256":
        raise SystemExit(f"{description} must be a valid SHA-256 hash")
    return parsed[1]


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
    parser = argparse.ArgumentParser(
        description="Build a Avorax known-bad .zsig pack from hash-only GitHub intelligence JSONL."
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    pack_version = required_text(args.version, "known-bad signature pack version")

    signatures = []
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    for line_number, indicator in enumerate(read_jsonl_objects(Path(args.input), "hash-only GitHub intelligence JSONL"), start=1):
        prefix = f"hash-only GitHub intelligence line {line_number}"
        indicator_type = required_text(indicator.get("indicator_type"), f"{prefix} indicator_type")
        if indicator_type == "github_metadata":
            continue
        if indicator_type not in TYPE_MAP:
            print(
                f"line {line_number}: kept {indicator_type} as lower-confidence metadata; only SHA-256 becomes active known-bad signature"
            )
            continue
        indicator_id = required_text(indicator.get("indicator_id"), f"{prefix} indicator_id")
        source_name = required_text(indicator.get("source_name"), f"{prefix} source_name")
        value = required_sha256(indicator.get("value"), f"{prefix} value")
        category = required_category(indicator.get("threat_category"), f"{prefix} threat_category")
        confidence = required_text(indicator.get("confidence"), f"{prefix} confidence")
        if confidence != "confirmed":
            raise SystemExit(f"{prefix} confidence must be confirmed for known-bad output")
        action_policy = required_text(indicator.get("action_policy"), f"{prefix} action_policy")
        if action_policy != "quarantine_if_policy_allows":
            raise SystemExit(
                f"{prefix} action_policy must be quarantine_if_policy_allows for known-bad output"
            )
        false_positive_notes = required_text(
            indicator.get("false_positive_notes"),
            f"{prefix} false_positive_notes",
        )
        created_at = optional_text(indicator.get("created_at"), f"{prefix} created_at", now)
        confidence = "confirmed"
        action_policy = "quarantine_if_policy_allows"
        signatures.append({
            "id": indicator_id,
            "name": f"GitHub malware-intel known-bad hash from {source_name}",
            "version": "1",
            "category": category,
            "confidence": confidence,
            "severity": "critical" if confidence == "confirmed" else "high",
            "signature_type": TYPE_MAP[indicator_type],
            "pattern": value,
            "mask": None,
            "offset": None,
            "file_types": ["*"],
            "min_file_size": None,
            "max_file_size": None,
            "required_context": [],
            "false_positive_notes": false_positive_notes,
            "action_policy": action_policy,
            "created_at": created_at,
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
    write_json(Path(args.output), output_pack, "known-bad signature pack")
    print(f"compiled {len(signatures)} known-bad hash signatures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
