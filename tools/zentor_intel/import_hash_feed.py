#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path

from github_intel_common import read_json, read_text_lines, required_category, write_jsonl

MAX_HASH_FEED_TEXT_BYTES = 4096


def required_text(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if not text:
        raise SystemExit(f"{description} must not be empty")
    if len(text.encode("utf-8")) > MAX_HASH_FEED_TEXT_BYTES:
        raise SystemExit(f"{description} exceeds {MAX_HASH_FEED_TEXT_BYTES} bytes")
    if any(ord(char) < 32 for char in text) or "\x00" in text:
        raise SystemExit(f"{description} contains control characters")
    return text


def optional_text(value: object, description: str, default: str | None = None) -> str | None:
    if value is None:
        return default
    return required_text(value, description)


def is_sha256(value: str) -> bool:
    value = value.lower().removeprefix("sha256:")
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import SHA-256 hash indicators into Avorax JSONL.")
    parser.add_argument("--source", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--category", required=True)
    args = parser.parse_args()

    source = read_json(Path(args.source), "hash feed source metadata")
    if "source_name" not in source and isinstance(source.get("manual_hash_source_template"), dict):
        source = source["manual_hash_source_template"]
    source_name = required_text(source.get("source_name"), "hash feed source_name")
    source_url = optional_text(source.get("source_url"), "hash feed source_url")
    source_type = optional_text(source.get("source_type"), "hash feed source_type", "manual_lab")
    malware_family = optional_text(source.get("malware_family"), "hash feed malware_family")
    threat_category = required_category(args.category, "hash feed category")

    rows: list[dict] = []
    for line_number, line in enumerate(read_text_lines(Path(args.input), "hash feed input"), start=1):
        value = line.split(",", 1)[0].strip().lower().removeprefix("sha256:")
        if not value or value.startswith("#"):
            continue
        if not is_sha256(value):
            raise SystemExit(f"invalid SHA-256 on line {line_number}")
        rows.append({
            "indicator_id": f"ZTI-{hashlib.sha256((source_name + value).encode()).hexdigest()[:16]}",
            "source_name": source_name,
            "source_url": source_url,
            "source_type": source_type,
            "indicator_type": "sha256",
            "value": value,
            "malware_family": malware_family,
            "threat_category": threat_category,
            "confidence": "confirmed",
            "false_positive_notes": "Exact SHA-256 indicator imported from supplied metadata feed.",
            "action_policy": "quarantine_if_policy_allows",
        })
    write_jsonl(Path(args.output), rows)
    print(f"imported {len(rows)} indicators")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
