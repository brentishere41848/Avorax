#!/usr/bin/env python3
import argparse
from pathlib import Path

from github_intel_common import (
    action_policy_for_hash,
    confidence_for_hash,
    indicator_type_for_hash,
    normalize_hash,
    read_json_value,
    read_text_lines,
    required_category,
    signature_id,
    utc_now,
    write_jsonl,
)

MAX_DEVELOPER_HASH_TEXT_BYTES = 4096


def required_text(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if not text:
        raise SystemExit(f"{description} must not be empty")
    if len(text.encode("utf-8")) > MAX_DEVELOPER_HASH_TEXT_BYTES:
        raise SystemExit(f"{description} exceeds {MAX_DEVELOPER_HASH_TEXT_BYTES} bytes")
    if any(ord(char) < 32 for char in text) or "\x00" in text:
        raise SystemExit(f"{description} contains control characters")
    return text


def optional_text(value: object, description: str) -> str | None:
    if value is None:
        return None
    return required_text(value, description)


def json_hash_lines(values: list, description: str) -> list[str]:
    lines: list[str] = []
    for index, value in enumerate(values, start=1):
        if not isinstance(value, str):
            raise SystemExit(f"{description} hash {index} must be a string")
        lines.append(value)
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import developer-provided hashes into Avorax JSONL without downloading malware samples."
    )
    parser.add_argument("--input", required=True, help="TXT/CSV hash list provided by a developer")
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--source-url", default=None)
    parser.add_argument("--category", required=True)
    args = parser.parse_args()
    source_name = required_text(args.source_name, "developer hash source_name")
    source_url = optional_text(args.source_url, "developer hash source_url")
    threat_category = required_category(args.category, "developer hash category")

    if args.input.lower().endswith(".json"):
        parsed = read_json_value(Path(args.input), "developer hash JSON input")
        if isinstance(parsed, dict) and isinstance(parsed.get("hashes"), list):
            hash_lines = json_hash_lines(parsed["hashes"], "developer hash JSON input")
        elif isinstance(parsed, list):
            hash_lines = json_hash_lines(parsed, "developer hash JSON input")
        else:
            raise SystemExit("developer hash JSON input must be a list or object with hashes list")
    else:
        hash_lines = read_text_lines(Path(args.input), "developer hash text input")
    rows: list[dict] = []
    for line_number, line in enumerate(hash_lines, start=1):
        try:
            parsed = normalize_hash(line)
        except ValueError as exc:
            raise SystemExit(f"line {line_number}: {exc}") from exc
        if parsed is None:
            continue
        hash_kind, value = parsed
        rows.append({
            "indicator_id": signature_id(source_name, hash_kind, value),
            "source_name": source_name,
            "source_url": source_url,
            "source_type": "developer_provided_hash_list",
            "indicator_type": indicator_type_for_hash(hash_kind),
            "value": value,
            "threat_category": threat_category,
            "confidence": confidence_for_hash(hash_kind),
            "false_positive_notes": "Hash-only indicator imported from a developer-provided list. No malware sample is included.",
            "action_policy": action_policy_for_hash(hash_kind),
            "created_at": utc_now(),
        })
    write_jsonl(Path(args.output), rows)
    print(f"imported {len(rows)} hash-only indicators")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
