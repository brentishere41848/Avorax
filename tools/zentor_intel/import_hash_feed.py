#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path


def is_sha256(value: str) -> bool:
    value = value.lower().removeprefix("sha256:")
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import SHA-256 hash indicators into Zentor JSONL.")
    parser.add_argument("--source", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--category", default="trojan")
    args = parser.parse_args()

    source = json.loads(Path(args.source).read_text(encoding="utf-8"))
    source_name = source.get("source_name")
    if not source_name:
        raise SystemExit("source_name is required")

    output = Path(args.output)
    count = 0
    with Path(args.input).open("r", encoding="utf-8") as handle, output.open("w", encoding="utf-8") as out:
        for line_number, line in enumerate(handle, start=1):
            value = line.split(",", 1)[0].strip().lower().removeprefix("sha256:")
            if not value or value.startswith("#"):
                continue
            if not is_sha256(value):
                raise SystemExit(f"invalid SHA-256 on line {line_number}")
            indicator = {
                "indicator_id": f"ZTI-{hashlib.sha256((source_name + value).encode()).hexdigest()[:16]}",
                "source_name": source_name,
                "source_url": source.get("source_url"),
                "source_type": source.get("source_type", "manual_lab"),
                "indicator_type": "sha256",
                "value": value,
                "malware_family": source.get("malware_family"),
                "threat_category": args.category,
                "confidence": "confirmed",
                "false_positive_notes": "Exact SHA-256 indicator imported from supplied metadata feed.",
                "action_policy": "quarantine_if_policy_allows",
            }
            out.write(json.dumps(indicator, sort_keys=True) + "\n")
            count += 1
    print(f"imported {count} indicators")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
