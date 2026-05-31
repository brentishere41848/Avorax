#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from github_intel_common import (
    action_policy_for_hash,
    confidence_for_hash,
    indicator_type_for_hash,
    normalize_hash,
    signature_id,
    utc_now,
    write_jsonl,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import developer-provided hashes into Avorax JSONL without downloading malware samples."
    )
    parser.add_argument("--input", required=True, help="TXT/CSV hash list provided by a developer")
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--source-url", default=None)
    parser.add_argument("--category", default="unknown")
    args = parser.parse_args()

    raw_input = Path(args.input).read_text(encoding="utf-8")
    hash_lines = raw_input.splitlines()
    if args.input.lower().endswith(".json"):
        parsed = json.loads(raw_input)
        if isinstance(parsed, dict) and isinstance(parsed.get("hashes"), list):
            hash_lines = [str(value) for value in parsed["hashes"]]
        elif isinstance(parsed, list):
            hash_lines = [str(value) for value in parsed]
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
            "indicator_id": signature_id(args.source_name, hash_kind, value),
            "source_name": args.source_name,
            "source_url": args.source_url,
            "source_type": "developer_provided_hash_list",
            "indicator_type": indicator_type_for_hash(hash_kind),
            "value": value,
            "threat_category": args.category,
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
