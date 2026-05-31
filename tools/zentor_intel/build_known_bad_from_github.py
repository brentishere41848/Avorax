#!/usr/bin/env python3
import argparse
import datetime as dt
import json
from pathlib import Path


TYPE_MAP = {
    "sha256": "exact_hash",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a Avorax known-bad .zsig pack from hash-only GitHub intelligence JSONL."
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", default="dev")
    args = parser.parse_args()

    signatures = []
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    for line_number, line in enumerate(Path(args.input).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        indicator = json.loads(line)
        indicator_type = indicator.get("indicator_type")
        if indicator_type == "github_metadata":
            continue
        if indicator_type not in TYPE_MAP:
            print(
                f"line {line_number}: kept {indicator_type} as lower-confidence metadata; only SHA-256 becomes active known-bad signature"
            )
            continue
        confidence = "confirmed"
        action_policy = "quarantine_if_policy_allows"
        signatures.append({
            "id": indicator["indicator_id"],
            "name": f"GitHub malware-intel known-bad hash from {indicator['source_name']}",
            "version": "1",
            "category": indicator.get("threat_category", "unknown"),
            "confidence": confidence,
            "severity": "critical" if confidence == "confirmed" else "high",
            "signature_type": TYPE_MAP[indicator_type],
            "pattern": indicator["value"],
            "mask": None,
            "offset": None,
            "file_types": ["*"],
            "min_file_size": None,
            "max_file_size": None,
            "required_context": [
                "Exact SHA-256 from GitHub malware-intel pack."
            ],
            "false_positive_notes": indicator.get(
                "false_positive_notes",
                "Hash-only signature. No malware sample is included in the repository.",
            ),
            "action_policy": action_policy,
            "created_at": indicator.get("created_at", now),
            "updated_at": now,
        })

    pack = {
        "format": "zentor-signature-pack-v1",
        "version": args.version,
        "signatures": sorted(signatures, key=lambda item: item["id"]),
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(pack, indent=2, sort_keys=True), encoding="utf-8")
    print(f"compiled {len(signatures)} known-bad hash signatures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
