#!/usr/bin/env python3
import argparse
import datetime as dt
import json
from pathlib import Path


TYPE_MAP = {
    "sha256": "exact_hash",
    "string_pattern": "ascii_string",
    "script_pattern": "script_pattern",
    "byte_pattern": "byte_pattern",
    "import_combo": "pe_import_combo",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile Avorax JSONL indicators to a .zsig JSON pack.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", default="dev")
    args = parser.parse_args()
    signatures = []
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    for line in Path(args.input).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        indicator = json.loads(line)
        indicator_type = indicator["indicator_type"]
        if indicator_type not in TYPE_MAP:
            raise SystemExit(f"unsupported indicator type for zsig: {indicator_type}")
        signatures.append({
            "id": indicator["indicator_id"],
            "name": f"{indicator.get('malware_family') or 'Threat'} indicator from {indicator['source_name']}",
            "version": "1",
            "category": indicator.get("threat_category", "unknown"),
            "confidence": indicator.get("confidence", "medium"),
            "severity": "critical" if indicator.get("confidence") == "confirmed" else "medium",
            "signature_type": TYPE_MAP[indicator_type],
            "pattern": indicator["value"],
            "mask": None,
            "offset": None,
            "file_types": ["*"],
            "min_file_size": None,
            "max_file_size": None,
            "required_context": ["Exact metadata indicator import." if indicator_type == "sha256" else "review context: imported indicator."],
            "false_positive_notes": indicator["false_positive_notes"],
            "action_policy": indicator.get("action_policy", "review"),
            "created_at": now,
            "updated_at": now,
        })
    pack = {
        "format": "zentor-signature-pack-v1",
        "version": args.version,
        "signatures": sorted(signatures, key=lambda item: item["id"]),
    }
    Path(args.output).write_text(json.dumps(pack, indent=2, sort_keys=True), encoding="utf-8")
    print(f"compiled {len(signatures)} signatures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
