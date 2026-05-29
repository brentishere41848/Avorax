#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Zentor indicator/signature/rule pack metadata.")
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    pack = json.loads(Path(args.input).read_text(encoding="utf-8"))
    fmt = pack.get("format")
    if fmt not in {"zentor-signature-pack-v1", "zentor-rule-pack-v1"}:
        raise SystemExit(f"unsupported pack format: {fmt}")
    items = pack.get("signatures") if fmt.endswith("signature-pack-v1") else pack.get("rules")
    if not isinstance(items, list):
        raise SystemExit("pack item list missing")
    for item in items:
        for key in ("id", "name", "false_positive_notes"):
            if not item.get(key):
                raise SystemExit(f"item missing {key}: {item}")
    print(f"validated {len(items)} items from {fmt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
