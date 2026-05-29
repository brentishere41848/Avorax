#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge Zentor .zrule JSON files into one rule pack.")
    parser.add_argument("--input", required=True, help="Directory containing .zrule files")
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", default="dev")
    args = parser.parse_args()
    rules = []
    for path in sorted(Path(args.input).glob("*.zrule")):
        pack = json.loads(path.read_text(encoding="utf-8"))
        rules.extend(pack.get("rules", []))
    Path(args.output).write_text(
        json.dumps({"format": "zentor-rule-pack-v1", "version": args.version, "rules": rules}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(f"compiled {len(rules)} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
