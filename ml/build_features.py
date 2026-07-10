#!/usr/bin/env python3
"""Build Zentor feature JSONL rows from already-extracted metadata.

This script does not execute files, detonate samples, download malware, or
upload user data. It validates feature rows for the offline training pipeline.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from static_ml_schema import (
    MAX_JSONL_ROWS,
    load_feature_schema,
    load_validated_jsonl_rows,
    write_jsonl_atomic,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--schema",
        default=str(Path(__file__).with_name("feature_schema.json")),
        help="Feature schema JSON file.",
    )
    parser.add_argument("--max-rows", type=int, default=MAX_JSONL_ROWS)
    args = parser.parse_args()

    schema = load_feature_schema(Path(args.schema))
    rows = load_validated_jsonl_rows(
        Path(args.input), schema, require_user_label=False, max_rows=args.max_rows
    )
    write_jsonl_atomic(Path(args.output), rows)
    print(json.dumps({"ok": True, "feature_rows": len(rows)}, sort_keys=True))


if __name__ == "__main__":
    main()
