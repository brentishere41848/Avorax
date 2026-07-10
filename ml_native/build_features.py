#!/usr/bin/env python3
"""Create safe fixture feature rows for Avorax Native ML development."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from evaluate_native_model import (
    NEGATIVE_LABELS,
    POSITIVE_LABELS,
    load_feature_schema,
    validate_fixture_row,
)
from native_ml_io import write_jsonl_atomic

GENERATED_ROWS: list[dict[str, Any]] = [
    {
        "label": "benign",
        "features": {
            "known_good_flag": 1.0,
            "encoded_command_flag": 0.0,
            "suspicious_string_count": 0.0,
            "double_extension": 0.0,
        },
    },
    {
        "label": "suspicious",
        "features": {
            "known_good_flag": 0.0,
            "encoded_command_flag": 1.0,
            "suspicious_string_count": 0.5,
            "double_extension": 0.0,
        },
    },
]


def build_rows(feature_schema_path: Path) -> list[dict[str, Any]]:
    schema_features = load_feature_schema(feature_schema_path)
    rows = [dict(row) for row in GENERATED_ROWS]
    for index, row in enumerate(rows, 1):
        validate_fixture_row(row, schema_features, f"generated native feature row {index}")

    labels = {row["label"] for row in rows}
    if not labels.intersection(NEGATIVE_LABELS) or not labels.intersection(POSITIVE_LABELS):
        raise SystemExit("Generated native feature rows require positive and negative labels.")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create minimal safe feature JSONL rows for Avorax Native ML development."
    )
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--feature-schema",
        default=str(Path(__file__).with_name("feature_schema.json")),
        help="Native feature schema JSON file.",
    )
    args = parser.parse_args()

    rows = build_rows(Path(args.feature_schema))
    write_jsonl_atomic(Path(args.output), rows, description="Feature output")
    print(json.dumps({"ok": True, "feature_rows": len(rows)}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(1)
