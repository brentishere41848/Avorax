#!/usr/bin/env python3
"""Train a conservative offline Zentor static malware classifier.

This script is a developer pipeline. The production Zentor app never retrains
itself silently from one user's labels.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from static_ml_schema import (
    KNOWN_USER_LABELS,
    SUPERVISED_NEGATIVE_LABELS,
    SUPERVISED_POSITIVE_LABELS,
    checked_output_dir,
    load_feature_schema,
    load_validated_jsonl_rows,
    write_json_atomic,
)

DEFAULT_MIN_RECORDS = 50


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Training labels JSONL")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument(
        "--schema",
        default=str(Path(__file__).with_name("feature_schema.json")),
        help="Feature schema JSON file.",
    )
    parser.add_argument("--min-records", type=int, default=DEFAULT_MIN_RECORDS)
    parser.add_argument("--min-positive", type=int, default=1)
    parser.add_argument("--min-negative", type=int, default=1)
    args = parser.parse_args()

    if args.min_records < 1:
        raise SystemExit("min-records must be at least 1.")
    if args.min_positive < 0 or args.min_negative < 0:
        raise SystemExit("min-positive and min-negative must not be negative.")

    schema = load_feature_schema(Path(args.schema))
    rows = load_validated_jsonl_rows(Path(args.input), schema, require_user_label=True)
    if len(rows) < args.min_records:
        raise SystemExit(
            f"Need at least {args.min_records} labeled records before training."
        )

    label_counts = {
        label: sum(1 for row in rows if row.get("user_label") == label)
        for label in sorted(KNOWN_USER_LABELS)
    }
    supervised_positive = sum(
        count for label, count in label_counts.items() if label in SUPERVISED_POSITIVE_LABELS
    )
    supervised_negative = sum(
        count for label, count in label_counts.items() if label in SUPERVISED_NEGATIVE_LABELS
    )
    if supervised_positive < args.min_positive:
        raise SystemExit(
            f"Need at least {args.min_positive} supervised positive labels before training."
        )
    if supervised_negative < args.min_negative:
        raise SystemExit(
            f"Need at least {args.min_negative} supervised negative labels before training."
        )

    output = checked_output_dir(Path(args.output))
    metadata = {
        "model_name": "zentor_static_malware_model",
        "model_version": "dev-untrained",
        "model_type": "static_feature_training_summary",
        "production_ready": False,
        "status": "development_training_summary_only",
        "feature_schema_version": "1.0.0",
        "training_sample_count": len(rows),
        "validation_sample_count": 0,
        "false_positive_rate": None,
        "precision": None,
        "recall": None,
        "label_counts": label_counts,
        "supervised_positive_labels": supervised_positive,
        "supervised_negative_labels": supervised_negative,
        "threshold_policy": {
            "suspicious": 0.75,
            "probable_malware": 0.92,
            "auto_quarantine_requires_behavior_or_signature": True,
        },
        "thresholds": {
            "suspicious": 0.75,
            "probable_malware": 0.92,
            "confirmed_malware": 0.995,
        },
        "limitations": [
            "Development training summary only; this script does not fit or export an ONNX classifier.",
            "Production release requires the pinned training/export environment and independent validation metrics.",
        ],
        "note": "Install the pinned training environment from requirements.txt and use export_onnx.py with explicit release evidence to produce a release candidate.",
    }
    write_json_atomic(output / "model_metadata.json", metadata)
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
