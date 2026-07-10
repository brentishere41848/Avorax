import argparse
import json
from pathlib import Path

from evaluate_native_model import (
    NEGATIVE_LABELS,
    POSITIVE_LABELS,
    load_feature_schema,
    load_jsonl,
    validate_fixture_row,
)
from native_ml_io import write_json_atomic


def main():
    parser = argparse.ArgumentParser(
        description="Train a conservative Zentor Native .zmodel from feature JSONL."
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--feature-schema",
        default=str(Path(__file__).with_name("feature_schema.json")),
    )
    args = parser.parse_args()

    schema_features = load_feature_schema(Path(args.feature_schema))
    rows = [
        validate_fixture_row(row, schema_features, f"{args.input}:{index}")
        for index, row in enumerate(load_jsonl(Path(args.input)), 1)
    ]
    if not rows:
        raise SystemExit("No training rows supplied.")

    positives = [(label, features) for label, features in rows if label in POSITIVE_LABELS]
    negatives = [(label, features) for label, features in rows if label in NEGATIVE_LABELS]
    if not positives or not negatives:
        raise SystemExit("Training requires positive and negative feature rows.")

    feature_names = sorted(schema_features)
    weights = {name: 0.0 for name in feature_names}
    for name in feature_names:
        # Training rows are sparse; absent schema-valid features are explicit zeroes.
        pos_avg = sum(features.get(name, 0.0) for _, features in positives) / len(positives)
        neg_avg = sum(features.get(name, 0.0) for _, features in negatives) / len(negatives)
        weights[name] = max(-4.0, min(4.0, (pos_avg - neg_avg) * 2.0))

    model = {
        "model_name": "Zentor Native Candidate Model",
        "model_version": "0.1.0-candidate",
        "model_format_version": "zmodel-v1",
        "feature_schema_version": "zne-features-v1",
        "production_ready": False,
        "precision": 0.0,
        "recall": 0.0,
        "false_positive_rate": 1.0,
        "bias": -3.0,
        "weights": weights,
        "thresholds": {
            "suspicious": 0.65,
            "probable_malware": 0.86,
            "confirmed_malware": 0.98,
        },
        "limitations": ["Candidate model; run evaluate_native_model.py before export."],
    }
    write_json_atomic(Path(args.output), model, description="Native model output")
    print(f"wrote {args.output}; production_ready remains false until evaluation passes")


if __name__ == "__main__":
    main()
