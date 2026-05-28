import argparse
import json
import math
from pathlib import Path


def load_jsonl(path: Path):
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def main():
    parser = argparse.ArgumentParser(description="Train a conservative Pasus Native .pmodel from feature JSONL.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    rows = load_jsonl(Path(args.input))
    if not rows:
        raise SystemExit("No training rows supplied.")

    feature_names = sorted(rows[0]["features"].keys())
    weights = {name: 0.0 for name in feature_names}
    positives = [row for row in rows if row.get("label") in {"malicious", "test_threat", "suspicious"}]
    negatives = [row for row in rows if row.get("label") in {"benign", "trusted"}]
    if not positives or not negatives:
        raise SystemExit("Training requires positive and negative feature rows.")

    for name in feature_names:
        pos_avg = sum(row["features"].get(name, 0.0) for row in positives) / len(positives)
        neg_avg = sum(row["features"].get(name, 0.0) for row in negatives) / len(negatives)
        weights[name] = max(-4.0, min(4.0, (pos_avg - neg_avg) * 2.0))

    model = {
        "model_name": "Pasus Native Candidate Model",
        "model_version": "0.1.0-candidate",
        "model_format_version": "pmodel-v1",
        "feature_schema_version": "pne-features-v1",
        "production_ready": False,
        "precision": 0.0,
        "recall": 0.0,
        "false_positive_rate": 1.0,
        "bias": -3.0,
        "weights": weights,
        "thresholds": {"suspicious": 0.65, "probable_malware": 0.86, "confirmed_malware": 0.98},
        "limitations": ["Candidate model; run evaluate_native_model.py before export."],
    }
    Path(args.output).write_text(json.dumps(model, indent=2), encoding="utf-8")
    print(f"wrote {args.output}; production_ready remains false until evaluation passes")


if __name__ == "__main__":
    main()
