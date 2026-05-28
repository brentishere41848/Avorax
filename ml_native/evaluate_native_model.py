import argparse
import json
import math
from pathlib import Path


def sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def score(model, features):
    raw = model.get("bias", 0.0)
    for name, weight in model.get("weights", {}).items():
        raw += features.get(name, 0.0) * weight
    return sigmoid(raw)


def main():
    parser = argparse.ArgumentParser(description="Evaluate a Pasus Native .pmodel on feature fixtures.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("--max-fpr", type=float, default=0.005)
    args = parser.parse_args()

    model = json.loads(Path(args.model).read_text(encoding="utf-8"))
    rows = load_jsonl(Path(args.fixtures))
    if not rows:
        raise SystemExit("No fixture rows supplied.")

    threshold = model["thresholds"]["probable_malware"]
    false_positives = 0
    negatives = 0
    for row in rows:
        probability = score(model, row["features"])
        if row.get("label") in {"benign", "trusted"}:
            negatives += 1
            false_positives += int(probability >= threshold)
    fpr = false_positives / max(1, negatives)
    print(json.dumps({"false_positive_rate": fpr, "false_positives": false_positives, "negative_rows": negatives}, indent=2))
    if fpr > args.max_fpr:
        raise SystemExit(f"false positive rate {fpr:.4f} exceeds limit {args.max_fpr:.4f}")


if __name__ == "__main__":
    main()
