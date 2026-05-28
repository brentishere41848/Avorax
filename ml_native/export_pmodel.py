import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Export an evaluated Pasus Native .pmodel into app assets.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--assets", required=True)
    args = parser.parse_args()

    model_path = Path(args.model)
    model = json.loads(model_path.read_text(encoding="utf-8"))
    assets = Path(args.assets)
    assets.mkdir(parents=True, exist_ok=True)
    (assets / "pasus_native_model.pmodel").write_text(json.dumps(model, indent=2), encoding="utf-8")
    metadata = {key: model.get(key) for key in [
        "model_name",
        "model_version",
        "model_format_version",
        "feature_schema_version",
        "production_ready",
        "precision",
        "recall",
        "false_positive_rate",
        "thresholds",
        "limitations",
    ]}
    (assets / "pasus_native_model.metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"exported {model_path} to {assets}")


if __name__ == "__main__":
    main()
