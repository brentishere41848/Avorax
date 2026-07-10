import argparse
import json
from pathlib import Path

from evaluate_native_model import (
    MAX_MODEL_BYTES,
    finite_unit_number,
    load_feature_schema,
    load_json,
    validate_model,
)
from native_ml_io import checked_output_directory, write_json_atomic


METADATA_KEYS = [
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
]

def require_unit_metric(model: dict, name: str) -> None:
    if finite_unit_number(model.get(name)) is None:
        raise SystemExit(f"Native model {name} must be a finite number between 0 and 1.")


def main():
    parser = argparse.ArgumentParser(description="Export an evaluated Zentor Native .zmodel into app assets.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--assets", required=True)
    parser.add_argument(
        "--feature-schema",
        default=str(Path(__file__).with_name("feature_schema.json")),
    )
    parser.add_argument(
        "--allow-development",
        action="store_true",
        help="Allow exporting production_ready=false models for explicit development builds.",
    )
    args = parser.parse_args()

    schema_features = load_feature_schema(Path(args.feature_schema))
    model_path = Path(args.model)
    model = load_json(model_path, "Native model", MAX_MODEL_BYTES)
    checks = []
    validate_model(model, schema_features, checks)
    failed_checks = [check for check in checks if not check["ok"]]
    if failed_checks:
        raise SystemExit(f"Native model failed export validation: {failed_checks}")
    for metric in ("precision", "recall", "false_positive_rate"):
        require_unit_metric(model, metric)
    if model.get("production_ready") is not True and not args.allow_development:
        raise SystemExit(
            "Refusing to export production_ready=false native model without --allow-development."
        )

    assets = Path(args.assets).resolve()
    checked_output_directory(assets, "Assets path")
    write_json_atomic(
        assets / "zentor_native_model.zmodel",
        model,
        description="Native model asset",
    )
    metadata = {key: model[key] for key in METADATA_KEYS}
    write_json_atomic(
        assets / "zentor_native_model.metadata.json",
        metadata,
        description="Native model metadata asset",
    )
    print(f"exported {model_path} to {assets}")


if __name__ == "__main__":
    main()
