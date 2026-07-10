#!/usr/bin/env python3
"""Evaluate Avorax Native .zmodel metadata and feature fixtures."""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import sys
import uuid
from pathlib import Path
from typing import Any

MAX_MODEL_BYTES = 1024 * 1024
MAX_FIXTURE_BYTES = 4 * 1024 * 1024
MAX_FEATURE_ABS = 1_000_000.0
NEGATIVE_LABELS = {"benign", "trusted"}
POSITIVE_LABELS = {"malicious", "test_threat", "suspicious"}
REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT_ATTRIBUTE
    )


def require_regular_file(path: Path, description: str, max_bytes: int) -> None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise SystemExit(f"{description} does not exist: {path}") from exc
    except OSError as exc:
        raise SystemExit(f"Unable to inspect {description} {path}: {exc}") from exc

    if is_link_or_reparse(metadata):
        raise SystemExit(f"{description} must not be a symbolic link or reparse point: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{description} is not a regular file: {path}")
    if metadata.st_size > max_bytes:
        raise SystemExit(f"{description} exceeds {max_bytes} bytes: {path}")


def load_json(path: Path, description: str, max_bytes: int) -> dict[str, Any]:
    require_regular_file(path, description, max_bytes)
    try:
        decoded = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{description} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"Unable to read {description} {path}: {exc}") from exc
    if not isinstance(decoded, dict):
        raise SystemExit(f"{description} must be a JSON object.")
    return decoded


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    require_regular_file(path, "Feature fixture file", MAX_FIXTURE_BYTES)
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    decoded = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise SystemExit(
                        f"Feature fixture {path}:{line_number} is not valid JSON: {exc}"
                    ) from exc
                if not isinstance(decoded, dict):
                    raise SystemExit(
                        f"Feature fixture {path}:{line_number} must be a JSON object."
                    )
                rows.append(decoded)
    except OSError as exc:
        raise SystemExit(f"Unable to read feature fixture file {path}: {exc}") from exc
    return rows


def finite_number(value: Any, *, max_abs: float = MAX_FEATURE_ABS) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or abs(number) > max_abs:
        return None
    return number


def finite_unit_number(value: Any) -> float | None:
    number = finite_number(value, max_abs=1.0)
    if number is None or number < 0.0 or number > 1.0:
        return None
    return number


def add_check(checks: list[dict[str, Any]], name: str, ok: bool, detail: str) -> None:
    checks.append({"name": name, "ok": ok, "detail": detail})


def load_feature_schema(path: Path) -> set[str]:
    schema = load_json(path, "Feature schema", MAX_MODEL_BYTES)
    features = schema.get("features")
    if not isinstance(features, list) or not features:
        raise SystemExit("Feature schema must contain a non-empty features array.")
    normalized: set[str] = set()
    for feature in features:
        if not isinstance(feature, str) or not feature.strip():
            raise SystemExit("Feature schema entries must be non-empty strings.")
        if feature in normalized:
            raise SystemExit(f"Feature schema contains duplicate feature: {feature}")
        normalized.add(feature)
    return normalized


def validate_thresholds(model: dict[str, Any], checks: list[dict[str, Any]]) -> tuple[float, float, float] | None:
    thresholds = model.get("thresholds")
    if not isinstance(thresholds, dict):
        add_check(checks, "thresholds", False, "thresholds must be a JSON object")
        return None

    names = ("suspicious", "probable_malware", "confirmed_malware")
    values: list[float] = []
    for name in names:
        value = finite_unit_number(thresholds.get(name))
        if value is None:
            add_check(
                checks,
                f"threshold:{name}",
                False,
                f"{name} threshold must be a finite number between 0 and 1",
            )
            return None
        values.append(value)

    ordered = values[0] < values[1] < values[2]
    add_check(
        checks,
        "thresholds",
        ordered,
        "thresholds are ordered suspicious < probable_malware < confirmed_malware"
        if ordered
        else "thresholds must be strictly ordered suspicious < probable_malware < confirmed_malware",
    )
    return (values[0], values[1], values[2]) if ordered else None


def validate_model(
    model: dict[str, Any], schema_features: set[str], checks: list[dict[str, Any]]
) -> tuple[float, dict[str, float], tuple[float, float, float] | None]:
    production_ready = model.get("production_ready")
    add_check(
        checks,
        "production_ready_type",
        isinstance(production_ready, bool),
        "production_ready is a JSON boolean"
        if isinstance(production_ready, bool)
        else "production_ready must be a JSON boolean",
    )

    bias = finite_number(model.get("bias"), max_abs=100.0)
    add_check(
        checks,
        "bias",
        bias is not None,
        f"bias={bias}" if bias is not None else "bias must be a finite number",
    )

    weights_raw = model.get("weights")
    weights: dict[str, float] = {}
    weights_ok = isinstance(weights_raw, dict) and bool(weights_raw)
    if weights_ok:
        for name, raw_weight in weights_raw.items():
            if not isinstance(name, str) or name not in schema_features:
                weights_ok = False
                break
            weight = finite_number(raw_weight, max_abs=100.0)
            if weight is None:
                weights_ok = False
                break
            weights[name] = weight
    add_check(
        checks,
        "weights",
        weights_ok,
        f"{len(weights)} schema-valid finite weights"
        if weights_ok
        else "weights must be a non-empty object whose names exist in the feature schema and values are finite numbers",
    )

    thresholds = validate_thresholds(model, checks)
    return (bias if bias is not None else 0.0, weights, thresholds)


def validate_fixture_row(
    row: dict[str, Any],
    schema_features: set[str],
    source: str,
) -> tuple[str, dict[str, float]]:
    label = row.get("label")
    if label not in NEGATIVE_LABELS and label not in POSITIVE_LABELS:
        raise SystemExit(f"{source} has unsupported label: {label!r}")
    features_raw = row.get("features")
    if not isinstance(features_raw, dict):
        raise SystemExit(f"{source} must contain a features object.")

    features: dict[str, float] = {}
    for name, raw_value in features_raw.items():
        if not isinstance(name, str) or name not in schema_features:
            raise SystemExit(f"{source} contains feature outside schema: {name!r}")
        value = finite_number(raw_value)
        if value is None:
            raise SystemExit(f"{source} feature {name!r} must be a finite bounded number.")
        features[name] = value
    return (label, features)


def sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def score(bias: float, weights: dict[str, float], features: dict[str, float]) -> float:
    raw = bias
    for name, weight in weights.items():
        # Fixtures use a sparse feature representation; absent schema-valid features are explicit zeroes.
        raw += features.get(name, 0.0) * weight
    return sigmoid(raw)


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    schema_features = load_feature_schema(Path(args.feature_schema))
    model = load_json(Path(args.model), "Native model", MAX_MODEL_BYTES)
    checks: list[dict[str, Any]] = []
    bias, weights, thresholds = validate_model(model, schema_features, checks)

    rows: list[tuple[str, dict[str, float]]] = []
    for fixture_path in args.fixtures:
        path = Path(fixture_path)
        for index, row in enumerate(load_jsonl(path), 1):
            rows.append(
                validate_fixture_row(row, schema_features, f"{path}:{index}")
            )

    negatives = sum(1 for label, _ in rows if label in NEGATIVE_LABELS)
    positives = sum(1 for label, _ in rows if label in POSITIVE_LABELS)
    add_check(
        checks,
        "fixture_rows",
        negatives > 0 and positives > 0,
        f"negative_rows={negatives}; positive_rows={positives}"
        if negatives > 0 and positives > 0
        else "evaluation requires at least one negative and one positive fixture row",
    )

    probable_threshold = thresholds[1] if thresholds is not None else 1.0
    false_positives = 0
    true_positives = 0
    predicted_positives = 0
    for label, features in rows:
        probability = score(bias, weights, features)
        predicted = probability >= probable_threshold
        if predicted:
            predicted_positives += 1
        if label in NEGATIVE_LABELS and predicted:
            false_positives += 1
        if label in POSITIVE_LABELS and predicted:
            true_positives += 1

    fpr = false_positives / negatives if negatives else 1.0
    recall = true_positives / positives if positives else 0.0
    precision = true_positives / predicted_positives if predicted_positives else 0.0

    add_check(
        checks,
        "false_positive_rate",
        fpr <= args.max_fpr,
        f"false_positive_rate={fpr:.6f}; limit={args.max_fpr:.6f}",
    )
    add_check(
        checks,
        "precision",
        precision >= args.min_precision,
        f"precision={precision:.6f}; minimum={args.min_precision:.6f}",
    )
    add_check(
        checks,
        "recall",
        recall >= args.min_recall,
        f"recall={recall:.6f}; minimum={args.min_recall:.6f}",
    )

    production_ready = model.get("production_ready")
    metrics_ok = all(check["ok"] for check in checks)
    allowed_by_development_override = production_ready is False and args.allow_development
    if production_ready is False:
        status = "development_blocked"
    else:
        status = "pass" if metrics_ok and production_ready is True else "fail"

    return {
        "ok": status == "pass",
        "status": status,
        "allowed_by_development_override": allowed_by_development_override,
        "model": str(args.model),
        "feature_schema": str(args.feature_schema),
        "fixtures": [str(path) for path in args.fixtures],
        "production_ready": production_ready,
        "sparse_missing_features_are_zero": True,
        "metrics": {
            "false_positive_rate": fpr,
            "false_positives": false_positives,
            "negative_rows": negatives,
            "precision": precision,
            "recall": recall,
            "positive_rows": positives,
            "predicted_positive_rows": predicted_positives,
            "true_positives": true_positives,
        },
        "limits": {
            "max_fpr": args.max_fpr,
            "min_precision": args.min_precision,
            "min_recall": args.min_recall,
        },
        "checks": checks,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path = path.resolve()
    parent = path.parent
    if parent.exists():
        metadata = os.stat(parent, follow_symlinks=False)
        if is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"Report directory must be a regular non-linked directory: {parent}")
    parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        metadata = os.stat(path, follow_symlinks=False)
        if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"Report output must be a regular non-linked file: {path}")

    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(temp_path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        metadata = os.stat(temp_path, follow_symlinks=False)
        if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"Temporary report output must be a regular non-linked file: {temp_path}")
        os.replace(temp_path, path)
    finally:
        try:
            if temp_path.exists():
                metadata = os.stat(temp_path, follow_symlinks=False)
                if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
                    raise SystemExit(f"Refusing to remove unsafe temporary report output: {temp_path}")
                temp_path.unlink()
        except FileNotFoundError as exc:
            if exc.filename is not None and Path(exc.filename) != temp_path:
                raise SystemExit(f"Unexpected missing temporary report output during cleanup: {exc.filename}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate a Zentor Native .zmodel on safe feature fixtures."
    )
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--feature-schema",
        default=str(Path(__file__).with_name("feature_schema.json")),
    )
    parser.add_argument("--fixtures", required=True, nargs="+")
    parser.add_argument("--max-fpr", type=float, default=0.005)
    parser.add_argument("--min-precision", type=float, default=0.98)
    parser.add_argument("--min-recall", type=float, default=0.90)
    parser.add_argument(
        "--allow-development",
        action="store_true",
        help="Exit successfully for production_ready=false while reporting development_blocked.",
    )
    parser.add_argument("--report", help="Optional JSON report output path.")
    args = parser.parse_args()

    for name in ("max_fpr", "min_precision", "min_recall"):
        value = getattr(args, name)
        if not math.isfinite(value) or value < 0.0 or value > 1.0:
            raise SystemExit(f"{name.replace('_', '-')} must be between 0 and 1.")

    report = evaluate(args)
    if args.report:
        write_report(Path(args.report), report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["ok"] and not report["allowed_by_development_override"]:
        sys.exit("Native model did not pass release validation.")


if __name__ == "__main__":
    main()
