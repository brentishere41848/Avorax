#!/usr/bin/env python3
"""Shared validators for the offline Avorax static-ML tooling."""

from __future__ import annotations

import json
import math
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 1024 * 1024
MAX_JSONL_BYTES = 64 * 1024 * 1024
MAX_JSONL_LINE_BYTES = 1024 * 1024
MAX_JSONL_ROWS = 1_000_000
MAX_STRING_BYTES = 4096
REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

KNOWN_USER_LABELS = frozenset(
    {
        "falsePositive",
        "confirmedMalicious",
        "unsure",
        "trustedApp",
        "potentiallyUnwantedButAllowed",
    }
)
SUPERVISED_POSITIVE_LABELS = frozenset({"confirmedMalicious"})
SUPERVISED_NEGATIVE_LABELS = frozenset(
    {"falsePositive", "trustedApp", "potentiallyUnwantedButAllowed"}
)


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT_ATTRIBUTE
    )


@dataclass(frozen=True)
class FeatureSchema:
    required: tuple[str, ...]
    properties: dict[str, dict[str, Any]]


def require_regular_input_file(path: Path, description: str, max_bytes: int) -> None:
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


def checked_output_dir(path: Path) -> Path:
    if path.exists():
        metadata = os.stat(path, follow_symlinks=False)
        if is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"Output directory must be a regular non-linked directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    metadata = os.stat(path, follow_symlinks=False)
    if is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"Output directory must be a regular non-linked directory: {path}")
    return path


def checked_output_file(path: Path) -> Path:
    path = path.resolve()
    checked_output_dir(path.parent)
    if path.exists():
        metadata = os.stat(path, follow_symlinks=False)
        if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"Output file must be a regular non-linked file: {path}")
    return path


def _open_exclusive_text(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="\n")


def _open_exclusive_binary(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "wb")


def _validate_temp_output(path: Path) -> None:
    metadata = os.stat(path, follow_symlinks=False)
    if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"Temporary output must be a regular non-linked file: {path}")


def _cleanup_temp_output(path: Path) -> None:
    try:
        if path.exists():
            _validate_temp_output(path)
            path.unlink()
    except FileNotFoundError as exc:
        if exc.filename is not None and Path(exc.filename) != path:
            raise SystemExit(f"Unexpected missing temporary output during cleanup: {exc.filename}") from exc


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path = checked_output_file(path)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with _open_exclusive_text(temp_path) as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _validate_temp_output(temp_path)
        os.replace(temp_path, path)
    finally:
        _cleanup_temp_output(temp_path)


def write_jsonl_atomic(path: Path, rows: list[dict[str, Any]]) -> None:
    path = checked_output_file(path)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with _open_exclusive_text(temp_path) as handle:
            for row in rows:
                handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _validate_temp_output(temp_path)
        os.replace(temp_path, path)
    finally:
        _cleanup_temp_output(temp_path)


def write_bytes_atomic(path: Path, data: bytes) -> None:
    path = checked_output_file(path)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with _open_exclusive_binary(temp_path) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_temp_output(temp_path)
        os.replace(temp_path, path)
    finally:
        _cleanup_temp_output(temp_path)


def load_json_object(path: Path, description: str) -> dict[str, Any]:
    require_regular_input_file(path, description, MAX_JSON_BYTES)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{description} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"Unable to read {description} {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{description} must be a JSON object: {path}")
    return data


def load_feature_schema(path: Path) -> FeatureSchema:
    schema = load_json_object(path, "feature schema")
    required = schema.get("required")
    properties = schema.get("properties")
    if not isinstance(required, list) or not all(
        isinstance(item, str) and item for item in required
    ):
        raise SystemExit("feature schema required list is malformed")
    if not isinstance(properties, dict):
        raise SystemExit("feature schema properties object is malformed")

    typed_properties: dict[str, dict[str, Any]] = {}
    for name, rules in properties.items():
        if not isinstance(name, str) or not name:
            raise SystemExit("feature schema contains an invalid property name")
        if not isinstance(rules, dict):
            raise SystemExit(f"feature schema property {name} is malformed")
        typed_properties[name] = rules

    missing = [name for name in required if name not in typed_properties]
    if missing:
        raise SystemExit("feature schema required fields lack properties: " + ", ".join(missing))

    return FeatureSchema(required=tuple(required), properties=typed_properties)


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise SystemExit(f"{context} must be a string up to {MAX_STRING_BYTES} bytes")
    return value


def validate_feature_value(value: Any, rules: dict[str, Any], context: str) -> None:
    value_type = rules.get("type")
    if value_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise SystemExit(f"{context} must be an integer")
        minimum = rules.get("minimum")
        maximum = rules.get("maximum")
        if isinstance(minimum, int) and value < minimum:
            raise SystemExit(f"{context} must be >= {minimum}")
        if isinstance(maximum, int) and value > maximum:
            raise SystemExit(f"{context} must be <= {maximum}")
        return

    if value_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SystemExit(f"{context} must be a number")
        number = float(value)
        if not math.isfinite(number):
            raise SystemExit(f"{context} must be finite")
        minimum = rules.get("minimum")
        maximum = rules.get("maximum")
        if isinstance(minimum, (int, float)) and number < float(minimum):
            raise SystemExit(f"{context} must be >= {minimum}")
        if isinstance(maximum, (int, float)) and number > float(maximum):
            raise SystemExit(f"{context} must be <= {maximum}")
        return

    if value_type == "string":
        text = _require_string(value, context)
        enum = rules.get("enum")
        if isinstance(enum, list) and text not in enum:
            raise SystemExit(f"{context} has unsupported value: {text}")
        return

    if value_type == "boolean":
        if not isinstance(value, bool):
            raise SystemExit(f"{context} must be a boolean")
        return

    raise SystemExit(f"{context} has unsupported schema type: {value_type}")


def validate_features(features: Any, schema: FeatureSchema, context: str) -> None:
    if not isinstance(features, dict):
        raise SystemExit(f"{context} must be a JSON object")

    missing = [name for name in schema.required if name not in features]
    if missing:
        raise SystemExit(f"{context} missing required features: {', '.join(missing)}")

    unknown = [name for name in features if name not in schema.properties]
    if unknown:
        raise SystemExit(f"{context} contains unknown features: {', '.join(unknown)}")

    for name, rules in schema.properties.items():
        if name in features:
            validate_feature_value(features[name], rules, f"{context}.{name}")


def validate_feature_row(
    row: Any,
    schema: FeatureSchema,
    context: str,
    require_user_label: bool,
) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise SystemExit(f"{context} must be a JSON object")
    if "extracted_features" not in row:
        raise SystemExit(f"{context} missing extracted_features")
    validate_features(row["extracted_features"], schema, f"{context}.extracted_features")

    label = row.get("user_label")
    if require_user_label and label is None:
        raise SystemExit(f"{context} missing user_label")
    if label is not None and label not in KNOWN_USER_LABELS:
        raise SystemExit(f"{context}.user_label has unsupported value: {label}")

    for field_name in ("file_sha256", "file_name", "label_id", "app_version", "model_version"):
        if field_name in row:
            _require_string(row[field_name], f"{context}.{field_name}")

    return row


def load_validated_jsonl_rows(
    path: Path,
    schema: FeatureSchema,
    *,
    require_user_label: bool,
    max_rows: int = MAX_JSONL_ROWS,
) -> list[dict[str, Any]]:
    if max_rows <= 0 or max_rows > MAX_JSONL_ROWS:
        raise SystemExit(f"max rows must be between 1 and {MAX_JSONL_ROWS}")

    require_regular_input_file(path, "feature JSONL input", MAX_JSONL_BYTES)
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                if len(line.encode("utf-8")) > MAX_JSONL_LINE_BYTES:
                    raise SystemExit(
                        f"{path}:{line_number} exceeds {MAX_JSONL_LINE_BYTES} bytes"
                    )
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    decoded = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise SystemExit(f"{path}:{line_number} is not valid JSON: {exc}") from exc
                rows.append(
                    validate_feature_row(
                        decoded,
                        schema,
                        f"{path}:{line_number}",
                        require_user_label=require_user_label,
                    )
                )
                if len(rows) > max_rows:
                    raise SystemExit(f"{path} contains more than {max_rows} rows")
    except OSError as exc:
        raise SystemExit(f"Unable to read feature JSONL input {path}: {exc}") from exc

    if not rows:
        raise SystemExit(f"{path} contains no feature rows")
    return rows
