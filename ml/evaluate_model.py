#!/usr/bin/env python3
"""Validate offline Avorax static-model release metadata."""

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

MAX_METADATA_BYTES = 1024 * 1024
REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT_ATTRIBUTE
    )


def require_regular_metadata_file(path: Path) -> None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise SystemExit(f"Model metadata file does not exist: {path}") from exc
    except OSError as exc:
        raise SystemExit(f"Unable to inspect model metadata file {path}: {exc}") from exc

    if is_link_or_reparse(metadata):
        raise SystemExit(f"Model metadata file must not be a symbolic link or reparse point: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"Model metadata path is not a regular file: {path}")
    if metadata.st_size > MAX_METADATA_BYTES:
        raise SystemExit(
            f"Model metadata file exceeds {MAX_METADATA_BYTES} bytes: {path}"
        )


def load_metadata(path: Path) -> dict[str, Any]:
    require_regular_metadata_file(path)
    try:
        decoded = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Model metadata is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"Unable to read model metadata file {path}: {exc}") from exc
    if not isinstance(decoded, dict):
        raise SystemExit("Model metadata must be a JSON object.")
    return decoded


def metric_source(metadata: dict[str, Any]) -> dict[str, Any]:
    nested = metadata.get("metrics")
    if isinstance(nested, dict):
        return nested
    return metadata


def finite_unit_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0.0 or number > 1.0:
        return None
    return number


def add_check(
    checks: list[dict[str, Any]], name: str, ok: bool, detail: str
) -> None:
    checks.append({"name": name, "ok": ok, "detail": detail})


def validate_thresholds(metadata: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    thresholds = metadata.get("thresholds")
    if not isinstance(thresholds, dict):
        add_check(checks, "thresholds", False, "thresholds must be a JSON object")
        return

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
            return
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


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    metadata_path = Path(args.metadata)
    metadata = load_metadata(metadata_path)
    checks: list[dict[str, Any]] = []
    metrics = metric_source(metadata)

    production_ready = metadata.get("production_ready")
    add_check(
        checks,
        "production_ready_type",
        isinstance(production_ready, bool),
        "production_ready is a JSON boolean"
        if isinstance(production_ready, bool)
        else "production_ready must be a JSON boolean",
    )

    fpr = finite_unit_number(metrics.get("false_positive_rate"))
    precision = finite_unit_number(metrics.get("precision"))
    recall = finite_unit_number(metrics.get("recall"))

    add_check(
        checks,
        "false_positive_rate",
        fpr is not None and fpr <= args.max_fpr,
        f"false_positive_rate={fpr} limit={args.max_fpr}"
        if fpr is not None
        else "false_positive_rate must be a finite number between 0 and 1",
    )
    add_check(
        checks,
        "precision",
        precision is not None and precision >= args.min_precision,
        f"precision={precision} minimum={args.min_precision}"
        if precision is not None
        else "precision must be a finite number between 0 and 1",
    )
    add_check(
        checks,
        "recall",
        recall is not None and recall >= args.min_recall,
        f"recall={recall} minimum={args.min_recall}"
        if recall is not None
        else "recall must be a finite number between 0 and 1",
    )

    validation_count = metadata.get("validation_sample_count")
    validation_ok = isinstance(validation_count, int) and not isinstance(
        validation_count, bool
    ) and validation_count > 0
    add_check(
        checks,
        "validation_sample_count",
        validation_ok,
        f"validation_sample_count={validation_count}"
        if validation_ok
        else "validation_sample_count must be a positive integer",
    )

    validate_thresholds(metadata, checks)

    limitations = metadata.get("limitations")
    limitations_ok = isinstance(limitations, list) and all(
        isinstance(item, str) and item.strip() for item in limitations
    )
    if production_ready is False:
        add_check(
            checks,
            "development_limitations",
            limitations_ok,
            "development limitations are documented"
            if limitations_ok
            else "development models must document limitations",
        )

    metrics_ok = all(check["ok"] for check in checks)
    allowed_by_development_override = production_ready is False and args.allow_development
    if production_ready is False:
        status = "development_blocked"
    else:
        status = "pass" if metrics_ok and production_ready is True else "fail"
    ok = status == "pass"

    return {
        "ok": ok,
        "status": status,
        "allowed_by_development_override": allowed_by_development_override,
        "metadata": str(metadata_path),
        "model_name": metadata.get("model_name"),
        "model_version": metadata.get("model_version"),
        "production_ready": production_ready,
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
        description="Validate Avorax static ML model metadata before release use."
    )
    parser.add_argument("--metadata", required=True)
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
        sys.exit("Model metadata did not pass release validation.")


if __name__ == "__main__":
    main()
