#!/usr/bin/env python3
"""Checked output helpers for Avorax Native ML development tooling."""

from __future__ import annotations

import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Iterable

REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT_ATTRIBUTE
    )


def checked_output_directory(path: Path, description: str = "Output directory") -> None:
    if path.exists():
        try:
            metadata = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise SystemExit(f"Unable to inspect {description} {path}: {exc}") from exc
        if is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"{description} must be a regular non-linked directory: {path}")
    try:
        path.mkdir(parents=True, exist_ok=True)
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise SystemExit(f"Unable to create {description} {path}: {exc}") from exc
    if is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"{description} must be a regular non-linked directory: {path}")


def checked_output_file(path: Path, description: str = "Output file") -> Path:
    path = path.resolve()
    checked_output_directory(path.parent)
    if not path.exists():
        return path
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise SystemExit(f"Unable to inspect {description} {path}: {exc}") from exc
    if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{description} must be a regular non-linked file: {path}")
    return path


def _open_exclusive_temp(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="\n")


def _validate_temp_file(path: Path, description: str) -> None:
    metadata = os.stat(path, follow_symlinks=False)
    if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{description} temporary output must be a regular non-linked file: {path}")


def _cleanup_temp_file(path: Path, description: str) -> None:
    try:
        if path.exists():
            _validate_temp_file(path, description)
            path.unlink()
    except FileNotFoundError as exc:
        if exc.filename is not None and Path(exc.filename) != path:
            raise SystemExit(f"Unexpected missing {description} temporary output during cleanup: {exc.filename}") from exc


def write_json_atomic(
    path: Path,
    data: dict[str, Any],
    *,
    description: str = "JSON output",
) -> Path:
    path = checked_output_file(path, description)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with _open_exclusive_temp(temp_path) as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _validate_temp_file(temp_path, description)
        os.replace(temp_path, path)
    finally:
        _cleanup_temp_file(temp_path, description)
    return path


def write_jsonl_atomic(
    path: Path,
    rows: Iterable[dict[str, Any]],
    *,
    description: str = "JSONL output",
) -> Path:
    path = checked_output_file(path, description)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with _open_exclusive_temp(temp_path) as handle:
            for row in rows:
                handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _validate_temp_file(temp_path, description)
        os.replace(temp_path, path)
    finally:
        _cleanup_temp_file(temp_path, description)
    return path
