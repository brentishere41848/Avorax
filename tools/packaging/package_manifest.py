#!/usr/bin/env python3
"""Create and verify bounded integrity manifests for Avorax desktop bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


MANIFEST_NAME = "install-manifest.json"
MAX_FILES = 50_000
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_RELATIVE_PATH_CHARS = 4096
READ_CHUNK_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
ALLOWED_PLATFORMS = {"linux-x64", "macos-arm64", "macos-x64"}
ALLOWED_SIGNING = {"unsigned", "ad-hoc", "developer-id"}


CAPABILITIES: dict[str, dict[str, str]] = {
    "linux-x64": {
        "quick_full_custom_scans": "included",
        "quarantine_restore_delete": "included",
        "allowlist_exclusions_logs": "included",
        "real_time_file_process_observation": "partial_user_mode",
        "background_system_service": "disabled_not_packaged",
        "pre_execution_blocking": "disabled_no_kernel_component",
        "in_app_binary_update_apply": "disabled_manual_reinstall_required",
    },
    "macos-arm64": {
        "quick_full_custom_scans": "included",
        "quarantine_restore_delete": "included",
        "allowlist_exclusions_logs": "included",
        "real_time_file_process_observation": "partial_user_mode",
        "background_system_service": "disabled_not_packaged",
        "pre_execution_blocking": "disabled_no_endpoint_security_extension",
        "in_app_binary_update_apply": "disabled_manual_reinstall_required",
    },
    "macos-x64": {
        "quick_full_custom_scans": "included",
        "quarantine_restore_delete": "included",
        "allowlist_exclusions_logs": "included",
        "real_time_file_process_observation": "partial_user_mode",
        "background_system_service": "disabled_not_packaged",
        "pre_execution_blocking": "disabled_no_endpoint_security_extension",
        "in_app_binary_update_apply": "disabled_manual_reinstall_required",
    },
}


class ManifestError(RuntimeError):
    pass


def _is_reparse(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _assert_safe_existing_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ManifestError(f"{label} must be an absolute path: {path}")
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ManifestError(f"{label} does not exist: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        raise ManifestError(f"{label} must not be a link or reparse point: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ManifestError(f"{label} is not a directory: {path}")
    return path


def _safe_relative_path(relative: str) -> PurePosixPath:
    if not isinstance(relative, str) or not relative or len(relative) > MAX_RELATIVE_PATH_CHARS:
        raise ManifestError("manifest file path is empty or too long")
    if "\\" in relative or relative.startswith("/"):
        raise ManifestError(f"manifest file path is not normalized: {relative!r}")
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ManifestError(f"manifest file path is unsafe: {relative!r}")
    if path.as_posix() != relative:
        raise ManifestError(f"manifest file path is not canonical: {relative!r}")
    return path


def _safe_symlink_target(root: Path, path: Path) -> str:
    target = os.readlink(path)
    if not target or "\\" in target or os.path.isabs(target):
        raise ManifestError(f"bundle symlink target is not a relative POSIX path: {path} -> {target!r}")
    target_path = PurePosixPath(target)
    if any(part in {"", ".", ".."} for part in target_path.parts):
        raise ManifestError(f"bundle symlink target is unsafe: {path} -> {target!r}")
    resolved_root = root.resolve(strict=True)
    try:
        resolved_target = (path.parent / Path(*target_path.parts)).resolve(strict=True)
        resolved_target.relative_to(resolved_root)
    except (FileNotFoundError, ValueError) as error:
        raise ManifestError(f"bundle symlink escapes the bundle or has no target: {path}") from error
    return target_path.as_posix()


def _walk_bundle_entries(root: Path) -> list[tuple[str, str, Path, os.stat_result, str | None]]:
    files: list[tuple[str, str, Path, os.stat_result, str | None]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                entry_path = Path(entry.path)
                metadata = entry.stat(follow_symlinks=False)
                relative = entry_path.relative_to(root).as_posix()
                _safe_relative_path(relative)
                if entry.is_symlink():
                    if os.name == "nt":
                        raise ManifestError(f"Windows bundle contains a link: {entry_path}")
                    files.append(
                        (
                            relative,
                            "symlink",
                            entry_path,
                            metadata,
                            _safe_symlink_target(root, entry_path),
                        )
                    )
                    if len(files) > MAX_FILES:
                        raise ManifestError(f"bundle exceeds the {MAX_FILES} entry limit")
                    continue
                if _is_reparse(metadata):
                    raise ManifestError(f"bundle contains a reparse point: {entry_path}")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(entry_path)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise ManifestError(f"bundle contains a non-regular file: {entry_path}")
                if relative == MANIFEST_NAME:
                    continue
                files.append((relative, "file", entry_path, metadata, None))
                if len(files) > MAX_FILES:
                    raise ManifestError(f"bundle exceeds the {MAX_FILES} entry limit")
    files.sort(key=lambda item: item[0])
    return files


def _hash_regular_file(path: Path, expected: os.stat_result | None = None) -> tuple[str, int]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or _is_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise ManifestError(f"bundle file is not a regular non-link file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    after = path.lstat()
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or size != after.st_size
    ):
        raise ManifestError(f"bundle file changed while hashing: {path}")
    if expected is not None and expected.st_size != after.st_size:
        raise ManifestError(f"bundle file size changed during enumeration: {path}")
    return digest.hexdigest(), size


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_MANIFEST_BYTES:
        raise ManifestError(f"manifest exceeds the {MAX_MANIFEST_BYTES} byte limit")
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise ManifestError(f"manifest target is not a regular non-link file: {path}")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def create_manifest(root: Path, version: str, platform: str, signing: str) -> dict[str, Any]:
    root = _assert_safe_existing_directory(root, "bundle root")
    if not VERSION_RE.fullmatch(version):
        raise ManifestError(f"version is invalid: {version!r}")
    if platform not in ALLOWED_PLATFORMS:
        raise ManifestError(f"unsupported package platform: {platform!r}")
    if signing not in ALLOWED_SIGNING:
        raise ManifestError(f"unsupported signing status: {signing!r}")

    file_rows: list[dict[str, Any]] = []
    total_bytes = 0
    for relative, entry_type, path, metadata, target in _walk_bundle_entries(root):
        if entry_type == "symlink":
            file_rows.append({"path": relative, "type": "symlink", "target": target})
        else:
            sha256, size = _hash_regular_file(path, metadata)
            file_rows.append(
                {"path": relative, "type": "file", "bytes": size, "sha256": sha256}
            )
            total_bytes += size

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "product": "Avorax Anti-Virus",
        "version": version,
        "platform": platform,
        "package_profile": "desktop-beta",
        "signing_status": signing,
        "capabilities": CAPABILITIES[platform],
        "integrity_scope": (
            "Detects accidental or post-build file changes. This unsigned manifest "
            "does not authenticate publisher identity."
        ),
        "file_count": len(file_rows),
        "total_bytes": total_bytes,
        "files": file_rows,
    }
    _write_json_atomic(root / MANIFEST_NAME, manifest)
    return manifest


def _load_manifest(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ManifestError(f"manifest is not a regular non-link file: {path}")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        raise ManifestError(f"manifest exceeds the {MAX_MANIFEST_BYTES} byte limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"manifest is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise ManifestError("manifest root must be an object")
    return value


def _validate_manifest_header(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != 1:
        raise ManifestError("manifest schema_version must be 1")
    if manifest.get("product") != "Avorax Anti-Virus":
        raise ManifestError("manifest product is invalid")
    version = manifest.get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ManifestError("manifest version is invalid")
    platform = manifest.get("platform")
    if platform not in ALLOWED_PLATFORMS:
        raise ManifestError("manifest platform is invalid")
    if manifest.get("signing_status") not in ALLOWED_SIGNING:
        raise ManifestError("manifest signing_status is invalid")
    if manifest.get("capabilities") != CAPABILITIES[platform]:
        raise ManifestError("manifest capabilities do not match the platform profile")


def verify_manifest(root: Path) -> dict[str, Any]:
    root = _assert_safe_existing_directory(root, "bundle root")
    manifest_path = root / MANIFEST_NAME
    manifest = _load_manifest(manifest_path)
    _validate_manifest_header(manifest)
    rows = manifest.get("files")
    if not isinstance(rows, list) or len(rows) > MAX_FILES:
        raise ManifestError("manifest files must be a bounded array")

    expected_paths: set[str] = set()
    verified_bytes = 0
    for row in rows:
        if not isinstance(row, dict) or row.get("type") not in {"file", "symlink"}:
            raise ManifestError("manifest file row has an invalid shape")
        relative = row["path"]
        path_parts = _safe_relative_path(relative)
        if relative in expected_paths:
            raise ManifestError(f"manifest contains a duplicate path: {relative}")
        expected_paths.add(relative)
        path = root.joinpath(*path_parts.parts)
        if row["type"] == "symlink":
            if set(row) != {"path", "type", "target"}:
                raise ManifestError(f"manifest symlink row has an invalid shape: {relative}")
            target = row["target"]
            if not isinstance(target, str) or _safe_symlink_target(root, path) != target:
                raise ManifestError(f"bundle symlink target mismatch for {relative}")
            continue
        if set(row) != {"path", "type", "bytes", "sha256"}:
            raise ManifestError(f"manifest file row has an invalid shape: {relative}")
        expected_size = row["bytes"]
        expected_hash = row["sha256"]
        if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
            raise ManifestError(f"manifest file size is invalid: {relative}")
        if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
            raise ManifestError(f"manifest SHA-256 is invalid: {relative}")
        actual_hash, actual_size = _hash_regular_file(path)
        if actual_size != expected_size:
            raise ManifestError(
                f"bundle file size mismatch for {relative}: expected {expected_size}, got {actual_size}"
            )
        if actual_hash != expected_hash:
            raise ManifestError(f"bundle file SHA-256 mismatch for {relative}")
        verified_bytes += actual_size

    actual_paths = {relative for relative, _, _, _, _ in _walk_bundle_entries(root)}
    if actual_paths != expected_paths:
        missing = sorted(expected_paths - actual_paths)
        unlisted = sorted(actual_paths - expected_paths)
        raise ManifestError(
            f"bundle file set mismatch; missing={missing[:10]!r}; unlisted={unlisted[:10]!r}"
        )
    if manifest.get("file_count") != len(rows) or manifest.get("total_bytes") != verified_bytes:
        raise ManifestError("manifest aggregate counts do not match verified files")
    return {
        "status": "passed",
        "platform": manifest["platform"],
        "version": manifest["version"],
        "signing_status": manifest["signing_status"],
        "verified_files": len(rows),
        "verified_bytes": verified_bytes,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="create a bundle manifest")
    create.add_argument("--root", required=True, type=Path)
    create.add_argument("--version", required=True)
    create.add_argument("--platform", required=True, choices=sorted(ALLOWED_PLATFORMS))
    create.add_argument("--signing-status", required=True, choices=sorted(ALLOWED_SIGNING))
    verify = subparsers.add_parser("verify", help="verify a bundle manifest")
    verify.add_argument("--root", required=True, type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        root = args.root.absolute()
        if args.command == "create":
            result = create_manifest(root, args.version, args.platform, args.signing_status)
            summary = {
                "status": "created",
                "platform": result["platform"],
                "version": result["version"],
                "file_count": result["file_count"],
                "total_bytes": result["total_bytes"],
            }
        else:
            summary = verify_manifest(root)
    except (ManifestError, OSError) as error:
        print(f"package manifest error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
