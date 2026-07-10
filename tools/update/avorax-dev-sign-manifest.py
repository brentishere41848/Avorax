#!/usr/bin/env python
"""Sign an Avorax .aup manifest with the development Ed25519 key.

This helper is intentionally for dev-channel packages. Production releases should
provide AVORAX_UPDATE_SIGNER and AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX from a
protected signing environment instead of using the all-zero development seed.
"""
from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEV_PRIVATE_KEY_HEX = "0" * 64
MAX_MANIFEST_BYTES = 1024 * 1024
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_reparse_point(file_stat: os.stat_result) -> bool:
    return bool(getattr(file_stat, "st_file_attributes", 0) & REPARSE_POINT_ATTRIBUTE)


def _require_absolute_path(path: Path, description: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{description} must be an absolute path")
    if os.name == "nt" and not re.fullmatch(r"[A-Za-z]:", path.drive):
        raise ValueError(f"{description} must be on a local Windows drive")
    return path


def _require_no_link_ancestors(path: Path, description: str) -> None:
    current = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts[:-1]:
        current = current / part
        try:
            ancestor_stat = current.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(ancestor_stat.st_mode) or _is_reparse_point(ancestor_stat):
            raise ValueError(
                f"{description} must not traverse a link or reparse point: {current}"
            )
        if not stat.S_ISDIR(ancestor_stat.st_mode):
            raise ValueError(f"{description} ancestor is not a directory: {current}")


def _require_regular_input_file(path: Path, description: str) -> os.stat_result:
    _require_absolute_path(path, description)
    _require_no_link_ancestors(path, description)
    file_stat = path.lstat()
    if stat.S_ISLNK(file_stat.st_mode) or _is_reparse_point(file_stat):
        raise ValueError(f"{description} must not be a link or reparse point: {path}")
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"{description} must be a regular file: {path}")
    if file_stat.st_size > MAX_MANIFEST_BYTES:
        raise ValueError(
            f"{description} exceeds {MAX_MANIFEST_BYTES} bytes: {file_stat.st_size}"
        )
    return file_stat


def _require_existing_directory(path: Path, description: str) -> None:
    _require_absolute_path(path, description)
    _require_no_link_ancestors(path, description)
    dir_stat = path.lstat()
    if stat.S_ISLNK(dir_stat.st_mode) or _is_reparse_point(dir_stat):
        raise ValueError(f"{description} must not be a link or reparse point: {path}")
    if not stat.S_ISDIR(dir_stat.st_mode):
        raise ValueError(f"{description} must be a directory: {path}")


def _require_new_output_file(path: Path, description: str) -> None:
    _require_absolute_path(path, description)
    _require_no_link_ancestors(path, description)
    _require_existing_directory(path.parent, f"{description} directory")
    try:
        output_stat = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(output_stat.st_mode) or _is_reparse_point(output_stat):
        raise ValueError(f"{description} must not be a link or reparse point: {path}")
    raise FileExistsError(f"{description} already exists: {path}")


def _write_new_signature(path: Path, signature_hex: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as signature_file:
        signature_file.write(signature_hex)
        signature_file.write("\n")


def _load_private_key_bytes() -> bytes:
    private_key_hex = os.environ.get("AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX")
    if private_key_hex is None or private_key_hex.strip() == "":
        allow_dev_key = os.environ.get("AVORAX_ALLOW_DEV_UPDATE_SIGNING", "").strip().lower()
        if allow_dev_key not in {"1", "true", "yes"}:
            raise ValueError(
                "AVORAX_UPDATE_SIGNING_PRIVATE_KEY_HEX is required unless "
                "AVORAX_ALLOW_DEV_UPDATE_SIGNING=1 is set for dev-channel signing"
            )
        private_key_hex = DEV_PRIVATE_KEY_HEX
    else:
        private_key_hex = private_key_hex.strip()

    if len(private_key_hex) not in (64, 128) or not HEX_RE.fullmatch(private_key_hex):
        raise ValueError(
            "Ed25519 private key must be 64 or 128 hexadecimal characters"
        )

    key_bytes = bytes.fromhex(private_key_hex)
    if len(key_bytes) not in (32, 64):
        raise ValueError("Ed25519 private key must be a 32-byte seed or 64-byte expanded key")
    return key_bytes[:32]


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: avorax-dev-sign-manifest.py <manifest.json> <manifest.sig>",
            file=sys.stderr,
        )
        return 2

    manifest_path = _require_absolute_path(Path(sys.argv[1]), "manifest path")
    signature_path = _require_absolute_path(Path(sys.argv[2]), "signature path")
    _require_regular_input_file(manifest_path, "manifest path")
    _require_new_output_file(signature_path, "signature output")

    signing_key = Ed25519PrivateKey.from_private_bytes(_load_private_key_bytes())
    signature = signing_key.sign(manifest_path.read_bytes())
    _write_new_signature(signature_path, signature.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
