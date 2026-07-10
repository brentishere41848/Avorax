#!/usr/bin/env python3
"""Create a deterministic SHA256SUMS file for Avorax release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import uuid
from pathlib import Path


ARTIFACT_SUFFIXES = (".msi", ".exe", ".deb", ".tar.gz", ".dmg")
READ_CHUNK_BYTES = 1024 * 1024
MAX_ARTIFACTS = 32


class ChecksumError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ChecksumError(f"release artifact is not a regular non-link file: {path}")
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
    if size != after.st_size or metadata.st_size != after.st_size:
        raise ChecksumError(f"release artifact changed while hashing: {path}")
    return digest.hexdigest()


def create_checksums(input_dir: Path, output: Path) -> list[tuple[str, str]]:
    input_dir = input_dir.absolute()
    if not input_dir.is_dir() or input_dir.is_symlink():
        raise ChecksumError(f"release input is not a regular directory: {input_dir}")
    output = output.absolute()
    artifacts = sorted(
        (
            path
            for path in input_dir.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and path.name.endswith(ARTIFACT_SUFFIXES)
        ),
        key=lambda path: path.name,
    )
    if not artifacts:
        raise ChecksumError("no release artifacts were found")
    if len(artifacts) > MAX_ARTIFACTS:
        raise ChecksumError(f"release artifact count exceeds {MAX_ARTIFACTS}")
    names = [path.name for path in artifacts]
    if len(set(names)) != len(names):
        raise ChecksumError("release artifact basenames must be unique")
    rows = [(path.name, _sha256(path)) for path in artifacts]
    payload = "".join(f"{digest}  {name}\n" for name, digest in rows).encode("ascii")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise ChecksumError(f"checksum output is not a regular file: {output}")
    temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        rows = create_checksums(args.input_dir, args.output)
    except (ChecksumError, OSError) as error:
        print(f"release checksum error: {error}", file=sys.stderr)
        return 1
    print(f"Created {args.output} for {len(rows)} release artifacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
