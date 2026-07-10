#!/usr/bin/env python3
"""Create a deterministic CycloneDX inventory from reviewed lockfiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tomllib
import urllib.parse
import uuid
from pathlib import Path
from typing import Any


MAX_LOCKFILE_BYTES = 2 * 1024 * 1024
MAX_COMPONENTS = 4096
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?$")
PACKAGE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
PACKAGE_VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REQUIREMENT_PATTERN = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127})$"
)


class SbomError(RuntimeError):
    pass


class ComponentRecord:
    def __init__(
        self,
        ecosystem: str,
        name: str,
        version: str,
        purl: str,
        checksum: str | None,
        origin: str,
        source: str,
        dependency_kind: str,
    ) -> None:
        self.ecosystem = ecosystem
        self.name = name
        self.version = version
        self.purl = purl
        self.checksum = checksum
        self.origins = {origin}
        self.sources = {source}
        self.dependency_kinds = {dependency_kind}


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    file_attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(file_attributes & reparse_flag)


def _assert_no_link_ancestors(path: Path, description: str) -> None:
    current = path.absolute()
    while True:
        if current.exists() and _is_link_or_reparse(current.lstat()):
            raise SbomError(f"{description} traverses a link/reparse point: {current}")
        if current.parent == current:
            return
        current = current.parent


def _read_regular_utf8(path: Path) -> str:
    path = path.absolute()
    _assert_no_link_ancestors(path.parent, "lockfile path")
    before = path.lstat()
    if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise SbomError(f"lockfile is not a regular non-link file: {path}")
    if before.st_size > MAX_LOCKFILE_BYTES:
        raise SbomError(f"lockfile exceeds {MAX_LOCKFILE_BYTES} bytes: {path}")
    with path.open("rb") as handle:
        payload = handle.read(MAX_LOCKFILE_BYTES + 1)
    if len(payload) > MAX_LOCKFILE_BYTES:
        raise SbomError(f"lockfile exceeds {MAX_LOCKFILE_BYTES} bytes: {path}")
    after = path.lstat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(payload) != after.st_size:
        raise SbomError(f"lockfile changed while reading: {path}")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise SbomError(f"lockfile is not valid UTF-8: {path}") from error
    if "\x00" in text or "\t" in text:
        raise SbomError(f"lockfile contains unsupported control characters: {path}")
    return text


def _validate_package(name: str, version: str, description: str) -> None:
    if not PACKAGE_NAME_PATTERN.fullmatch(name):
        raise SbomError(f"{description} has invalid package name: {name!r}")
    if not PACKAGE_VERSION_PATTERN.fullmatch(version):
        raise SbomError(f"{description} has invalid package version: {version!r}")


def _purl(ecosystem: str, name: str, version: str) -> str:
    normalized = name.lower().replace("_", "-") if ecosystem == "pypi" else name
    encoded = urllib.parse.quote(normalized, safe="._-~")
    return f"pkg:{ecosystem}/{encoded}@{urllib.parse.quote(version, safe='.+_-~')}"


def _add_component(
    records: dict[str, ComponentRecord],
    *,
    ecosystem: str,
    name: str,
    version: str,
    checksum: str | None,
    origin: str,
    source: str,
    dependency_kind: str,
) -> None:
    _validate_package(name, version, origin)
    if checksum is not None and not SHA256_PATTERN.fullmatch(checksum):
        raise SbomError(f"{origin} has invalid SHA-256 for {name} {version}")
    purl = _purl(ecosystem, name, version)
    existing = records.get(purl)
    if existing is None:
        if len(records) >= MAX_COMPONENTS:
            raise SbomError(f"component count exceeds {MAX_COMPONENTS}")
        records[purl] = ComponentRecord(
            ecosystem,
            name,
            version,
            purl,
            checksum,
            origin,
            source,
            dependency_kind,
        )
        return
    if existing.checksum and checksum and existing.checksum != checksum:
        raise SbomError(f"conflicting SHA-256 values for {purl}")
    if existing.checksum is None:
        existing.checksum = checksum
    existing.origins.add(origin)
    existing.sources.add(source)
    existing.dependency_kinds.add(dependency_kind)


def add_cargo_lock(records: dict[str, ComponentRecord], path: Path) -> None:
    text = _read_regular_utf8(path)
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise SbomError(f"Cargo lockfile is invalid TOML: {path}: {error}") from error
    packages = document.get("package")
    if not isinstance(packages, list) or not packages:
        raise SbomError(f"Cargo lockfile has no package entries: {path}")
    origin = path.as_posix()
    for package in packages:
        if not isinstance(package, dict):
            raise SbomError(f"Cargo lockfile package entry is not an object: {path}")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source", "workspace-or-path")
        checksum = package.get("checksum")
        if not isinstance(name, str) or not isinstance(version, str):
            raise SbomError(f"Cargo lockfile package is missing name/version: {path}")
        if not isinstance(source, str) or (checksum is not None and not isinstance(checksum, str)):
            raise SbomError(f"Cargo lockfile package has invalid source/checksum: {path}")
        _add_component(
            records,
            ecosystem="cargo",
            name=name,
            version=version,
            checksum=checksum,
            origin=origin,
            source=source,
            dependency_kind="locked",
        )


def _yaml_scalar(value: str, description: str) -> str:
    value = value.strip()
    if not value:
        raise SbomError(f"missing scalar value for {description}")
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as error:
            raise SbomError(f"invalid quoted scalar for {description}") from error
        if not isinstance(parsed, str):
            raise SbomError(f"non-string scalar for {description}")
        return parsed
    if not re.fullmatch(r"[0-9A-Za-z_.+:/<>= -]+", value):
        raise SbomError(f"unsupported scalar for {description}: {value!r}")
    return value


def add_pub_lock(records: dict[str, ComponentRecord], path: Path) -> None:
    lines = _read_regular_utf8(path).splitlines()
    try:
        package_start = lines.index("packages:") + 1
        sdk_start = lines.index("sdks:")
    except ValueError as error:
        raise SbomError(f"pub lockfile is missing packages/sdks sections: {path}") from error
    if package_start >= sdk_start:
        raise SbomError(f"pub lockfile packages section is empty: {path}")
    blocks: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []
    for line in lines[package_start:sdk_start]:
        match = re.fullmatch(r"  ([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}):", line)
        if match:
            if current_name is not None:
                blocks.append((current_name, current_lines))
            current_name = match.group(1)
            current_lines = []
            continue
        if current_name is None or not line.startswith("    "):
            raise SbomError(f"unexpected pub lockfile structure in {path}: {line!r}")
        current_lines.append(line)
    if current_name is not None:
        blocks.append((current_name, current_lines))
    if not blocks:
        raise SbomError(f"pub lockfile has no package entries: {path}")

    origin = path.as_posix()
    for package_name, block in blocks:
        fields: dict[str, str] = {}
        description: dict[str, str] = {}
        in_description = False
        for line in block:
            nested = re.fullmatch(r"      ([A-Za-z0-9_-]+):\s*(.+)", line)
            if nested and in_description:
                nested_key = nested.group(1)
                if nested_key in description:
                    raise SbomError(
                        f"duplicate pub description field {nested_key!r} in {path}"
                    )
                description[nested_key] = _yaml_scalar(
                    nested.group(2), f"{origin} {package_name} description"
                )
                continue
            field = re.fullmatch(r"    ([A-Za-z0-9_-]+):(?:\s*(.*))?", line)
            if not field:
                raise SbomError(f"unexpected pub package field in {path}: {line!r}")
            key, raw_value = field.group(1), field.group(2) or ""
            if key not in {"dependency", "description", "source", "version"}:
                raise SbomError(f"unsupported pub package field {key!r} in {path}")
            in_description = key == "description" and not raw_value.strip()
            if not in_description:
                if key in fields:
                    raise SbomError(f"duplicate pub package field {key!r} in {path}")
                fields[key] = _yaml_scalar(raw_value, f"{origin} {package_name} {key}")
        source = fields.get("source")
        version = fields.get("version")
        dependency_kind = fields.get("dependency")
        if source not in {"hosted", "sdk", "path", "git"}:
            raise SbomError(f"unsupported pub source for {package_name} in {path}: {source!r}")
        if version is None or dependency_kind is None:
            raise SbomError(f"pub package is missing version/dependency in {path}: {package_name}")
        described_name = description.get("name", package_name)
        if described_name != package_name:
            raise SbomError(f"pub package name mismatch in {path}: {package_name}/{described_name}")
        checksum = description.get("sha256")
        if source == "hosted":
            if description.get("url") != "https://pub.dev" or checksum is None:
                raise SbomError(
                    f"hosted pub package lacks pub.dev SHA-256 evidence: {package_name}"
                )
        elif checksum is not None:
            raise SbomError(f"non-hosted pub package has unexpected SHA-256: {package_name}")
        _add_component(
            records,
            ecosystem="pub",
            name=package_name,
            version=version,
            checksum=checksum,
            origin=origin,
            source=source,
            dependency_kind=dependency_kind,
        )


def add_requirements_lock(records: dict[str, ComponentRecord], path: Path) -> None:
    origin = path.as_posix()
    found = 0
    for raw_line in _read_regular_utf8(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = REQUIREMENT_PATTERN.fullmatch(line)
        if not match:
            raise SbomError(f"Python requirement is not exact-pinned: {origin}: {line!r}")
        found += 1
        _add_component(
            records,
            ecosystem="pypi",
            name=match.group("name"),
            version=match.group("version"),
            checksum=None,
            origin=origin,
            source="exact-version-lock",
            dependency_kind="verification",
        )
    if found == 0:
        raise SbomError(f"Python requirements lock is empty: {origin}")


def create_bom(
    *,
    version: str,
    cargo_locks: list[Path],
    pub_locks: list[Path],
    requirements_locks: list[Path],
) -> dict[str, Any]:
    if not VERSION_PATTERN.fullmatch(version):
        raise SbomError(f"invalid Avorax version: {version!r}")
    if not cargo_locks or not pub_locks or not requirements_locks:
        raise SbomError("at least one Cargo, pub, and Python lockfile is required")
    records: dict[str, ComponentRecord] = {}
    for path in cargo_locks:
        add_cargo_lock(records, path)
    for path in pub_locks:
        add_pub_lock(records, path)
    for path in requirements_locks:
        add_requirements_lock(records, path)

    components: list[dict[str, Any]] = []
    for purl in sorted(records):
        record = records[purl]
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": record.purl,
            "name": record.name,
            "version": record.version,
            "purl": record.purl,
            "properties": [
                {
                    "name": "avorax:dependency-kinds",
                    "value": ",".join(sorted(record.dependency_kinds)),
                },
                {"name": "avorax:ecosystem", "value": record.ecosystem},
                {"name": "avorax:license-review-status", "value": "not-recorded-in-lockfile"},
                {"name": "avorax:lockfiles", "value": ",".join(sorted(record.origins))},
                {"name": "avorax:sources", "value": ",".join(sorted(record.sources))},
            ],
        }
        if record.checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": record.checksum}]
        components.append(component)

    component_digest = hashlib.sha256(
        json.dumps(components, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    application_ref = f"pkg:generic/avorax@{version}"
    serial = uuid.uuid5(uuid.NAMESPACE_URL, application_ref + "/" + component_digest)
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": application_ref,
                "name": "Avorax Anti-Virus",
                "version": version,
                "purl": application_ref,
            },
            "properties": [
                {"name": "avorax:component-inventory-scope", "value": "reviewed-lockfiles"},
                {"name": "avorax:final-binary-resolution", "value": "false"},
                {"name": "avorax:license-review-status", "value": "partial"},
                {"name": "avorax:machine-wide-installation", "value": "false"},
                {"name": "avorax:network-access-required", "value": "false"},
            ],
        },
        "components": components,
        "compositions": [
            {
                "aggregate": "incomplete",
                "assemblies": [application_ref],
                "dependencies": [component["bom-ref"] for component in components],
            }
        ],
    }


def _write_atomic(output: Path, bom: dict[str, Any]) -> None:
    output = output.absolute()
    if not output.parent.is_dir():
        raise SbomError(f"SBOM output directory does not exist: {output.parent}")
    _assert_no_link_ancestors(output.parent, "SBOM output path")
    if output.exists() and (
        _is_link_or_reparse(output.lstat())
        or not output.is_file()
        or output.lstat().st_nlink != 1
    ):
        raise SbomError(f"SBOM output is not a regular file: {output}")
    payload = (json.dumps(bom, indent=2, sort_keys=True) + "\n").encode("utf-8")
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--cargo-lock", action="append", required=True, type=Path)
    parser.add_argument("--pub-lock", action="append", required=True, type=Path)
    parser.add_argument("--requirements-lock", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        bom = create_bom(
            version=args.version,
            cargo_locks=args.cargo_lock,
            pub_locks=args.pub_lock,
            requirements_locks=args.requirements_lock,
        )
        _write_atomic(args.output, bom)
    except (OSError, SbomError) as error:
        print(f"dependency SBOM error: {error}", file=sys.stderr)
        return 1
    print(
        f"Created {args.output} with {len(bom['components'])} lockfile components; "
        "license review remains partial."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
