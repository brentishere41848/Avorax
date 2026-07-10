#!/usr/bin/env python3
"""Exercise a packaged Avorax local core with health and harmless lifecycle checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


MAX_PROCESS_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_DIAGNOSTIC_CHARS = 4096


class SmokeError(RuntimeError):
    pass


def _bounded(value: object) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value))
    return text if len(text) <= MAX_DIAGNOSTIC_CHARS else text[: MAX_DIAGNOSTIC_CHARS - 3] + "..."


def _regular_executable(path: Path) -> Path:
    path = path.absolute()
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SmokeError(f"local core is not a regular non-link file: {path}")
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise SmokeError(f"local core is not executable: {path}")
    return path


def _invoke(core: Path, command: dict[str, Any], env: dict[str, str], timeout: int) -> dict[str, Any]:
    request = json.dumps(command, separators=(",", ":")) + "\n"
    try:
        completed = subprocess.run(
            [str(core)],
            input=request.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=core.parent,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise SmokeError(f"local core timed out after {timeout}s") from error
    if len(completed.stdout) > MAX_PROCESS_OUTPUT_BYTES or len(completed.stderr) > MAX_PROCESS_OUTPUT_BYTES:
        raise SmokeError("local core output exceeded the smoke-test limit")
    stdout = completed.stdout.decode("utf-8", errors="strict")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    if completed.returncode != 0:
        raise SmokeError(f"local core exited with {completed.returncode}: {_bounded(stderr)}")
    responses: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            response = json.loads(line)
        except json.JSONDecodeError as error:
            raise SmokeError(f"local core emitted non-JSON stdout: {_bounded(line)}") from error
        if not isinstance(response, dict):
            raise SmokeError("local core JSON response is not an object")
        if response.get("type") in {"scan_progress", "progress"}:
            continue
        responses.append(response)
    if not responses:
        raise SmokeError(f"local core produced no JSON response: {_bounded(stderr)}")
    return responses[-1]


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise SmokeError(f"smoke report target is not a regular file: {path}")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
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


def _write_signature_pack(engine: Path, fixture_hash: str) -> None:
    for child in ("signatures", "rules", "ml", "trust", "config"):
        (engine / child).mkdir(parents=True, exist_ok=True)
    canonical = (
        '{"compiler_version":null,"created_at":null,"format":"zentor-signature-pack-v1",'
        '"signatures":[{"action_policy":"quarantine_if_policy_allows","category":"testThreat",'
        '"confidence":"confirmed","created_at":"2026-07-06T00:00:00Z",'
        '"false_positive_notes":"Safe fixture hash only; no malware binary is included or generated.",'
        '"file_types":["*"],"id":"ZNE-SAFE-RELEASE-SMOKE-001","mask":null,'
        '"max_file_size":null,"min_file_size":null,'
        '"name":"Release smoke harmless known-bad hash fixture","offset":null,"pattern":"'
        + fixture_hash
        + '","required_context":[],"severity":"test","signature_type":"exact_hash",'
        '"updated_at":"2026-07-06T00:00:00Z","version":"1"}],"version":"1.0.0"}'
    )
    signature = {
        "id": "ZNE-SAFE-RELEASE-SMOKE-001",
        "name": "Release smoke harmless known-bad hash fixture",
        "version": "1",
        "category": "testThreat",
        "confidence": "confirmed",
        "severity": "test",
        "signature_type": "exact_hash",
        "pattern": fixture_hash,
        "mask": None,
        "offset": None,
        "file_types": ["*"],
        "min_file_size": None,
        "max_file_size": None,
        "required_context": [],
        "false_positive_notes": "Safe fixture hash only; no malware binary is included or generated.",
        "action_policy": "quarantine_if_policy_allows",
        "created_at": "2026-07-06T00:00:00Z",
        "updated_at": "2026-07-06T00:00:00Z",
    }
    pack = {
        "format": "zentor-signature-pack-v1",
        "version": "1.0.0",
        "compiler_version": None,
        "created_at": None,
        "pack_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "signatures": [signature],
    }
    (engine / "signatures" / "avorax_core.asig").write_text(
        json.dumps(pack, indent=2) + "\n", encoding="utf-8"
    )


def _confirmed(threat: dict[str, Any]) -> bool:
    return threat.get("confidence") == "confirmed" or "signature" in str(
        threat.get("reason_summary", "")
    ).lower()


def run_smoke(core: Path, packaged_engine_root: Path, timeout: int) -> dict[str, Any]:
    core = _regular_executable(core)
    packaged_engine_root = packaged_engine_root.absolute()
    if not (packaged_engine_root / "engine").is_dir():
        raise SmokeError(f"packaged engine directory is missing: {packaged_engine_root / 'engine'}")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="avorax-package-smoke-") as temporary:
        root = Path(temporary)
        base_env = os.environ.copy()
        base_env.update(
            {
                "AVORAX_DATA_DIR": str(root / "data"),
                "ZENTOR_LEGACY_DATA_DIR": str(root / "legacy-data"),
                "AVORAX_QUARANTINE_DIR": str(root / "quarantine"),
                "ZENTOR_ALLOWLIST_FILE": str(root / "allowlist.json"),
                "AVORAX_ENGINE_ROOT": str(packaged_engine_root),
            }
        )
        (root / "data").mkdir()
        (root / "legacy-data").mkdir()
        health = _invoke(core, {"command": "health"}, base_env, timeout)
        body = health.get("body", health)
        if health.get("ok") is not True or not isinstance(body, dict):
            raise SmokeError(f"packaged engine health failed: {_bounded(health)}")
        if body.get("engine_status") != "available" or body.get("native_self_test") is not True:
            raise SmokeError(f"packaged native engine is not ready: {_bounded(body)}")
        if not isinstance(body.get("native_signature_count"), int) or body["native_signature_count"] < 1:
            raise SmokeError("packaged native engine loaded no signatures")
        if not isinstance(body.get("native_rule_count"), int) or body["native_rule_count"] < 1:
            raise SmokeError("packaged native engine loaded no rules")

        fixture = b"harmless-known-bad-fixture"
        fixture_hash = hashlib.sha256(fixture).hexdigest()
        isolated_engine = root / "isolated-engine"
        _write_signature_pack(isolated_engine, fixture_hash)
        detect_path = root / "safe-release-detect.bin"
        quarantine_path = root / "safe-release-quarantine.bin"
        detect_path.write_bytes(fixture)
        quarantine_path.write_bytes(fixture)
        lifecycle_env = base_env.copy()
        lifecycle_env.pop("AVORAX_ENGINE_ROOT", None)
        lifecycle_env["AVORAX_ENGINE_DIR"] = str(isolated_engine)

        detect = _invoke(
            core,
            {
                "command": "scan_file",
                "path": str(detect_path),
                "action_mode": "detectOnly",
                "scan_kind": "custom",
            },
            lifecycle_env,
            timeout,
        )
        detect_threats = detect.get("threats")
        if (
            detect.get("status") != "threatsFound"
            or not isinstance(detect_threats, list)
            or not any(isinstance(item, dict) and _confirmed(item) for item in detect_threats)
            or detect.get("quarantined_files", 0) != 0
            or not detect_path.is_file()
        ):
            raise SmokeError(f"detect-only harmless fixture flow failed: {_bounded(detect)}")

        quarantine = _invoke(
            core,
            {
                "command": "scan_file",
                "path": str(quarantine_path),
                "action_mode": "autoQuarantineConfirmedOnly",
                "scan_kind": "custom",
            },
            lifecycle_env,
            timeout,
        )
        threats = quarantine.get("threats")
        quarantined = None
        if isinstance(threats, list):
            quarantined = next(
                (
                    item
                    for item in threats
                    if isinstance(item, dict)
                    and item.get("status") == "quarantined"
                    and _confirmed(item)
                ),
                None,
            )
        if (
            quarantine.get("status") != "threatsFound"
            or not isinstance(quarantined, dict)
            or not quarantined.get("quarantine_id")
            or not str(quarantined.get("quarantine_path", "")).endswith(".avoraxq")
            or quarantine_path.exists()
        ):
            raise SmokeError(f"quarantine harmless fixture flow failed: {_bounded(quarantine)}")

        listing = _invoke(core, {"command": "list_quarantine"}, lifecycle_env, timeout)
        records = listing.get("records")
        record = None
        if listing.get("ok") is True and isinstance(records, list):
            record = next(
                (
                    item
                    for item in records
                    if isinstance(item, dict)
                    and item.get("quarantine_id") == quarantined["quarantine_id"]
                    and item.get("status") == "quarantined"
                ),
                None,
            )
        if not isinstance(record, dict):
            raise SmokeError(f"quarantine listing did not contain the fixture: {_bounded(listing)}")

        restore = _invoke(
            core,
            {
                "command": "restore_quarantine_item",
                "quarantine_id": record["quarantine_id"],
                "confirmed": True,
            },
            lifecycle_env,
            timeout,
        )
        restored_record = restore.get("record")
        if (
            restore.get("ok") is not True
            or not isinstance(restored_record, dict)
            or restored_record.get("status") != "restored"
            or quarantine_path.read_bytes() != fixture
            or Path(record["quarantine_path"]).exists()
        ):
            raise SmokeError(f"quarantine restore flow failed: {_bounded(restore)}")

    return {
        "schema_version": 1,
        "status": "passed",
        "core": str(core),
        "packaged_engine_root": str(packaged_engine_root),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "engine_health": {
            "engine_status": body["engine_status"],
            "native_signature_count": body["native_signature_count"],
            "native_rule_count": body["native_rule_count"],
            "native_self_test": body["native_self_test"],
            "native_ml_production_ready": body.get("native_ml_production_ready"),
        },
        "verified_flows": [
            "packaged engine health",
            "detect-only confirmed harmless exact-hash fixture",
            "confirmed-only quarantine",
            "quarantine list",
            "integrity-preserving restore",
        ],
        "fixture_policy": {
            "live_malware_used": False,
            "standard_eicar_string_written": False,
            "network_access_required": False,
            "machine_wide_changes": False,
        },
        "technical_limits": [
            "local core and packaged engine proof only",
            "no installed GUI click-through proof",
            "no service, driver, or pre-execution blocking proof",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--engine-root", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report: dict[str, Any]
    try:
        if args.timeout < 1 or args.timeout > 600:
            raise SmokeError("timeout must be between 1 and 600 seconds")
        report = run_smoke(args.core, args.engine_root, args.timeout)
    except (SmokeError, OSError, UnicodeError, json.JSONDecodeError) as error:
        report = {
            "schema_version": 1,
            "status": "failed",
            "error": _bounded(error),
            "fixture_policy": {
                "live_malware_used": False,
                "standard_eicar_string_written": False,
                "network_access_required": False,
                "machine_wide_changes": False,
            },
        }
        if args.report:
            _write_json_atomic(args.report.absolute(), report)
        print(f"packaged local-core smoke failed: {_bounded(error)}", file=sys.stderr)
        return 1
    if args.report:
        _write_json_atomic(args.report.absolute(), report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
