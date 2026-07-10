#!/usr/bin/env sh
set -eu

REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if [ -z "${CARGO:-}" ]; then
  echo "CARGO is required. Refusing to launch ambient cargo from PATH." >&2
  exit 2
fi
case "$CARGO" in
  /*) ;;
  *) echo "CARGO must be an absolute regular Cargo executable path." >&2; exit 2 ;;
esac
if [ ! -f "$CARGO" ] || [ -L "$CARGO" ]; then
  echo "CARGO must be an absolute regular Cargo executable path." >&2
  exit 2
fi

if [ -z "${AVORAX_PYTHON:-}" ]; then
  echo "AVORAX_PYTHON is required. Refusing to launch ambient python from PATH." >&2
  exit 2
fi
case "$AVORAX_PYTHON" in
  /*) ;;
  *) echo "AVORAX_PYTHON must be an absolute regular Python executable path." >&2; exit 2 ;;
esac
if [ ! -f "$AVORAX_PYTHON" ] || [ -L "$AVORAX_PYTHON" ]; then
  echo "AVORAX_PYTHON must be an absolute regular Python executable path." >&2
  exit 2
fi

validate_zne_metadata() {
  "$AVORAX_PYTHON" - "$1" <<'PY'
import json
import os
import pathlib
import re
import sys
import uuid

mode = sys.argv[1]
MAX_JSON_BYTES = 1024 * 1024
REPO_ROOT = pathlib.Path.cwd().resolve(strict=True)

def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)

def within(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False

def reject_symlink_components(path: pathlib.Path, description: str) -> None:
    absolute = path if path.is_absolute() else (REPO_ROOT / path)
    current = pathlib.Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.exists() and current.is_symlink():
            fail(f"{description} must not use symbolic links: {current}")

def checked_json_file(path: str, description: str) -> pathlib.Path:
    candidate = pathlib.Path(path)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    reject_symlink_components(candidate, description)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        fail(f"{description} could not be resolved: {exc}")
    if not within(resolved, REPO_ROOT):
        fail(f"{description} must resolve inside the repository: {resolved}")
    try:
        metadata = resolved.stat()
    except OSError as exc:
        fail(f"{description} could not be inspected: {exc}")
    if not resolved.is_file():
        fail(f"{description} must be a regular file: {resolved}")
    if metadata.st_size > MAX_JSON_BYTES:
        fail(f"{description} exceeds {MAX_JSON_BYTES} bytes: {resolved}")
    return resolved

def load(path: str) -> dict:
    checked = checked_json_file(path, path)
    try:
        with checked.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except json.JSONDecodeError as exc:
        fail(f"{path} is not valid bounded JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object.")
    return value

def checked_report_path(raw_path: str) -> pathlib.Path:
    if not raw_path.strip():
        fail("ZNE report path must not be empty.")
    candidate = pathlib.Path(raw_path)
    if any(part == ".." for part in candidate.parts):
        fail(f"ZNE report path must not contain traversal: {raw_path}")
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    reject_symlink_components(candidate.parent, "ZNE report directory")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        fail(f"ZNE report directory could not be resolved: {exc}")
    if not within(parent, REPO_ROOT):
        fail(f"ZNE report path must resolve inside the repository: {candidate}")
    if not parent.is_dir():
        fail(f"ZNE report directory must be a regular directory: {parent}")
    target = parent / candidate.name
    if target.exists():
        if target.is_symlink() or not target.is_file():
            fail(f"Existing ZNE report must be a regular non-link file: {target}")
    return target

def write_report_atomic(raw_path: str, report: dict) -> None:
    target = checked_report_path(raw_path)
    temp = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(temp, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if target.exists() and (target.is_symlink() or not target.is_file()):
            fail(f"Existing ZNE report changed before activation: {target}")
        os.replace(temp, target)
    except BaseException:
        try:
            if temp.exists() and not temp.is_symlink() and temp.is_file():
                temp.unlink()
        except OSError as cleanup_error:
            print(
                f"Failed to clean up temporary ZNE report {temp}: {cleanup_error}",
                file=sys.stderr,
            )
        raise

def require_bool(value: dict, key: str, description: str) -> bool:
    candidate = value.get(key)
    if not isinstance(candidate, bool):
        fail(f"{description}.{key} must be a JSON boolean.")
    return candidate

def require_sha256(value: dict, key: str, description: str) -> str:
    candidate = value.get(key)
    if not isinstance(candidate, str) or not re.fullmatch(r"[A-Fa-f0-9]{64}", candidate):
        fail(f"{description}.{key} must be a 64-character SHA-256 hex string.")
    return candidate.lower()

def require_positive_int(value: dict, key: str, description: str) -> int:
    candidate = value.get(key)
    if isinstance(candidate, bool) or not isinstance(candidate, int):
        fail(f"{description}.{key} must be a JSON integer.")
    if candidate < 1:
        fail(f"{description}.{key} must be at least 1.")
    return candidate

ml = load("assets/zentor_native/ml/zentor_native_model.metadata.json")
production_ready = require_bool(ml, "production_ready", "ZNE ML metadata")
if not production_ready:
    print("Native ML is development-only; AI-only auto-quarantine must remain disabled.")

signature = load("assets/zentor_native/signatures/zentor_core.metadata.json")
signature_hash = require_sha256(signature, "pack_sha256", "ZNE signature metadata")
signature_count = require_positive_int(signature, "signature_count", "ZNE signature metadata")

rules = load("assets/zentor_native/rules/zentor_rules.metadata.json")
rule_count = require_positive_int(rules, "rule_count", "ZNE rules metadata")

if mode == "report":
    report = {
        "native_engine": "pass",
        "signatures": signature_count,
        "signature_pack_sha256": signature_hash,
        "rules": rule_count,
        "compatibility_engines_enabled_by_default": False,
    }
    write_report_atomic(os.environ.get("ZNE_REPORT_PATH", "zne_release_gate_report.json"), report)
elif mode != "validate":
    fail(f"Unsupported ZNE metadata validation mode: {mode}")
PY
}

for path in \
  core/zentor_native_engine/Cargo.toml \
  assets/zentor_native/signatures/zentor_core.zsig \
  assets/zentor_native/signatures/zentor_core.metadata.json \
  assets/zentor_native/rules/zentor_rules.zrule \
  assets/zentor_native/rules/zentor_rules.metadata.json \
  assets/zentor_native/ml/zentor_native_model.zmodel \
  assets/zentor_native/ml/zentor_native_model.metadata.json \
  assets/zentor_native/trust/zentor_known_good.ztrust \
  assets/zentor_native/trust/zentor_known_bad_test.ztrust
do
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    echo "Missing or unsafe required ZNE artifact: $path" >&2
    exit 1
  fi
done

validate_zne_metadata validate

"$CARGO" build --manifest-path core/zentor_native_engine/Cargo.toml --bin zentor-signature-compiler
"$CARGO" test --manifest-path core/zentor_native_engine/Cargo.toml
"$CARGO" test --manifest-path core/zentor_local_core/Cargo.toml
"$CARGO" test --manifest-path core/zentor_guard_service/Cargo.toml

old_brand="Pa""sus"
old_brand_upper="PA""SUS"
old_brand_lower="pa""sus"
old_anti_cheat="anti""-cheat"
old_fair_play="fair"" play"
old_gaming_protection="gaming"" protection"
old_game_setup="game"" setup"
old_player_session="player"" session"
old_match_telemetry="match"" telemetry"
bad_pattern="ClamAV through Avorax local core|YARA Rules|bundled ClamAV|${old_brand}|${old_brand_upper}|${old_brand_lower}|${old_anti_cheat}|${old_fair_play}|${old_gaming_protection}|${old_game_setup}|${old_player_session}|${old_match_telemetry}"
if rg -n "$bad_pattern" apps/zentor_client/lib --glob "*.dart" --glob "*.tsx" --glob "*.ts"; then
  echo "User-facing UI still contains old primary-engine or gaming copy." >&2
  exit 1
fi

validate_zne_metadata report
echo "ZNE release gate passed."
