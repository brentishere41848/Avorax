#!/usr/bin/env python3
import argparse
import hashlib
import json
import math
import re
from pathlib import Path

from github_intel_common import read_json, required_canonical_category


MAX_PACK_TEXT_BYTES = 4096
PACK_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
CANONICAL_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
GENERAL_PROFILE = "general"
KNOWN_BAD_SHA256_PROFILE = "known-bad-sha256"
SIGNATURE_PACK_KEYS = {
    "format",
    "version",
    "compiler_version",
    "created_at",
    "pack_sha256",
    "signatures",
}
RULE_PACK_KEYS = {
    "format",
    "version",
    "compiler_version",
    "created_at",
    "pack_sha256",
    "rules",
}
SIGNATURE_KEYS = {
    "id",
    "name",
    "version",
    "category",
    "confidence",
    "severity",
    "signature_type",
    "pattern",
    "mask",
    "offset",
    "file_types",
    "min_file_size",
    "max_file_size",
    "required_context",
    "false_positive_notes",
    "action_policy",
    "created_at",
    "updated_at",
}
RULE_KEYS = {
    "id",
    "name",
    "description",
    "category",
    "confidence",
    "verdict",
    "false_positive_notes",
    "conditions",
    "min_condition_matches",
    "action",
}
CONDITION_KEYS = {"type", "equals", "value", "category"}
REQUIRED_SIGNATURE_TEXT_KEYS = (
    "id",
    "name",
    "version",
    "category",
    "confidence",
    "severity",
    "signature_type",
    "pattern",
    "false_positive_notes",
    "action_policy",
    "created_at",
    "updated_at",
)
REQUIRED_RULE_TEXT_KEYS = (
    "id",
    "name",
    "description",
    "category",
    "confidence",
    "verdict",
    "false_positive_notes",
    "action",
)
ALLOWED_CONFIDENCE = {"low", "medium", "high", "confirmed"}
ALLOWED_SIGNATURE_SEVERITY = {"test", "low", "medium", "high", "critical"}
ALLOWED_SIGNATURE_TYPE = {
    "exact_hash",
    "partial_hash",
    "byte_pattern",
    "masked_byte_pattern",
    "ascii_string",
    "utf16_string",
    "pe_import_combo",
    "pe_section_entropy",
    "pe_resource_indicator",
    "script_pattern",
    "powershell_encoded_command",
    "archive_nested_executable",
    "eicar_test_signature",
}
ALLOWED_SIGNATURE_ACTION_POLICY = {
    "observe",
    "review_only",
    "review_or_block_by_policy",
    "quarantine_if_policy_allows",
    "block_or_quarantine_if_policy_allows",
}
ALLOWED_RULE_VERDICT = {
    "observation",
    "suspicious",
    "probableMalware",
    "confirmedMalware",
}
ALLOWED_RULE_ACTION = {
    "observe",
    "review_only",
    "review_or_block_by_policy",
    "quarantine_if_policy_allows",
}
ALLOWED_RULE_CONDITION_TYPE = {
    "file_type",
    "contains_ascii",
    "contains_utf16",
    "entropy_greater_than",
    "suspicious_imports_at_least",
    "encoded_command",
    "downloader_and_execution",
    "archive_contains_executable",
    "archive_suspicious_nested_name_at_least",
    "path_contains",
    "script_obfuscation_at_least",
    "script_persistence_at_least",
    "script_security_tamper_at_least",
    "embedded_urls_at_least",
    "suspicious_strings_at_least",
    "pe_import_category_at_least",
    "ransom_note_text",
    "miner_pool_string",
    "credential_access_string",
    "adware_pup_string",
}
ALLOWED_FILE_TYPE_FILTER = {
    "*",
    "pe",
    "elf",
    "macho",
    "powershell_script",
    "javascript",
    "batch",
    "vbs",
    "zip",
    "text",
    "document",
    "unknown",
}
ALLOWED_PE_IMPORT_CATEGORY = {
    "process_injection",
    "credential_access",
    "persistence",
    "network",
    "crypto",
    "process_manipulation",
    "service_control",
    "registry_autorun",
    "anti_debugging",
}


def reject_unknown_fields(value: dict, allowed: set[str], description: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise SystemExit(f"{description} has unknown fields: {', '.join(sorted(unknown))}")


def required_text(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if not text:
        raise SystemExit(f"{description} must not be empty")
    if len(text.encode("utf-8")) > MAX_PACK_TEXT_BYTES:
        raise SystemExit(f"{description} exceeds {MAX_PACK_TEXT_BYTES} bytes")
    if any(ord(char) < 32 for char in text) or "\x00" in text:
        raise SystemExit(f"{description} contains control characters")
    return text


def required_choice(value: object, description: str, allowed: set[str]) -> str:
    text = required_text(value, description)
    if text not in allowed:
        raise SystemExit(f"{description} must be one of: {', '.join(sorted(allowed))}")
    return text


def optional_text(value: object, description: str) -> str | None:
    if value is None:
        return None
    return required_text(value, description)


def optional_text_list(value: object, description: str) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise SystemExit(f"{description} must be a list")
    for index, item in enumerate(value):
        required_text(item, f"{description} item {index}")


def optional_choice_list(value: object, description: str, allowed: set[str]) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise SystemExit(f"{description} must be a list")
    for index, item in enumerate(value):
        required_choice(item, f"{description} item {index}", allowed)


def optional_nonnegative_int(value: object, description: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SystemExit(f"{description} must be a non-negative integer")


def required_item_list(pack: dict, key: str, description: str) -> list:
    items = pack.get(key)
    if not isinstance(items, list):
        raise SystemExit(f"{description} {key} must be a list")
    return items


def validate_pack_sha256(value: object, description: str, required: bool) -> str | None:
    if value is None:
        if required:
            raise SystemExit(f"{description} missing pack_sha256")
        return None
    if not isinstance(value, str) or not PACK_SHA256_RE.match(value):
        raise SystemExit(f"{description} pack_sha256 must be a 64-character SHA-256 hex string")
    return value


def validate_signature_item(item: object, description: str) -> None:
    if not isinstance(item, dict):
        raise SystemExit(f"{description} must be an object")
    reject_unknown_fields(item, SIGNATURE_KEYS, description)
    for key in REQUIRED_SIGNATURE_TEXT_KEYS:
        if key == "category":
            required_canonical_category(item.get(key), f"{description} {key}")
        elif key == "confidence":
            required_choice(item.get(key), f"{description} {key}", ALLOWED_CONFIDENCE)
        elif key == "severity":
            required_choice(item.get(key), f"{description} {key}", ALLOWED_SIGNATURE_SEVERITY)
        elif key == "signature_type":
            required_choice(item.get(key), f"{description} {key}", ALLOWED_SIGNATURE_TYPE)
        elif key == "action_policy":
            required_choice(item.get(key), f"{description} {key}", ALLOWED_SIGNATURE_ACTION_POLICY)
        else:
            required_text(item.get(key), f"{description} {key}")
    optional_text(item.get("mask"), f"{description} mask")
    optional_nonnegative_int(item.get("offset"), f"{description} offset")
    optional_choice_list(item.get("file_types"), f"{description} file_types", ALLOWED_FILE_TYPE_FILTER)
    optional_nonnegative_int(item.get("min_file_size"), f"{description} min_file_size")
    optional_nonnegative_int(item.get("max_file_size"), f"{description} max_file_size")
    optional_text_list(item.get("required_context"), f"{description} required_context")


def validate_condition_value(value: object, description: str) -> None:
    if isinstance(value, str):
        required_text(value, description)
        return
    if isinstance(value, bool):
        raise SystemExit(f"{description} must not be boolean")
    if isinstance(value, int):
        if value < 0:
            raise SystemExit(f"{description} must be non-negative")
        return
    if isinstance(value, float):
        if not math.isfinite(value) or value < 0:
            raise SystemExit(f"{description} must be finite and non-negative")
        return
    raise SystemExit(f"{description} must be a string or non-negative number")


def validate_rule_condition(condition: object, description: str) -> None:
    if not isinstance(condition, dict):
        raise SystemExit(f"{description} must be an object")
    reject_unknown_fields(condition, CONDITION_KEYS, description)
    condition_type = required_choice(
        condition.get("type"),
        f"{description} type",
        ALLOWED_RULE_CONDITION_TYPE,
    )
    if "equals" in condition:
        if condition_type == "file_type":
            required_choice(condition.get("equals"), f"{description} equals", ALLOWED_FILE_TYPE_FILTER - {"*"})
        else:
            required_text(condition.get("equals"), f"{description} equals")
    if "category" in condition:
        if condition_type == "pe_import_category_at_least":
            required_choice(condition.get("category"), f"{description} category", ALLOWED_PE_IMPORT_CATEGORY)
        else:
            required_text(condition.get("category"), f"{description} category")
    if "value" in condition:
        validate_condition_value(condition.get("value"), f"{description} value")


def validate_rule_item(item: object, description: str) -> None:
    if not isinstance(item, dict):
        raise SystemExit(f"{description} must be an object")
    reject_unknown_fields(item, RULE_KEYS, description)
    for key in REQUIRED_RULE_TEXT_KEYS:
        if key == "category":
            required_canonical_category(item.get(key), f"{description} {key}")
        elif key == "confidence":
            required_choice(item.get(key), f"{description} {key}", ALLOWED_CONFIDENCE)
        elif key == "verdict":
            required_choice(item.get(key), f"{description} {key}", ALLOWED_RULE_VERDICT)
        elif key == "action":
            required_choice(item.get(key), f"{description} {key}", ALLOWED_RULE_ACTION)
        else:
            required_text(item.get(key), f"{description} {key}")
    conditions = item.get("conditions")
    if not isinstance(conditions, list):
        raise SystemExit(f"{description} conditions must be a list")
    if not conditions:
        raise SystemExit(f"{description} conditions must not be empty")
    for index, condition in enumerate(conditions):
        validate_rule_condition(condition, f"{description} condition {index}")
    min_matches = item.get("min_condition_matches")
    if isinstance(min_matches, bool) or not isinstance(min_matches, int) or min_matches <= 0:
        raise SystemExit(f"{description} min_condition_matches must be a positive integer")
    if min_matches > len(conditions):
        raise SystemExit(f"{description} min_condition_matches exceeds condition count")


def canonical_signature_pack(pack: dict) -> bytes:
    canonical = {
        "format": pack.get("format"),
        "version": pack.get("version"),
        "compiler_version": pack.get("compiler_version"),
        "created_at": pack.get("created_at"),
        "signatures": pack["signatures"],
    }
    return json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")


def canonical_rule_pack(pack: dict) -> bytes:
    canonical = {
        "format": pack.get("format"),
        "version": pack.get("version"),
        "compiler_version": pack.get("compiler_version"),
        "created_at": pack.get("created_at"),
        "rules": pack["rules"],
    }
    return json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")


def validate_signature_pack(pack: dict) -> list:
    reject_unknown_fields(pack, SIGNATURE_PACK_KEYS, "signature pack")
    required_text(pack.get("version"), "signature pack version")
    optional_text(pack.get("compiler_version"), "signature pack compiler_version")
    optional_text(pack.get("created_at"), "signature pack created_at")
    items = required_item_list(pack, "signatures", "signature pack")
    for index, item in enumerate(items):
        validate_signature_item(item, f"signature pack item {index}")
    expected = validate_pack_sha256(pack.get("pack_sha256"), "signature pack", bool(items))
    if expected:
        actual = hashlib.sha256(canonical_signature_pack(pack)).hexdigest()
        if actual.lower() != expected.lower():
            raise SystemExit("signature pack hash mismatch")
    return items


def validate_known_bad_sha256_profile(fmt: str, pack: dict, items: list) -> None:
    if fmt != "zentor-signature-pack-v1":
        raise SystemExit("known-bad-sha256 profile requires a signature pack")
    if not items:
        raise SystemExit("known-bad-sha256 profile requires at least one signature")
    if not CANONICAL_SHA256_RE.fullmatch(pack["pack_sha256"]):
        raise SystemExit(
            "known-bad-sha256 profile requires a lowercase pack_sha256"
        )

    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for index, item in enumerate(items):
        description = f"known-bad-sha256 signature {index}"
        signature_id = item["id"]
        if signature_id in seen_ids:
            raise SystemExit(f"{description} duplicates signature id {signature_id}")
        seen_ids.add(signature_id)

        if item["signature_type"] != "exact_hash":
            raise SystemExit(f"{description} must use exact_hash")
        pattern = item["pattern"]
        if not CANONICAL_SHA256_RE.fullmatch(pattern):
            raise SystemExit(
                f"{description} pattern must be a lowercase 64-character SHA-256"
            )
        if pattern in seen_hashes:
            raise SystemExit(f"{description} duplicates SHA-256 {pattern}")
        seen_hashes.add(pattern)

        if item["confidence"] != "confirmed":
            raise SystemExit(f"{description} confidence must be confirmed")
        if item["severity"] != "critical":
            raise SystemExit(f"{description} severity must be critical")
        if item["action_policy"] != "quarantine_if_policy_allows":
            raise SystemExit(
                f"{description} action_policy must be quarantine_if_policy_allows"
            )
        if item["category"] in {"unknown", "testThreat"}:
            raise SystemExit(f"{description} must use a production threat category")
        if item.get("file_types") != ["*"]:
            raise SystemExit(f"{description} file_types must be exactly ['*']")
        if item.get("required_context") != []:
            raise SystemExit(f"{description} required_context must be empty")
        for optional_field in ("mask", "offset", "min_file_size", "max_file_size"):
            if item.get(optional_field) is not None:
                raise SystemExit(f"{description} {optional_field} must be null")


def validate_rule_pack(pack: dict) -> list:
    reject_unknown_fields(pack, RULE_PACK_KEYS, "rule pack")
    required_text(pack.get("version"), "rule pack version")
    optional_text(pack.get("compiler_version"), "rule pack compiler_version")
    optional_text(pack.get("created_at"), "rule pack created_at")
    items = required_item_list(pack, "rules", "rule pack")
    for index, item in enumerate(items):
        validate_rule_item(item, f"rule pack item {index}")
    expected = validate_pack_sha256(pack.get("pack_sha256"), "rule pack", bool(items))
    if expected:
        actual = hashlib.sha256(canonical_rule_pack(pack)).hexdigest()
        if actual.lower() != expected.lower():
            raise SystemExit("rule pack hash mismatch")
    return items


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Avorax indicator/signature/rule pack metadata.")
    parser.add_argument("--input", required=True)
    parser.add_argument(
        "--profile",
        choices=(GENERAL_PROFILE, KNOWN_BAD_SHA256_PROFILE),
        default=GENERAL_PROFILE,
    )
    args = parser.parse_args()
    pack = read_json(Path(args.input), "indicator pack")
    fmt = required_text(pack.get("format"), "pack format")
    if fmt not in {"zentor-signature-pack-v1", "zentor-rule-pack-v1"}:
        raise SystemExit(f"unsupported pack format: {fmt}")
    if fmt == "zentor-signature-pack-v1":
        items = validate_signature_pack(pack)
    else:
        items = validate_rule_pack(pack)
    if args.profile == KNOWN_BAD_SHA256_PROFILE:
        validate_known_bad_sha256_profile(fmt, pack, items)
    print(f"validated {len(items)} items from {fmt} with profile {args.profile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
