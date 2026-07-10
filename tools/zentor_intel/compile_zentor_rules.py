#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

from github_intel_common import iter_regular_files, read_json, required_category, write_json

MAX_RULE_TEXT_BYTES = 4096
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
CONDITION_KEYS = {"type", "equals", "value"}
ALLOWED_CONFIDENCE = {"low", "medium", "high", "confirmed"}
ALLOWED_VERDICT = {"observation", "suspicious", "probableMalware", "confirmedMalware"}
ALLOWED_ACTION = {"observe", "review_only", "review_or_block_by_policy"}


def required_text(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if not text:
        raise SystemExit(f"{description} must not be empty")
    if len(text.encode("utf-8")) > MAX_RULE_TEXT_BYTES:
        raise SystemExit(f"{description} exceeds {MAX_RULE_TEXT_BYTES} bytes")
    if any(ord(char) < 32 for char in text) or "\x00" in text:
        raise SystemExit(f"{description} contains control characters")
    return text


def required_choice(value: object, description: str, allowed: set[str]) -> str:
    text = required_text(value, description)
    if text not in allowed:
        raise SystemExit(f"{description} must be one of: {', '.join(sorted(allowed))}")
    return text


def validate_condition(condition: object, description: str) -> dict:
    if not isinstance(condition, dict):
        raise SystemExit(f"{description} must be a JSON object")
    unknown = set(condition) - CONDITION_KEYS
    if unknown:
        raise SystemExit(f"{description} has unknown fields: {', '.join(sorted(unknown))}")
    validated = {"type": required_text(condition.get("type"), f"{description} type")}
    if "equals" in condition:
        validated["equals"] = required_text(condition.get("equals"), f"{description} equals")
    if "value" in condition:
        value = condition.get("value")
        if isinstance(value, bool):
            raise SystemExit(f"{description} value must be a string or non-negative integer")
        if isinstance(value, int):
            if value < 0:
                raise SystemExit(f"{description} value must be a non-negative integer")
            validated["value"] = value
        else:
            validated["value"] = required_text(value, f"{description} value")
    return validated


def validate_rule(rule: object, description: str) -> dict:
    if not isinstance(rule, dict):
        raise SystemExit(f"{description} must be a JSON object")
    unknown = set(rule) - RULE_KEYS
    if unknown:
        raise SystemExit(f"{description} has unknown fields: {', '.join(sorted(unknown))}")
    conditions = rule.get("conditions")
    if not isinstance(conditions, list):
        raise SystemExit(f"{description} conditions must be a list")
    if not conditions:
        raise SystemExit(f"{description} conditions must not be empty")
    validated_conditions = [
        validate_condition(condition, f"{description} condition {index}")
        for index, condition in enumerate(conditions, start=1)
    ]
    min_matches = rule.get("min_condition_matches")
    if not isinstance(min_matches, int) or isinstance(min_matches, bool):
        raise SystemExit(f"{description} min_condition_matches must be an integer")
    if min_matches <= 0:
        raise SystemExit(f"{description} min_condition_matches must be positive")
    if min_matches > len(validated_conditions):
        raise SystemExit(f"{description} min_condition_matches exceeds condition count")
    return {
        "id": required_text(rule.get("id"), f"{description} id"),
        "name": required_text(rule.get("name"), f"{description} name"),
        "description": required_text(rule.get("description"), f"{description} description"),
        "category": required_category(rule.get("category"), f"{description} category"),
        "confidence": required_choice(rule.get("confidence"), f"{description} confidence", ALLOWED_CONFIDENCE),
        "verdict": required_choice(rule.get("verdict"), f"{description} verdict", ALLOWED_VERDICT),
        "false_positive_notes": required_text(rule.get("false_positive_notes"), f"{description} false_positive_notes"),
        "conditions": validated_conditions,
        "min_condition_matches": min_matches,
        "action": required_choice(rule.get("action"), f"{description} action", ALLOWED_ACTION),
    }


def validate_rule_pack(pack: dict, path: Path) -> list[dict]:
    if pack.get("format") != "zentor-rule-pack-v1":
        raise SystemExit(f"rule-pack input has unsupported format: {path}")
    required_text(pack.get("version"), f"rule-pack input {path} version")
    rules = pack.get("rules")
    if not isinstance(rules, list):
        raise SystemExit(f"rule-pack input {path} rules must be a list")
    return [
        validate_rule(rule, f"rule-pack input {path} rule {index}")
        for index, rule in enumerate(rules, start=1)
    ]


def canonical_rule_pack(pack: dict) -> bytes:
    canonical = {
        "format": pack["format"],
        "version": pack["version"],
        "compiler_version": pack["compiler_version"],
        "created_at": pack["created_at"],
        "rules": pack["rules"],
    }
    return json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge Avorax .zrule JSON files into one rule pack.")
    parser.add_argument("--input", required=True, help="Directory containing .zrule files")
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    pack_version = required_text(args.version, "rule pack version")
    rules = []
    for path in iter_regular_files(Path(args.input), "*.zrule", "rule-pack input directory"):
        pack = read_json(path, "rule-pack input")
        rules.extend(validate_rule_pack(pack, path))
    pack = {
        "format": "zentor-rule-pack-v1",
        "version": pack_version,
        "compiler_version": None,
        "created_at": None,
        "pack_sha256": None,
        "rules": rules,
    }
    if rules:
        pack["pack_sha256"] = hashlib.sha256(canonical_rule_pack(pack)).hexdigest()
    output_pack = {
        "format": pack["format"],
        "version": pack["version"],
        "compiler_version": pack["compiler_version"],
        "created_at": pack["created_at"],
    }
    if pack["pack_sha256"]:
        output_pack["pack_sha256"] = pack["pack_sha256"]
    output_pack["rules"] = pack["rules"]
    write_json(Path(args.output), output_pack, "compiled rule pack output")
    print(f"compiled {len(rules)} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
