#!/usr/bin/env python3
import argparse
import hashlib
import re
from pathlib import Path
from urllib.parse import urlsplit

from github_intel_common import read_json, read_text_lines, required_category, write_jsonl

MAX_HASH_FEED_TEXT_BYTES = 4096
MAX_HASH_FEED_ROWS = 100_000
SOURCE_METADATA_KEYS = {
    "source_name",
    "source_url",
    "source_type",
    "malware_family",
}
SOURCE_REGISTRY_KEYS = {"sources", "manual_hash_source_template"}
HTTPS_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def required_text(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if not text:
        raise SystemExit(f"{description} must not be empty")
    if len(text.encode("utf-8")) > MAX_HASH_FEED_TEXT_BYTES:
        raise SystemExit(f"{description} exceeds {MAX_HASH_FEED_TEXT_BYTES} bytes")
    if any(ord(char) < 32 for char in text) or "\x00" in text:
        raise SystemExit(f"{description} contains control characters")
    return text


def optional_text(value: object, description: str, default: str | None = None) -> str | None:
    if value is None:
        return default
    return required_text(value, description)


def reject_unknown_fields(value: dict, allowed: set[str], description: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SystemExit(f"{description} contains unknown fields: {', '.join(unknown)}")


def resolve_source_metadata(value: dict) -> dict:
    registry_mode = bool(set(value) & SOURCE_REGISTRY_KEYS)
    if not registry_mode:
        reject_unknown_fields(value, SOURCE_METADATA_KEYS, "hash feed source metadata")
        return value

    reject_unknown_fields(value, SOURCE_REGISTRY_KEYS, "hash feed source registry")
    sources = value.get("sources", [])
    if not isinstance(sources, list):
        raise SystemExit("hash feed source registry sources must be a list")
    template = value.get("manual_hash_source_template")
    if not isinstance(template, dict):
        raise SystemExit(
            "hash feed source registry manual_hash_source_template must be an object"
        )
    reject_unknown_fields(
        template,
        SOURCE_METADATA_KEYS,
        "hash feed manual_hash_source_template",
    )
    return template


def optional_https_url(value: object, description: str) -> str | None:
    text = optional_text(value, description)
    if text is None:
        return None
    if "\\" in text:
        raise SystemExit(f"{description} must not contain backslashes")
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise SystemExit(f"{description} is not a valid HTTPS URL: {exc}") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise SystemExit(f"{description} must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise SystemExit(f"{description} must not contain credentials")
    if parsed.fragment:
        raise SystemExit(f"{description} must not contain a fragment")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise SystemExit(f"{description} contains an invalid hostname") from exc
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or not labels
        or any(not HTTPS_HOST_LABEL_RE.fullmatch(label) for label in labels)
    ):
        raise SystemExit(f"{description} contains an invalid hostname")
    if port is not None and not 1 <= port <= 65535:
        raise SystemExit(f"{description} contains an invalid port")
    return text


def is_sha256(value: str) -> bool:
    value = value.lower().removeprefix("sha256:")
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import SHA-256 hash indicators into Avorax JSONL.")
    parser.add_argument("--source", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--category", required=True)
    args = parser.parse_args()

    source = resolve_source_metadata(
        read_json(Path(args.source), "hash feed source metadata")
    )
    source_name = required_text(source.get("source_name"), "hash feed source_name")
    source_url = optional_https_url(source.get("source_url"), "hash feed source_url")
    source_type = optional_text(source.get("source_type"), "hash feed source_type", "manual_lab")
    malware_family = optional_text(source.get("malware_family"), "hash feed malware_family")
    threat_category = required_category(args.category, "hash feed category")

    rows: list[dict] = []
    first_hash_line: dict[str, int] = {}
    for line_number, line in enumerate(read_text_lines(Path(args.input), "hash feed input"), start=1):
        value = line.split(",", 1)[0].strip().lower().removeprefix("sha256:")
        if not value or value.startswith("#"):
            continue
        if not is_sha256(value):
            raise SystemExit(f"invalid SHA-256 on line {line_number}")
        if value in first_hash_line:
            raise SystemExit(
                f"duplicate SHA-256 on line {line_number}; first seen on line "
                f"{first_hash_line[value]}"
            )
        if len(rows) >= MAX_HASH_FEED_ROWS:
            raise SystemExit(f"hash feed contains more than {MAX_HASH_FEED_ROWS} rows")
        first_hash_line[value] = line_number
        rows.append({
            "indicator_id": f"ZTI-{hashlib.sha256((source_name + value).encode()).hexdigest()[:16]}",
            "source_name": source_name,
            "source_url": source_url,
            "source_type": source_type,
            "indicator_type": "sha256",
            "value": value,
            "malware_family": malware_family,
            "threat_category": threat_category,
            "confidence": "confirmed",
            "false_positive_notes": "Exact SHA-256 indicator imported from supplied metadata feed.",
            "action_policy": "quarantine_if_policy_allows",
        })
    write_jsonl(Path(args.output), rows)
    print(f"imported {len(rows)} indicators")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
