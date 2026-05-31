#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


HASH_RE = {
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
}

MALWARE_SAMPLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".cpl", ".sys", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar", ".apk", ".elf",
    ".so", ".dylib", ".bin", ".dat", ".zip", ".rar", ".7z", ".iso", ".img",
}

SAFE_BINARY_NAMES = (
    "Zentor-AntiVirus-",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def parse_github_repo_url(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        raise ValueError(f"not a GitHub repository URL: {url}")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise ValueError(f"GitHub URL must include owner/repo: {url}")
    return parts[0], parts[1].removesuffix(".git")


def github_api_get(url: str, token: str | None = None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Zentor-safe-metadata-importer",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub API request failed with HTTP {exc.code}: {url}") from exc


def repo_default_branch(owner: str, repo: str, token: str | None = None) -> str:
    info = github_api_get(f"https://api.github.com/repos/{owner}/{repo}", token)
    return info.get("default_branch") or "main"


def repo_tree(owner: str, repo: str, branch: str, token: str | None = None) -> list[dict]:
    tree = github_api_get(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
        token,
    )
    if tree.get("truncated"):
        print(
            f"warning: GitHub tree for {owner}/{repo}@{branch} is truncated; metadata output is incomplete",
            file=sys.stderr,
        )
    return [item for item in tree.get("tree", []) if item.get("type") == "blob"]


def load_sources(config: Path, include_disabled: bool = False) -> list[dict]:
    data = read_json(config)
    sources = data.get("sources")
    if isinstance(sources, list):
        return [
            source for source in sources
            if include_disabled or bool(source.get("enabled", False))
        ]
    if data.get("source_url") or data.get("url"):
        return [data]
    return []


def infer_category(path: str) -> str:
    value = path.lower()
    mapping = [
        ("ransom", "ransomware"),
        ("stealer", "infostealer"),
        ("credential", "credentialTheftIndicator"),
        ("keylog", "keylogger"),
        ("miner", "miner"),
        ("worm", "worm"),
        ("trojan", "trojan"),
        ("rootkit", "rootkitIndicator"),
        ("adware", "adware"),
        ("pup", "potentiallyUnwantedApp"),
        ("downloader", "suspiciousDownloader"),
        ("script", "suspiciousScript"),
    ]
    for marker, category in mapping:
        if marker in value:
            return category
    return "unknown"


def metadata_indicator_id(source_name: str, path: str, blob_sha: str | None) -> str:
    seed = f"{source_name}\0{path}\0{blob_sha or ''}".encode("utf-8")
    return f"ZGI-META-{hashlib.sha256(seed).hexdigest()[:20].upper()}"


def normalize_hash(value: str) -> tuple[str, str] | None:
    normalized = value.strip().lower()
    for prefix in ("sha256:", "sha1:", "md5:"):
        normalized = normalized.removeprefix(prefix)
    normalized = normalized.split(",", 1)[0].strip()
    if not normalized or normalized.startswith("#"):
        return None
    for kind, pattern in HASH_RE.items():
        if pattern.match(normalized):
            return kind, normalized
    raise ValueError(f"unsupported or malformed hash: {value.strip()}")


def signature_id(source_name: str, hash_kind: str, value: str) -> str:
    seed = f"{source_name}\0{hash_kind}\0{value}".encode("utf-8")
    return f"ZGI-HASH-{hashlib.sha256(seed).hexdigest()[:20].upper()}"


def confidence_for_hash(hash_kind: str) -> str:
    return "confirmed" if hash_kind == "sha256" else "high"


def indicator_type_for_hash(hash_kind: str) -> str:
    return hash_kind


def action_policy_for_hash(hash_kind: str) -> str:
    return "quarantine_if_policy_allows" if hash_kind == "sha256" else "review_or_block_by_policy"


def is_lab_download_enabled(args: argparse.Namespace) -> bool:
    return (
        getattr(args, "mode", "") == "lab_download"
        and bool(getattr(args, "download_samples", False))
        and os.environ.get("ZENTOR_LAB_I_UNDERSTAND_RISK") == "true"
        and bool(getattr(args, "isolated_malware_lab", False))
    )


def repo_root_from(start: Path) -> Path | None:
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def path_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False
