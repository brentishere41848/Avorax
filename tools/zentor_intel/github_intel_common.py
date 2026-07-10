#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import quote, urlparse

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_JSONL_ROWS = 1_000_000
MAX_GITHUB_API_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_GITHUB_OWNER_BYTES = 39
MAX_GITHUB_REPO_BYTES = 100
MAX_GITHUB_BRANCH_BYTES = 1024
MAX_GITHUB_TREE_ITEMS = 200_000
MAX_GITHUB_TREE_PATH_BYTES = 4096
MAX_GITHUB_TREE_SHA_BYTES = 128
MAX_CATEGORY_TEXT_BYTES = 4096
MAX_ACTION_POLICY_TEXT_BYTES = 4096
REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


HASH_RE = {
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
}
GITHUB_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+$")

MALWARE_SAMPLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".cpl", ".sys", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar", ".apk", ".elf",
    ".so", ".dylib", ".bin", ".dat", ".zip", ".rar", ".7z", ".iso", ".img",
}

SAFE_BINARY_NAMES = (
    "Avorax-AntiVirus-",
)

THREAT_CATEGORY_ALIASES = {
    "trojan": "trojan",
    "ransomware": "ransomware",
    "spyware": "spyware",
    "infostealer": "infostealer",
    "info_stealer": "infostealer",
    "info-stealer": "infostealer",
    "adware": "adware",
    "worm": "worm",
    "keylogger": "keylogger",
    "key_logger": "keylogger",
    "key-logger": "keylogger",
    "miner": "miner",
    "rootkitindicator": "rootkitIndicator",
    "rootkit_indicator": "rootkitIndicator",
    "rootkit-indicator": "rootkitIndicator",
    "potentiallyunwantedapp": "potentiallyUnwantedApp",
    "potentially_unwanted_app": "potentiallyUnwantedApp",
    "potentially-unwanted-app": "potentiallyUnwantedApp",
    "pua": "potentiallyUnwantedApp",
    "pup": "potentiallyUnwantedApp",
    "suspiciousdownloader": "suspiciousDownloader",
    "suspicious_downloader": "suspiciousDownloader",
    "suspicious-downloader": "suspiciousDownloader",
    "suspiciousscript": "suspiciousScript",
    "suspicious_script": "suspiciousScript",
    "suspicious-script": "suspiciousScript",
    "maliciousmacro": "maliciousMacro",
    "malicious_macro": "maliciousMacro",
    "malicious-macro": "maliciousMacro",
    "exploitdropper": "exploitDropper",
    "exploit_dropper": "exploitDropper",
    "exploit-dropper": "exploitDropper",
    "credentialtheftindicator": "credentialTheftIndicator",
    "credential_theft_indicator": "credentialTheftIndicator",
    "credential-theft-indicator": "credentialTheftIndicator",
    "persistenceindicator": "persistenceIndicator",
    "persistence_indicator": "persistenceIndicator",
    "persistence-indicator": "persistenceIndicator",
    "securitytamperindicator": "securityTamperIndicator",
    "security_tamper_indicator": "securityTamperIndicator",
    "security-tamper-indicator": "securityTamperIndicator",
    "testthreat": "testThreat",
    "test_threat": "testThreat",
    "test-threat": "testThreat",
    "unknown": "unknown",
}

ACTION_POLICY_ALIASES = {
    "observe": "observe",
    "observation_only": "observe",
    "observation-only": "observe",
    "review": "review_only",
    "review_only": "review_only",
    "review-only": "review_only",
    "revieworblockbypolicy": "review_or_block_by_policy",
    "review_or_block_by_policy": "review_or_block_by_policy",
    "review-or-block-by-policy": "review_or_block_by_policy",
    "quarantineifpolicyallows": "quarantine_if_policy_allows",
    "quarantine_if_policy_allows": "quarantine_if_policy_allows",
    "quarantine-if-policy-allows": "quarantine_if_policy_allows",
    "blockorquarantineifpolicyallows": "block_or_quarantine_if_policy_allows",
    "block_or_quarantine_if_policy_allows": "block_or_quarantine_if_policy_allows",
    "block-or-quarantine-if-policy-allows": "block_or_quarantine_if_policy_allows",
}


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT_ATTRIBUTE
    )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def require_regular_file(path: Path, description: str, max_bytes: int) -> None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise SystemExit(f"{description} does not exist: {path}") from exc
    except OSError as exc:
        raise SystemExit(f"unable to inspect {description} {path}: {exc}") from exc
    if is_link_or_reparse(metadata):
        raise SystemExit(f"{description} must not be a symbolic link or reparse point: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{description} is not a regular file: {path}")
    if metadata.st_size > max_bytes:
        raise SystemExit(f"{description} exceeds {max_bytes} bytes: {path}")


def require_regular_directory(path: Path, description: str) -> None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise SystemExit(f"{description} does not exist: {path}") from exc
    except OSError as exc:
        raise SystemExit(f"unable to inspect {description} {path}: {exc}") from exc
    if is_link_or_reparse(metadata):
        raise SystemExit(f"{description} must not be a symbolic link or reparse point: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"{description} is not a regular directory: {path}")


def iter_regular_files(path: Path, pattern: str, description: str) -> list[Path]:
    require_regular_directory(path, description)
    files: list[Path] = []
    try:
        candidates = sorted(path.glob(pattern))
    except OSError as exc:
        raise SystemExit(f"unable to enumerate {description} {path}: {exc}") from exc
    for candidate in candidates:
        require_regular_file(candidate, f"{description} entry", MAX_JSON_BYTES)
        files.append(candidate)
    return files


def checked_output_file(path: Path, description: str) -> Path:
    path = path.resolve()
    if path.parent.exists():
        try:
            parent_metadata = os.stat(path.parent, follow_symlinks=False)
        except OSError as exc:
            raise SystemExit(f"unable to inspect {description} parent {path.parent}: {exc}") from exc
        if is_link_or_reparse(parent_metadata) or not stat.S_ISDIR(parent_metadata.st_mode):
            raise SystemExit(f"{description} parent must be a regular non-linked directory: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        parent_metadata = os.stat(path.parent, follow_symlinks=False)
    except OSError as exc:
        raise SystemExit(f"unable to inspect {description} parent {path.parent}: {exc}") from exc
    if is_link_or_reparse(parent_metadata) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise SystemExit(f"{description} parent must be a regular non-linked directory: {path.parent}")
    if path.exists():
        metadata = os.stat(path, follow_symlinks=False)
        if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"{description} must be a regular non-linked file: {path}")
    return path


def _open_exclusive_text(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="\n")


def _validate_temp_output(path: Path, description: str) -> None:
    metadata = os.stat(path, follow_symlinks=False)
    if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"temporary {description} must be a regular non-linked file: {path}")


def _cleanup_temp_output(path: Path, description: str) -> None:
    try:
        if path.exists():
            _validate_temp_output(path, description)
            path.unlink()
    except FileNotFoundError as exc:
        if exc.filename is not None and Path(exc.filename) != path:
            raise SystemExit(f"unexpected missing temporary {description} during cleanup: {exc.filename}") from exc


def read_json_value(path: Path, description: str = "JSON input", max_bytes: int = MAX_JSON_BYTES):
    require_regular_file(path, description, max_bytes)
    try:
        decoded = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{description} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"unable to read {description} {path}: {exc}") from exc
    return decoded


def read_json(path: Path, description: str = "JSON input", max_bytes: int = MAX_JSON_BYTES) -> dict:
    decoded = read_json_value(path, description, max_bytes)
    if not isinstance(decoded, dict):
        raise SystemExit(f"{description} must be a JSON object: {path}")
    return decoded


def read_text_lines(
    path: Path,
    description: str = "text input",
    max_bytes: int = MAX_TEXT_BYTES,
    max_line_bytes: int = MAX_LINE_BYTES,
) -> list[str]:
    require_regular_file(path, description, max_bytes)
    lines: list[str] = []
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                if len(line.encode("utf-8")) > max_line_bytes:
                    raise SystemExit(f"{description} line {line_number} exceeds {max_line_bytes} bytes: {path}")
                lines.append(line.rstrip("\r\n"))
    except OSError as exc:
        raise SystemExit(f"unable to read {description} {path}: {exc}") from exc
    return lines


def read_jsonl_objects(
    path: Path,
    description: str = "JSONL input",
    max_bytes: int = MAX_TEXT_BYTES,
    max_rows: int = MAX_JSONL_ROWS,
) -> list[dict]:
    rows: list[dict] = []
    for line_number, line in enumerate(read_text_lines(path, description, max_bytes), start=1):
        if not line.strip():
            continue
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{description} line {line_number} is not valid JSON: {exc}") from exc
        if not isinstance(decoded, dict):
            raise SystemExit(f"{description} line {line_number} must be a JSON object")
        rows.append(decoded)
        if len(rows) > max_rows:
            raise SystemExit(f"{description} contains more than {max_rows} rows: {path}")
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path = checked_output_file(path, "JSONL output")
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with _open_exclusive_text(temp_path) as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        _validate_temp_output(temp_path, "JSONL output")
        os.replace(temp_path, path)
    finally:
        _cleanup_temp_output(temp_path, "JSONL output")


def write_json(path: Path, data: dict, description: str = "JSON output") -> None:
    path = checked_output_file(path, description)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with _open_exclusive_text(temp_path) as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _validate_temp_output(temp_path, description)
        os.replace(temp_path, path)
    finally:
        _cleanup_temp_output(temp_path, description)


def validate_github_owner(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{description} must be a string")
    owner = value.strip()
    if not owner:
        raise ValueError(f"{description} must not be empty")
    if len(owner.encode("utf-8")) > MAX_GITHUB_OWNER_BYTES:
        raise ValueError(f"{description} exceeds {MAX_GITHUB_OWNER_BYTES} bytes")
    if not GITHUB_OWNER_RE.fullmatch(owner):
        raise ValueError(f"{description} must be a safe GitHub owner token")
    return owner


def validate_github_repo_name(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{description} must be a string")
    repo = value.strip().removesuffix(".git")
    if not repo:
        raise ValueError(f"{description} must not be empty")
    if len(repo.encode("utf-8")) > MAX_GITHUB_REPO_BYTES:
        raise ValueError(f"{description} exceeds {MAX_GITHUB_REPO_BYTES} bytes")
    if repo in (".", "..") or "/" in repo or "\\" in repo:
        raise ValueError(f"{description} must be a repository name, not a path")
    if not GITHUB_REPO_RE.fullmatch(repo):
        raise ValueError(f"{description} must be a safe GitHub repository token")
    return repo


def parse_github_repo_url(url: object) -> tuple[str, str]:
    if not isinstance(url, str):
        raise ValueError("GitHub repository URL must be a string")
    repo_url = url.strip()
    if not repo_url:
        raise ValueError("GitHub repository URL must not be empty")
    parsed = urlparse(repo_url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise ValueError(f"not a GitHub repository URL: {url}")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError(f"GitHub repository URL must not include query or fragment: {url}")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise ValueError(f"GitHub URL must include owner/repo: {url}")
    owner = validate_github_owner(parts[0], "GitHub repository owner")
    repo = validate_github_repo_name(parts[1], "GitHub repository name")
    return owner, repo


def read_bounded_github_response(response, description: str) -> str:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise RuntimeError(f"{description} has malformed Content-Length") from exc
        if length < 0:
            raise RuntimeError(f"{description} has negative Content-Length")
        if length > MAX_GITHUB_API_RESPONSE_BYTES:
            raise RuntimeError(
                f"{description} exceeds {MAX_GITHUB_API_RESPONSE_BYTES} bytes"
            )
    payload = response.read(MAX_GITHUB_API_RESPONSE_BYTES + 1)
    if len(payload) > MAX_GITHUB_API_RESPONSE_BYTES:
        raise RuntimeError(f"{description} exceeds {MAX_GITHUB_API_RESPONSE_BYTES} bytes")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{description} is not valid UTF-8") from exc


def github_api_get(url: str, token: str | None = None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Avorax-safe-metadata-importer",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = read_bounded_github_response(response, "GitHub API response")
            decoded = json.loads(body)
            if not isinstance(decoded, dict):
                raise RuntimeError("GitHub API response must be a JSON object")
            return decoded
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub API request failed with HTTP {exc.code}: {url}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"GitHub API response is not valid bounded JSON: {url}") from exc


def validate_github_branch(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"{description} must be a string")
    branch = value.strip()
    if not branch:
        raise RuntimeError(f"{description} must not be empty")
    if len(branch.encode("utf-8")) > MAX_GITHUB_BRANCH_BYTES:
        raise RuntimeError(f"{description} exceeds {MAX_GITHUB_BRANCH_BYTES} bytes")
    if any(ord(char) < 32 for char in branch) or "\x00" in branch:
        raise RuntimeError(f"{description} contains control characters")
    return branch


def repo_default_branch(owner: str, repo: str, token: str | None = None) -> str:
    owner = validate_github_owner(owner, "GitHub repository owner")
    repo = validate_github_repo_name(repo, "GitHub repository name")
    info = github_api_get(f"https://api.github.com/repos/{owner}/{repo}", token)
    return validate_github_branch(info.get("default_branch"), "GitHub default_branch")


def validate_github_tree_path(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"{description} path must be a string")
    path = value.strip()
    if not path:
        raise RuntimeError(f"{description} path must not be empty")
    if len(path.encode("utf-8")) > MAX_GITHUB_TREE_PATH_BYTES:
        raise RuntimeError(f"{description} path exceeds {MAX_GITHUB_TREE_PATH_BYTES} bytes")
    if path.startswith("/") or "\\" in path:
        raise RuntimeError(f"{description} path must be repository-relative POSIX text")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise RuntimeError(f"{description} path contains unsafe path components")
    if any(ord(char) < 32 for char in path) or "\x00" in path:
        raise RuntimeError(f"{description} path contains control characters")
    return path


def validate_github_tree_sha(value: object, description: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError(f"{description} sha must be a string")
    sha = value.strip()
    if not sha:
        raise RuntimeError(f"{description} sha must not be empty")
    if len(sha.encode("utf-8")) > MAX_GITHUB_TREE_SHA_BYTES:
        raise RuntimeError(f"{description} sha exceeds {MAX_GITHUB_TREE_SHA_BYTES} bytes")
    if any(ord(char) < 32 for char in sha) or "\x00" in sha:
        raise RuntimeError(f"{description} sha contains control characters")
    return sha


def validate_github_tree_size(value: object, description: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuntimeError(f"{description} size must be a non-negative integer")
    return value


def repo_tree(owner: str, repo: str, branch: str, token: str | None = None) -> list[dict]:
    owner = validate_github_owner(owner, "GitHub repository owner")
    repo = validate_github_repo_name(repo, "GitHub repository name")
    branch = validate_github_branch(branch, "GitHub tree branch")
    encoded_branch = quote(branch, safe="")
    tree = github_api_get(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{encoded_branch}?recursive=1",
        token,
    )
    truncated = tree.get("truncated")
    if not isinstance(truncated, bool):
        raise RuntimeError("GitHub tree truncated flag must be a boolean")
    tree_items = tree.get("tree")
    if not isinstance(tree_items, list):
        raise RuntimeError("GitHub tree response must include a tree list")
    if len(tree_items) > MAX_GITHUB_TREE_ITEMS:
        raise RuntimeError(f"GitHub tree response exceeds {MAX_GITHUB_TREE_ITEMS} items")
    if truncated:
        raise RuntimeError(f"GitHub tree response for {owner}/{repo}@{branch} is truncated")
    blobs: list[dict] = []
    for index, item in enumerate(tree_items):
        if not isinstance(item, dict):
            raise RuntimeError(f"GitHub tree item {index} must be a JSON object")
        item_type = item.get("type")
        if not isinstance(item_type, str):
            raise RuntimeError(f"GitHub tree item {index} type must be a string")
        if item_type != "blob":
            continue
        path = validate_github_tree_path(item.get("path"), f"GitHub tree item {index}")
        sha = validate_github_tree_sha(item.get("sha"), f"GitHub tree item {index}")
        size = validate_github_tree_size(item.get("size"), f"GitHub tree item {index}")
        blobs.append({"path": path, "sha": sha, "size": size, "type": item_type})
    return blobs


def load_sources(config: Path, include_disabled: bool = False) -> list[dict]:
    data = read_json(config)
    if "sources" in data:
        sources = data.get("sources")
        if not isinstance(sources, list):
            raise SystemExit(f"source config sources must be a list: {config}")
        rows: list[dict] = []
        for index, source in enumerate(sources):
            if not isinstance(source, dict):
                raise SystemExit(f"source config entry {index} must be a JSON object")
            enabled = source.get("enabled", False)
            if not isinstance(enabled, bool):
                raise SystemExit(f"source config entry {index} enabled must be a boolean")
            if include_disabled or enabled:
                rows.append(source)
        return rows
    if "source_url" in data or "url" in data:
        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise SystemExit(f"source config enabled must be a boolean: {config}")
        return [data] if include_disabled or enabled else []
    raise SystemExit(f"source config must include a sources list or source_url/url: {config}")


def normalize_category(value: str) -> str | None:
    token = value.strip()
    if not token:
        return None
    key = token.replace("-", "_").replace(" ", "_").lower()
    return THREAT_CATEGORY_ALIASES.get(key) or THREAT_CATEGORY_ALIASES.get(key.replace("_", ""))


def required_category(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if not text:
        raise SystemExit(f"{description} must not be empty")
    if len(text.encode("utf-8")) > MAX_CATEGORY_TEXT_BYTES:
        raise SystemExit(f"{description} exceeds {MAX_CATEGORY_TEXT_BYTES} bytes")
    if any(ord(char) < 32 for char in text) or "\x00" in text:
        raise SystemExit(f"{description} contains control characters")
    normalized = normalize_category(text)
    if normalized is None:
        allowed = ", ".join(sorted(set(THREAT_CATEGORY_ALIASES.values())))
        raise SystemExit(f"{description} must be one of: {allowed}")
    return normalized


def required_canonical_category(value: object, description: str) -> str:
    normalized = required_category(value, description)
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if text != normalized:
        raise SystemExit(f"{description} must use canonical category spelling: {normalized}")
    return normalized


def optional_category(value: object, description: str) -> str | None:
    if value is None:
        return None
    return required_category(value, description)


def normalize_action_policy(value: str) -> str | None:
    token = value.strip()
    if not token:
        return None
    key = token.replace("-", "_").replace(" ", "_").lower()
    return ACTION_POLICY_ALIASES.get(key) or ACTION_POLICY_ALIASES.get(key.replace("_", ""))


def required_action_policy(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{description} must be a string")
    text = value.strip()
    if not text:
        raise SystemExit(f"{description} must not be empty")
    if len(text.encode("utf-8")) > MAX_ACTION_POLICY_TEXT_BYTES:
        raise SystemExit(f"{description} exceeds {MAX_ACTION_POLICY_TEXT_BYTES} bytes")
    if any(ord(char) < 32 for char in text) or "\x00" in text:
        raise SystemExit(f"{description} contains control characters")
    normalized = normalize_action_policy(text)
    if normalized is None:
        allowed = ", ".join(sorted(set(ACTION_POLICY_ALIASES.values())))
        raise SystemExit(f"{description} must be one of: {allowed}")
    return normalized


def optional_action_policy(value: object, description: str) -> str | None:
    if value is None:
        return None
    return required_action_policy(value, description)


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
