#!/usr/bin/env python
"""Safe Avorax performance benchmark harness.

This script uses harmless synthetic files and existing test commands. It is not a
malware benchmark and it does not claim kernel-driver or elevated update-service
performance. Results are intended for trend tracking in development/CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any


REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
MAX_FILE_COUNT = 10_000
MAX_FILE_SIZE = 16 * 1024 * 1024
MAX_BENCHMARK_DIAGNOSTIC_CHARS = 2048
MAX_BENCHMARK_COMMAND_OUTPUT_BYTES = 64 * 1024
BENCHMARK_COMMAND_OUTPUT_CHUNK_BYTES = 8192
BENCHMARK_COMMAND_TIMEOUT_SECONDS = 180
TRUNCATION_MARKER = "...[truncated]"


def bounded_benchmark_diagnostic(value: object) -> str:
    text = str(value).replace("\x00", "\\0")
    normalized = "".join(
        char if char in "\r\n\t" or ord(char) >= 32 else "?" for char in text
    )
    if len(normalized) <= MAX_BENCHMARK_DIAGNOSTIC_CHARS:
        return normalized
    limit = max(0, MAX_BENCHMARK_DIAGNOSTIC_CHARS - len(TRUNCATION_MARKER))
    return normalized[:limit] + TRUNCATION_MARKER


def is_link_or_reparse(file_stat: os.stat_result) -> bool:
    return stat.S_ISLNK(file_stat.st_mode) or bool(
        getattr(file_stat, "st_file_attributes", 0) & REPARSE_POINT_ATTRIBUTE
    )


def ensure_regular_output_path(path: Path, description: str) -> None:
    if path.exists():
        file_stat = path.lstat()
        if is_link_or_reparse(file_stat) or not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"{description} must be a regular non-linked file: {path}")


def ensure_output_directory(path: Path, description: str) -> None:
    if path.exists():
        file_stat = path.lstat()
        if is_link_or_reparse(file_stat) or not stat.S_ISDIR(file_stat.st_mode):
            raise ValueError(f"{description} must be a regular non-linked directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    file_stat = path.lstat()
    if is_link_or_reparse(file_stat) or not stat.S_ISDIR(file_stat.st_mode):
        raise ValueError(f"{description} must be a regular non-linked directory: {path}")


def require_regular_input_path(path: Path, description: str) -> None:
    try:
        file_stat = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{description} is missing: {path}") from exc
    if is_link_or_reparse(file_stat) or not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"{description} must be a regular non-linked file: {path}")


def open_regular_input_file(path: Path, description: str):
    require_regular_input_path(path, description)
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    file_stat = os.fstat(fd)
    if is_link_or_reparse(file_stat) or not stat.S_ISREG(file_stat.st_mode):
        os.close(fd)
        raise ValueError(f"{description} must be a regular non-linked file: {path}")
    return os.fdopen(fd, "rb")


def write_json_report(path: Path, payload: dict[str, Any]) -> None:
    path = path.resolve()
    ensure_output_directory(path.parent, "benchmark report directory")
    ensure_regular_output_path(path, "benchmark report")
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(temp_path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        ensure_regular_output_path(temp_path, "temporary benchmark report")
        os.replace(temp_path, path)
    finally:
        try:
            if temp_path.exists():
                ensure_regular_output_path(temp_path, "temporary benchmark report")
                temp_path.unlink()
        except FileNotFoundError as exc:
            if exc.filename is not None and Path(exc.filename) != temp_path:
                raise SystemExit(f"Unexpected missing temporary benchmark report during cleanup: {exc.filename}") from exc


def write_corpus_file(path: Path, payload: bytes) -> None:
    ensure_output_directory(path.parent, "benchmark corpus bucket")
    if path.exists():
        ensure_regular_output_path(path, "benchmark corpus file")
        raise ValueError(f"benchmark corpus file already exists: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ValueError(f"benchmark corpus file already exists: {path}") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    ensure_regular_output_path(path, "benchmark corpus file")


def cleanup_partial_copy_target(path: Path) -> None:
    try:
        if path.exists():
            ensure_regular_output_path(path, "partial benchmark copy target")
            path.unlink()
    except FileNotFoundError as exc:
        if exc.filename is not None and Path(exc.filename) != path:
            raise ValueError(f"unexpected missing partial benchmark copy target: {exc.filename}") from exc


def copy_benchmark_file(source: Path, target: Path) -> None:
    ensure_output_directory(target.parent, "benchmark copy target directory")
    if target.exists():
        ensure_regular_output_path(target, "benchmark copy target")
        raise ValueError(f"benchmark copy target already exists: {target}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    created_target = False
    try:
        with open_regular_input_file(source, "benchmark copy source") as source_handle:
            fd = os.open(target, flags, 0o600)
            created_target = True
            with os.fdopen(fd, "wb") as target_handle:
                for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                    target_handle.write(chunk)
                target_handle.flush()
                os.fsync(target_handle.fileno())
        ensure_regular_output_path(target, "benchmark copy target")
    except Exception as copy_error:
        if created_target:
            try:
                cleanup_partial_copy_target(target)
            except Exception as cleanup_error:
                raise RuntimeError(
                    "benchmark copy failed and partial target cleanup also failed: "
                    f"copy_error={bounded_benchmark_diagnostic(copy_error)}; "
                    f"cleanup_error={bounded_benchmark_diagnostic(cleanup_error)}"
                ) from copy_error
        raise


def now_ms() -> float:
    return time.perf_counter() * 1000.0


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((p / 100.0) * (len(ordered) - 1))))
    return ordered[index]


def timed(name: str, fn) -> dict[str, Any]:
    start = now_ms()
    try:
        payload = fn()
        status = "pass"
        error = None
    except Exception as exc:  # noqa: BLE001 - benchmark should report and continue.
        payload = {}
        status = "error"
        error = bounded_benchmark_diagnostic(exc)
    elapsed = now_ms() - start
    return {
        "name": name,
        "status": status,
        "elapsed_ms": round(elapsed, 3),
        "error": error,
        **payload,
    }


def create_corpus(root: Path, file_count: int, file_size: int) -> list[Path]:
    files: list[Path] = []
    for index in range(file_count):
        bucket = root / f"bucket-{index % 16:02d}"
        bucket.mkdir(parents=True, exist_ok=True)
        path = bucket / f"sample-{index:04d}.bin"
        seed = f"avorax-safe-benchmark-{index}".encode("utf-8")
        body = hashlib.sha256(seed).digest()
        repeated = (body * ((file_size // len(body)) + 1))[:file_size]
        write_corpus_file(path, repeated)
        files.append(path)
    return files


def benchmark_traversal_and_hashing(file_count: int, file_size: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="avorax-bench-") as tmp:
        root = Path(tmp)
        files = create_corpus(root, file_count, file_size)

        start = now_ms()
        discovered = [Path(base) / name for base, _, names in os.walk(root) for name in names]
        traversal_ms = now_ms() - start

        per_file_ms: list[float] = []
        start = now_ms()
        digest = hashlib.sha256()
        for path in discovered:
            file_start = now_ms()
            h = hashlib.sha256()
            with open_regular_input_file(path, "benchmark hash input") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    h.update(chunk)
            digest.update(h.digest())
            per_file_ms.append(now_ms() - file_start)
        hashing_ms = now_ms() - start

        return {
            "measured_by": "Python synthetic harmless corpus traversal and SHA-256 streaming",
            "file_count": len(files),
            "file_size_bytes": file_size,
            "total_bytes": len(files) * file_size,
            "traversal_ms": round(traversal_ms, 3),
            "hashing_ms": round(hashing_ms, 3),
            "hash_per_file_p50_ms": round(percentile(per_file_ms, 50), 3),
            "hash_per_file_p95_ms": round(percentile(per_file_ms, 95), 3),
            "combined_digest_prefix": digest.hexdigest()[:16],
        }


def _append_bounded_output_tail(
    output_tail: bytearray,
    chunk: bytes,
) -> bool:
    if len(output_tail) + len(chunk) <= MAX_BENCHMARK_COMMAND_OUTPUT_BYTES:
        output_tail.extend(chunk)
        return False
    combined = output_tail + chunk
    output_tail.clear()
    output_tail.extend(combined[-MAX_BENCHMARK_COMMAND_OUTPUT_BYTES:])
    return True


def _decode_command_output_tail(output: bytes, truncated: bool) -> str:
    tail = output.decode("utf-8", errors="replace")
    lines = tail.splitlines()[-20:]
    if truncated:
        lines.insert(
            0,
            f"{TRUNCATION_MARKER} kept last {MAX_BENCHMARK_COMMAND_OUTPUT_BYTES} bytes",
        )
    return "\n".join(lines)


def run_command(repo_root: Path, command: list[str]) -> dict[str, Any]:
    start = now_ms()
    process = subprocess.Popen(
        command,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output_tail = bytearray()
    output_truncated = False
    read_error: Exception | None = None

    def read_output() -> None:
        nonlocal output_truncated, read_error
        try:
            if process.stdout is None:
                return
            for chunk in iter(
                lambda: process.stdout.read(BENCHMARK_COMMAND_OUTPUT_CHUNK_BYTES),
                b"",
            ):
                output_truncated = (
                    _append_bounded_output_tail(output_tail, chunk) or output_truncated
                )
        except Exception as error:  # noqa: BLE001 - output evidence must remain visible.
            read_error = error

    reader = threading.Thread(target=read_output, name="avorax-benchmark-output-reader")
    reader.start()
    timed_out = False
    timeout_cleanup_notes: list[str] = []
    try:
        exit_code = process.wait(timeout=BENCHMARK_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
            timeout_cleanup_notes.append("termination requested")
        except Exception as error:  # noqa: BLE001 - timeout cleanup evidence.
            timeout_cleanup_notes.append(
                "failed to kill timed-out benchmark command: "
                + bounded_benchmark_diagnostic(error)
            )
        try:
            exit_code = process.wait(timeout=5)
        except Exception as error:  # noqa: BLE001 - timeout cleanup evidence.
            timeout_cleanup_notes.append(
                "failed to reap timed-out benchmark command: "
                + bounded_benchmark_diagnostic(error)
            )
            exit_code = process.returncode if process.returncode is not None else -1
    reader.join(timeout=5)
    elapsed = now_ms() - start
    tail = _decode_command_output_tail(bytes(output_tail), output_truncated)
    if read_error is not None:
        output_error = bounded_benchmark_diagnostic(read_error)
        tail = f"{tail}\noutput read error: {output_error}".strip()
    if timed_out:
        timeout_message = (
            f"command timed out after {BENCHMARK_COMMAND_TIMEOUT_SECONDS} seconds"
        )
        if timeout_cleanup_notes:
            timeout_message = f"{timeout_message}; {'; '.join(timeout_cleanup_notes)}"
        tail = f"{tail}\n{timeout_message}".strip()
    return {
        "measured_by": "subprocess wall-clock timing",
        "command": command,
        "exit_code": exit_code,
        "elapsed_ms": round(elapsed, 3),
        "status": "pass"
        if exit_code == 0 and not timed_out and read_error is None
        else "blocked_or_failed",
        "output_truncated": output_truncated,
        "output_tail": tail,
    }


def benchmark_update_copy_simulation(file_count: int, file_size: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="avorax-update-bench-") as tmp:
        root = Path(tmp)
        staged = root / "staged"
        install = root / "install"
        staged.mkdir()
        install.mkdir()
        create_corpus(staged, file_count, file_size)

        per_file_ms: list[float] = []
        start = now_ms()
        copied = 0
        for source in staged.rglob("*"):
            if source.is_dir():
                continue
            relative = source.relative_to(staged)
            target = install / relative
            file_start = now_ms()
            copy_benchmark_file(source, target)
            per_file_ms.append(now_ms() - file_start)
            copied += 1
        elapsed = now_ms() - start
        return {
            "measured_by": "non-elevated synthetic copy simulation; not real Avorax Update Service apply",
            "file_count": copied,
            "file_size_bytes": file_size,
            "total_bytes": copied * file_size,
            "copy_ms": round(elapsed, 3),
            "copy_per_file_p50_ms": round(percentile(per_file_ms, 50), 3),
            "copy_per_file_p95_ms": round(percentile(per_file_ms, 95), 3),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run safe Avorax performance benchmarks.")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--out", default="dist/performance/benchmark_report.json")
    parser.add_argument("--cargo-path", required=True)
    parser.add_argument("--file-count", type=int, default=128)
    parser.add_argument("--file-size", type=int, default=8192)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    cargo_path = Path(args.cargo_path)
    if not cargo_path.is_absolute() or not cargo_path.is_file():
        parser.error("--cargo-path must be an absolute Cargo executable path")
    if Path(args.out).is_absolute() or ".." in Path(args.out).parts:
        parser.error("--out must be a repository-relative path without traversal")
    out = (repo_root / args.out).resolve()
    if out != repo_root and repo_root not in out.parents:
        parser.error("--out must resolve inside --repo-root")
    if args.file_count < 1 or args.file_count > MAX_FILE_COUNT:
        parser.error(f"--file-count must be between 1 and {MAX_FILE_COUNT}")
    if args.file_size < 1 or args.file_size > MAX_FILE_SIZE:
        parser.error(f"--file-size must be between 1 and {MAX_FILE_SIZE}")

    metrics = [
        timed(
            "synthetic_traversal_and_hashing",
            lambda: benchmark_traversal_and_hashing(args.file_count, args.file_size),
        ),
        timed(
            "native_signature_matching_test_wall_clock",
            lambda: run_command(
                repo_root,
                [
                    str(cargo_path),
                    "test",
                    "--manifest-path",
                    "core/zentor_native_engine/Cargo.toml",
                    "normal_exe_in_downloads_is_not_malware",
                ],
            ),
        ),
        timed(
            "guard_pre_execution_known_good_wall_clock",
            lambda: run_command(
                repo_root,
                [
                    str(cargo_path),
                    "test",
                    "--manifest-path",
                    "core/zentor_guard_service/Cargo.toml",
                    "driver_request_known_good_allows_in_lockdown",
                ],
            ),
        ),
        timed(
            "synthetic_update_copy_simulation",
            lambda: benchmark_update_copy_simulation(args.file_count, args.file_size),
        ),
    ]

    report = {
        "schema_version": 1,
        "generated_at_unix_ms": int(time.time() * 1000),
        "repo_root": str(repo_root),
        "host": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
        },
        "safe_fixture_policy": "synthetic harmless files only; no malware samples; no destructive update apply",
        "metrics": metrics,
    }
    write_json_report(out, report)
    print(f"Wrote benchmark report: {out}")
    print(json.dumps({"metrics": [m["name"] + ':' + m["status"] for m in metrics]}, indent=2))
    return 0 if all(m["status"] == "pass" for m in metrics) else 1


if __name__ == "__main__":
    raise SystemExit(main())
