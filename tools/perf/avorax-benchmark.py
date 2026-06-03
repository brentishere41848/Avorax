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
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


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
        error = str(exc)
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
        path.write_bytes(repeated)
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
            with path.open("rb") as handle:
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


def run_command(repo_root: Path, command: list[str]) -> dict[str, Any]:
    start = now_ms()
    completed = subprocess.run(
        command,
        cwd=repo_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    elapsed = now_ms() - start
    tail = "\n".join(completed.stdout.splitlines()[-20:])
    return {
        "measured_by": "subprocess wall-clock timing",
        "command": command,
        "exit_code": completed.returncode,
        "elapsed_ms": round(elapsed, 3),
        "status": "pass" if completed.returncode == 0 else "blocked_or_failed",
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
            target.parent.mkdir(parents=True, exist_ok=True)
            file_start = now_ms()
            shutil.copy2(source, target)
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
    parser.add_argument("--file-count", type=int, default=128)
    parser.add_argument("--file-size", type=int, default=8192)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    out = (repo_root / args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

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
                    "cargo",
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
                    "cargo",
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
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote benchmark report: {out}")
    print(json.dumps({"metrics": [m["name"] + ':' + m["status"] for m in metrics]}, indent=2))
    return 0 if all(m["status"] in {"pass", "error"} for m in metrics) else 1


if __name__ == "__main__":
    raise SystemExit(main())
