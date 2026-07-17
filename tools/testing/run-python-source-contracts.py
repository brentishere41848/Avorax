#!/usr/bin/env python3
"""Run dependency-free Python source-contract tests without pytest.

This is a fallback runner for validation hosts where installing pytest is not
approved or not available. It imports each requested test module and executes
zero-argument functions whose names start with ``test_``.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import traceback
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TEST_FILES = (
    ROOT / "tests" / "test_custom_driver_contract.py",
    ROOT / "tests" / "test_hash_intel_update.py",
)
MAX_FAILURE_DIAGNOSTIC_CHARS = 16_384
TRUNCATION_MARKER = "...[truncated]"


def bounded_failure_diagnostic(text: str) -> str:
    normalized = text.replace("\x00", "\\0")
    normalized = "".join(
        char if char in "\r\n\t" or ord(char) >= 32 else "?" for char in normalized
    )
    if len(normalized) <= MAX_FAILURE_DIAGNOSTIC_CHARS:
        return normalized
    limit = max(0, MAX_FAILURE_DIAGNOSTIC_CHARS - len(TRUNCATION_MARKER))
    return normalized[:limit] + TRUNCATION_MARKER


def load_module(path: Path, index: int):
    module_name = f"avorax_source_contract_{index}_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load source-contract module {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_test_module(path: Path, index: int) -> tuple[int, list[str]]:
    failures: list[str] = []
    try:
        module = load_module(path, index)
    except Exception:
        failures.append(
            f"{path}: import failed\n"
            f"{bounded_failure_diagnostic(traceback.format_exc())}"
        )
        return 0, failures
    count = 0
    for name in sorted(vars(module)):
        if not name.startswith("test_"):
            continue
        test = getattr(module, name)
        if not callable(test):
            continue
        signature = inspect.signature(test)
        if signature.parameters:
            failures.append(f"{path}: {name} requires pytest fixtures/parameters")
            continue
        count += 1
        try:
            test()
        except Exception:
            failures.append(
                f"{path}: {name} failed\n"
                f"{bounded_failure_diagnostic(traceback.format_exc())}"
            )
    return count, failures


def main(argv: list[str]) -> int:
    test_files = [Path(value) for value in argv] if argv else list(DEFAULT_TEST_FILES)
    total = 0
    failures: list[str] = []
    for index, path in enumerate(test_files):
        path = path if path.is_absolute() else ROOT / path
        if not path.is_file():
            failures.append(f"missing source-contract file: {path}")
            continue
        count, module_failures = run_test_module(path, index)
        total += count
        failures.extend(module_failures)

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        print(
            f"python source-contract run failed: {len(failures)} failure(s), {total} executed",
            file=sys.stderr,
        )
        return 1

    print(f"python source-contract run passed: {total} tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
