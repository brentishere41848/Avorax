#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from github_intel_common import MAX_JSON_BYTES, checked_output_file, require_regular_file


MAX_TOOL_BYTES = 64 * 1024 * 1024
MAX_CHILD_OUTPUT_BYTES = 64 * 1024
MAX_CHILD_OUTPUT_CHUNK_BYTES = 8192
MAX_CHILD_OUTPUT_CHARS = 12_000
MAX_CHILD_SECONDS = 120
TRUNCATION_MARKER = "...<truncated>"


def bounded_output(text: str) -> str:
    text = text.replace("\x00", "\\0")
    if len(text) > MAX_CHILD_OUTPUT_CHARS:
        return text[:MAX_CHILD_OUTPUT_CHARS] + TRUNCATION_MARKER
    return text


def append_output_tail(output_tail: bytearray, chunk: bytes) -> bool:
    if len(output_tail) + len(chunk) <= MAX_CHILD_OUTPUT_BYTES:
        output_tail.extend(chunk)
        return False
    combined = output_tail + chunk
    output_tail.clear()
    output_tail.extend(combined[-MAX_CHILD_OUTPUT_BYTES:])
    return True


def decode_output_tail(output_tail: bytearray, truncated: bool) -> str:
    text = bytes(output_tail).decode("utf-8", errors="replace")
    if truncated:
        text = (
            f"{TRUNCATION_MARKER} kept last {MAX_CHILD_OUTPUT_BYTES} bytes\n"
            + text
        )
    return bounded_output(text)


def current_python() -> str:
    if not sys.executable:
        raise SystemExit("current Python executable is unavailable")
    path = Path(sys.executable)
    if not path.is_absolute():
        raise SystemExit(f"current Python executable must be absolute: {path}")
    require_regular_file(path, "current Python executable", MAX_TOOL_BYTES)
    return str(path)


def tool_script(name: str) -> str:
    path = Path(__file__).resolve().with_name(name)
    require_regular_file(path, f"threat-intel helper script {name}", MAX_JSON_BYTES)
    return str(path)


def run_tool(label: str, command: list[str]) -> None:
    stdout_tail = bytearray()
    stderr_tail = bytearray()
    stdout_truncated = False
    stderr_truncated = False
    read_errors: list[str] = []

    def read_stream(stream, output_tail: bytearray, name: str) -> None:
        nonlocal stdout_truncated, stderr_truncated
        try:
            if stream is None:
                return
            for chunk in iter(lambda: stream.read(MAX_CHILD_OUTPUT_CHUNK_BYTES), b""):
                truncated = append_output_tail(output_tail, chunk)
                if name == "stdout":
                    stdout_truncated = stdout_truncated or truncated
                else:
                    stderr_truncated = stderr_truncated or truncated
        except Exception as exc:  # noqa: BLE001 - child output read errors are evidence.
            read_errors.append(f"{name}: {exc}")

    process: subprocess.Popen[bytes] | None = None
    timed_out = False
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise SystemExit(f"{label} failed to start: {exc}") from exc

    stdout_reader = threading.Thread(
        target=read_stream,
        args=(process.stdout, stdout_tail, "stdout"),
        name=f"{label} stdout reader",
    )
    stderr_reader = threading.Thread(
        target=read_stream,
        args=(process.stderr, stderr_tail, "stderr"),
        name=f"{label} stderr reader",
    )
    stdout_reader.start()
    stderr_reader.start()
    try:
        return_code = process.wait(timeout=MAX_CHILD_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
            read_errors.append("timeout cleanup: termination requested")
        except Exception as exc:  # noqa: BLE001 - timeout cleanup evidence.
            read_errors.append(f"timeout cleanup: failed to kill child: {exc}")
        try:
            return_code = process.wait(timeout=5)
        except Exception as exc:  # noqa: BLE001 - timeout cleanup evidence.
            read_errors.append(f"timeout cleanup: failed to reap child: {exc}")
            return_code = process.returncode if process.returncode is not None else -1
    stdout_reader.join(timeout=5)
    stderr_reader.join(timeout=5)
    if stdout_reader.is_alive():
        read_errors.append("stdout: reader did not finish")
    if stderr_reader.is_alive():
        read_errors.append("stderr: reader did not finish")

    stdout = decode_output_tail(stdout_tail, stdout_truncated)
    stderr = decode_output_tail(stderr_tail, stderr_truncated)
    if read_errors:
        stderr = bounded_output(
            f"{stderr}\noutput read errors: {'; '.join(read_errors)}".strip()
        )
    if timed_out:
        raise SystemExit(
            f"{label} timed out after {MAX_CHILD_SECONDS}s\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
    if return_code != 0:
        raise SystemExit(
            f"{label} failed with exit {return_code}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
    if stdout.strip():
        print(stdout.rstrip())


def unique_temp_jsonl(output: Path) -> Path:
    output = output.resolve()
    temp = output.with_name(f".{output.name}.{uuid.uuid4().hex}.jsonl")
    try:
        os.stat(temp, follow_symlinks=False)
    except FileNotFoundError:
        return temp
    except OSError as exc:
        raise SystemExit(f"unable to inspect temporary indicator JSONL {temp}: {exc}") from exc
    raise SystemExit(f"temporary indicator JSONL already exists: {temp}")


def cleanup_temp_jsonl(path: Path) -> None:
    try:
        os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SystemExit(f"unable to inspect temporary indicator JSONL during cleanup {path}: {exc}") from exc
    require_regular_file(path, "temporary indicator JSONL cleanup target", MAX_JSON_BYTES)
    try:
        path.unlink()
    except OSError as exc:
        raise SystemExit(f"unable to remove temporary indicator JSONL {path}: {exc}") from exc


def unique_temp_pack(output: Path) -> Path:
    output = output.resolve()
    temp = output.with_name(f".{output.name}.{uuid.uuid4().hex}.zsig.tmp")
    try:
        os.stat(temp, follow_symlinks=False)
    except FileNotFoundError:
        return temp
    except OSError as exc:
        raise SystemExit(f"unable to inspect temporary signature pack {temp}: {exc}") from exc
    raise SystemExit(f"temporary signature pack already exists: {temp}")


def cleanup_temp_pack(path: Path) -> None:
    try:
        os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SystemExit(f"unable to inspect temporary signature pack during cleanup {path}: {exc}") from exc
    require_regular_file(path, "temporary signature pack cleanup target", MAX_JSON_BYTES)
    try:
        path.unlink()
    except OSError as exc:
        raise SystemExit(f"unable to remove temporary signature pack {path}: {exc}") from exc


def activate_validated_pack(temp: Path, output: Path) -> None:
    require_regular_file(temp, "validated temporary signature pack", MAX_JSON_BYTES)
    target = checked_output_file(output, "signature pack output")
    try:
        os.replace(temp, target)
    except OSError as exc:
        raise SystemExit(f"unable to atomically activate validated signature pack {target}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a real-world Avorax detection pack from local indicator files.")
    parser.add_argument("--source", required=True)
    parser.add_argument("--hashes", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    python = current_python()
    import_script = tool_script("import_hash_feed.py")
    compile_script = tool_script("compile_zentor_signatures.py")
    validate_script = tool_script("validate_indicator_pack.py")
    output = Path(args.output)
    temp = unique_temp_jsonl(output)
    temp_pack = unique_temp_pack(output)
    try:
        run_tool(
            "hash feed import",
            [
                python,
                import_script,
                "--source",
                args.source,
                "--input",
                args.hashes,
                "--output",
                str(temp),
                "--category",
                args.category,
            ],
        )
        run_tool(
            "signature compilation",
            [
                python,
                compile_script,
                "--input",
                str(temp),
                "--output",
                str(temp_pack),
                "--version",
                args.version,
            ],
        )
        run_tool(
            "known-bad SHA-256 pack validation",
            [
                python,
                validate_script,
                "--input",
                str(temp_pack),
                "--profile",
                "known-bad-sha256",
            ],
        )
        activate_validated_pack(temp_pack, output)
    finally:
        try:
            cleanup_temp_jsonl(temp)
        finally:
            cleanup_temp_pack(temp_pack)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
