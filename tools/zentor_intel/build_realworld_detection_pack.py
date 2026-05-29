#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a real-world Zentor detection pack from local indicator files.")
    parser.add_argument("--source", required=True)
    parser.add_argument("--hashes", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--category", default="trojan")
    args = parser.parse_args()
    temp = Path(args.output).with_suffix(".jsonl")
    subprocess.check_call([sys.executable, str(Path(__file__).with_name("import_hash_feed.py")), "--source", args.source, "--input", args.hashes, "--output", str(temp), "--category", args.category])
    subprocess.check_call([sys.executable, str(Path(__file__).with_name("compile_zentor_signatures.py")), "--input", str(temp), "--output", args.output])
    subprocess.check_call([sys.executable, str(Path(__file__).with_name("validate_indicator_pack.py")), "--input", args.output])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
