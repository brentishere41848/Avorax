import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Create minimal safe feature JSONL rows for Pasus Native ML development.")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    rows = [
        {"label": "benign", "features": {"known_good_flag": 1.0, "encoded_command_flag": 0.0, "suspicious_string_count": 0.0}},
        {"label": "suspicious", "features": {"known_good_flag": 0.0, "encoded_command_flag": 1.0, "suspicious_string_count": 0.5}},
    ]
    Path(args.output).write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
