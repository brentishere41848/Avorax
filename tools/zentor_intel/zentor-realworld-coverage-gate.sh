#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
cargo test --manifest-path core/zentor_native_engine/Cargo.toml
bash tools/branding/branding-check.sh
if find . -type f \( -name '*.vir' -o -name '*.malware' -o -name '*.sample' \) \
  ! -path './target/*' ! -path './build/*' ! -path './archive/*' ! -path './dist/*' ! -path './.git/*' | grep -q .; then
  echo "Forbidden malware sample-like file extension found" >&2
  exit 1
fi
echo "Avorax real-world coverage gate passed."
