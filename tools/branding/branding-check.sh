#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
legacy="Pa""sus"
terms=(
  "$legacy"
  "$(printf '%s' "$legacy" | tr '[:lower:]' '[:upper:]')"
  "$(printf '%s' "$legacy" | tr '[:upper:]' '[:lower:]')"
  "anti""-cheat"
  "fair"" play"
  "gaming"" protection"
  "game"" setup"
  "player"" session"
  "match"" telemetry"
)
migration_note="docs/migration-from-$(printf '%s' "$legacy" | tr '[:upper:]' '[:lower:]').md"

failed=0
for term in "${terms[@]}"; do
  if matches=$(rg -n -S "$term" "$ROOT" \
      --glob '!.git/**' \
      --glob '!archive/**' \
      --glob '!**/target/**' \
      --glob '!**/build/**' \
      --glob '!**/.dart_tool/**' \
      --glob '!**/node_modules/**' \
      --glob '!**/dist/**' \
      --glob "!$migration_note" 2>/dev/null); then
    if [[ -n "$matches" ]]; then
      printf 'Forbidden active branding term [%s]:\n%s\n' "$term" "$matches" >&2
      failed=1
    fi
  fi
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

printf 'Avorax branding check passed.\n'
