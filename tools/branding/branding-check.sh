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
max_diagnostic_bytes=65536
rg_stderr="$(mktemp "${TMPDIR:-/tmp}/avorax-branding-rg-stderr.XXXXXX")"
trap 'rm -f "$rg_stderr"' EXIT

read_bounded_stderr() {
  local content
  if [[ ! -f "$rg_stderr" ]]; then
    printf '<ripgrep stderr unavailable>'
    return
  fi
  if ! content="$(head -c "$max_diagnostic_bytes" "$rg_stderr")"; then
    printf '<unable to read ripgrep stderr>'
    return
  fi
  printf '%s' "$content"
}

failed=0
for term in "${terms[@]}"; do
  : > "$rg_stderr"
  if matches=$(rg -n -S "$term" "$ROOT" \
      --glob '!.git/**' \
      --glob '!archive/**' \
      --glob '!**/target/**' \
      --glob '!**/build/**' \
      --glob '!**/.dart_tool/**' \
      --glob '!**/node_modules/**' \
      --glob '!**/dist/**' \
      --glob "!$migration_note" 2>"$rg_stderr"); then
    if [[ -n "$matches" ]]; then
      printf 'Forbidden active branding term [%s]:\n%s\n' "$term" "$matches" >&2
      failed=1
    fi
  else
    rg_status=$?
    if [[ "$rg_status" -gt 1 ]]; then
      printf 'Branding check search failed for term [%s] with exit %s:\n%s\n' \
        "$term" "$rg_status" "$(read_bounded_stderr)" >&2
      failed=1
    fi
  fi
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

printf 'Avorax branding check passed.\n'
