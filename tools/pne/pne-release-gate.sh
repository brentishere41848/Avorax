#!/usr/bin/env sh
set -eu

REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$REPO_ROOT"

for path in \
  core/pasus_native_engine/Cargo.toml \
  assets/pasus_native/signatures/pasus_core.psig \
  assets/pasus_native/rules/pasus_rules.prule \
  assets/pasus_native/ml/pasus_native_model.pmodel \
  assets/pasus_native/trust/pasus_known_good.ptrust \
  assets/pasus_native/trust/pasus_known_bad_test.ptrust
do
  test -f "$path" || { echo "Missing required PNE artifact: $path" >&2; exit 1; }
done

cargo test --manifest-path core/pasus_native_engine/Cargo.toml
cargo test --manifest-path core/pasus_local_core/Cargo.toml
cargo test --manifest-path core/pasus_guard_service/Cargo.toml

if rg -n "ClamAV through Pasus local core|YARA Rules|bundled ClamAV|anti-cheat|gaming protection|fair play|game setup" apps/pasus_client/lib apps/pasus_website --glob "*.dart" --glob "*.tsx" --glob "*.ts"; then
  echo "User-facing UI still contains old primary-engine or gaming copy." >&2
  exit 1
fi

cat > pne_release_gate_report.json <<'JSON'
{
  "native_engine": "pass",
  "compatibility_engines_enabled_by_default": false
}
JSON
echo "PNE release gate passed."
