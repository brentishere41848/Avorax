#!/usr/bin/env sh
set -eu

REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$REPO_ROOT"

for path in \
  core/zentor_native_engine/Cargo.toml \
  assets/zentor_native/signatures/zentor_core.zsig \
  assets/zentor_native/signatures/zentor_core.metadata.json \
  assets/zentor_native/rules/zentor_rules.zrule \
  assets/zentor_native/ml/zentor_native_model.zmodel \
  assets/zentor_native/ml/zentor_native_model.metadata.json \
  assets/zentor_native/trust/zentor_known_good.ztrust \
  assets/zentor_native/trust/zentor_known_bad_test.ztrust
do
  test -f "$path" || { echo "Missing required ZNE artifact: $path" >&2; exit 1; }
done

grep -q '"pack_sha256"' assets/zentor_native/signatures/zentor_core.metadata.json || {
  echo "Native signature metadata is missing pack_sha256." >&2
  exit 1
}

cargo build --manifest-path core/zentor_native_engine/Cargo.toml --bin zentor-signature-compiler
cargo test --manifest-path core/zentor_native_engine/Cargo.toml
cargo test --manifest-path core/zentor_local_core/Cargo.toml
cargo test --manifest-path core/zentor_guard_service/Cargo.toml

old_brand="Pa""sus"
old_brand_upper="PA""SUS"
old_brand_lower="pa""sus"
old_anti_cheat="anti""-cheat"
old_fair_play="fair"" play"
old_gaming_protection="gaming"" protection"
old_game_setup="game"" setup"
old_player_session="player"" session"
old_match_telemetry="match"" telemetry"
bad_pattern="ClamAV through Avorax local core|YARA Rules|bundled ClamAV|${old_brand}|${old_brand_upper}|${old_brand_lower}|${old_anti_cheat}|${old_fair_play}|${old_gaming_protection}|${old_game_setup}|${old_player_session}|${old_match_telemetry}"
if rg -n "$bad_pattern" apps/zentor_client/lib --glob "*.dart" --glob "*.tsx" --glob "*.ts"; then
  echo "User-facing UI still contains old primary-engine or gaming copy." >&2
  exit 1
fi

cat > zne_release_gate_report.json <<'JSON'
{
  "native_engine": "pass",
  "compatibility_engines_enabled_by_default": false
}
JSON
echo "ZNE release gate passed."
