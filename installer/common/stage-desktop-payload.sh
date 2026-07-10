#!/usr/bin/env bash

stage_avorax_desktop_payload() {
  if [[ $# -ne 2 ]]; then
    printf 'stage_avorax_desktop_payload expects <repo-root> <destination>\n' >&2
    return 2
  fi
  local repo_root="$1"
  local destination="$2"
  local source

  for source in \
    "$repo_root/assets/zentor_native" \
    "$repo_root/assets/models" \
    "$repo_root/assets/yara" \
    "$repo_root/assets/test" \
    "$repo_root/assets/trust" \
    "$repo_root/assets/threats"; do
    if [[ ! -d "$source" ]]; then
      printf 'Required Avorax asset directory is missing: %s\n' "$source" >&2
      return 1
    fi
    if find "$source" -type l -print -quit | grep -q .; then
      printf 'Avorax source asset trees must not contain symlinks: %s\n' "$source" >&2
      return 1
    fi
  done

  mkdir -p \
    "$destination/engine/config" \
    "$destination/assets" \
    "$destination/docs"
  cp -a "$repo_root/assets/zentor_native/." "$destination/engine/"
  cp -a "$repo_root/assets/zentor_native" "$destination/assets/zentor_native"
  cp -a "$repo_root/assets/models" "$destination/assets/models"
  cp -a "$repo_root/assets/yara" "$destination/assets/yara"
  cp -a "$repo_root/assets/test" "$destination/assets/test"
  cp -a "$repo_root/assets/trust" "$destination/assets/trust"
  cp -a "$repo_root/assets/threats" "$destination/assets/threats"

  cp "$repo_root/assets/zentor_native/signatures/zentor_core.zsig" \
    "$destination/engine/signatures/avorax_core.asig"
  cp "$repo_root/assets/zentor_native/rules/zentor_rules.zrule" \
    "$destination/engine/rules/avorax_core.arule"
  cp "$repo_root/assets/zentor_native/ml/zentor_native_model.zmodel" \
    "$destination/engine/ml/avorax_native_model.amodel"
  cp "$repo_root/assets/zentor_native/ml/zentor_native_model.metadata.json" \
    "$destination/engine/ml/avorax_native_model.metadata.json"
  cp "$repo_root/assets/zentor_native/trust/zentor_known_good.ztrust" \
    "$destination/engine/trust/avorax_known_good.atrust"
  cp "$repo_root/assets/zentor_native/trust/zentor_known_bad_test.ztrust" \
    "$destination/engine/trust/avorax_known_bad_test.atrust"

  # The preferred Avorax core aliases and their legacy copies contain identical
  # IDs. Keep only the aliases in the active engine tree so duplicate-ID checks
  # remain fail-closed while optional legacy sibling packs still load.
  rm -- \
    "$destination/engine/signatures/zentor_core.zsig" \
    "$destination/engine/rules/zentor_rules.zrule"

  printf '%s\n' \
    '{' \
    '  "compatibility_engines_enabled": false,' \
    '  "engine": "Avorax Native Engine",' \
    '  "installed_layout_version": 1,' \
    '  "product": "Avorax Anti-Virus"' \
    '}' >"$destination/engine/config/engine.default.json"

  cp "$repo_root/README.md" "$destination/docs/README.md"
  cp "$repo_root/docs/privacy.md" "$destination/docs/privacy.md"
  cp "$repo_root/docs/limitations.md" "$destination/docs/limitations.md"
  cp "$repo_root/docs/dependency-license-inventory.md" \
    "$destination/docs/dependency-license-inventory.md"
  if [[ -f "$repo_root/docs/installers.md" ]]; then
    cp "$repo_root/docs/installers.md" "$destination/docs/installers.md"
  fi
  cp "$repo_root/installer/common/BETA-NOTICE.txt" "$destination/BETA-NOTICE.txt"
}
