#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

VERSION="0.1.15"
SKIP_BUILD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || { printf 'Missing value for --version\n' >&2; exit 2; }
      VERSION="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    -h|--help)
      printf 'Usage: %s [--version X.Y.Z] [--skip-build]\n' "$0"
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'Invalid release version: %s\n' "$VERSION" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  printf 'The Linux beta builder currently requires a native x86_64 Linux host.\n' >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
source "$REPO_ROOT/installer/common/stage-desktop-payload.sh"

resolve_tool() {
  local configured="$1"
  local fallback="$2"
  local label="$3"
  local candidate="$configured"
  if [[ -z "$candidate" ]]; then
    candidate="$(command -v "$fallback" || true)"
  fi
  if [[ -z "$candidate" || "$candidate" != /* || ! -f "$candidate" || ! -x "$candidate" ]]; then
    printf '%s must resolve to an absolute executable file.\n' "$label" >&2
    return 1
  fi
  printf '%s\n' "$candidate"
}

FLUTTER_BIN="$(resolve_tool "${FLUTTER:-}" flutter Flutter)"
CARGO_BIN="$(resolve_tool "${CARGO:-}" cargo Cargo)"
PYTHON_BIN="$(resolve_tool "${PYTHON:-}" python3 Python)"
for tool in dpkg-deb tar gzip sha256sum ldd file; do
  command -v "$tool" >/dev/null || { printf 'Required packaging tool is missing: %s\n' "$tool" >&2; exit 1; }
done

DIST_ROOT="$REPO_ROOT/dist/linux"
STAGE_ROOT="$DIST_ROOT/stage/Avorax"
DEB_ROOT="$DIST_ROOT/deb-root"
EXTRACT_ROOT="$DIST_ROOT/deb-extracted"
TAR_EXTRACT_ROOT="$DIST_ROOT/tar-extracted"
VERIFY_ROOT="$DIST_ROOT/verification"
case "$DIST_ROOT" in
  "$REPO_ROOT"/dist/linux) ;;
  *) printf 'Refusing unsafe Linux output path: %s\n' "$DIST_ROOT" >&2; exit 1 ;;
esac
rm -rf -- "$DIST_ROOT"
mkdir -p "$STAGE_ROOT" "$VERIFY_ROOT"

BUILD_NUMBER="$(printf '%s' "$VERSION" | tr -cd '0-9')"
BUILD_NUMBER="${BUILD_NUMBER:-1}"
CLIENT_ROOT="$REPO_ROOT/apps/zentor_client"
FLUTTER_BUNDLE="$CLIENT_ROOT/build/linux/x64/release/bundle"
TARGET_ROOT="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
if [[ "$TARGET_ROOT" != /* ]]; then
  printf 'CARGO_TARGET_DIR must be absolute when set.\n' >&2
  exit 1
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  (
    cd "$CLIENT_ROOT"
    "$FLUTTER_BIN" pub get
    "$FLUTTER_BIN" build linux --release \
      --build-name="$VERSION" \
      --build-number="$BUILD_NUMBER" \
      --dart-define="AVORAX_APP_VERSION=$VERSION" \
      --dart-define="ZENTOR_APP_VERSION=$VERSION" \
      --dart-define="AVORAX_UPDATE_CHANNEL=dev" \
      --dart-define="AVORAX_UPDATES_REPO_OWNER=brentishere41848" \
      --dart-define="AVORAX_UPDATES_REPO_NAME=Avorax"
  )
  (
    cd "$REPO_ROOT"
    "$CARGO_BIN" build --locked --release \
      --package zentor_local_core \
      --package zentor_guard_service
  )
fi

for required in \
  "$FLUTTER_BUNDLE/Avorax" \
  "$TARGET_ROOT/release/zentor_local_core" \
  "$TARGET_ROOT/release/zentor_guard_service"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Required Linux release file is missing or linked: %s\n' "$required" >&2
    exit 1
  fi
done

cp -a "$FLUTTER_BUNDLE/." "$STAGE_ROOT/"
install -m 0755 "$TARGET_ROOT/release/zentor_local_core" "$STAGE_ROOT/avorax_core_service"
install -m 0755 "$TARGET_ROOT/release/zentor_guard_service" "$STAGE_ROOT/avorax_guard_service"
stage_avorax_desktop_payload "$REPO_ROOT" "$STAGE_ROOT"
printf '%s\n' \
  '{' \
  '  "code_signed": false,' \
  '  "package_repository_signed": false,' \
  '  "status": "unsigned-beta"' \
  '}' >"$STAGE_ROOT/package-signing.json"
chmod 0755 "$STAGE_ROOT/Avorax" "$STAGE_ROOT/avorax_core_service" "$STAGE_ROOT/avorax_guard_service"

for executable in "$STAGE_ROOT/Avorax" "$STAGE_ROOT/avorax_core_service" "$STAGE_ROOT/avorax_guard_service"; do
  file "$executable"
  if ldd "$executable" 2>&1 | tee "$VERIFY_ROOT/$(basename "$executable").ldd.txt" | grep -F 'not found'; then
    printf 'Unresolved Linux runtime dependency in %s\n' "$executable" >&2
    exit 1
  fi
done

"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/package_manifest.py" create \
  --root "$STAGE_ROOT" \
  --version "$VERSION" \
  --platform linux-x64 \
  --signing-status unsigned
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/package_manifest.py" verify --root "$STAGE_ROOT"
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/smoke_local_core.py" \
  --core "$STAGE_ROOT/avorax_core_service" \
  --engine-root "$STAGE_ROOT" \
  --report "$VERIFY_ROOT/linux-stage-core-smoke.json"

SOURCE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" log -1 --format=%ct)}"
TARBALL="$REPO_ROOT/dist/Avorax-AntiVirus-$VERSION-linux-x64.tar.gz"
tar --sort=name --mtime="@$SOURCE_EPOCH" --owner=0 --group=0 --numeric-owner \
  -C "$DIST_ROOT/stage" -cf - Avorax | gzip -n -9 >"$TARBALL"
mkdir -p "$TAR_EXTRACT_ROOT"
tar -xzf "$TARBALL" --no-same-owner --no-same-permissions -C "$TAR_EXTRACT_ROOT"
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/package_manifest.py" verify \
  --root "$TAR_EXTRACT_ROOT/Avorax"
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/smoke_local_core.py" \
  --core "$TAR_EXTRACT_ROOT/Avorax/avorax_core_service" \
  --engine-root "$TAR_EXTRACT_ROOT/Avorax" \
  --report "$VERIFY_ROOT/linux-tar-core-smoke.json"

mkdir -p \
  "$DEB_ROOT/DEBIAN" \
  "$DEB_ROOT/opt" \
  "$DEB_ROOT/usr/bin" \
  "$DEB_ROOT/usr/share/applications" \
  "$DEB_ROOT/usr/share/icons/hicolor/512x512/apps"
cp -a "$STAGE_ROOT" "$DEB_ROOT/opt/avorax"
INSTALLED_KIB="$(du -sk "$DEB_ROOT/opt/avorax" | awk '{print $1}')"
printf '%s\n' \
  'Package: avorax-antivirus' \
  "Version: $VERSION" \
  'Section: utils' \
  'Priority: optional' \
  'Architecture: amd64' \
  'Maintainer: Avorax Security <brentishere41848@users.noreply.github.com>' \
  "Installed-Size: $INSTALLED_KIB" \
  'Depends: libc6, libgcc-s1, libglib2.0-0, libgtk-3-0 | libgtk-3-0t64, libstdc++6' \
  'Homepage: https://github.com/brentishere41848/Avorax' \
  'Description: Avorax desktop anti-malware scanner beta' \
  ' Manual offline scans, quarantine, allowlists, logs, and best-effort' \
  ' user-mode observation. This beta is not a replacement for a supported' \
  ' antivirus and provides no kernel or pre-execution blocking.' \
  >"$DEB_ROOT/DEBIAN/control"
printf '%s\n' \
  '#!/bin/sh' \
  'exec /opt/avorax/Avorax "$@"' \
  >"$DEB_ROOT/usr/bin/avorax"
chmod 0755 "$DEB_ROOT/usr/bin/avorax"
printf '%s\n' \
  '[Desktop Entry]' \
  'Type=Application' \
  'Name=Avorax Anti-Virus' \
  'Comment=Scan local files with Avorax Desktop Beta' \
  'Exec=/opt/avorax/Avorax' \
  'Icon=com.avorax.security' \
  'Terminal=false' \
  'Categories=Utility;Security;' \
  'StartupWMClass=com.avorax.security' \
  >"$DEB_ROOT/usr/share/applications/com.avorax.security.desktop"
install -m 0644 "$REPO_ROOT/apps/zentor_client/assets/branding/avorax_icon_512.png" \
  "$DEB_ROOT/usr/share/icons/hicolor/512x512/apps/com.avorax.security.png"
if command -v desktop-file-validate >/dev/null; then
  desktop-file-validate "$DEB_ROOT/usr/share/applications/com.avorax.security.desktop"
fi
if find "$DEB_ROOT" -type f -perm /6000 -print -quit | grep -q .; then
  printf 'Linux package must not contain setuid or setgid files.\n' >&2
  exit 1
fi

DEB="$REPO_ROOT/dist/Avorax-AntiVirus-$VERSION-linux-x64.deb"
dpkg-deb --root-owner-group --build "$DEB_ROOT" "$DEB"
dpkg-deb --info "$DEB" | tee "$VERIFY_ROOT/deb-info.txt"
dpkg-deb --contents "$DEB" >"$VERIFY_ROOT/deb-contents.txt"
mkdir -p "$EXTRACT_ROOT"
dpkg-deb --extract "$DEB" "$EXTRACT_ROOT"
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/package_manifest.py" verify \
  --root "$EXTRACT_ROOT/opt/avorax"
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/smoke_local_core.py" \
  --core "$EXTRACT_ROOT/opt/avorax/avorax_core_service" \
  --engine-root "$EXTRACT_ROOT/opt/avorax" \
  --report "$VERIFY_ROOT/linux-deb-core-smoke.json"

(
  cd "$REPO_ROOT/dist"
  sha256sum "$(basename "$DEB")" "$(basename "$TARBALL")" >SHA256SUMS-linux.txt
)
printf 'Created Linux DEB: %s\n' "$DEB"
printf 'Created Linux tarball: %s\n' "$TARBALL"
