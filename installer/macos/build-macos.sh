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
if [[ "$(uname -s)" != "Darwin" ]]; then
  printf 'The macOS builder requires a native macOS host.\n' >&2
  exit 1
fi
case "$(uname -m)" in
  arm64) PACKAGE_ARCH="arm64"; MANIFEST_PLATFORM="macos-arm64" ;;
  x86_64) PACKAGE_ARCH="x64"; MANIFEST_PLATFORM="macos-x64" ;;
  *) printf 'Unsupported macOS architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac

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
for tool in codesign hdiutil file shasum ditto spctl; do
  command -v "$tool" >/dev/null || { printf 'Required packaging tool is missing: %s\n' "$tool" >&2; exit 1; }
done

DIST_ROOT="$REPO_ROOT/dist/macos-$PACKAGE_ARCH"
DMG_ROOT="$DIST_ROOT/dmg-root"
VERIFY_ROOT="$DIST_ROOT/verification"
MOUNT_ROOT="$DIST_ROOT/mount"
case "$DIST_ROOT" in
  "$REPO_ROOT"/dist/macos-arm64|"$REPO_ROOT"/dist/macos-x64) ;;
  *) printf 'Refusing unsafe macOS output path: %s\n' "$DIST_ROOT" >&2; exit 1 ;;
esac
rm -rf -- "$DIST_ROOT"
mkdir -p "$DMG_ROOT" "$VERIFY_ROOT"

BUILD_NUMBER="$(printf '%s' "$VERSION" | tr -cd '0-9')"
BUILD_NUMBER="${BUILD_NUMBER:-1}"
CLIENT_ROOT="$REPO_ROOT/apps/zentor_client"
APP="$CLIENT_ROOT/build/macos/Build/Products/Release/Avorax.app"
TARGET_ROOT="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
if [[ "$TARGET_ROOT" != /* ]]; then
  printf 'CARGO_TARGET_DIR must be absolute when set.\n' >&2
  exit 1
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  (
    cd "$CLIENT_ROOT"
    "$FLUTTER_BIN" pub get
    "$FLUTTER_BIN" build macos --release \
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
  "$APP/Contents/MacOS/Avorax" \
  "$TARGET_ROOT/release/zentor_local_core" \
  "$TARGET_ROOT/release/zentor_guard_service"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Required macOS release file is missing or linked: %s\n' "$required" >&2
    exit 1
  fi
done

install -m 0755 "$TARGET_ROOT/release/zentor_local_core" \
  "$APP/Contents/MacOS/avorax_core_service"
install -m 0755 "$TARGET_ROOT/release/zentor_guard_service" \
  "$APP/Contents/MacOS/avorax_guard_service"
stage_avorax_desktop_payload "$REPO_ROOT" "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Resources/Avorax"
printf '%s\n' \
  '{' \
  '  "apple_developer_id_signed": false,' \
  '  "apple_notarized": false,' \
  '  "code_signing": "ad-hoc",' \
  '  "status": "development-beta"' \
  '}' >"$APP/Contents/Resources/Avorax/package-signing.json"

file "$APP/Contents/MacOS/Avorax" | tee "$VERIFY_ROOT/flutter-app-file.txt"
file "$APP/Contents/MacOS/avorax_core_service" | tee "$VERIFY_ROOT/local-core-file.txt"
codesign --force --sign - "$APP/Contents/MacOS/avorax_core_service"
codesign --force --sign - "$APP/Contents/MacOS/avorax_guard_service"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign -d --entitlements :- "$APP" >"$VERIFY_ROOT/entitlements.plist" 2>&1 || true
if grep -Fq 'com.apple.security.app-sandbox' "$VERIFY_ROOT/entitlements.plist"; then
  printf 'Release app unexpectedly enables the macOS App Sandbox; scanner file access would be misleading.\n' >&2
  exit 1
fi

"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/smoke_local_core.py" \
  --core "$APP/Contents/MacOS/avorax_core_service" \
  --engine-root "$APP/Contents/MacOS" \
  --report "$VERIFY_ROOT/macos-app-core-smoke.json"

ditto "$APP" "$DMG_ROOT/Avorax.app"
cp "$REPO_ROOT/installer/common/BETA-NOTICE.txt" "$DMG_ROOT/READ-BEFORE-INSTALLING.txt"
cp "$REPO_ROOT/docs/installers.md" "$DMG_ROOT/INSTALLING.md"
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/package_manifest.py" create \
  --root "$DMG_ROOT" \
  --version "$VERSION" \
  --platform "$MANIFEST_PLATFORM" \
  --signing-status ad-hoc
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/package_manifest.py" verify --root "$DMG_ROOT"

DMG="$REPO_ROOT/dist/Avorax-AntiVirus-$VERSION-macos-$PACKAGE_ARCH.dmg"
hdiutil create \
  -volname "Avorax Anti-Virus $VERSION" \
  -srcfolder "$DMG_ROOT" \
  -format UDZO \
  -ov \
  "$DMG"

verify_dmg() {
  local attempt output status
  : >"$VERIFY_ROOT/hdiutil-verify.txt"
  for attempt in 1 2 3; do
    set +e
    output="$(hdiutil verify "$DMG" 2>&1)"
    status=$?
    set -e
    printf 'Attempt %s/3\n%s\n' "$attempt" "$output" | tee -a "$VERIFY_ROOT/hdiutil-verify.txt"
    if [[ "$status" -eq 0 ]]; then
      return 0
    fi
    if [[ "$attempt" -eq 3 || "$output" != *"Resource temporarily unavailable"* ]]; then
      return "$status"
    fi
    sleep "$((attempt * 2))"
  done
  return 1
}
verify_dmg

mkdir -p "$MOUNT_ROOT"
ATTACHED=0
cleanup_mount() {
  if [[ "$ATTACHED" -eq 1 ]]; then
    hdiutil detach "$MOUNT_ROOT" >/dev/null || true
  fi
}
trap cleanup_mount EXIT
hdiutil attach "$DMG" -readonly -nobrowse -mountpoint "$MOUNT_ROOT" >/dev/null
ATTACHED=1
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/package_manifest.py" verify --root "$MOUNT_ROOT"
codesign --verify --deep --strict --verbose=2 "$MOUNT_ROOT/Avorax.app"
"$PYTHON_BIN" "$REPO_ROOT/tools/packaging/smoke_local_core.py" \
  --core "$MOUNT_ROOT/Avorax.app/Contents/MacOS/avorax_core_service" \
  --engine-root "$MOUNT_ROOT/Avorax.app/Contents/MacOS" \
  --report "$VERIFY_ROOT/macos-dmg-core-smoke.json"
hdiutil detach "$MOUNT_ROOT" >/dev/null
ATTACHED=0

set +e
spctl --assess --type execute --verbose=4 "$APP" >"$VERIFY_ROOT/gatekeeper-assessment.txt" 2>&1
SPCTL_EXIT=$?
set -e
printf 'Gatekeeper assessment exit code (expected nonzero for ad-hoc beta): %s\n' "$SPCTL_EXIT" \
  >>"$VERIFY_ROOT/gatekeeper-assessment.txt"
(
  cd "$REPO_ROOT/dist"
  shasum -a 256 "$(basename "$DMG")" >"SHA256SUMS-macos-$PACKAGE_ARCH.txt"
)
printf 'Created macOS DMG: %s\n' "$DMG"
