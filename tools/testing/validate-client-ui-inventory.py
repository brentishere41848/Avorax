#!/usr/bin/env python3
"""Validate that the client UI inventory is source-accounted.

This gate is intentionally dependency-free. It cross-checks the documented
routes, major controls, settings, and verification statuses against the Flutter
sources so a dead button, hidden route, or stale matrix row fails the release
verifier instead of drifting silently.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOC_PATH = ROOT / "docs" / "client-ui.md"
ROUTER_PATH = ROOT / "apps" / "zentor_client" / "lib" / "app" / "router.dart"
SIDEBAR_PATH = (
    ROOT
    / "apps"
    / "zentor_client"
    / "lib"
    / "shared"
    / "widgets"
    / "zentor_sidebar.dart"
)
BOTTOM_NAV_PATH = (
    ROOT
    / "apps"
    / "zentor_client"
    / "lib"
    / "shared"
    / "widgets"
    / "zentor_bottom_nav.dart"
)

EXPECTED_ROUTES = (
    "/onboarding",
    "/home",
    "/scan",
    "/quarantine",
    "/allowlist",
    "/protection",
    "/device",
    "/logs",
    "/settings",
    "/updates",
    "/privacy",
)
EXPECTED_DESKTOP_DESTINATIONS = (
    ("/home", "Home"),
    ("/scan", "Scan"),
    ("/protection", "Protection"),
    ("/quarantine", "Quarantine"),
    ("/allowlist", "Allowlist"),
    ("/logs", "Security Events"),
    ("/device", "Device"),
    ("/updates", "Updates"),
    ("/settings", "Settings"),
)
EXPECTED_MOBILE_ROUTES = ("/home", "/scan", "/quarantine", "/settings")
VERIFICATION_STATUS_MARKERS = (
    "verified",
    "partial",
    "limited",
    "guarded",
    "intentional",
    "optional",
)


@dataclass(frozen=True)
class RequiredControl:
    screen: str
    control: str
    backing_action: str
    source: str
    source_markers: tuple[str, ...]


REQUIRED_CONTROLS = (
    RequiredControl(
        "Home",
        "Run Quick Scan",
        "controller.runQuickScan(actionMode: detectOnly)",
        "apps/zentor_client/lib/features/home/home_screen.dart",
        ("'Run Quick Scan'", "runQuickScan(", "ScanActionMode.detectOnly"),
    ),
    RequiredControl(
        "Home",
        "Run Full Scan",
        "controller.runFullScan(actionMode: detectOnly)",
        "apps/zentor_client/lib/features/home/home_screen.dart",
        ("'Run Full Scan'", "runFullScan(", "ScanActionMode.detectOnly"),
    ),
    RequiredControl(
        "Home",
        "Enable Protection",
        "controller.startProtection(confirmed: true)",
        "apps/zentor_client/lib/features/home/home_screen.dart",
        ("'Enable Protection'", "startProtection(confirmed: true)"),
    ),
    RequiredControl(
        "Home",
        "Stop Protection",
        "controller.stopProtection(confirmed: true)",
        "apps/zentor_client/lib/features/home/home_screen.dart",
        ("'Stop Protection'", "stopProtection(confirmed: true)"),
    ),
    RequiredControl(
        "Home",
        "Download, verify, install",
        "controller.installUpdateInApp(confirmed: true)",
        "apps/zentor_client/lib/features/home/home_screen.dart",
        ("'Download, verify, install'", "installUpdateInApp(confirmed: true)"),
    ),
    RequiredControl(
        "Home",
        "View all security events",
        "context.go('/logs')",
        "apps/zentor_client/lib/features/home/home_screen.dart",
        ("context.go('/logs')",),
    ),
    RequiredControl(
        "Scan",
        "Scan action mode segmented control: Detect only, Auto quarantine confirmed, Legacy confirmed-only",
        "controller.setScanActionMode",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("SegmentedButton<ScanActionMode>", "controller.setScanActionMode"),
    ),
    RequiredControl(
        "Scan",
        "Quick Scan",
        "controller.runQuickScan(confirmedAutoAction: ...)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Quick Scan'", "runQuickScan(", "confirmedAutoAction:"),
    ),
    RequiredControl(
        "Scan",
        "Full Scan",
        "controller.runFullScan(confirmedAutoAction: ...)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Full Scan'", "runFullScan(", "confirmedAutoAction:"),
    ),
    RequiredControl(
        "Scan",
        "Custom File",
        "controller.scanSelectedFile(confirmedAutoAction: ...)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Custom File'", "scanSelectedFile(", "confirmedAutoAction:"),
    ),
    RequiredControl(
        "Scan",
        "Custom Folder",
        "controller.scanSelectedFolder(confirmedAutoAction: ...)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Custom Folder'", "scanSelectedFolder(", "confirmedAutoAction:"),
    ),
    RequiredControl(
        "Scan",
        "Cancel scan",
        "controller.cancelScan",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Cancel'", "onCancel: controller.cancelScan"),
    ),
    RequiredControl(
        "Scan",
        "Retry engine/service status",
        "retry callback from engine status panel",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Retry'", "onRetry: controller.unawaitedCheckMalwareEngine"),
    ),
    RequiredControl(
        "Scan",
        "Start Core Service",
        "onStartCoreService(confirmed: true)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Start Core Service'", "onStartCoreService(confirmed: true)"),
    ),
    RequiredControl(
        "Scan",
        "Open install report",
        "onOpenInstallReport(confirmed: true)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Open install report'", "onOpenInstallReport(confirmed: true)"),
    ),
    RequiredControl(
        "Scan",
        "Repair installation",
        "onRepairInstallation(confirmed: true)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Repair installation'", "onRepairInstallation(confirmed: true)"),
    ),
    RequiredControl(
        "Scan result card",
        "Quarantine",
        "controller.quarantineThreat(threat, confirmed: true)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Quarantine'", "_confirmQuarantine", "quarantineThreat("),
    ),
    RequiredControl(
        "Scan result card",
        "Keep / Ignore",
        "controller.ignoreThreat(threat, confirmed: true)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Keep / Ignore'", "_confirmIgnoreThreat", "ignoreThreat("),
    ),
    RequiredControl(
        "Scan result card",
        "Mark false positive",
        "controller.markThreatFalsePositive(threat, confirmed: true)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Mark false positive'", "markThreatFalsePositive("),
    ),
    RequiredControl(
        "Scan result card",
        "Mark malicious",
        "controller.markThreatMalicious(threat, confirmed: true)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Mark malicious'", "markThreatMalicious("),
    ),
    RequiredControl(
        "Scan result card",
        "Add to allowlist",
        "controller.addThreatToAllowlist(threat, confirmed: true)",
        "apps/zentor_client/lib/features/scan/scan_screen.dart",
        ("'Add to allowlist'", "addThreatToAllowlist("),
    ),
    RequiredControl(
        "Protection",
        "Enable Protection",
        "controller.startProtection(confirmed: true)",
        "apps/zentor_client/lib/features/protection/protection_screen.dart",
        ("'Enable Protection'", "startProtection(confirmed: true)"),
    ),
    RequiredControl(
        "Protection",
        "Stop Protection",
        "controller.stopProtection(confirmed: true)",
        "apps/zentor_client/lib/features/protection/protection_screen.dart",
        ("'Stop Protection'", "stopProtection(confirmed: true)"),
    ),
    RequiredControl(
        "Protection",
        "Run protection self-test",
        "controller.runProtectionSelfTest",
        "apps/zentor_client/lib/features/protection/protection_screen.dart",
        ("'Run protection self-test'", "runProtectionSelfTest"),
    ),
    RequiredControl(
        "Protection",
        "Run Quick Scan",
        "controller.runQuickScan(actionMode: detectOnly)",
        "apps/zentor_client/lib/features/protection/protection_screen.dart",
        ("'Run Quick Scan'", "runQuickScan(", "ScanActionMode.detectOnly"),
    ),
    RequiredControl(
        "Quarantine",
        "Refresh",
        "controller.unawaitedRefreshQuarantine",
        "apps/zentor_client/lib/features/quarantine/quarantine_screen.dart",
        ("'Refresh'", "unawaitedRefreshQuarantine"),
    ),
    RequiredControl(
        "Quarantine item",
        "Restore / Keep",
        "controller.restoreQuarantineItem(item, confirmed: true)",
        "apps/zentor_client/lib/features/quarantine/quarantine_screen.dart",
        ("'Restore / Keep'", "restoreQuarantineItem("),
    ),
    RequiredControl(
        "Quarantine item",
        "Delete permanently",
        "controller.deleteQuarantineItem(item, confirmed: true)",
        "apps/zentor_client/lib/features/quarantine/quarantine_screen.dart",
        ("'Delete permanently'", "deleteQuarantineItem("),
    ),
    RequiredControl(
        "Quarantine item",
        "Scan original path",
        "controller.rescanQuarantineOriginal(item)",
        "apps/zentor_client/lib/features/quarantine/quarantine_screen.dart",
        ("'Scan original path'", "rescanQuarantineOriginal("),
    ),
    RequiredControl(
        "Allowlist",
        "Refresh",
        "controller.unawaitedRefreshAllowlist",
        "apps/zentor_client/lib/features/allowlist/allowlist_screen.dart",
        ("'Refresh'", "unawaitedRefreshAllowlist"),
    ),
    RequiredControl(
        "Allowlist entry",
        "Remove",
        "controller.removeAllowlistEntry(entry, confirmed: true)",
        "apps/zentor_client/lib/features/allowlist/allowlist_screen.dart",
        ("'Remove'", "removeAllowlistEntry("),
    ),
    RequiredControl(
        "Security Events",
        "Export logs",
        "controller.exportLogs(confirmed: true)",
        "apps/zentor_client/lib/features/logs/logs_screen.dart",
        ("'Export logs'", "exportLogs("),
    ),
    RequiredControl(
        "Security Events",
        "Export support bundle",
        "controller.exportSupportBundle(confirmed: true)",
        "apps/zentor_client/lib/features/logs/logs_screen.dart",
        ("'Export support bundle'", "exportSupportBundle("),
    ),
    RequiredControl(
        "Settings",
        "Test Cloud Connection",
        "controller.testCloudConnection",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Test Cloud Connection'", "testCloudConnection"),
    ),
    RequiredControl(
        "Settings",
        "Check for updates",
        "controller.unawaitedCheckForUpdates",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Check for updates'", "unawaitedCheckForUpdates"),
    ),
    RequiredControl(
        "Settings",
        "Download, verify, install",
        "controller.installUpdateInApp(confirmed: true)",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Download, verify, install'", "installUpdateInApp("),
    ),
    RequiredControl(
        "Settings",
        "Protection mode dropdown",
        "controller.setProtectionMode(mode, confirmed: true)",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("labelText: 'Protection mode'", "setProtectionMode("),
    ),
    RequiredControl(
        "Settings",
        "Run Protection Self-Test",
        "controller.runProtectionSelfTest",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Run Protection Self-Test'", "runProtectionSelfTest"),
    ),
    RequiredControl(
        "Settings",
        "Ransomware protected folders text field",
        "`_ransomwareProtectedRoots` controller",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("_ransomwareProtectedRoots", "'Ransomware protected folders'"),
    ),
    RequiredControl(
        "Settings",
        "Trusted backup/sync processes text field",
        "`_ransomwareTrustedProcesses` controller",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("_ransomwareTrustedProcesses", "'Trusted backup/sync processes'"),
    ),
    RequiredControl(
        "Settings",
        "Save ransomware protection settings",
        "controller.updateRansomwareGuardSettings(..., confirmed: true)",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Save ransomware protection settings'", "updateRansomwareGuardSettings("),
    ),
    RequiredControl(
        "Settings",
        "Enable in-app scheduled quick scan switch",
        "controller.updateScheduledQuickScanSettings(..., confirmed: true)",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Enable in-app scheduled quick scan'", "updateScheduledQuickScanSettings("),
    ),
    RequiredControl(
        "Settings",
        "Scan interval dropdown",
        "same as scheduled quick scan settings",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("labelText: 'Scan interval'", "updateScheduledQuickScanSettings("),
    ),
    RequiredControl(
        "Settings",
        "Check engine",
        "controller.unawaitedCheckMalwareEngine",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Check engine'", "unawaitedCheckMalwareEngine"),
    ),
    RequiredControl(
        "Settings",
        "View privacy policy",
        "context.go('/privacy')",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'View privacy policy'", "context.go('/privacy')"),
    ),
    RequiredControl(
        "Settings",
        "Developer options switch",
        "local `_developerOptions`; may disable saved override",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Developer options'", "_developerOptions"),
    ),
    RequiredControl(
        "Settings",
        "API endpoint, Project ID, Public Client Key fields",
        "text controllers",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'API endpoint'", "'Project ID'", "'Public Client Key'"),
    ),
    RequiredControl(
        "Settings",
        "Save developer override / Disable developer override",
        "controller.saveDeveloperCloudOverride(..., confirmed: true)",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Save developer override'", "'Disable developer override'", "saveDeveloperCloudOverride("),
    ),
    RequiredControl(
        "Settings",
        "Export logs",
        "controller.exportLogs(confirmed: true)",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Export logs'", "exportLogs("),
    ),
    RequiredControl(
        "Settings",
        "Export support bundle",
        "controller.exportSupportBundle(confirmed: true)",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Export support bundle'", "exportSupportBundle("),
    ),
    RequiredControl(
        "Settings",
        "Reset configuration",
        "controller.resetConfiguration(confirmed: true)",
        "apps/zentor_client/lib/features/settings/settings_screen.dart",
        ("'Reset configuration'", "resetConfiguration("),
    ),
    RequiredControl(
        "Updates",
        "Check for updates",
        "controller.checkForInAppUpdate",
        "apps/zentor_client/lib/features/update/update_screen.dart",
        ("'Check for updates'", "checkForInAppUpdate"),
    ),
    RequiredControl(
        "Updates",
        "Download, verify, install",
        "controller.downloadVerifyAndInstallUpdate(confirmed: true)",
        "apps/zentor_client/lib/features/update/update_screen.dart",
        ("'Download, verify, install'", "downloadVerifyAndInstallUpdate("),
    ),
    RequiredControl(
        "Updates",
        "Rollback previous version",
        "controller.rollbackUpdateInApp(confirmed: true)",
        "apps/zentor_client/lib/features/update/update_screen.dart",
        ("'Rollback previous version'", "rollbackUpdateInApp("),
    ),
    RequiredControl(
        "Protected Apps",
        "Rescan",
        "controller.unawaitedDetectApps",
        "apps/zentor_client/lib/features/protected_apps/protected_apps_screen.dart",
        ("'Rescan'", "unawaitedDetectApps"),
    ),
    RequiredControl(
        "Protected Apps",
        "Add file or app",
        "controller.addManualProtectedAppFile(confirmed: true)",
        "apps/zentor_client/lib/features/protected_apps/protected_apps_screen.dart",
        ("'Add file or app'", "addManualProtectedAppFile("),
    ),
    RequiredControl(
        "Protected Apps",
        "Add folder",
        "controller.addManualProtectedAppFolder(confirmed: true)",
        "apps/zentor_client/lib/features/protected_apps/protected_apps_screen.dart",
        ("'Add folder'", "addManualProtectedAppFolder("),
    ),
    RequiredControl(
        "Protected Apps",
        "Calculate build hash",
        "controller.calculateProtectedAppHash(confirmed: true)",
        "apps/zentor_client/lib/features/protected_apps/protected_apps_screen.dart",
        ("'Calculate build hash'", "calculateProtectedAppHash("),
    ),
    RequiredControl(
        "Protected Apps",
        "Select detected app row",
        "controller.selectDetectedApp(app, confirmed: true)",
        "apps/zentor_client/lib/features/protected_apps/protected_apps_screen.dart",
        ("selectDetectedApp(",),
    ),
    RequiredControl(
        "Onboarding",
        "Continue",
        "controller.completeOnboarding",
        "apps/zentor_client/lib/features/onboarding/onboarding_screen.dart",
        ("'Continue'", "completeOnboarding"),
    ),
    RequiredControl(
        "Onboarding",
        "Privacy details",
        "context.go('/privacy')",
        "apps/zentor_client/lib/features/onboarding/onboarding_screen.dart",
        ("'Privacy details'", "context.go('/privacy')"),
    ),
)


class InventoryFailure(Exception):
    pass


def read(path: Path) -> str:
    if not path.is_file():
        raise InventoryFailure(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def fail(message: str) -> None:
    raise InventoryFailure(message)


def extract_control_rows(doc: str) -> dict[tuple[str, str], tuple[str, str, str]]:
    try:
        start = doc.index("## Control Matrix")
        end = doc.index("## Visible Engine", start)
    except ValueError as exc:
        raise InventoryFailure("docs/client-ui.md is missing the Control Matrix section") from exc

    rows: dict[tuple[str, str], tuple[str, str, str]] = {}
    malformed: list[str] = []
    for line in doc[start:end].splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells[0] == "Screen" or set(cells[0]) == {"-"}:
            continue
        if len(cells) != 5:
            malformed.append(line)
            continue
        screen, control, backing_action, behavior, status = cells
        if not screen or not control or not backing_action or not behavior or not status:
            malformed.append(line)
            continue
        status_lower = status.lower()
        if not any(marker in status_lower for marker in VERIFICATION_STATUS_MARKERS):
            malformed.append(line)
            continue
        key = (screen, control)
        if key in rows:
            fail(f"duplicate UI control matrix row: {screen} / {control}")
        rows[key] = (backing_action, behavior, status)

    if malformed:
        sample = "\n".join(malformed[:5])
        fail(f"malformed or unverifiable UI control matrix row(s):\n{sample}")
    return rows


def assert_route_inventory(doc: str, router: str, sidebar: str, bottom_nav: str) -> None:
    router_routes = tuple(
        dict.fromkeys(
            re.findall(r"GoRoute\s*\(\s*path:\s*'([^']+)'", router, flags=re.S)
        )
    )
    if set(router_routes) != set(EXPECTED_ROUTES):
        fail(
            "router.dart route set mismatch: "
            f"expected {EXPECTED_ROUTES}, found {router_routes}"
        )

    sidebar_destinations = tuple(
        re.findall(
            r"ZentorNavDestination\(\s*'([^']+)'\s*,\s*'([^']+)'",
            sidebar,
            flags=re.S,
        )
    )
    if sidebar_destinations != EXPECTED_DESKTOP_DESTINATIONS:
        fail(
            "desktop sidebar destinations changed without matrix update: "
            f"expected {EXPECTED_DESKTOP_DESTINATIONS}, found {sidebar_destinations}"
        )

    bottom_routes = tuple(
        re.findall(r"destination\.path == '([^']+)'", bottom_nav, flags=re.S)
    )
    if bottom_routes != EXPECTED_MOBILE_ROUTES:
        fail(
            "mobile bottom navigation changed without matrix update: "
            f"expected {EXPECTED_MOBILE_ROUTES}, found {bottom_routes}"
        )

    for route in EXPECTED_ROUTES:
        if f"| `{route}`" not in doc:
            fail(f"docs/client-ui.md Navigation Matrix does not list {route}")
    for route, label in EXPECTED_DESKTOP_DESTINATIONS:
        if f"| `{route}` {label} | visible" not in doc:
            fail(f"docs/client-ui.md does not mark desktop route {route} / {label}")
    for route in EXPECTED_MOBILE_ROUTES:
        if f"| `{route}`" not in doc or "| visible |" not in doc:
            fail(f"docs/client-ui.md does not mark mobile route {route} visible")
    if "packaged navigation E2E partial" not in doc:
        fail("docs/client-ui.md must keep packaged navigation E2E limitation visible")


def assert_control_inventory(doc: str, rows: dict[tuple[str, str], tuple[str, str, str]]) -> None:
    if len(rows) < 50:
        fail(f"Control Matrix is unexpectedly small: {len(rows)} rows")

    source_cache: dict[Path, str] = {}
    for control in REQUIRED_CONTROLS:
        row = rows.get((control.screen, control.control))
        if row is None:
            fail(f"missing UI control matrix row: {control.screen} / {control.control}")
        backing_action, _behavior, status = row
        if control.backing_action not in backing_action:
            fail(
                "UI control matrix backing action drift: "
                f"{control.screen} / {control.control} expected "
                f"{control.backing_action!r}, found {backing_action!r}"
            )
        if "verified" not in status.lower() and "partial" not in status.lower():
            fail(
                "UI control matrix row lacks explicit verification status: "
                f"{control.screen} / {control.control} => {status}"
            )

        source_path = ROOT / control.source
        source_text = source_cache.setdefault(source_path, read(source_path))
        for marker in control.source_markers:
            if marker not in source_text:
                fail(
                    "UI source marker missing for matrix row "
                    f"{control.screen} / {control.control}: {control.source} lacks {marker!r}"
                )

    required_doc_markers = (
        "No scan results.",
        "No threats found.",
        "No quarantined files.",
        "No allowlist entries.",
        "No activity yet.",
        "Update check failed.",
        "Unable to read platform info.",
        "Pre-execution blocking",
        "In-app scheduled quick scan",
        "Avorax does not promise secure erasure on SSDs.",
    )
    for marker in required_doc_markers:
        if marker not in doc:
            fail(f"docs/client-ui.md missing required limitation/empty-state marker: {marker}")


def main() -> int:
    try:
        doc = read(DOC_PATH)
        rows = extract_control_rows(doc)
        assert_route_inventory(
            doc,
            read(ROUTER_PATH),
            read(SIDEBAR_PATH),
            read(BOTTOM_NAV_PATH),
        )
        assert_control_inventory(doc, rows)
    except InventoryFailure as exc:
        print(f"client UI inventory validation failed: {exc}", file=sys.stderr)
        return 1

    print(
        "client UI inventory validation passed: "
        f"{len(EXPECTED_ROUTES)} routes, "
        f"{len(EXPECTED_DESKTOP_DESTINATIONS)} desktop destinations, "
        f"{len(EXPECTED_MOBILE_ROUTES)} mobile destinations, "
        f"{len(REQUIRED_CONTROLS)} source-accounted controls"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
