from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "core" / "zentor_windows_minifilter" / "driver"
INSTALLER = ROOT / "installer" / "windows" / "build-msi.ps1"
GUARD_HEALTH = ROOT / "core" / "zentor_guard_service" / "src" / "driver_health.rs"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def test_custom_minifilter_registers_execution_write_and_rename_callbacks():
    driver_c = read(DRIVER / "Driver.c")
    assert "IRP_MJ_CREATE" in driver_c
    assert "IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION" in driver_c
    assert "IRP_MJ_WRITE" in driver_c
    assert "IRP_MJ_SET_INFORMATION" in driver_c
    assert "ZentorPreWrite" in driver_c
    assert "ZentorPreSetInformation" in driver_c


def test_create_callback_classifies_create_open_and_execute_events():
    filter_c = read(DRIVER / "Filter.c")
    assert "ZentorClassifyCreateEvent" in filter_c
    assert "FILE_CREATE" in filter_c
    assert "FILE_OPEN_IF" in filter_c
    assert "FILE_EXECUTE" in filter_c
    assert "ZentorEventImageExecuteAttempt" in filter_c
    assert "ZentorEventFileCreate" in filter_c
    assert "ZentorEventFileOpen" in filter_c


def test_driver_request_captures_basic_file_metadata_and_rename_target():
    header = read(DRIVER / "ZentorAvFilter.h")
    scan = read(DRIVER / "ScanRequest.c")
    assert "FileAttributes" in header
    assert "CreateDisposition" in header
    assert "RenameTarget" in header
    assert "ZENTOR_MAX_RENAME_TARGET_CHARS" in header
    assert "FltQueryInformationFile" in scan
    assert "ZentorTryCaptureRenameTarget" in scan


def test_guard_service_has_live_filter_manager_message_loop():
    port = read(ROOT / "core" / "zentor_guard_service" / "src" / "driver_port.rs")
    main = read(ROOT / "core" / "zentor_guard_service" / "src" / "main.rs")
    assert "FilterConnectCommunicationPort" in port
    assert "FilterGetMessage" in port
    assert "FilterReplyMessage" in port
    assert "NativeScanRequest" in port
    assert "NativeScanVerdict" in port
    assert "driver_port::start_background_worker" in main


def test_driver_name_is_consistent_across_inf_installer_and_guard_health():
    inf = read(DRIVER / "ZentorAvFilter.inf")
    installer = read(INSTALLER)
    guard = read(GUARD_HEALTH)
    assert 'const DRIVER_SERVICE_NAME: &str = "ZentorAvFilter"' in guard
    assert "AddService = ZentorAvFilter" in inf
    assert "ServiceBinary = %12%\\ZentorAvFilter.sys" in inf
    assert "ZentorAvFilter" in installer
    assert "Avorax AV Minifilter" in inf


def test_driver_health_reports_testsigning_policy_when_installed_but_not_loaded():
    guard = read(GUARD_HEALTH)
    assert "testSigningRequired" in guard
    assert "TESTSIGNING is off" in guard
    assert "bcdedit /set testsigning on" in guard


def test_update_package_excludes_driver_and_self_overwriting_update_service():
    builder = read(ROOT / "tools" / "update" / "avorax-build-update-package.ps1")
    assert "driver-tools" in builder
    assert "driver_update_included = $false" in builder
    assert "avorax_update_service.exe" in builder
    assert "CreateEntryFromFile" in builder
    # Existing updater compatibility: do not use Compress-Archive because it writes backslash entries.
    assert "Compress-Archive" not in re.sub(r"#.*", "", builder)
