from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "core" / "zentor_windows_minifilter" / "driver"
INSTALLER = ROOT / "installer" / "windows" / "build-msi.ps1"
GUARD_HEALTH = ROOT / "core" / "zentor_guard_service" / "src" / "driver_health.rs"
TOOLS_WINDOWS = ROOT / "tools" / "windows"


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


def test_guard_pre_execution_reuses_native_engine_instance():
    ipc = read(ROOT / "core" / "zentor_guard_service" / "src" / "driver_ipc.rs")
    assert "NativeEngineCache" in ipc
    assert "OnceLock" in ipc
    assert "cached_native_engine_verdict" in ipc
    assert ipc.count("ZentorNativeEngine::initialize") == 1
    assert "Mutex<ZentorNativeEngine>" in ipc


def test_guard_hashes_driver_files_with_streaming_io():
    ipc = read(ROOT / "core" / "zentor_guard_service" / "src" / "driver_ipc.rs")
    assert "BufReader" in ipc
    assert "std::io::copy" in ipc
    assert "fs::read(path)" not in ipc


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
    assert "reboot_required" in guard
    assert "load_attempted" in guard
    assert "try_load_driver_filter" in guard
    assert "TESTSIGNING is off" in guard
    assert "bcdedit /set testsigning on" in guard


def test_driver_installer_does_not_silently_enable_testsigning():
    installer = read(INSTALLER)
    start = installer.index("$testSigningRequired")
    end = installer.index("'@ | Set-Content -LiteralPath $driverInstallScript", start)
    generated_script = installer[start:end]
    assert "bcdedit.exe /set testsigning on" not in generated_script
    assert "testsigning_required" in generated_script
    assert "Avorax will not enable TESTSIGNING silently" in generated_script
    assert "pnputil.exe /add-driver" in generated_script
    assert "fltmc.exe load ZentorAvFilter" in generated_script


def test_separate_testsigning_helper_requires_admin_and_reboot():
    helper = read(TOOLS_WINDOWS / "avorax-enable-test-signing.ps1")
    assert "#Requires -RunAsAdministrator" in helper
    assert "bcdedit.exe /set testsigning on" in helper
    assert "Reboot is required" in helper
    assert "development driver validation" in helper


def test_update_package_excludes_driver_and_self_overwriting_update_service():
    builder = read(ROOT / "tools" / "update" / "avorax-build-update-package.ps1")
    assert "driver-tools" in builder
    assert "driver_update_included = $false" in builder
    assert "avorax_update_service.exe" in builder
    assert "CreateEntryFromFile" in builder
    # Existing updater compatibility: do not use Compress-Archive because it writes backslash entries.
    assert "Compress-Archive" not in re.sub(r"#.*", "", builder)


def test_update_service_rejects_development_keys_unless_explicitly_allowed():
    verifier = read(ROOT / "core" / "avorax_update_service" / "src" / "update_verifier.rs")
    main = read(ROOT / "core" / "avorax_update_service" / "src" / "main.rs")
    applier = read(ROOT / "core" / "avorax_update_service" / "src" / "update_applier.rs")

    assert "pub fn production" in verifier
    assert "allow_dev_key: false" in verifier
    assert "UpdateChannel::Stable" in verifier
    assert "pub fn for_cli" in verifier
    assert "AVORAX_ALLOW_DEVELOPMENT_UPDATES" in verifier
    assert "--allow-development-key" in main
    assert "VerificationPolicy::for_cli" in main
    assert "VerificationPolicy::development(current_version)" not in main
    assert "VerificationPolicy::development(current_version)" not in applier


def test_update_apply_restores_snapshot_on_payload_failure():
    applier = read(ROOT / "core" / "avorax_update_service" / "src" / "update_applier.rs")
    rollback = read(ROOT / "core" / "avorax_update_service" / "src" / "rollback.rs")

    assert "pub fn restore_snapshot" in rollback
    assert "if let Err(error) = apply_payload_sections" in applier
    assert "restore_snapshot(&rollback, install_dir)" in applier
    assert "rollback_ok" in applier
    assert "rollback_error" in applier
    assert "update apply failed; rollback snapshot was restored" in applier
    assert "let _ = start_services()" in applier
