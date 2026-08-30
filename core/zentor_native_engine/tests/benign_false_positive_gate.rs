use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use zentor_native_engine::{
    EngineConfig, FileScanVerdict, ScanActionMode, Verdict, ZentorNativeEngine,
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("native-engine crate must remain below the repository root")
        .canonicalize()
        .expect("repository root must remain resolvable")
}

fn scan_benign_fixture(file_name: &str, contents: &[u8]) -> (TempDir, FileScanVerdict) {
    let temp = tempfile::tempdir().expect("benign fixture root must be created");
    let downloads = temp.path().join("Downloads");
    fs::create_dir_all(&downloads).expect("benign fixture directory must be created");
    let fixture = downloads.join(file_name);
    fs::write(&fixture, contents).expect("benign fixture must be written");

    let mut config =
        EngineConfig::from_repo_root(repository_root()).expect("bundled engine assets must load");
    config.quarantine_dir = temp.path().join("quarantine");
    let mut engine = ZentorNativeEngine::initialize(config).expect("native engine must initialize");
    let verdict = engine
        .scan_file(fixture, ScanActionMode::DetectOnly)
        .expect("benign fixture scan must complete");

    assert!(
        verdict.quarantine_record.is_none(),
        "detect-only benign fixture scan must not create quarantine state"
    );
    assert!(
        !config_quarantine_exists(&temp),
        "detect-only benign fixture scan must not create a quarantine directory"
    );
    (temp, verdict)
}

fn config_quarantine_exists(temp: &TempDir) -> bool {
    temp.path().join("quarantine").exists()
}

#[test]
fn benign_normal_executable_remains_non_malicious() {
    let (_temp, verdict) =
        scan_benign_fixture("expressvpn-windows-x64.exe", b"normal installer fixture");
    assert!(matches!(
        verdict.final_verdict.verdict,
        Verdict::Clean | Verdict::LikelyClean | Verdict::Observation
    ));
}

#[test]
fn benign_avorax_installer_remains_clean_without_trust_invention() {
    let (_temp, verdict) = scan_benign_fixture(
        "Avorax-AntiVirus-0.2.2-x64-setup.exe",
        b"avorax installer fixture",
    );
    assert!(matches!(
        verdict.final_verdict.verdict,
        Verdict::Clean | Verdict::LikelyClean
    ));
    assert!(!verdict.final_verdict.evidence.iter().any(|evidence| {
        evidence.id == "trusted_local_artifact" || evidence.id == "trusted_publisher"
    }));
}

#[test]
fn benign_avorax_msi_remains_clean_without_trust_invention() {
    let (_temp, verdict) =
        scan_benign_fixture("Avorax-AntiVirus-0.2.2-x64.msi", b"avorax msi fixture");
    assert!(matches!(
        verdict.final_verdict.verdict,
        Verdict::Clean | Verdict::LikelyClean
    ));
    assert!(!verdict.final_verdict.evidence.iter().any(|evidence| {
        evidence.id == "trusted_local_artifact" || evidence.id == "trusted_publisher"
    }));
}
