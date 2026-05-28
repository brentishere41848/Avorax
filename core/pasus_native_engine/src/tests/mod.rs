#[cfg(test)]
mod tests {
    use std::fs;

    use crate::analyzers::{analyze_path, FileType};
    use crate::config::EngineConfig;
    use crate::engine::{sha256_bytes, PasusNativeEngine};
    use crate::heuristics;
    use crate::ml::NativeModelRunner;
    use crate::rules::RuleDb;
    use crate::scan::ScanActionMode;
    use crate::signatures::eicar_signature::EICAR_ASCII;
    use crate::signatures::SignatureDb;
    use crate::trust::Allowlist;
    use crate::verdict::Verdict;

    fn test_engine() -> (tempfile::TempDir, PasusNativeEngine) {
        let dir = tempfile::tempdir().unwrap();
        let assets = dir.path().join("assets/pasus_native");
        fs::create_dir_all(assets.join("signatures")).unwrap();
        fs::create_dir_all(assets.join("rules")).unwrap();
        fs::create_dir_all(assets.join("ml")).unwrap();
        fs::create_dir_all(assets.join("trust")).unwrap();
        fs::write(
            assets.join("signatures/pasus_core.psig"),
            r#"{"format":"pasus-signature-pack-v1","version":"1","signatures":[]}"#,
        )
        .unwrap();
        fs::write(
            assets.join("rules/pasus_rules.prule"),
            r#"{"format":"pasus-rule-pack-v1","version":"1","rules":[{"id":"ps_encoded_download_exec","name":"Suspicious PowerShell encoded downloader execution","description":"Encoded PowerShell with download and execution indicators.","category":"suspiciousScript","confidence":"high","verdict":"probableMalware","false_positive_notes":"Admin scripts can contain encoded commands; this rule requires download and execution indicators.","conditions":[{"type":"file_type","equals":"powershell_script"},{"type":"encoded_command"},{"type":"downloader_and_execution"}],"min_condition_matches":3,"action":"review_or_block_by_policy"}]}"#,
        )
        .unwrap();
        fs::write(
            assets.join("ml/pasus_native_model.pmodel"),
            r#"{"model_name":"Pasus Native Development Model","model_version":"0.1.0-dev","model_format_version":"pmodel-v1","feature_schema_version":"pne-features-v1","production_ready":false,"precision":0.0,"recall":0.0,"false_positive_rate":1.0,"bias":-3.0,"weights":{"encoded_command_flag":2.5,"suspicious_string_count":1.5,"double_extension":1.3,"known_bad_flag":5.0},"thresholds":{"suspicious":0.65,"probable_malware":0.86,"confirmed_malware":0.98},"limitations":["Development fixture model; not production protection."]}"#,
        )
        .unwrap();
        let known_bad_hash = sha256_bytes(b"harmless-known-bad-fixture");
        fs::write(assets.join("trust/pasus_known_good.ptrust"), r#"{"hashes":[]}"#).unwrap();
        fs::write(
            assets.join("trust/pasus_known_bad_test.ptrust"),
            format!(r#"{{"hashes":["{known_bad_hash}"]}}"#),
        )
        .unwrap();
        let mut config = EngineConfig::from_repo_root(dir.path());
        config.quarantine_dir = dir.path().join("quarantine");
        let engine = PasusNativeEngine::initialize(config).unwrap();
        (dir, engine)
    }

    #[test]
    fn eicar_detected_by_native_signature() {
        let (_dir, mut engine) = test_engine();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("eicar.txt"),
                EICAR_ASCII.as_bytes(),
                ScanActionMode::DetectOnly,
            )
            .unwrap();
        assert_eq!(verdict.engine, "Pasus Native Engine");
        assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
    }

    #[test]
    fn normal_exe_in_downloads_is_not_malware() {
        let (dir, mut engine) = test_engine();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("expressvpn-windows-x64.exe");
        fs::write(&file, b"normal installer fixture").unwrap();
        let verdict = engine.scan_file(file, ScanActionMode::DetectOnly).unwrap();
        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::Clean | Verdict::LikelyClean | Verdict::Observation
        ));
    }

    #[test]
    fn encoded_powershell_rule_returns_probable() {
        let (dir, mut engine) = test_engine();
        let file = dir.path().join("dropper.ps1");
        fs::write(
            &file,
            b"powershell -EncodedCommand AAAA; IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/a')",
        )
        .unwrap();
        let verdict = engine.scan_file(file, ScanActionMode::DetectOnly).unwrap();
        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::Suspicious | Verdict::ProbableMalware
        ));
    }

    #[test]
    fn detect_only_never_quarantines() {
        let (dir, mut engine) = test_engine();
        let file = dir.path().join("eicar-memory.txt");
        let verdict = engine
            .scan_bytes_for_test(file.clone(), EICAR_ASCII.as_bytes(), ScanActionMode::DetectOnly)
            .unwrap();
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn confirmed_mode_quarantines_eicar() {
        let (dir, mut engine) = test_engine();
        let file = dir.path().join("known_bad_fixture.bin");
        fs::write(&file, b"harmless-known-bad-fixture").unwrap();
        let verdict = engine
            .scan_file(file.clone(), ScanActionMode::AutoQuarantineConfirmed)
            .unwrap();
        assert!(verdict.quarantine_record.is_some());
        assert!(!file.exists());
    }

    #[test]
    fn signature_pack_loads_and_counts_builtin() {
        let (dir, _) = test_engine();
        let db = SignatureDb::load_pack(
            &dir.path()
                .join("assets/pasus_native/signatures/pasus_core.psig"),
        )
        .unwrap();
        assert!(db.count() >= 1);
    }

    #[test]
    fn rule_pack_loads() {
        let (dir, _) = test_engine();
        let db = RuleDb::load_pack(&dir.path().join("assets/pasus_native/rules/pasus_rules.prule"))
            .unwrap();
        assert_eq!(db.count(), 1);
    }

    #[test]
    fn pmodel_loads_and_is_development_only() {
        let (dir, _) = test_engine();
        let runner = NativeModelRunner::load(
            &dir.path()
                .join("assets/pasus_native/ml/pasus_native_model.pmodel"),
        )
        .unwrap();
        assert!(runner.is_loaded());
        assert!(!runner.production_ready());
    }

    #[test]
    fn archive_zip_slip_is_detected_by_analyzer() {
        let file = std::path::Path::new("sample.zip");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&[0; 22]);
        let name = b"../evil.exe";
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name);
        let analysis = analyze_path(file, &bytes).unwrap();
        assert_eq!(analysis.file_type, FileType::Zip);
        assert!(analysis.archive.unwrap().zip_slip_blocked);
    }

    #[test]
    fn allowlist_blocks_root_paths() {
        assert!(!Allowlist::validate_path("C:\\"));
        assert!(!Allowlist::validate_path("/"));
        assert!(Allowlist::validate_path("C:\\Users\\Brent\\Downloads"));
    }

    #[test]
    fn double_extension_increases_score() {
        let path = std::path::Path::new("invoice.pdf.exe");
        assert!(heuristics::filename::filename_risk(path) >= 25);
    }

    #[test]
    fn self_test_detects_eicar() {
        let (_, mut engine) = test_engine();
        let report = engine.engine_self_test().unwrap();
        assert!(report.eicar_detected);
        assert_eq!(report.overall_result, "pass");
    }
}
