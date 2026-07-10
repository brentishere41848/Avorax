#[cfg(test)]
mod tests {
    use std::fs;

    use crate::analyzers::{analyze_path, FileType};
    use crate::behavior::{BehaviorDecision, FileActivityEvent};
    use crate::config::EngineConfig;
    use crate::detection_provider::{
        DetectionProvider, DetectionProviderRegistry, DetectionProviderStatus, ScanContext,
    };
    use crate::engine::{sha256_bytes, ZentorNativeEngine};
    use crate::heuristics;
    use crate::ml::NativeModelRunner;
    use crate::rules::{NativeRule, RuleCondition, RuleDb};
    use crate::scan::quick_scan_planner;
    use crate::scan::ScanActionMode;
    use crate::signatures::eicar_signature::EICAR_ASCII;
    use crate::signatures::pack_format::SignaturePack;
    use crate::signatures::{NativeSignature, SignatureDb, SignatureType};
    use crate::threat_intel::{IndicatorType, ThreatIntelIndicator};
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
        let github_known_bad_signature = NativeSignature {
            id: "ZGI-HASH-UNIT-001".to_string(),
            name: "GitHub malware-intel known-bad hash fixture".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Trojan,
            confidence: Confidence::Confirmed,
            severity: "critical".to_string(),
            signature_type: SignatureType::ExactHash,
            pattern: github_known_bad_hash,
            mask: None,
            offset: None,
            file_types: vec!["*".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Hash-only test fixture; no malware binary is included."
                .to_string(),
            action_policy: "quarantine_if_policy_allows".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let (github_known_bad_pack, _) = crate::signatures::signature_compiler::compile_pack(
            vec![github_known_bad_signature],
            "1.0.0".to_string(),
        )
        .unwrap();
        fs::write(
            assets.join("signatures/zentor_github_known_bad.zsig"),
            serde_json::to_string(&github_known_bad_pack).unwrap(),
        )
        .unwrap();
        let mut rule_pack = crate::rules::RulePack {
            format: crate::rules::rule_compiler::RULE_PACK_FORMAT.to_string(),
            version: "1.0.0".to_string(),
            compiler_version: None,
            created_at: None,
            pack_sha256: None,
            rules: vec![crate::rules::NativeRule {
                id: "ps_encoded_download_exec".to_string(),
                name: "Suspicious PowerShell encoded downloader execution".to_string(),
                description: "Encoded PowerShell with download and execution indicators."
                    .to_string(),
                category: ThreatCategory::SuspiciousScript,
                confidence: Confidence::High,
                verdict: Verdict::ProbableMalware,
                false_positive_notes:
                    "Admin scripts can contain encoded commands; this rule requires download and execution indicators."
                        .to_string(),
                conditions: vec![
                    crate::rules::RuleCondition::FileType {
                        equals: "powershell_script".to_string(),
                    },
                    crate::rules::RuleCondition::EncodedCommand,
                    crate::rules::RuleCondition::DownloaderAndExecution,
                ],
                min_condition_matches: 3,
                action: "review_or_block_by_policy".to_string(),
            }],
        };
        rule_pack.pack_sha256 = Some(sha256_bytes(
            &crate::rules::rule_compiler::canonical_rule_pack_bytes(&rule_pack).unwrap(),
        ));
        fs::write(
            assets.join("rules/zentor_rules.zrule"),
            serde_json::to_string(&rule_pack).unwrap(),
        )
        .unwrap();
        fs::write(
            assets.join("ml/zentor_native_model.zmodel"),
            r#"{"model_name":"Avorax Native Development Model","model_version":"0.1.0-dev","model_format_version":"zmodel-v1","feature_schema_version":"zne-features-v1","production_ready":false,"precision":0.0,"recall":0.0,"false_positive_rate":1.0,"bias":-3.0,"weights":{"encoded_command_flag":2.5,"suspicious_string_count":1.5,"double_extension":1.3,"known_bad_flag":5.0},"thresholds":{"suspicious":0.65,"probable_malware":0.86,"confirmed_malware":0.98},"limitations":["Development fixture model; not production protection."]}"#,
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
        let mut config = EngineConfig::from_repo_root(dir.path()).unwrap();
        config.quarantine_dir = dir.path().join("quarantine");
        let engine = ZentorNativeEngine::initialize(config).unwrap();
        (dir, engine)
    }

    fn zip_with_stored_entries(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (name, body) in entries {
            bytes.extend_from_slice(b"PK\x03\x04");
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(body);
        }
        bytes
    }

    fn zip_with_owned_stored_entries(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let borrowed = entries
            .iter()
            .map(|(name, body)| (name.as_slice(), body.as_slice()))
            .collect::<Vec<_>>();
        zip_with_stored_entries(&borrowed)
    }

    fn zip_with_deflated_entries(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (name, body) in entries {
            let payload = deflate_raw(body);
            bytes.extend_from_slice(b"PK\x03\x04");
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&8u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(&payload);
        }
        bytes
    }

    fn deflate_raw(body: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
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
        assert_eq!(verdict.engine, "Avorax Native Engine");
        assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
    }

    #[test]
    fn eicar_inside_zip_entry_is_detected_without_extracting_archive() {
        let (_dir, mut engine) = test_engine();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("eicar-archive.zip"),
                &zip_with_stored_entries(&[(b"payload/eicar.txt", EICAR_ASCII.as_bytes())]),
                ScanActionMode::DetectOnly,
            )
            .unwrap();

        assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "eicar_test_signature"
                && evidence.title.contains("Archived entry signature")
                && evidence.detail.contains("payload/eicar.txt")
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn eicar_inside_jar_entry_is_detected_without_extracting_archive() {
        let (_dir, mut engine) = test_engine();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("support-library.jar"),
                &zip_with_stored_entries(&[(b"payload/eicar.txt", EICAR_ASCII.as_bytes())]),
                ScanActionMode::DetectOnly,
            )
            .unwrap();

        assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "eicar_test_signature"
                && evidence.title.contains("Archived entry signature")
                && evidence.detail.contains("support-library.jar")
                && evidence.detail.contains("payload/eicar.txt")
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn eicar_inside_apk_entry_is_detected_without_extracting_archive() {
        let (_dir, mut engine) = test_engine();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("mobile-package.apk"),
                &zip_with_stored_entries(&[(b"assets/eicar.txt", EICAR_ASCII.as_bytes())]),
                ScanActionMode::DetectOnly,
            )
            .unwrap();

        assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "eicar_test_signature"
                && evidence.title.contains("Archived entry signature")
                && evidence.detail.contains("mobile-package.apk")
                && evidence.detail.contains("assets/eicar.txt")
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn eicar_inside_xpi_entry_is_detected_without_extracting_archive() {
        let (_dir, mut engine) = test_engine();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("browser-extension.xpi"),
                &zip_with_stored_entries(&[(b"assets/eicar.txt", EICAR_ASCII.as_bytes())]),
                ScanActionMode::DetectOnly,
            )
            .unwrap();

        assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "eicar_test_signature"
                && evidence.title.contains("Archived entry signature")
                && evidence.detail.contains("browser-extension.xpi")
                && evidence.detail.contains("assets/eicar.txt")
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn eicar_inside_vsix_entry_is_detected_without_extracting_archive() {
        let (_dir, mut engine) = test_engine();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("editor-extension.vsix"),
                &zip_with_stored_entries(&[(
                    b"extension/assets/eicar.txt",
                    EICAR_ASCII.as_bytes(),
                )]),
                ScanActionMode::DetectOnly,
            )
            .unwrap();

        assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "eicar_test_signature"
                && evidence.title.contains("Archived entry signature")
                && evidence.detail.contains("editor-extension.vsix")
                && evidence.detail.contains("extension/assets/eicar.txt")
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn eicar_inside_nupkg_entry_is_detected_without_extracting_archive() {
        let (_dir, mut engine) = test_engine();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("library-package.nupkg"),
                &zip_with_stored_entries(&[(
                    b"contentfiles/any/any/eicar.txt",
                    EICAR_ASCII.as_bytes(),
                )]),
                ScanActionMode::DetectOnly,
            )
            .unwrap();

        assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "eicar_test_signature"
                && evidence.title.contains("Archived entry signature")
                && evidence.detail.contains("library-package.nupkg")
                && evidence.detail.contains("contentfiles/any/any/eicar.txt")
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn eicar_inside_appx_and_msix_entries_is_detected_without_extracting_package() {
        let cases: [(&str, &[u8]); 2] = [
            ("store-package.appx", &b"assets/eicar.txt"[..]),
            (
                "desktop-package.msix",
                &b"vfs/programfiles/app/eicar.txt"[..],
            ),
        ];

        for (package_name, entry_name) in cases {
            let (_dir, mut engine) = test_engine();
            let entry_text = String::from_utf8_lossy(entry_name);
            let verdict = engine
                .scan_bytes_for_test(
                    std::path::PathBuf::from(package_name),
                    &zip_with_stored_entries(&[(entry_name, EICAR_ASCII.as_bytes())]),
                    ScanActionMode::DetectOnly,
                )
                .unwrap();

            assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
            assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
                evidence.id == "eicar_test_signature"
                    && evidence.title.contains("Archived entry signature")
                    && evidence.detail.contains(package_name)
                    && evidence.detail.contains(entry_text.as_ref())
            }));
            assert!(verdict.quarantine_record.is_none());
        }
    }

    #[test]
    fn eicar_inside_appxbundle_and_msixbundle_nested_packages_is_detected() {
        let cases: [(&str, &[u8], &[u8]); 2] = [
            (
                "store-package.appxbundle",
                &b"packages/store-package.appx"[..],
                &b"assets/eicar.txt"[..],
            ),
            (
                "desktop-package.msixbundle",
                &b"packages/desktop-package.msix"[..],
                &b"vfs/programfiles/app/eicar.txt"[..],
            ),
        ];

        for (bundle_name, package_entry_name, payload_entry_name) in cases {
            let (_dir, mut engine) = test_engine();
            let package_text = String::from_utf8_lossy(package_entry_name);
            let payload_text = String::from_utf8_lossy(payload_entry_name);
            let inner_package =
                zip_with_stored_entries(&[(payload_entry_name, EICAR_ASCII.as_bytes())]);
            let outer_bundle = zip_with_stored_entries(&[(package_entry_name, &inner_package)]);
            let verdict = engine
                .scan_bytes_for_test(
                    std::path::PathBuf::from(bundle_name),
                    &outer_bundle,
                    ScanActionMode::DetectOnly,
                )
                .unwrap();

            assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
            assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
                evidence.id == "eicar_test_signature"
                    && evidence.title.contains("Archived entry signature")
                    && evidence.detail.contains(bundle_name)
                    && evidence.detail.contains(package_text.as_ref())
                    && evidence.detail.contains(payload_text.as_ref())
            }));
            assert!(verdict.quarantine_record.is_none());
        }
    }

    #[test]
    fn eicar_inside_nested_zip_entry_is_detected_without_extracting_archive() {
        let (_dir, mut engine) = test_engine();
        let inner_zip =
            zip_with_deflated_entries(&[(b"payload/eicar.txt", EICAR_ASCII.as_bytes())]);
        let outer_zip = zip_with_stored_entries(&[(b"archives/inner.zip", &inner_zip)]);
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("nested-eicar-archive.zip"),
                &outer_zip,
                ScanActionMode::DetectOnly,
            )
            .unwrap();

        assert_eq!(verdict.final_verdict.verdict, Verdict::TestThreat);
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "eicar_test_signature"
                && evidence.title.contains("Archived entry signature")
                && evidence.detail.contains("archives/inner.zip")
                && evidence.detail.contains("payload/eicar.txt")
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn script_rule_and_heuristics_inside_zip_entry_are_reported_without_extracting_archive() {
        let (_dir, mut engine) = test_engine();
        let script = b"powershell -EncodedCommand AAAA; IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/a')";
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("script-archive.zip"),
                &zip_with_deflated_entries(&[(b"scripts/dropper.ps1", script)]),
                ScanActionMode::DetectOnly,
            )
            .unwrap();

        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::Suspicious | Verdict::ProbableMalware
        ));
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "ps_encoded_download_exec"
                && evidence.title.contains("Archived entry rule")
                && evidence.detail.contains("scripts/dropper.ps1")
        }));
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "download_execute_script"
                && evidence.title.contains("Archived entry heuristic")
                && evidence.detail.contains("scripts/dropper.ps1")
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn benign_archive_entry_location_observations_do_not_accumulate_into_threat() {
        let (_dir, mut engine) = test_engine();
        let entries = (0..65)
            .map(|index| {
                (
                    format!("payload/count-entry-{index:03}.txt").into_bytes(),
                    b"benign archive entry-count fixture".to_vec(),
                )
            })
            .collect::<Vec<_>>();
        let verdict = engine
            .scan_bytes_for_test(
                std::path::PathBuf::from("C:\\Users\\fixture\\Downloads\\entry-count-limit.zip"),
                &zip_with_owned_stored_entries(&entries),
                ScanActionMode::DetectOnly,
            )
            .unwrap();

        assert_eq!(verdict.final_verdict.verdict, Verdict::Clean);
        assert!(verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "archive_content_scan_limited"
                && evidence
                    .detail
                    .contains("did not extract files or treat unscanned archive content as clean")
        }));
        assert!(!verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "location_observation"
                && evidence.title.contains("Archived entry heuristic")
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn provider_registry_runs_enabled_provider_and_reports_inventory() {
        struct FixtureProvider;

        impl DetectionProvider for FixtureProvider {
            fn id(&self) -> &'static str {
                "fixture.provider"
            }

            fn display_name(&self) -> &'static str {
                "Fixture Provider"
            }

            fn source(&self) -> crate::verdict::EvidenceSource {
                crate::verdict::EvidenceSource::NativeRule
            }

            fn evaluate(
                &self,
                context: &ScanContext<'_>,
            ) -> anyhow::Result<Vec<crate::verdict::Evidence>> {
                assert_eq!(context.sha256, sha256_bytes(context.bytes));
                Ok(vec![crate::verdict::Evidence {
                    id: "fixture_provider_hit".to_string(),
                    title: "Fixture provider hit".to_string(),
                    detail: format!("{} bytes observed", context.bytes.len()),
                    weight: 45,
                    source: self.source(),
                }])
            }
        }

        let path = std::path::PathBuf::from("fixture.ps1");
        let bytes = b"Write-Host fixture";
        let analysis = analyze_path(&path, bytes).unwrap();
        let sha256 = sha256_bytes(bytes);
        let mut registry = DetectionProviderRegistry::default();
        registry.register(Box::new(FixtureProvider));

        let providers = registry.providers();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id, "fixture.provider");
        assert_eq!(providers[0].status, DetectionProviderStatus::Enabled);

        let evidence = registry
            .evaluate(&ScanContext {
                path: &path,
                sha256: &sha256,
                bytes,
                analysis: &analysis,
            })
            .unwrap();

        assert!(evidence
            .iter()
            .any(|item| item.id == "fixture_provider_hit"));
    }

    #[test]
    fn disabled_provider_is_reported_but_not_evaluated() {
        struct DisabledFixtureProvider;

        impl DetectionProvider for DisabledFixtureProvider {
            fn id(&self) -> &'static str {
                "fixture.disabled"
            }

            fn display_name(&self) -> &'static str {
                "Disabled Fixture Provider"
            }

            fn source(&self) -> crate::verdict::EvidenceSource {
                crate::verdict::EvidenceSource::NativeRule
            }

            fn status(&self) -> DetectionProviderStatus {
                DetectionProviderStatus::Disabled
            }

            fn evaluate(
                &self,
                _context: &ScanContext<'_>,
            ) -> anyhow::Result<Vec<crate::verdict::Evidence>> {
                panic!("disabled providers must not be evaluated");
            }
        }

        let path = std::path::PathBuf::from("fixture.ps1");
        let bytes = b"Write-Host fixture";
        let analysis = analyze_path(&path, bytes).unwrap();
        let sha256 = sha256_bytes(bytes);
        let mut registry = DetectionProviderRegistry::default();
        registry.register(Box::new(DisabledFixtureProvider));

        assert_eq!(
            registry.providers()[0].status,
            DetectionProviderStatus::Disabled
        );
        let evidence = registry
            .evaluate(&ScanContext {
                path: &path,
                sha256: &sha256,
                bytes,
                analysis: &analysis,
            })
            .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn engine_status_exposes_detection_provider_inventory_without_ui_coupling() {
        let (_dir, engine) = test_engine();
        let provider_ids = engine
            .status()
            .detection_providers
            .into_iter()
            .map(|provider| provider.id)
            .collect::<Vec<_>>();

        assert!(provider_ids.contains(&"native.signatures".to_string()));
        assert!(provider_ids.contains(&"native.rules".to_string()));
        assert!(provider_ids.contains(&"native.heuristics".to_string()));
        assert!(provider_ids.contains(&"native.ml".to_string()));
    }

    #[test]
    fn large_file_scan_reports_full_hash_and_sample_limit() {
        let (dir, mut engine) = test_engine();
        let file = dir.path().join("large-benign.bin");
        let mut content = vec![b'A'; crate::scan::content_reader::MAX_FILE_BYTES as usize + 8192];
        content[crate::scan::content_reader::MAX_FILE_BYTES as usize] = b'Z';
        fs::write(&file, &content).unwrap();

        let verdict = engine.scan_file(file, ScanActionMode::DetectOnly).unwrap();

        assert_eq!(verdict.sha256, sha256_bytes(&content));
        assert_eq!(verdict.file_size_bytes, content.len() as u64);
        assert!(verdict.scan_sample_limited);
        assert_eq!(
            verdict.scanned_bytes,
            crate::scan::content_reader::MAX_FILE_BYTES
        );
    }

    #[test]
    fn quarantine_copy_fallback_rejects_hash_mismatch_before_delete() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.exe");
        let destination = dir.path().join("payload.avoraxq");
        fs::write(&source, b"benign test payload").unwrap();

        let error = crate::quarantine::quarantine_store::copy_then_remove_verified(
            &source,
            &destination,
            &"0".repeat(64),
        )
        .unwrap_err();

        assert!(source.exists());
        assert!(!destination.exists());
        assert!(error.to_string().contains("hash verification failed"));
    }

    #[test]
    fn file_walker_excludes_quarantine_cache_and_generated_build_dirs() {
        let dir = tempfile::tempdir().unwrap();
        for relative in [
            "safe/app.exe",
            "quarantine/infected.exe",
            ".avorax/cache/cached.exe",
            "target/release/generated.exe",
            "build/windows/generated.exe",
        ] {
            let path = dir.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture").unwrap();
        }

        let walk = crate::scan::file_walker::collect_files(dir.path(), None);

        assert_eq!(walk.files.len(), 1);
        assert!(walk.files[0].ends_with("app.exe"));
    }

    #[test]
    fn quick_scan_plan_includes_browser_downloads_startup_and_temp_without_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("User");
        let local_appdata = profile.join("AppData").join("Local");
        let program_data = dir.path().join("ProgramData");
        let temp = local_appdata.join("Temp");
        for path in [
            profile.join("Downloads"),
            profile.join("Desktop"),
            profile
                .join("AppData")
                .join("Roaming")
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
            local_appdata
                .join("Microsoft")
                .join("Edge")
                .join("User Data"),
            local_appdata
                .join("Google")
                .join("Chrome")
                .join("User Data"),
            temp.clone(),
            program_data
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
        ] {
            fs::create_dir_all(path).unwrap();
        }

        let roots = quick_scan_planner::quick_scan_roots_from_env(
            Some(profile.as_path()),
            Some(temp.as_path()),
            Some(local_appdata.as_path()),
            Some(program_data.as_path()),
        )
        .unwrap();

        assert!(roots.iter().any(|path| path.ends_with("Downloads")));
        assert!(roots.iter().any(|path| path.ends_with("Desktop")));
        assert!(roots
            .iter()
            .any(|path| path.to_string_lossy().contains("Microsoft\\Edge")
                || path.to_string_lossy().contains("Microsoft/Edge")));
        assert!(roots
            .iter()
            .any(|path| path.to_string_lossy().contains("Google\\Chrome")
                || path.to_string_lossy().contains("Google/Chrome")));
        let unique: std::collections::BTreeSet<_> = roots.iter().collect();
        assert_eq!(unique.len(), roots.len());
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
    fn avorax_installer_exe_is_likely_clean_not_quarantine_eligible() {
        let (dir, mut engine) = test_engine();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("Avorax-AntiVirus-0.2.2-x64-setup.exe");
        fs::write(&file, b"avorax installer fixture").unwrap();
        let verdict = engine
            .scan_file(file, ScanActionMode::AutoQuarantineConfirmed)
            .unwrap();
        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::LikelyClean | Verdict::Clean
        ));
        assert!(!verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "trusted_local_artifact" || evidence.id == "trusted_publisher"
        }));
        assert!(verdict.quarantine_record.is_none());
    }

    #[test]
    fn avorax_msi_is_likely_clean_not_quarantine_eligible() {
        let (dir, mut engine) = test_engine();
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let file = downloads.join("Avorax-AntiVirus-0.2.2-x64.msi");
        fs::write(&file, b"avorax msi fixture").unwrap();
        let verdict = engine
            .scan_file(file, ScanActionMode::AutoQuarantineConfirmed)
            .unwrap();
        assert!(matches!(
            verdict.final_verdict.verdict,
            Verdict::LikelyClean | Verdict::Clean
        ));
        assert!(!verdict.final_verdict.evidence.iter().any(|evidence| {
            evidence.id == "trusted_local_artifact" || evidence.id == "trusted_publisher"
        }));
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
        assert!(verdict
            .final_verdict
            .user_visible_explanation
            .contains("GitHub malware-intel known-bad hash fixture"));
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
        let record = verdict.quarantine_record.as_ref().unwrap();
        assert!(record.quarantine_path.ends_with(".avoraxq"));
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
        assert!(!Allowlist::validate_path("C:\\ProgramData"));
        assert!(!Allowlist::validate_path("C:\\Users"));
        assert!(!Allowlist::validate_path("D:\\"));
        assert!(!Allowlist::validate_path("D:\\Windows"));
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
        assert!(report.signature_pack_loaded);
        assert!(report.rule_pack_loaded);
        assert_eq!(report.overall_result, "pass");
    }

    #[test]
    fn self_test_fails_when_required_packs_are_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = EngineConfig::from_repo_root(dir.path()).unwrap();
        config.quarantine_dir = dir.path().join("quarantine");
        let mut engine = ZentorNativeEngine::initialize(config).unwrap();

        let report = engine.engine_self_test().unwrap();

        assert!(report.eicar_detected);
        assert!(!report.signature_pack_loaded);
        assert!(!report.rule_pack_loaded);
        assert_eq!(report.overall_result, "fail");
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
    fn compiler_rejects_malformed_exact_hash_signature() {
        let signature = NativeSignature {
            id: "ZNE-BAD-HASH".to_string(),
            name: "Bad hash signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Confirmed,
            severity: "high".to_string(),
            signature_type: SignatureType::ExactHash,
            pattern: "not-a-sha256".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["*".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Malformed exact hash fixture must be rejected.".to_string(),
            action_policy: "quarantine_if_policy_allows".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();

        assert!(error.contains("valid SHA-256 pattern"));
    }

    #[test]
    fn compiler_rejects_unsafe_signature_identity() {
        let mut signature = NativeSignature {
            id: "ZNE/UNSAFE".to_string(),
            name: "Unsafe identity signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "long-enough-pattern".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Unsafe signature identity fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error =
            crate::signatures::signature_compiler::validate_signatures(&[signature.clone()])
                .unwrap_err()
                .to_string();
        assert!(error.contains("unsafe id"));

        signature.id = "ZNE-UNSAFE-VERSION".to_string();
        signature.version = "latest".to_string();
        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();
        assert!(error.contains("dotted numeric version"));
    }

    #[test]
    fn compiler_rejects_short_partial_hash_signature() {
        let signature = NativeSignature {
            id: "ZNE-SHORT-PARTIAL-HASH".to_string(),
            name: "Short partial hash signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::PartialHash,
            pattern: "aaaaaaaaaaaaaaaa".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["*".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Short partial hash fixture must be rejected.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();

        assert!(error.contains("partial hash signature"));
    }

    #[test]
    fn compiler_rejects_unsupported_signature_filters() {
        let mut signature = NativeSignature {
            id: "ZNE-BAD-FILTER".to_string(),
            name: "Bad filter signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "long-enough-pattern".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["made_up_type".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Unsupported filter fixture must be rejected.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error =
            crate::signatures::signature_compiler::validate_signatures(&[signature.clone()])
                .unwrap_err()
                .to_string();
        assert!(error.contains("unsupported file_type filter"));

        signature.file_types = vec!["text".to_string()];
        signature.min_file_size = Some(1024);
        signature.max_file_size = Some(16);
        let error =
            crate::signatures::signature_compiler::validate_signatures(&[signature.clone()])
                .unwrap_err()
                .to_string();
        assert!(error.contains("invalid file size bounds"));

        signature.min_file_size = None;
        signature.max_file_size = None;
        signature.severity = "urgent".to_string();
        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported severity"));
    }

    #[test]
    fn compiler_rejects_noncanonical_signature_filters() {
        let mut signature = NativeSignature {
            id: "ZNE-NONCANONICAL-FILTER".to_string(),
            name: "Noncanonical filter signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "long-enough-pattern".to_string(),
            mask: None,
            offset: None,
            file_types: vec![" Text ".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Noncanonical filter fixture must be rejected.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error =
            crate::signatures::signature_compiler::validate_signatures(&[signature.clone()])
                .unwrap_err()
                .to_string();
        assert!(error.contains("non-canonical file_type filter"));

        signature.file_types = vec!["text".to_string()];
        signature.required_context = vec!["encoded_command ".to_string()];
        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();
        assert!(error.contains("non-canonical required_context"));
    }

    #[test]
    fn compiler_rejects_noncanonical_string_signature_pattern() {
        let signature = NativeSignature {
            id: "ZNE-NONCANONICAL-STRING-PATTERN".to_string(),
            name: "Noncanonical string pattern signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: " suspicious-marker ".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Noncanonical string pattern fixture must be rejected."
                .to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();

        assert!(error.contains("non-canonical string pattern"));
    }

    #[test]
    fn compiler_rejects_duplicate_signature_ids() {
        let first = NativeSignature {
            id: "ZNE-DUPLICATE-ID".to_string(),
            name: "Duplicate identity signature one".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "long-enough-pattern-one".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Duplicate signature identity fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let mut second = first.clone();
        second.name = "Duplicate identity signature two".to_string();
        second.pattern = "long-enough-pattern-two".to_string();

        let error = crate::signatures::signature_compiler::validate_signatures(&[first, second])
            .unwrap_err()
            .to_string();

        assert!(error.contains("duplicate signature id"));
    }

    #[test]
    fn compiler_rejects_oversized_signature_metadata() {
        let mut signature = NativeSignature {
            id: "ZNE-OVERSIZED-METADATA".to_string(),
            name: "Oversized metadata signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "long-enough-pattern".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Oversized signature metadata fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        signature.name = "n".repeat(161);
        let error =
            crate::signatures::signature_compiler::validate_signatures(&[signature.clone()])
                .unwrap_err()
                .to_string();
        assert!(error.contains("name is too long"));

        signature.name = "Oversized metadata signature".to_string();
        signature.false_positive_notes = "n".repeat(513);
        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();
        assert!(error.contains("false_positive_notes is too long"));
    }

    #[test]
    fn compiler_rejects_malformed_byte_pattern_signature() {
        let signature = NativeSignature {
            id: "ZNE-BAD-BYTE-PATTERN".to_string(),
            name: "Bad byte pattern signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::BytePattern,
            pattern: "DE AD ZZ".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["*".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Malformed byte pattern fixture must be rejected.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();

        assert!(error.contains("valid even-length hex bytes"));
    }

    #[test]
    fn compiler_rejects_masked_byte_pattern_length_mismatch() {
        let signature = NativeSignature {
            id: "ZNE-BAD-MASKED-BYTE-PATTERN".to_string(),
            name: "Bad masked byte pattern signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::MaskedBytePattern,
            pattern: "DE AD BE EF".to_string(),
            mask: Some("FF FF".to_string()),
            offset: None,
            file_types: vec!["*".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Malformed mask fixture must be rejected.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();

        assert!(error.contains("mask length must match pattern length"));
    }

    #[test]
    fn compiler_rejects_unknown_required_context() {
        let mut signature = NativeSignature {
            id: "ZNE-BAD-CONTEXT".to_string(),
            name: "Bad context signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "long-enough-pattern".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec!["review context: prose should not match".to_string()],
            false_positive_notes: "Unknown context fixture must be rejected.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error =
            crate::signatures::signature_compiler::validate_signatures(&[signature.clone()])
                .unwrap_err()
                .to_string();
        assert!(error.contains("unsupported required_context"));

        signature.required_context = vec!["encoded_command".to_string()];
        assert!(crate::signatures::signature_compiler::validate_signatures(&[signature]).is_ok());
    }

    #[test]
    fn compiler_allows_only_known_legacy_core_required_context() {
        let mut signature = NativeSignature {
            id: "ZNE-LEGACY-CONTEXT".to_string(),
            name: "Legacy context signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::TestThreat,
            confidence: Confidence::Confirmed,
            severity: "test".to_string(),
            signature_type: SignatureType::EicarTestSignature,
            pattern: EICAR_ASCII.to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec!["Exact EICAR safe test string.".to_string()],
            false_positive_notes: "Legacy core-pack context compatibility fixture.".to_string(),
            action_policy: "quarantine_if_policy_allows".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(
            crate::signatures::signature_compiler::validate_signatures(&[signature.clone()])
                .is_ok()
        );

        signature.required_context = vec!["Exact arbitrary prose context.".to_string()];
        assert!(crate::signatures::signature_compiler::validate_signatures(&[signature]).is_err());
    }

    #[test]
    fn compiler_rejects_unsupported_signature_action_policy() {
        let signature = NativeSignature {
            id: "ZNE-BAD-ACTION".to_string(),
            name: "Bad action signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "long-enough-pattern".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Unsupported action policy fixture.".to_string(),
            action_policy: "delete_immediately".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let error = crate::signatures::signature_compiler::validate_signatures(&[signature])
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported action_policy"));
    }

    fn safe_rule_fixture() -> NativeRule {
        NativeRule {
            id: "ZNR-UNIT-RULE".to_string(),
            name: "Unit rule".to_string(),
            description: "Synthetic unit rule with multiple conditions.".to_string(),
            category: ThreatCategory::SuspiciousScript,
            confidence: Confidence::High,
            verdict: Verdict::Suspicious,
            false_positive_notes: "Synthetic rule validation fixture.".to_string(),
            conditions: vec![
                RuleCondition::FileType {
                    equals: "powershell_script".to_string(),
                },
                RuleCondition::ContainsAscii {
                    value: "EncodedCommand".to_string(),
                },
            ],
            min_condition_matches: 2,
            action: "review_or_block_by_policy".to_string(),
        }
    }

    #[test]
    fn rule_compiler_rejects_zero_or_impossible_match_counts() {
        let mut zero = safe_rule_fixture();
        zero.min_condition_matches = 0;
        assert!(crate::rules::rule_compiler::validate_rules(&[zero]).is_err());

        let mut impossible = safe_rule_fixture();
        impossible.min_condition_matches = impossible.conditions.len() + 1;
        assert!(crate::rules::rule_compiler::validate_rules(&[impossible]).is_err());
    }

    #[test]
    fn rule_compiler_rejects_empty_or_short_string_conditions() {
        let mut empty = safe_rule_fixture();
        empty.conditions.push(RuleCondition::ContainsAscii {
            value: "".to_string(),
        });
        empty.min_condition_matches = 2;
        let error = crate::rules::rule_compiler::validate_rules(&[empty])
            .unwrap_err()
            .to_string();
        assert!(error.contains("string condition is empty"));

        let mut rule = safe_rule_fixture();
        rule.confidence = Confidence::Low;
        rule.conditions = vec![RuleCondition::ContainsAscii {
            value: "cmd".to_string(),
        }];
        rule.min_condition_matches = 1;

        assert!(crate::rules::rule_compiler::validate_rules(&[rule]).is_err());
    }

    #[test]
    fn rule_compiler_rejects_noncanonical_string_conditions() {
        let mut rule = safe_rule_fixture();
        rule.conditions.push(RuleCondition::PathContains {
            value: " Startup ".to_string(),
        });
        rule.min_condition_matches = 2;

        let error = crate::rules::rule_compiler::validate_rules(&[rule])
            .unwrap_err()
            .to_string();

        assert!(error.contains("non-canonical string condition"));
    }

    #[test]
    fn rule_compiler_rejects_oversized_string_conditions() {
        let mut rule = safe_rule_fixture();
        rule.conditions.push(RuleCondition::ContainsAscii {
            value: "a".repeat(257),
        });
        rule.min_condition_matches = 2;

        let error = crate::rules::rule_compiler::validate_rules(&[rule])
            .unwrap_err()
            .to_string();

        assert!(error.contains("string condition is too long"));
    }

    #[test]
    fn rule_compiler_rejects_noncanonical_file_type_condition() {
        let mut rule = safe_rule_fixture();
        rule.conditions = vec![
            RuleCondition::FileType {
                equals: " PowerShell_Script ".to_string(),
            },
            RuleCondition::EncodedCommand,
        ];
        rule.min_condition_matches = 2;

        let error = crate::rules::rule_compiler::validate_rules(&[rule])
            .unwrap_err()
            .to_string();

        assert!(error.contains("non-canonical file_type condition"));
    }

    #[test]
    fn rule_compiler_allows_short_string_only_as_supporting_context() {
        let mut rule = safe_rule_fixture();
        rule.conditions.push(RuleCondition::ContainsAscii {
            value: "zip".to_string(),
        });
        rule.min_condition_matches = 2;

        assert!(crate::rules::rule_compiler::validate_rules(&[rule]).is_ok());
    }

    #[test]
    fn rule_compiler_rejects_unknown_import_category() {
        let mut rule = safe_rule_fixture();
        rule.conditions
            .push(RuleCondition::PeImportCategoryAtLeast {
                category: "unknown_category".to_string(),
                value: 1,
            });
        rule.min_condition_matches = 2;

        assert!(crate::rules::rule_compiler::validate_rules(&[rule]).is_err());
    }

    #[test]
    fn rule_compiler_rejects_noncanonical_import_category() {
        let mut rule = safe_rule_fixture();
        rule.conditions
            .push(RuleCondition::PeImportCategoryAtLeast {
                category: " Network ".to_string(),
                value: 1,
            });
        rule.min_condition_matches = 2;

        let error = crate::rules::rule_compiler::validate_rules(&[rule])
            .unwrap_err()
            .to_string();

        assert!(error.contains("non-canonical PE import category"));
    }

    #[test]
    fn rule_compiler_rejects_unsupported_action() {
        let mut rule = safe_rule_fixture();
        rule.action = "delete_immediately".to_string();

        let error = crate::rules::rule_compiler::validate_rules(&[rule])
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported action"));
    }

    #[test]
    fn rule_compiler_rejects_excessive_condition_bounds() {
        let mut too_many = safe_rule_fixture();
        too_many.conditions = (0..17)
            .map(|index| RuleCondition::ContainsAscii {
                value: format!("marker-{index}"),
            })
            .collect();
        too_many.min_condition_matches = 2;
        let error = crate::rules::rule_compiler::validate_rules(&[too_many])
            .unwrap_err()
            .to_string();
        assert!(error.contains("too many conditions"));

        let mut excessive_threshold = safe_rule_fixture();
        excessive_threshold
            .conditions
            .push(RuleCondition::EmbeddedUrlsAtLeast { value: 65 });
        excessive_threshold.min_condition_matches = 2;
        let error = crate::rules::rule_compiler::validate_rules(&[excessive_threshold])
            .unwrap_err()
            .to_string();
        assert!(error.contains("excessive condition threshold"));

        let mut excessive_import_threshold = safe_rule_fixture();
        excessive_import_threshold
            .conditions
            .push(RuleCondition::PeImportCategoryAtLeast {
                category: "network".to_string(),
                value: 65,
            });
        excessive_import_threshold.min_condition_matches = 2;
        let error = crate::rules::rule_compiler::validate_rules(&[excessive_import_threshold])
            .unwrap_err()
            .to_string();
        assert!(error.contains("excessive import threshold"));
    }

    #[test]
    fn rule_compiler_rejects_duplicate_rule_ids() {
        let first = safe_rule_fixture();
        let mut second = safe_rule_fixture();
        second.name = "Second unit rule with duplicate id".to_string();
        second.description = "Duplicate rule identity fixture.".to_string();

        let error = crate::rules::rule_compiler::validate_rules(&[first, second])
            .unwrap_err()
            .to_string();

        assert!(error.contains("duplicate rule id"));
    }

    #[test]
    fn rule_compiler_rejects_oversized_rule_metadata() {
        let mut rule = safe_rule_fixture();
        rule.description = "d".repeat(513);

        let error = crate::rules::rule_compiler::validate_rules(&[rule])
            .unwrap_err()
            .to_string();

        assert!(error.contains("description is too long"));
    }

    #[test]
    fn rule_compiler_rejects_unsafe_rule_identity() {
        let mut rule = safe_rule_fixture();
        rule.id = "..\\unsafe-rule".to_string();

        let error = crate::rules::rule_compiler::validate_rules(&[rule])
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsafe id"));
    }

    #[test]
    fn rule_pack_validation_rejects_wrong_format_or_empty_version() {
        let mut pack = crate::rules::RulePack {
            format: crate::rules::rule_compiler::RULE_PACK_FORMAT.to_string(),
            version: "1".to_string(),
            compiler_version: None,
            created_at: None,
            pack_sha256: Some(String::new()),
            rules: vec![safe_rule_fixture()],
        };
        let hash =
            sha256_bytes(&crate::rules::rule_compiler::canonical_rule_pack_bytes(&pack).unwrap());
        pack.pack_sha256 = Some(hash);
        assert!(crate::rules::rule_compiler::validate_rule_pack(&pack).is_ok());

        pack.format = "not-a-rule-pack".to_string();
        assert!(crate::rules::rule_compiler::validate_rule_pack(&pack).is_err());

        pack.format = crate::rules::rule_compiler::RULE_PACK_FORMAT.to_string();
        pack.version.clear();
        assert!(crate::rules::rule_compiler::validate_rule_pack(&pack).is_err());
    }

    #[test]
    fn rule_pack_validation_rejects_malformed_version() {
        let pack = crate::rules::RulePack {
            format: crate::rules::rule_compiler::RULE_PACK_FORMAT.to_string(),
            version: "latest".to_string(),
            compiler_version: None,
            created_at: None,
            pack_sha256: None,
            rules: vec![],
        };

        let error = crate::rules::rule_compiler::validate_rule_pack(&pack)
            .unwrap_err()
            .to_string();

        assert!(error.contains("rule pack version must be a dotted numeric version"));
    }

    #[test]
    fn rule_pack_validation_rejects_excessive_rule_count() {
        let pack = crate::rules::RulePack {
            format: crate::rules::rule_compiler::RULE_PACK_FORMAT.to_string(),
            version: "1".to_string(),
            compiler_version: None,
            created_at: None,
            pack_sha256: None,
            rules: vec![safe_rule_fixture(); 513],
        };

        let error = crate::rules::rule_compiler::validate_rule_pack(&pack)
            .unwrap_err()
            .to_string();

        assert!(error.contains("too many rules"));
    }

    #[test]
    fn rule_pack_validation_rejects_non_empty_pack_without_hash() {
        let pack = crate::rules::RulePack {
            format: crate::rules::rule_compiler::RULE_PACK_FORMAT.to_string(),
            version: "1".to_string(),
            compiler_version: None,
            created_at: None,
            pack_sha256: None,
            rules: vec![safe_rule_fixture()],
        };
        let error = crate::rules::rule_compiler::validate_rule_pack(&pack)
            .unwrap_err()
            .to_string();
        assert!(error.contains("non-empty rule pack must declare pack_sha256"));
    }

    #[test]
    fn rule_pack_validation_rejects_malformed_pack_hash() {
        let pack = crate::rules::RulePack {
            format: crate::rules::rule_compiler::RULE_PACK_FORMAT.to_string(),
            version: "1".to_string(),
            compiler_version: None,
            created_at: None,
            pack_sha256: Some("not-a-sha256".to_string()),
            rules: vec![safe_rule_fixture()],
        };
        let error = crate::rules::rule_compiler::validate_rule_pack(&pack)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rule pack hash is not a valid SHA-256 value"));
    }

    #[test]
    fn rule_pack_validation_rejects_hash_mismatch() {
        let pack = crate::rules::RulePack {
            format: crate::rules::rule_compiler::RULE_PACK_FORMAT.to_string(),
            version: "1".to_string(),
            compiler_version: None,
            created_at: None,
            pack_sha256: Some(sha256_bytes(b"different-rule-pack")),
            rules: vec![safe_rule_fixture()],
        };
        let error = crate::rules::rule_compiler::validate_rule_pack(&pack)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rule pack hash mismatch"));
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
    fn verifier_rejects_non_empty_signature_pack_without_hash() {
        let signature = NativeSignature {
            id: "ZNE-MISSING-PACK-HASH".to_string(),
            name: "Missing pack hash test signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::TestThreat,
            confidence: Confidence::Confirmed,
            severity: "test".to_string(),
            signature_type: SignatureType::ExactHash,
            pattern: sha256_bytes(b"missing-pack-hash-fixture").to_string(),
            mask: None,
            offset: None,
            file_types: vec!["*".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Safe verifier test fixture.".to_string(),
            action_policy: "quarantine_if_policy_allows".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let (mut pack, _) = crate::signatures::signature_compiler::compile_pack(
            vec![signature],
            "9.9.9".to_string(),
        )
        .unwrap();
        pack.pack_sha256 = None;
        let canonical = crate::signatures::signature_compiler::canonical_pack_bytes(&pack).unwrap();
        let error = crate::signatures::pack_verifier::verify_pack(&pack, &canonical)
            .unwrap_err()
            .to_string();
        assert!(error.contains("non-empty signature pack must declare pack_sha256"));
    }

    #[test]
    fn verifier_rejects_malformed_signature_pack_version() {
        let pack = SignaturePack {
            format: crate::signatures::pack_verifier::SIGNATURE_PACK_FORMAT.to_string(),
            version: "latest".to_string(),
            compiler_version: None,
            created_at: None,
            pack_sha256: None,
            signatures: vec![],
        };
        let canonical = crate::signatures::signature_compiler::canonical_pack_bytes(&pack).unwrap();

        let error = crate::signatures::pack_verifier::verify_pack(&pack, &canonical)
            .unwrap_err()
            .to_string();

        assert!(error.contains("signature pack version must be a dotted numeric version"));
    }

    #[test]
    fn verifier_rejects_excessive_signature_count() {
        let signature = NativeSignature {
            id: "ZNE-OVERSIZED-PACK-SIGNATURE".to_string(),
            name: "Oversized pack signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "long-enough-pattern".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Oversized pack fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let pack = SignaturePack {
            format: crate::signatures::pack_verifier::SIGNATURE_PACK_FORMAT.to_string(),
            version: "1".to_string(),
            compiler_version: None,
            created_at: None,
            pack_sha256: None,
            signatures: vec![signature; 1025],
        };
        let canonical = crate::signatures::signature_compiler::canonical_pack_bytes(&pack).unwrap();

        let error = crate::signatures::pack_verifier::verify_pack(&pack, &canonical)
            .unwrap_err()
            .to_string();

        assert!(error.contains("too many signatures"));
    }

    #[test]
    fn verifier_rejects_malformed_signature_pack_hash() {
        let signature = NativeSignature {
            id: "ZNE-MALFORMED-PACK-HASH".to_string(),
            name: "Malformed pack hash test signature".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::TestThreat,
            confidence: Confidence::Confirmed,
            severity: "test".to_string(),
            signature_type: SignatureType::ExactHash,
            pattern: sha256_bytes(b"malformed-pack-hash-fixture").to_string(),
            mask: None,
            offset: None,
            file_types: vec!["*".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Safe verifier test fixture.".to_string(),
            action_policy: "quarantine_if_policy_allows".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let (mut pack, _) = crate::signatures::signature_compiler::compile_pack(
            vec![signature],
            "9.9.9".to_string(),
        )
        .unwrap();
        pack.pack_sha256 = Some("not-a-sha256".to_string());
        let canonical = crate::signatures::signature_compiler::canonical_pack_bytes(&pack).unwrap();
        let error = crate::signatures::pack_verifier::verify_pack(&pack, &canonical)
            .unwrap_err()
            .to_string();
        assert!(error.contains("signature pack hash is not a valid SHA-256 value"));
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
        .unwrap()
        .is_some());

        let other_bytes = b"xxxx\xde\xad\xbe\xef";
        let other_analysis = analyze_path(std::path::Path::new("sample.bin"), other_bytes).unwrap();
        assert!(crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("sample.bin"),
            &sha256_bytes(other_bytes),
            other_bytes,
            &other_analysis
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn signature_required_ransom_context_requires_ransom_text() {
        let signature = NativeSignature {
            id: "ZNE-RANSOM-CONTEXT-TEST".to_string(),
            name: "Ransom context byte pattern".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Ransomware,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "payment instructions".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec!["ransom_note_text".to_string()],
            false_positive_notes: "Context matcher regression fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let clean = b"payment instructions for an invoice";
        let clean_analysis = analyze_path(std::path::Path::new("invoice.txt"), clean).unwrap();

        assert!(crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("invoice.txt"),
            &sha256_bytes(clean),
            clean,
            &clean_analysis,
        )
        .unwrap()
        .is_none());

        let ransom = b"your files have been encrypted; payment instructions follow";
        let ransom_analysis = analyze_path(std::path::Path::new("note.txt"), ransom).unwrap();
        assert!(crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("note.txt"),
            &sha256_bytes(ransom),
            ransom,
            &ransom_analysis,
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn signature_matcher_reports_unsupported_required_context() {
        let signature = NativeSignature {
            id: "ZNE-BAD-CONTEXT-TEST".to_string(),
            name: "Unsupported context fixture".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "payment instructions".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec!["unsupported_context".to_string()],
            false_positive_notes: "Malformed context regression fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let bytes = b"payment instructions";
        let analysis = analyze_path(std::path::Path::new("sample.txt"), bytes).unwrap();

        let error = crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("sample.txt"),
            &sha256_bytes(bytes),
            bytes,
            &analysis,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unsupported required_context unsupported_context"));
    }

    #[test]
    fn signature_matcher_reports_invalid_byte_pattern() {
        let signature = NativeSignature {
            id: "ZNE-BAD-BYTE-PATTERN-TEST".to_string(),
            name: "Invalid byte pattern fixture".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::BytePattern,
            pattern: "DE AD ZZ".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Malformed byte pattern regression fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let bytes = b"plain text";
        let analysis = analyze_path(std::path::Path::new("sample.txt"), bytes).unwrap();

        let error = crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("sample.txt"),
            &sha256_bytes(bytes),
            bytes,
            &analysis,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("byte pattern hex contains invalid byte"));
    }

    #[test]
    fn signature_matcher_reports_unsupported_file_type_filter() {
        let signature = NativeSignature {
            id: "ZNE-BAD-FILE-TYPE-TEST".to_string(),
            name: "Unsupported file type fixture".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: "plain text".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["made_up_type".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Malformed file-type filter regression fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let bytes = b"plain text";
        let analysis = analyze_path(std::path::Path::new("sample.txt"), bytes).unwrap();

        let error = crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("sample.txt"),
            &sha256_bytes(bytes),
            bytes,
            &analysis,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unsupported file_type filter made_up_type"));
    }

    #[test]
    fn signature_matcher_reports_invalid_exact_hash_pattern() {
        let signature = NativeSignature {
            id: "ZNE-BAD-HASH-TEST".to_string(),
            name: "Invalid exact hash fixture".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::ExactHash,
            pattern: "not-a-sha256".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Malformed hash regression fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let bytes = b"plain text";
        let analysis = analyze_path(std::path::Path::new("sample.txt"), bytes).unwrap();

        let error = crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("sample.txt"),
            &sha256_bytes(bytes),
            bytes,
            &analysis,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("exact hash signature pattern is not a valid SHA-256 value"));
    }

    #[test]
    fn signature_matcher_reports_empty_string_pattern() {
        let signature = NativeSignature {
            id: "ZNE-EMPTY-STRING-TEST".to_string(),
            name: "Empty string pattern fixture".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::Unknown,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::AsciiString,
            pattern: " ".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["text".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Malformed string pattern regression fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let bytes = b"plain text";
        let analysis = analyze_path(std::path::Path::new("sample.txt"), bytes).unwrap();

        let error = crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("sample.txt"),
            &sha256_bytes(bytes),
            bytes,
            &analysis,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("string signature pattern is empty"));
    }

    #[test]
    fn signature_matcher_reports_missing_expected_script_analysis() {
        let signature = NativeSignature {
            id: "ZNE-MISSING-SCRIPT-ANALYSIS-TEST".to_string(),
            name: "Missing script analysis fixture".to_string(),
            version: "1".to_string(),
            category: ThreatCategory::SuspiciousScript,
            confidence: Confidence::Low,
            severity: "low".to_string(),
            signature_type: SignatureType::PowershellEncodedCommand,
            pattern: "encoded_command".to_string(),
            mask: None,
            offset: None,
            file_types: vec!["powershell_script".to_string()],
            min_file_size: None,
            max_file_size: None,
            required_context: vec![],
            false_positive_notes: "Malformed analysis regression fixture.".to_string(),
            action_policy: "review_only".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let bytes = b"powershell -EncodedCommand AAAA";
        let mut analysis = analyze_path(std::path::Path::new("sample.ps1"), bytes).unwrap();
        analysis.script = None;

        let error = crate::signatures::signature_matcher::matches_signature(
            &signature,
            std::path::Path::new("sample.ps1"),
            &sha256_bytes(bytes),
            bytes,
            &analysis,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("requires script analysis"));
    }

    #[test]
    fn rule_vm_reports_missing_expected_script_analysis() {
        let rule = NativeRule {
            id: "ZNR-MISSING-SCRIPT-ANALYSIS-TEST".to_string(),
            name: "Missing script analysis rule fixture".to_string(),
            description: "Regression fixture for inconsistent script analysis.".to_string(),
            category: ThreatCategory::SuspiciousScript,
            confidence: Confidence::Low,
            verdict: Verdict::Suspicious,
            false_positive_notes: "Malformed analysis regression fixture.".to_string(),
            conditions: vec![
                RuleCondition::FileType {
                    equals: "powershell_script".to_string(),
                },
                RuleCondition::EncodedCommand,
            ],
            min_condition_matches: 2,
            action: "review_only".to_string(),
        };
        let bytes = b"powershell -EncodedCommand AAAA";
        let mut analysis = analyze_path(std::path::Path::new("sample.ps1"), bytes).unwrap();
        analysis.script = None;

        let error = crate::rules::rule_vm::evaluate_rule(
            &rule,
            std::path::Path::new("sample.ps1"),
            bytes,
            &analysis,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("requires script analysis"));
    }

    #[test]
    fn rule_vm_reports_empty_string_condition() {
        let rule = NativeRule {
            id: "ZNR-EMPTY-STRING-CONDITION-TEST".to_string(),
            name: "Empty string condition rule fixture".to_string(),
            description: "Regression fixture for malformed runtime rule strings.".to_string(),
            category: ThreatCategory::SuspiciousScript,
            confidence: Confidence::Low,
            verdict: Verdict::Suspicious,
            false_positive_notes: "Malformed rule condition regression fixture.".to_string(),
            conditions: vec![
                RuleCondition::FileType {
                    equals: "powershell_script".to_string(),
                },
                RuleCondition::ContainsAscii {
                    value: "".to_string(),
                },
            ],
            min_condition_matches: 2,
            action: "review_only".to_string(),
        };
        let bytes = b"powershell -NoProfile";
        let analysis = analyze_path(std::path::Path::new("sample.ps1"), bytes).unwrap();

        let error = crate::rules::rule_vm::evaluate_rule(
            &rule,
            std::path::Path::new("sample.ps1"),
            bytes,
            &analysis,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("string condition is empty"));
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
        let mut config = EngineConfig::from_repo_root(repo_root()).unwrap();
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
    fn threat_intel_hash_pack_signature_matches_without_dead_context() {
        let bytes = b"threat intel exact hash fixture";
        let hash = sha256_bytes(bytes);
        let indicator = ThreatIntelIndicator {
            indicator_id: "ZTI-UNIT-0001".to_string(),
            source_name: "Unit test feed".to_string(),
            source_url: None,
            source_type: "internal".to_string(),
            indicator_type: IndicatorType::Sha256,
            value: hash.clone(),
            malware_family: Some("Known bad".to_string()),
            threat_category: ThreatCategory::Trojan,
            confidence: Confidence::Confirmed,
            first_seen: None,
            last_seen: None,
            false_positive_notes: "Synthetic exact-hash threat-intel fixture.".to_string(),
            action_policy: "quarantine_if_policy_allows".to_string(),
            expires_at: None,
        };
        let json = crate::threat_intel::zentor_pack_builder::indicators_to_signature_pack_json(
            &[indicator],
            "unit",
        )
        .unwrap();
        let pack: SignaturePack = serde_json::from_str(&json).unwrap();
        let signature = &pack.signatures[0];
        let analysis = analyze_path(std::path::Path::new("fixture.bin"), bytes).unwrap();

        assert!(signature.required_context.is_empty());
        assert!(crate::signatures::signature_matcher::matches_signature(
            signature,
            std::path::Path::new("fixture.bin"),
            &hash,
            bytes,
            &analysis
        )
        .unwrap()
        .is_some());
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
        assert_eq!(
            verdict.final_verdict.category,
            ThreatCategory::SuspiciousDownloader
        );
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
    fn threat_intel_hash_field_defaults_are_explicit() {
        use crate::threat_intel::{import_hash_lines, ThreatIntelSource, ThreatIntelSourceType};
        let source = ThreatIntelSource {
            source_name: "unit-test-feed".to_string(),
            source_url: None,
            source_type: ThreatIntelSourceType::TestFixture,
        };

        let indicators = import_hash_lines(
            &source,
            vec![
                "".to_string(),
                "# comment".to_string(),
                "84335dd8dd5b649882212609dc875225260878ceadbca9713d4079b7112e3514,tag".to_string(),
            ],
            ThreatCategory::Trojan,
        )
        .unwrap();

        assert_eq!(indicators.len(), 1);

        let source = include_str!("../threat_intel/hash_feed_importer.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(production.contains("fn first_hash_field(raw: &str) -> Option<&str>"));
        assert!(production.contains("let Some(value) = first_hash_field(&raw) else"));
        assert!(production.contains("return None;"));
        assert!(!production.contains(".unwrap_or_default()"));
    }

    #[test]
    fn microsoft_publisher_trust_probe_errors_are_explainable_evidence() {
        let engine_source = include_str!("../engine.rs");
        let trust_source = include_str!("../trust/microsoft_trust.rs");
        let publisher_source = include_str!("../trust/publisher_trust.rs");

        assert!(engine_source.contains("microsoft_signature_verdict(&path)"));
        assert!(engine_source.contains("publisher_trust_diagnostic"));
        assert!(engine_source.contains("Microsoft publisher trust probe failed"));
        assert!(engine_source.contains("weight: 0"));
        assert!(!engine_source.contains("microsoft_trust::has_valid_microsoft_signature(&path)"));
        assert!(trust_source
            .contains("pub fn microsoft_signature_verdict(path: &Path) -> Result<bool>"));
        assert!(publisher_source.contains(
            "pub fn trusted_publisher_for(path: &Path) -> Result<Option<TrustedPublisher>>"
        ));
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

    #[test]
    fn native_engine_does_not_export_placeholder_updates_namespace() {
        let lib_source = include_str!("../lib.rs");
        let dead_export = ["pub mod ", "updates;"].concat();

        assert!(!lib_source.contains(&dead_export));
    }
}
