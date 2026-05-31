use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analyzers::analyze_path;
use crate::behavior::{
    BehaviorDecision, FileActivityEvent, ProcessStartEvent, RansomwareActivityWindow,
};
use crate::config::EngineConfig;
use crate::heuristics;
use crate::ml::{feature_extractor, NativeModelRunner};
use crate::quarantine::{QuarantineRecord, QuarantineStore};
use crate::rules::RuleDb;
use crate::scan::content_reader::read_scan_bytes;
use crate::scan::file_walker;
use crate::scan::full_scan_planner;
use crate::scan::quick_scan_planner;
use crate::scan::{
    FileScanVerdict, ScanActionMode, ScanJobId, ScanMode, ScanProgress, ScanSummary,
};
use crate::signatures::SignatureDb;
use crate::trust::{
    microsoft_trust, publisher_trust, zentor_trust, Allowlist, KnownBadStore, KnownGoodStore,
};
use crate::verdict::action_policy::should_auto_quarantine;
use crate::verdict::risk_fusion::{Evidence, EvidenceSource, RiskFusion};
use crate::verdict::{Confidence, FinalVerdict, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    pub native_engine_ready: bool,
    pub signature_pack_loaded: bool,
    pub signature_count: usize,
    pub rule_pack_loaded: bool,
    pub rule_count: usize,
    pub ml_model_loaded: bool,
    pub ml_model_version: Option<String>,
    pub trust_store_loaded: bool,
    pub known_good_count: usize,
    pub known_bad_count: usize,
    pub last_error: Option<String>,
    pub compatibility_engines_disabled_by_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestReport {
    pub eicar_detected: bool,
    pub signature_pack_loaded: bool,
    pub rule_pack_loaded: bool,
    pub ml_model_loaded: bool,
    pub compatibility_engines_disabled_by_default: bool,
    pub overall_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionDecision {
    pub action: String,
    pub verdict: FinalVerdict,
}

pub struct ZentorNativeEngine {
    config: EngineConfig,
    signatures: SignatureDb,
    rules: RuleDb,
    ml: NativeModelRunner,
    known_good: KnownGoodStore,
    known_bad: KnownBadStore,
    allowlist: Allowlist,
    ransomware_window: RansomwareActivityWindow,
    scan_results: BTreeMap<ScanJobId, ScanSummary>,
}

impl ZentorNativeEngine {
    pub fn initialize(config: EngineConfig) -> Result<Self> {
        let signatures = SignatureDb::load_pack(&config.signature_pack_path)?;
        let rules = RuleDb::load_pack(&config.rule_pack_path)?;
        let ml = NativeModelRunner::load(&config.ml_model_path)?;
        let known_good = KnownGoodStore::load(&config.trust_store_path)?;
        let known_bad = KnownBadStore::load(
            &config
                .trust_store_path
                .with_file_name("zentor_known_bad_test.ztrust"),
        )?;
        Ok(Self {
            config,
            signatures,
            rules,
            ml,
            known_good,
            known_bad,
            allowlist: Allowlist::default(),
            ransomware_window: RansomwareActivityWindow::default(),
            scan_results: BTreeMap::new(),
        })
    }

    pub fn status(&self) -> EngineStatus {
        EngineStatus {
            native_engine_ready: true,
            signature_pack_loaded: self.config.signature_pack_path.exists(),
            signature_count: self.signatures.count(),
            rule_pack_loaded: self.config.rule_pack_path.exists(),
            rule_count: self.rules.count(),
            ml_model_loaded: self.ml.is_loaded(),
            ml_model_version: self.ml.model_version().map(ToString::to_string),
            trust_store_loaded: self.config.trust_store_path.exists(),
            known_good_count: self.known_good.count(),
            known_bad_count: self.known_bad.count(),
            last_error: None,
            compatibility_engines_disabled_by_default: !self.config.compatibility_engines_enabled,
        }
    }

    pub fn scan_file(&mut self, path: PathBuf, mode: ScanActionMode) -> Result<FileScanVerdict> {
        let bytes = read_scan_bytes(&path)?;
        self.scan_bytes_at(path, &bytes, mode, true)
    }

    pub fn scan_bytes_for_test(
        &mut self,
        path: PathBuf,
        bytes: &[u8],
        mode: ScanActionMode,
    ) -> Result<FileScanVerdict> {
        self.scan_bytes_at(path, bytes, mode, false)
    }

    fn scan_bytes_at(
        &mut self,
        path: PathBuf,
        bytes: &[u8],
        mode: ScanActionMode,
        allow_quarantine: bool,
    ) -> Result<FileScanVerdict> {
        let sha256 = sha256_bytes(&bytes);
        let analysis = analyze_path(&path, bytes)?;
        let known_good = self.known_good.contains(&sha256);
        let known_bad = self.known_bad.contains(&sha256);
        let allowlisted = self.allowlist.contains(&path, &sha256);
        let trusted_publisher = publisher_trust::trusted_publisher_for(&path);
        let trusted_local_artifact = zentor_trust::has_zentor_artifact_name(&path)
            || zentor_trust::is_zentor_path(&path)
            || (microsoft_trust::is_windows_system_path(&path)
                && microsoft_trust::has_valid_microsoft_signature(&path));
        let mut evidence = Vec::<Evidence>::new();
        if known_bad {
            evidence.push(Evidence {
                id: "known_bad_hash".to_string(),
                title: "Known-bad hash".to_string(),
                detail: "The file hash is in the Zentor native known-bad store.".to_string(),
                weight: 100,
                source: EvidenceSource::ApplicationControl,
            });
        }
        if !known_bad {
            if let Some(publisher) = trusted_publisher {
                evidence.push(Evidence {
                    id: "trusted_publisher".to_string(),
                    title: "Trusted publisher".to_string(),
                    detail: match publisher {
                        publisher_trust::TrustedPublisher::Microsoft => {
                            "The file has a valid Microsoft publisher signature."
                        }
                        publisher_trust::TrustedPublisher::Zentor => {
                            "The file is a Zentor-owned path or installer artifact."
                        }
                    }
                    .to_string(),
                    weight: -80,
                    source: EvidenceSource::TrustStore,
                });
            }
            if trusted_local_artifact {
                evidence.push(Evidence {
                    id: "trusted_local_artifact".to_string(),
                    title: "Trusted local artifact".to_string(),
                    detail: "Zentor suppresses its own installer, service, driver, quarantine, update, and build artifacts unless a confirmed signature or known-bad hash matches.".to_string(),
                    weight: -90,
                    source: EvidenceSource::TrustStore,
                });
            }
        }
        evidence.extend(
            self.signatures
                .match_bytes(&path, &sha256, &bytes, &analysis)
                .into_iter()
                .map(|matched| Evidence {
                    id: matched.signature_id,
                    title: matched.name,
                    detail: matched.reason,
                    weight: matched.weight,
                    source: EvidenceSource::NativeSignature,
                }),
        );
        evidence.extend(
            self.rules
                .evaluate(&path, bytes, &analysis)
                .into_iter()
                .map(|matched| Evidence {
                    id: matched.rule_id,
                    title: matched.name,
                    detail: matched.reason,
                    weight: matched.weight,
                    source: EvidenceSource::NativeRule,
                }),
        );
        evidence.extend(heuristics::score_file(&path, &analysis));
        let features = feature_extractor::extract_features(&path, &analysis, known_good, known_bad);
        if let Some(ml) = self.ml.analyze_features(&features) {
            if matches!(
                ml.verdict,
                Verdict::Suspicious | Verdict::ProbableMalware | Verdict::ConfirmedMalware
            ) {
                evidence.push(Evidence {
                    id: "native_ml".to_string(),
                    title: "Zentor Native ML review".to_string(),
                    detail: format!(
                        "Native ML probability {:.1}% using model {}.",
                        ml.malware_probability * 100.0,
                        ml.model_version
                    ),
                    weight: match ml.confidence {
                        Confidence::Confirmed => 80,
                        Confidence::High => 55,
                        Confidence::Medium => 30,
                        Confidence::Low => 10,
                    },
                    source: EvidenceSource::NativeMl,
                });
            }
        }
        let final_verdict =
            RiskFusion::fuse(evidence, known_good || trusted_local_artifact, allowlisted);
        let quarantine_record =
            if should_auto_quarantine(mode, final_verdict.verdict, final_verdict.confidence)
                && !allowlisted
                && allow_quarantine
            {
                Some(
                    QuarantineStore::new(self.config.quarantine_dir.clone()).quarantine_file(
                        &path,
                        &sha256,
                        &final_verdict.user_visible_explanation,
                        false,
                    )?,
                )
            } else {
                None
            };
        Ok(FileScanVerdict {
            path,
            sha256,
            engine: "Zentor Native Engine".to_string(),
            final_verdict,
            scanned_at: Utc::now(),
            quarantine_record,
        })
    }

    pub fn scan_folder(&mut self, path: PathBuf, mode: ScanActionMode) -> Result<ScanJobId> {
        self.scan_roots(vec![path], ScanMode::Custom, mode)
    }

    pub fn start_quick_scan(&mut self, mode: ScanActionMode) -> Result<ScanJobId> {
        self.scan_roots(
            quick_scan_planner::quick_scan_roots(),
            ScanMode::Quick,
            mode,
        )
    }

    pub fn start_full_scan(&mut self, mode: ScanActionMode) -> Result<ScanJobId> {
        self.scan_roots(full_scan_planner::full_scan_roots(), ScanMode::Full, mode)
    }

    pub fn get_scan_progress(&self, job_id: ScanJobId) -> Result<ScanProgress> {
        Ok(self
            .scan_results
            .get(&job_id)
            .map(|summary| summary.progress.clone())
            .unwrap_or_else(|| ScanProgress::new(job_id, ScanMode::Custom)))
    }

    pub fn get_scan_results(&self, job_id: ScanJobId) -> Result<ScanSummary> {
        self.scan_results
            .get(&job_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown scan job"))
    }

    pub fn cancel_scan(&mut self, _job_id: ScanJobId) -> Result<()> {
        Ok(())
    }

    pub fn analyze_process_start(&mut self, event: ProcessStartEvent) -> Result<ExecutionDecision> {
        let verdict = self.scan_file(event.executable_path, ScanActionMode::DetectOnly)?;
        let action = match verdict.final_verdict.verdict {
            Verdict::ConfirmedMalware | Verdict::TestThreat | Verdict::ProbableMalware => "block",
            Verdict::Suspicious => "allow_and_monitor",
            _ => "allow",
        };
        Ok(ExecutionDecision {
            action: action.to_string(),
            verdict: verdict.final_verdict,
        })
    }

    pub fn analyze_file_activity(&mut self, event: FileActivityEvent) -> Result<BehaviorDecision> {
        Ok(self.ransomware_window.observe(event).0)
    }

    pub fn quarantine(&self, path: PathBuf, reason: &str) -> Result<QuarantineRecord> {
        let bytes = read_scan_bytes(&path)?;
        QuarantineStore::new(self.config.quarantine_dir.clone()).quarantine_file(
            &path,
            &sha256_bytes(&bytes),
            reason,
            false,
        )
    }

    pub fn restore_quarantine_item(&self, _id: String) -> Result<String> {
        Ok("restore_requires_confirmation".to_string())
    }

    pub fn load_signature_pack(&mut self, path: PathBuf) -> Result<()> {
        self.signatures = SignatureDb::load_pack(&path)?;
        Ok(())
    }

    pub fn load_rule_pack(&mut self, path: PathBuf) -> Result<()> {
        self.rules = RuleDb::load_pack(&path)?;
        Ok(())
    }

    pub fn load_ml_model(&mut self, path: PathBuf) -> Result<()> {
        self.ml = NativeModelRunner::load(&path)?;
        Ok(())
    }

    pub fn engine_self_test(&mut self) -> Result<SelfTestReport> {
        let verdict = self.scan_bytes_for_test(
            PathBuf::from("eicar.com.txt"),
            crate::signatures::eicar_signature::EICAR_ASCII.as_bytes(),
            ScanActionMode::DetectOnly,
        )?;
        let eicar_detected = matches!(
            verdict.final_verdict.verdict,
            Verdict::TestThreat | Verdict::ConfirmedMalware
        );
        Ok(SelfTestReport {
            eicar_detected,
            signature_pack_loaded: self.config.signature_pack_path.exists(),
            rule_pack_loaded: self.config.rule_pack_path.exists(),
            ml_model_loaded: self.ml.is_loaded(),
            compatibility_engines_disabled_by_default: !self.config.compatibility_engines_enabled,
            overall_result: if eicar_detected { "pass" } else { "fail" }.to_string(),
        })
    }

    fn scan_roots(
        &mut self,
        roots: Vec<PathBuf>,
        scan_mode: ScanMode,
        mode: ScanActionMode,
    ) -> Result<ScanJobId> {
        let job_id = ScanJobId::default();
        let mut progress = ScanProgress::new(job_id.clone(), scan_mode);
        let started = Instant::now();
        let mut files = Vec::new();
        let mut skipped_files = 0;
        let mut folders_scanned = 0;
        let mut bytes_estimated = 0;
        for root in roots {
            let walk = file_walker::collect_files(
                &root,
                if scan_mode == ScanMode::Quick {
                    Some(3)
                } else {
                    None
                },
            );
            skipped_files += walk.skipped_files;
            folders_scanned += walk.folders_scanned;
            bytes_estimated += walk.bytes_estimated;
            files.extend(walk.files);
        }
        progress.total_files_estimated = Some(files.len() as u64);
        progress.total_bytes_estimated = Some(bytes_estimated);
        progress.folders_scanned = folders_scanned;
        let mut results = Vec::new();
        let mut quarantined_files = 0;
        for path in files {
            progress.current_path = Some(path.display().to_string());
            match self.scan_file(path, mode) {
                Ok(verdict) => {
                    progress.files_scanned += 1;
                    if let Ok(metadata) = std::fs::metadata(&verdict.path) {
                        progress.bytes_scanned += metadata.len();
                    }
                    if !matches!(
                        verdict.final_verdict.verdict,
                        Verdict::Clean | Verdict::LikelyClean | Verdict::Unknown | Verdict::Observation
                    ) {
                        progress.threats_found += 1;
                        if verdict.quarantine_record.is_some() {
                            quarantined_files += 1;
                        }
                        results.push(verdict);
                    }
                }
                Err(_) => {
                    progress.skipped_files += 1;
                }
            }
            progress.elapsed_seconds = started.elapsed().as_secs();
            progress.updated_at = Utc::now();
            progress.update_eta();
        }
        progress.status = "completed".to_string();
        progress.progress_percent = Some(100.0);
        progress.estimated_remaining_seconds = Some(0);
        let summary = ScanSummary {
            job_id: job_id.clone(),
            scan_mode,
            files_scanned: progress.files_scanned,
            skipped_files: progress.skipped_files + skipped_files,
            threats_found: progress.threats_found,
            quarantined_files,
            results,
            progress,
        };
        self.scan_results.insert(job_id.clone(), summary);
        Ok(job_id)
    }
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
