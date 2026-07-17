use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analyzers::analyze_path_with_size;
use crate::behavior::{
    BehaviorDecision, FileActivityEvent, ProcessStartEvent, RansomwareActivityWindow,
};
use crate::config::EngineConfig;
use crate::detection_provider::{builtin_provider_inventory, DetectionProviderInfo};
use crate::heuristics;
use crate::ml::{feature_extractor, NativeModelRunner};
use crate::quarantine::{QuarantineRecord, QuarantineStore};
use crate::rules::RuleDb;
use crate::scan::archive_scanner;
use crate::scan::content_reader::{read_scan_bytes, read_scan_content};
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

const MAX_SCAN_SUMMARY_RESULTS: usize = 100;
const MAX_NATIVE_SCAN_ERROR_DETAILS: usize = 20;
const MAX_NATIVE_SCAN_ERROR_DETAIL_CHARS: usize = 4096;
const NATIVE_SCAN_ERROR_TRUNCATION_SUFFIX: &str = "...[truncated]";
type ScanContentMetadata = (String, u64, u64, bool);

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
    pub ml_model_production_ready: bool,
    pub trust_store_loaded: bool,
    pub known_good_count: usize,
    pub known_bad_count: usize,
    pub last_error: Option<String>,
    pub compatibility_engines_disabled_by_default: bool,
    #[serde(default)]
    pub detection_providers: Vec<DetectionProviderInfo>,
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
            signature_pack_loaded: self.signatures.pack_loaded(),
            signature_count: self.signatures.count(),
            rule_pack_loaded: self.rules.pack_loaded(),
            rule_count: self.rules.count(),
            ml_model_loaded: self.ml.is_loaded(),
            ml_model_version: self.ml.model_version().map(ToString::to_string),
            ml_model_production_ready: self.ml.production_ready(),
            trust_store_loaded: self.known_good.is_loaded() || self.known_bad.is_loaded(),
            known_good_count: self.known_good.count(),
            known_bad_count: self.known_bad.count(),
            last_error: None,
            compatibility_engines_disabled_by_default: !self.config.compatibility_engines_enabled,
            detection_providers: builtin_provider_inventory(
                self.signatures.count(),
                self.rules.count(),
                self.ml.is_loaded(),
                self.ml.production_ready(),
                self.config.compatibility_engines_enabled,
            ),
        }
    }

    pub fn scan_file(&mut self, path: PathBuf, mode: ScanActionMode) -> Result<FileScanVerdict> {
        let content = read_scan_content(&path)?;
        self.scan_bytes_at(
            path,
            &content.sampled_bytes,
            mode,
            true,
            Some((
                content.full_sha256,
                content.file_size_bytes,
                content.scanned_bytes,
                content.sample_limited,
            )),
        )
    }

    pub fn scan_bytes_for_test(
        &mut self,
        path: PathBuf,
        bytes: &[u8],
        mode: ScanActionMode,
    ) -> Result<FileScanVerdict> {
        self.scan_bytes_at(path, bytes, mode, false, None)
    }

    fn scan_bytes_at(
        &mut self,
        path: PathBuf,
        bytes: &[u8],
        mode: ScanActionMode,
        allow_quarantine: bool,
        content_metadata: Option<ScanContentMetadata>,
    ) -> Result<FileScanVerdict> {
        let (sha256, file_size_bytes, scanned_bytes, scan_sample_limited) =
            scan_content_metadata_or_computed(bytes, content_metadata);
        let analysis = analyze_path_with_size(&path, bytes, file_size_bytes)?;
        let known_good = self.known_good.contains(&sha256);
        let known_bad = self.known_bad.contains(&sha256);
        let allowlisted = self.allowlist.contains(&path, &sha256);
        let mut trust_diagnostics = Vec::<(&'static str, &'static str, String)>::new();
        let trusted_avorax_path = match zentor_trust::is_zentor_path(&path) {
            Ok(trusted) => trusted,
            Err(error) => {
                trust_diagnostics.push((
                    "local_artifact_trust_diagnostic",
                    "Local artifact trust unavailable",
                    format!("Avorax local artifact trust probe failed: {error:#}"),
                ));
                false
            }
        };
        let microsoft_signature_valid = match microsoft_trust::microsoft_signature_verdict(&path) {
            Ok(valid) => valid,
            Err(error) => {
                trust_diagnostics.push((
                    "publisher_trust_diagnostic",
                    "Publisher trust unavailable",
                    format!("Microsoft publisher trust probe failed: {error:#}"),
                ));
                false
            }
        };
        let microsoft_system_path = match microsoft_trust::is_windows_system_path(&path) {
            Ok(is_system_path) => is_system_path,
            Err(error) => {
                trust_diagnostics.push((
                    "windows_system_path_trust_diagnostic",
                    "Windows system path trust unavailable",
                    format!("Windows system path trust probe failed: {error:#}"),
                ));
                false
            }
        };
        let trusted_publisher = if microsoft_signature_valid {
            Some(publisher_trust::TrustedPublisher::Microsoft)
        } else if trusted_avorax_path {
            Some(publisher_trust::TrustedPublisher::Avorax)
        } else {
            None
        };
        let trusted_local_artifact =
            trusted_avorax_path || (microsoft_system_path && microsoft_signature_valid);
        let mut evidence = Vec::<Evidence>::new();
        for (id, title, detail) in trust_diagnostics {
            evidence.push(Evidence {
                id: id.to_string(),
                title: title.to_string(),
                detail,
                weight: 0,
                source: EvidenceSource::TrustStore,
            });
        }
        if known_bad {
            evidence.push(Evidence {
                id: "known_bad_hash".to_string(),
                title: "Known-bad hash".to_string(),
                detail: "The file hash is in the Avorax native known-bad store.".to_string(),
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
                        publisher_trust::TrustedPublisher::Avorax => {
                            "The file is an Avorax-owned path."
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
                    detail: "Avorax suppresses its own service, driver, quarantine, update, and build artifacts when they are under owned roots unless a confirmed signature or known-bad hash matches.".to_string(),
                    weight: -90,
                    source: EvidenceSource::TrustStore,
                });
            }
        }
        let signature_matches = self
            .signatures
            .match_bytes(&path, &sha256, bytes, &analysis)?;
        evidence.extend(signature_matches.into_iter().map(|matched| Evidence {
            id: matched.signature_id,
            title: matched.name,
            detail: format!("{} Category: {:?}", matched.reason, matched.category),
            weight: matched.weight,
            source: EvidenceSource::NativeSignature,
        }));
        evidence.extend(self.archive_entry_detection_evidence(&path, bytes)?);
        let rule_matches = self.rules.evaluate(&path, bytes, &analysis)?;
        evidence.extend(rule_matches.into_iter().map(|matched| Evidence {
            id: matched.rule_id,
            title: matched.name,
            detail: matched.reason,
            weight: matched.weight,
            source: EvidenceSource::NativeRule,
        }));
        evidence.extend(heuristics::score_file(&path, &analysis));
        if let Some(script) = analysis.script.as_ref() {
            if script.persistence_patterns >= 2 {
                evidence.push(Evidence {
                    id: "script_persistence_multiple_indicators".to_string(),
                    title: "Multiple script persistence indicators".to_string(),
                    detail: format!(
                        "Script contains {} scheduled-task, service, or autorun persistence indicators; review before allowing it to run.",
                        script.persistence_patterns
                    ),
                    weight: 45,
                    source: EvidenceSource::NativeHeuristic,
                });
            }
        }
        let features = feature_extractor::extract_features(&path, &analysis, known_good, known_bad);
        if let Some(ml) = self.ml.analyze_features(&features)? {
            if matches!(
                ml.verdict,
                Verdict::Suspicious | Verdict::ProbableMalware | Verdict::ConfirmedMalware
            ) {
                evidence.push(Evidence {
                    id: "native_ml".to_string(),
                    title: "Avorax Native ML review".to_string(),
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
            file_size_bytes,
            scanned_bytes,
            scan_sample_limited,
            engine: "Avorax Native Engine".to_string(),
            final_verdict,
            scanned_at: Utc::now(),
            quarantine_record,
        })
    }

    fn archive_entry_detection_evidence(&self, path: &Path, bytes: &[u8]) -> Result<Vec<Evidence>> {
        if !archive_path_is_zip(path) {
            return Ok(Vec::new());
        }
        let mut evidence = Vec::new();
        self.collect_archive_entry_detection_evidence(path, bytes, 0, &mut evidence)?;
        Ok(evidence)
    }

    fn collect_archive_entry_detection_evidence(
        &self,
        path: &Path,
        bytes: &[u8],
        depth: usize,
        evidence: &mut Vec<Evidence>,
    ) -> Result<()> {
        let samples = archive_scanner::collect_bounded_zip_entry_samples(bytes)?;
        if samples.limit_exceeded {
            push_archive_content_scan_limited_evidence(
                evidence,
                path,
                "ZIP entry content scanning was bounded by entry count, size, compression, encryption, or path-safety limits; Avorax did not extract files or treat unscanned archive content as clean.",
            );
        }
        for entry in samples.entries {
            let entry_path = archive_entry_path(path, &entry.name);
            let entry_sha256 = sha256_bytes(&entry.bytes);
            let entry_analysis =
                analyze_path_with_size(&entry_path, &entry.bytes, entry.bytes.len() as u64)?;
            let matches = self.signatures.match_bytes(
                &entry_path,
                &entry_sha256,
                &entry.bytes,
                &entry_analysis,
            )?;
            for matched in matches {
                evidence.push(Evidence {
                    id: matched.signature_id,
                    title: format!("Archived entry signature: {}", matched.name),
                    detail: format!(
                        "ZIP entry '{}' matched an Avorax native signature without extracting or executing archive contents. {} Category: {:?}",
                        archive_entry_display_name(&entry_path.display().to_string()),
                        matched.reason,
                        matched.category
                    ),
                    weight: matched.weight,
                    source: EvidenceSource::NativeSignature,
                });
            }
            let rule_matches = self
                .rules
                .evaluate(&entry_path, &entry.bytes, &entry_analysis)?;
            for matched in rule_matches {
                evidence.push(Evidence {
                    id: matched.rule_id,
                    title: format!("Archived entry rule: {}", matched.name),
                    detail: format!(
                        "ZIP entry '{}' matched an Avorax native rule without extracting or executing archive contents. {} Category: {:?} Verdict: {:?}",
                        archive_entry_display_name(&entry_path.display().to_string()),
                        matched.reason,
                        matched.category,
                        matched.verdict
                    ),
                    weight: matched.weight,
                    source: EvidenceSource::NativeRule,
                });
            }
            for heuristic in heuristics::score_file(&entry_path, &entry_analysis) {
                if !archive_entry_heuristic_is_actionable(&heuristic) {
                    continue;
                }
                evidence.push(Evidence {
                    id: heuristic.id,
                    title: format!("Archived entry heuristic: {}", heuristic.title),
                    detail: format!(
                        "ZIP entry '{}' produced bounded heuristic evidence without extracting or executing archive contents. {}",
                        archive_entry_display_name(&entry_path.display().to_string()),
                        heuristic.detail
                    ),
                    weight: heuristic.weight,
                    source: heuristic.source,
                });
            }
            if archive_entry_name_is_zip(&entry.name) {
                if depth + 1 >= archive_scanner::max_archive_depth() {
                    push_archive_content_scan_limited_evidence(
                        evidence,
                        &entry_path,
                        "Nested ZIP entry content scanning reached the configured archive-depth limit; Avorax did not extract files or treat deeper archive content as clean.",
                    );
                } else {
                    self.collect_archive_entry_detection_evidence(
                        &entry_path,
                        &entry.bytes,
                        depth + 1,
                        evidence,
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn scan_folder(&mut self, path: PathBuf, mode: ScanActionMode) -> Result<ScanJobId> {
        self.scan_roots(vec![path], ScanMode::Custom, mode)
    }

    pub fn start_quick_scan(&mut self, mode: ScanActionMode) -> Result<ScanJobId> {
        self.scan_roots(
            quick_scan_planner::quick_scan_roots()?,
            ScanMode::Quick,
            mode,
        )
    }

    pub fn start_full_scan(&mut self, mode: ScanActionMode) -> Result<ScanJobId> {
        self.scan_roots(full_scan_planner::full_scan_roots()?, ScanMode::Full, mode)
    }

    pub fn get_scan_progress(&self, job_id: ScanJobId) -> Result<ScanProgress> {
        self.scan_results
            .get(&job_id)
            .map(|summary| summary.progress.clone())
            .ok_or_else(|| anyhow::anyhow!("unknown scan job"))
    }

    pub fn get_scan_results(&self, job_id: ScanJobId) -> Result<ScanSummary> {
        self.scan_results
            .get(&job_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown scan job"))
    }

    pub fn cancel_scan(&mut self, job_id: ScanJobId) -> Result<()> {
        if self.scan_results.contains_key(&job_id) {
            anyhow::bail!("scan job is already completed");
        }
        anyhow::bail!("unknown scan job")
    }

    pub fn analyze_process_start(&mut self, event: ProcessStartEvent) -> Result<ExecutionDecision> {
        let verdict = self.scan_file(event.executable_path, ScanActionMode::DetectOnly)?;
        let action = execution_action_for_verdict(verdict.final_verdict.verdict);
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
        anyhow::bail!(
            "native quarantine restore is not supported in this engine; use the local-core Recovery Vault restore flow"
        )
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
        let signature_pack_loaded = self.signatures.pack_loaded();
        let rule_pack_loaded = self.rules.pack_loaded();
        let overall_pass = eicar_detected && signature_pack_loaded && rule_pack_loaded;
        Ok(SelfTestReport {
            eicar_detected,
            signature_pack_loaded,
            rule_pack_loaded,
            ml_model_loaded: self.ml.is_loaded(),
            compatibility_engines_disabled_by_default: !self.config.compatibility_engines_enabled,
            overall_result: if overall_pass { "pass" } else { "fail" }.to_string(),
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
        let mut scan_errors = Vec::new();
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
            extend_scan_errors(&mut scan_errors, walk.scan_errors);
            if walk.permission_denied_count > 0 {
                push_scan_error(
                    &mut scan_errors,
                    format!(
                        "{} permission-denied item(s) while walking {}",
                        walk.permission_denied_count,
                        root.display()
                    ),
                );
            }
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
                    progress.bytes_scanned += verdict.file_size_bytes;
                    if !matches!(
                        verdict.final_verdict.verdict,
                        Verdict::Clean
                            | Verdict::LikelyClean
                            | Verdict::Unknown
                            | Verdict::Observation
                    ) {
                        progress.threats_found += 1;
                        if verdict.quarantine_record.is_some() {
                            quarantined_files += 1;
                        }
                        push_scan_result(&mut results, verdict);
                    }
                }
                Err(error) => {
                    progress.skipped_files += 1;
                    push_scan_error(
                        &mut scan_errors,
                        format!(
                            "{}: scan failed: {error}",
                            progress_current_path_or_unknown(&progress)
                        ),
                    );
                }
            }
            progress.elapsed_seconds = started.elapsed().as_secs();
            progress.updated_at = Utc::now();
            progress.update_eta();
        }
        progress.status = if scan_errors.is_empty() {
            "completed".to_string()
        } else {
            "completed_with_errors".to_string()
        };
        progress.progress_percent = Some(100.0);
        progress.estimated_remaining_seconds = Some(0);
        let summary = ScanSummary {
            job_id: job_id.clone(),
            scan_mode,
            files_scanned: progress.files_scanned,
            skipped_files: progress.skipped_files + skipped_files,
            scan_errors,
            threats_found: progress.threats_found,
            quarantined_files,
            results,
            progress,
        };
        self.scan_results.insert(job_id.clone(), summary);
        Ok(job_id)
    }
}

fn push_scan_error(scan_errors: &mut Vec<String>, detail: String) {
    if scan_errors.len() < MAX_NATIVE_SCAN_ERROR_DETAILS {
        scan_errors.push(bounded_native_scan_error_detail(&detail));
    } else if let Some(last) = scan_errors.last_mut() {
        let notice = native_scan_error_omission_notice();
        if last != &notice {
            *last = notice;
        }
    }
}

fn native_scan_error_omission_notice() -> String {
    format!("additional native scan errors omitted after {MAX_NATIVE_SCAN_ERROR_DETAILS} details")
}

fn bounded_native_scan_error_detail(detail: &str) -> String {
    let normalized = detail.replace('\0', "\\0");
    if normalized.chars().count() <= MAX_NATIVE_SCAN_ERROR_DETAIL_CHARS {
        return normalized;
    }
    let prefix_len = MAX_NATIVE_SCAN_ERROR_DETAIL_CHARS
        .saturating_sub(NATIVE_SCAN_ERROR_TRUNCATION_SUFFIX.len());
    let mut bounded: String = normalized.chars().take(prefix_len).collect();
    bounded.push_str(NATIVE_SCAN_ERROR_TRUNCATION_SUFFIX);
    bounded
}

fn push_scan_result(results: &mut Vec<FileScanVerdict>, verdict: FileScanVerdict) {
    if results.len() < MAX_SCAN_SUMMARY_RESULTS {
        results.push(verdict);
    }
}

fn extend_scan_errors(scan_errors: &mut Vec<String>, details: Vec<String>) {
    for detail in details {
        push_scan_error(scan_errors, detail);
    }
}

fn scan_content_metadata_or_computed(
    bytes: &[u8],
    content_metadata: Option<ScanContentMetadata>,
) -> ScanContentMetadata {
    match content_metadata {
        Some(metadata) => metadata,
        None => computed_scan_content_metadata(bytes),
    }
}

fn computed_scan_content_metadata(bytes: &[u8]) -> ScanContentMetadata {
    (
        sha256_bytes(bytes),
        bytes.len() as u64,
        bytes.len() as u64,
        false,
    )
}

fn progress_current_path_or_unknown(progress: &ScanProgress) -> &str {
    match progress.current_path.as_deref() {
        Some(path) if !path.trim().is_empty() => path,
        Some(_) => "<unknown>",
        None => "<unknown>",
    }
}

fn execution_action_for_verdict(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::ConfirmedMalware | Verdict::TestThreat | Verdict::ProbableMalware => "block",
        Verdict::Suspicious => "allow_and_monitor",
        Verdict::Clean | Verdict::LikelyClean | Verdict::Observation | Verdict::Unknown => "allow",
    }
}

fn archive_entry_path(archive_path: &Path, entry_name: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}::{}",
        archive_path.display(),
        archive_entry_display_name(entry_name)
    ))
}

fn archive_entry_display_name(entry_name: &str) -> String {
    const MAX_ARCHIVE_ENTRY_DISPLAY_CHARS: usize = 180;
    let mut display = entry_name
        .chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .take(MAX_ARCHIVE_ENTRY_DISPLAY_CHARS)
        .collect::<String>();
    if entry_name.chars().count() > MAX_ARCHIVE_ENTRY_DISPLAY_CHARS {
        display.push_str("...");
    }
    display
}

fn archive_path_is_zip(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "zip"
                    | "jar"
                    | "apk"
                    | "xpi"
                    | "vsix"
                    | "nupkg"
                    | "appx"
                    | "msix"
                    | "appxbundle"
                    | "msixbundle"
            )
        })
        == Some(true)
}

fn archive_entry_name_is_zip(entry_name: &str) -> bool {
    entry_name
        .rsplit(['/', '\\'])
        .next()
        .and_then(|file_name| file_name.rsplit_once('.'))
        .map(|(_, extension)| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "zip"
                    | "jar"
                    | "apk"
                    | "xpi"
                    | "vsix"
                    | "nupkg"
                    | "appx"
                    | "msix"
                    | "appxbundle"
                    | "msixbundle"
            )
        })
        == Some(true)
}

fn archive_entry_heuristic_is_actionable(heuristic: &Evidence) -> bool {
    heuristic.weight > 0
        && !matches!(
            heuristic.id.as_str(),
            "location_observation" | "filename_observation"
        )
}

fn push_archive_content_scan_limited_evidence(
    evidence: &mut Vec<Evidence>,
    archive_path: &Path,
    detail: &str,
) {
    evidence.push(Evidence {
        id: "archive_content_scan_limited".to_string(),
        title: "Archive content scan limited".to_string(),
        detail: format!(
            "{} Archive path: '{}'.",
            detail,
            archive_entry_display_name(&archive_path.display().to_string())
        ),
        weight: 0,
        source: EvidenceSource::NativeHeuristic,
    });
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod engine_source_tests {
    #[test]
    fn scan_summary_results_are_bounded_without_changing_counts() {
        let source = include_str!("engine.rs");

        assert!(source.contains("MAX_SCAN_SUMMARY_RESULTS"));
        assert!(source.contains("fn push_scan_result"));
        assert!(source.contains("push_scan_result(&mut results, verdict)"));
        assert!(source.contains("progress.threats_found += 1"));
    }

    #[test]
    fn scan_progress_and_cancel_do_not_report_fake_success() {
        let source = include_str!("engine.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(source.contains(".ok_or_else(|| anyhow::anyhow!(\"unknown scan job\"))"));
        assert!(source.contains("scan job is already completed"));
        assert!(!production_source
            .contains("unwrap_or_else(|| ScanProgress::new(job_id, ScanMode::Custom))"));
        assert!(!production_source
            .contains("pub fn cancel_scan(&mut self, _job_id: ScanJobId) -> Result<()>"));
    }

    #[test]
    fn scan_progress_distinguishes_completed_with_errors() {
        let source = include_str!("engine.rs");

        assert!(source.contains("\"completed_with_errors\""));
        assert!(source.contains("if scan_errors.is_empty()"));
    }

    #[test]
    fn native_scan_error_details_are_bounded_and_report_omissions() {
        let long_detail = format!(
            "{}\0tail",
            "A".repeat(super::MAX_NATIVE_SCAN_ERROR_DETAIL_CHARS + 16)
        );
        let mut scan_errors = Vec::new();
        super::push_scan_error(&mut scan_errors, long_detail);

        assert_eq!(scan_errors.len(), 1);
        assert_eq!(
            scan_errors[0].chars().count(),
            super::MAX_NATIVE_SCAN_ERROR_DETAIL_CHARS
        );
        assert!(scan_errors[0].ends_with(super::NATIVE_SCAN_ERROR_TRUNCATION_SUFFIX));
        assert!(!scan_errors[0].contains('\0'));

        let mut capped = Vec::new();
        for index in 0..(super::MAX_NATIVE_SCAN_ERROR_DETAILS + 5) {
            super::push_scan_error(&mut capped, format!("native scan error {index}"));
        }

        assert_eq!(capped.len(), super::MAX_NATIVE_SCAN_ERROR_DETAILS);
        assert_eq!(
            capped.last().unwrap(),
            &super::native_scan_error_omission_notice()
        );
        assert!(!capped.iter().any(|error| error == "native scan error 24"));

        let source = include_str!("engine.rs");
        let helper_start = source.find("fn push_scan_error").unwrap();
        let result_start = source.find("fn push_scan_result").unwrap();
        let helper_source = &source[helper_start..result_start];

        assert!(
            helper_source.contains("scan_errors.push(bounded_native_scan_error_detail(&detail));")
        );
        assert!(helper_source.contains(
            "additional native scan errors omitted after {MAX_NATIVE_SCAN_ERROR_DETAILS} details"
        ));
        assert!(helper_source.contains("detail.replace('\\0', \"\\\\0\")"));
        assert!(!helper_source.contains("scan_errors.push(detail)"));
    }

    #[test]
    fn native_restore_returns_explicit_unsupported_error() {
        let source = include_str!("engine.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(source.contains("native quarantine restore is not supported in this engine"));
        assert!(!production_source.contains("restore_requires_confirmation"));
    }

    #[test]
    fn status_uses_loaded_databases_instead_of_path_existence() {
        let source = include_str!("engine.rs");
        let status_start = source.find("pub fn status(&self) -> EngineStatus").unwrap();
        let scan_start = source.find("pub fn scan_file").unwrap();
        let status_source = &source[status_start..scan_start];
        let self_test_start = source.find("pub fn engine_self_test").unwrap();
        let scan_roots_start = source.find("fn scan_roots").unwrap();
        let self_test_source = &source[self_test_start..scan_roots_start];
        let path_exists_pattern = ["config.", "signature_pack_path", ".exists()"].concat();
        let rule_exists_pattern = ["config.", "rule_pack_path", ".exists()"].concat();
        let trust_exists_pattern = ["config.", "trust_store_path", ".exists()"].concat();

        assert!(status_source.contains("self.signatures.pack_loaded()"));
        assert!(status_source.contains("self.rules.pack_loaded()"));
        assert!(status_source.contains("self.known_good.is_loaded() || self.known_bad.is_loaded()"));
        assert!(
            self_test_source.contains("let signature_pack_loaded = self.signatures.pack_loaded()")
        );
        assert!(self_test_source.contains("let rule_pack_loaded = self.rules.pack_loaded()"));
        assert!(self_test_source.contains(
            "let overall_pass = eicar_detected && signature_pack_loaded && rule_pack_loaded"
        ));
        assert!(!status_source.contains(&path_exists_pattern));
        assert!(!status_source.contains(&rule_exists_pattern));
        assert!(!status_source.contains(&trust_exists_pattern));
        assert!(!self_test_source.contains(&path_exists_pattern));
        assert!(!self_test_source.contains(&rule_exists_pattern));
    }

    #[test]
    fn native_scan_progress_uses_validated_verdict_size() {
        let source = include_str!("engine.rs");
        let scan_roots_start = source.find("fn scan_roots").unwrap();
        let helpers_start = source.find("fn push_scan_error").unwrap();
        let scan_roots_source = &source[scan_roots_start..helpers_start];
        let old_progress_metadata_probe = ["std::fs::", "metadata(&verdict.path)"].concat();

        assert!(scan_roots_source.contains("progress.bytes_scanned += verdict.file_size_bytes"));
        assert!(!scan_roots_source.contains(&old_progress_metadata_probe));
    }

    #[test]
    fn process_start_action_mapping_is_exhaustive() {
        let source = include_str!("engine.rs");
        let helper_start = source.find("fn execution_action_for_verdict").unwrap();
        let helper_end = source.find("pub fn sha256_bytes").unwrap();
        let helper_source = &source[helper_start..helper_end];
        let process_start = source.find("pub fn analyze_process_start").unwrap();
        let file_activity_start = source.find("pub fn analyze_file_activity").unwrap();
        let process_source = &source[process_start..file_activity_start];

        assert_eq!(
            super::execution_action_for_verdict(super::Verdict::Clean),
            "allow"
        );
        assert_eq!(
            super::execution_action_for_verdict(super::Verdict::LikelyClean),
            "allow"
        );
        assert_eq!(
            super::execution_action_for_verdict(super::Verdict::Unknown),
            "allow"
        );
        assert_eq!(
            super::execution_action_for_verdict(super::Verdict::Observation),
            "allow"
        );
        assert_eq!(
            super::execution_action_for_verdict(super::Verdict::Suspicious),
            "allow_and_monitor"
        );
        assert_eq!(
            super::execution_action_for_verdict(super::Verdict::ProbableMalware),
            "block"
        );
        assert_eq!(
            super::execution_action_for_verdict(super::Verdict::ConfirmedMalware),
            "block"
        );
        assert_eq!(
            super::execution_action_for_verdict(super::Verdict::TestThreat),
            "block"
        );
        assert!(process_source.contains("execution_action_for_verdict"));
        assert!(!helper_source.contains("_ => \"allow\""));
    }

    #[test]
    fn windows_system_path_trust_failures_are_reported_before_trust_credit() {
        let source = include_str!("engine.rs");
        let scan_start = source.find("fn scan_bytes_at").unwrap();
        let evidence_start = source
            .find("let mut evidence = Vec::<Evidence>::new();")
            .unwrap();
        let trust_source = &source[scan_start..evidence_start];

        assert!(trust_source.contains(
            "let microsoft_system_path = match microsoft_trust::is_windows_system_path(&path)"
        ));
        assert!(trust_source.contains("windows_system_path_trust_diagnostic"));
        assert!(trust_source.contains("Windows system path trust probe failed"));
        assert!(trust_source.contains("false"));
        assert!(trust_source.contains(
            "trusted_avorax_path || (microsoft_system_path && microsoft_signature_valid)"
        ));
        assert!(!trust_source.contains(
            "microsoft_trust::is_windows_system_path(&path) && microsoft_signature_valid"
        ));
    }

    #[test]
    fn scan_content_metadata_fallback_is_explicit() {
        let computed = super::scan_content_metadata_or_computed(b"abc", None);
        let provided = ("known".to_string(), 100, 12, true);
        let preserved = super::scan_content_metadata_or_computed(b"abc", Some(provided.clone()));
        let source = include_str!("engine.rs");
        let helper_start = source.find("fn scan_content_metadata_or_computed").unwrap();
        let hash_start = source.find("pub fn sha256_bytes").unwrap();
        let helper_source = &source[helper_start..hash_start];
        let scan_start = source.find("fn scan_bytes_at").unwrap();
        let analysis_start = source
            .find("let analysis = analyze_path_with_size")
            .unwrap();
        let scan_source = &source[scan_start..analysis_start];

        assert_eq!(computed.0, super::sha256_bytes(b"abc"));
        assert_eq!(computed.1, 3);
        assert_eq!(computed.2, 3);
        assert!(!computed.3);
        assert_eq!(preserved, provided);
        assert!(helper_source.contains("match content_metadata"));
        assert!(helper_source.contains("Some(metadata) => metadata"));
        assert!(helper_source.contains("None => computed_scan_content_metadata(bytes)"));
        assert!(!scan_source.contains("content_metadata\n            .unwrap_or_else"));
    }

    #[test]
    fn native_scan_error_current_path_fallback_is_explicit() {
        let mut progress = crate::scan::ScanProgress::new(
            crate::scan::ScanJobId("job".to_string()),
            crate::scan::ScanMode::Custom,
        );
        let source = include_str!("engine.rs");
        let helper_start = source.find("fn progress_current_path_or_unknown").unwrap();
        let hash_start = source.find("pub fn sha256_bytes").unwrap();
        let helper_source = &source[helper_start..hash_start];
        let scan_start = source.find("fn scan_roots").unwrap();
        let helpers_start = source.find("fn push_scan_error").unwrap();
        let scan_source = &source[scan_start..helpers_start];

        assert_eq!(
            super::progress_current_path_or_unknown(&progress),
            "<unknown>"
        );
        progress.current_path = Some("   ".to_string());
        assert_eq!(
            super::progress_current_path_or_unknown(&progress),
            "<unknown>"
        );
        progress.current_path = Some("C:\\safe\\file.txt".to_string());
        assert_eq!(
            super::progress_current_path_or_unknown(&progress),
            "C:\\safe\\file.txt"
        );
        assert!(helper_source.contains("Some(path) if !path.trim().is_empty() => path"));
        assert!(helper_source.contains("Some(_) => \"<unknown>\""));
        assert!(helper_source.contains("None => \"<unknown>\""));
        assert!(!scan_source.contains("current_path.as_deref().unwrap_or(\"<unknown>\")"));
    }
}
