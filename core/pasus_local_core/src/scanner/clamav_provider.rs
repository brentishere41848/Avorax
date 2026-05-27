use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::{ScanResult, ScanStatus, ScannerProvider};

pub struct ClamAvProvider;

#[derive(Clone, Debug)]
struct ClamAvCommand {
    executable: PathBuf,
    engine_name: String,
    database_dir: Option<PathBuf>,
}

impl ClamAvProvider {
    pub fn engine_status(&self) -> &'static str {
        if self.command().is_some() {
            "available"
        } else {
            "unavailable"
        }
    }

    fn command(&self) -> Option<ClamAvCommand> {
        if let Some(command) = configured_clamscan() {
            return Some(command);
        }
        if command_available("clamdscan") {
            return Some(ClamAvCommand {
                executable: PathBuf::from("clamdscan"),
                engine_name: "clamdscan".to_string(),
                database_dir: None,
            });
        }
        if command_available("clamscan") {
            return Some(ClamAvCommand {
                executable: PathBuf::from("clamscan"),
                engine_name: "clamscan".to_string(),
                database_dir: None,
            });
        }
        bundled_clamscan()
    }
}

impl ScannerProvider for ClamAvProvider {
    fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        let started = Instant::now();
        let sha256 = sha256_file(path).unwrap_or_default();
        if local_eicar_signature_match(path) {
            return Ok(ScanResult {
                status: ScanStatus::Infected,
                scanned_path: path.display().to_string(),
                sha256,
                engine: "pasus-local-signatures".to_string(),
                signature_name: Some("EICAR-Test-Signature".to_string()),
                threat_name: Some("EICAR test signature".to_string()),
                scanned_at: Utc::now(),
                duration_ms: started.elapsed().as_millis(),
                raw_engine_summary: Some(
                    "Matched the standard EICAR antivirus test signature locally.".to_string(),
                ),
            });
        }
        let Some(command) = self.command() else {
            return Ok(ScanResult {
                status: ScanStatus::EngineUnavailable,
                scanned_path: path.display().to_string(),
                sha256,
                engine: "clamav".to_string(),
                signature_name: None,
                threat_name: None,
                scanned_at: Utc::now(),
                duration_ms: started.elapsed().as_millis(),
                raw_engine_summary: Some(
                    "Neither clamdscan nor clamscan is installed.".to_string(),
                ),
            });
        };
        let mut process = Command::new(&command.executable);
        process.arg("--no-summary");
        if let Some(database_dir) = &command.database_dir {
            process.arg("--database").arg(database_dir);
        }
        let output = process.arg(path).output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");
        let infected = output.status.code() == Some(1);
        let clean = output.status.success();
        let threat = if infected {
            combined
                .split(':')
                .nth(1)
                .map(|value| value.replace("FOUND", "").trim().to_string())
                .filter(|value| !value.is_empty())
        } else {
            None
        };
        Ok(ScanResult {
            status: if infected {
                ScanStatus::Infected
            } else if clean {
                ScanStatus::Clean
            } else {
                ScanStatus::Error
            },
            scanned_path: path.display().to_string(),
            sha256,
            engine: command.engine_name,
            signature_name: threat.clone(),
            threat_name: threat,
            scanned_at: Utc::now(),
            duration_ms: started.elapsed().as_millis(),
            raw_engine_summary: Some(combined),
        })
    }
}

const EICAR_TEST_SIGNATURE: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn local_eicar_signature_match(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    local_eicar_signature_match_bytes(&bytes)
}

fn local_eicar_signature_match_bytes(bytes: &[u8]) -> bool {
    bytes
        .windows(EICAR_TEST_SIGNATURE.len())
        .any(|window| window == EICAR_TEST_SIGNATURE.as_bytes())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn command_available(command: &str) -> bool {
    let probe = if cfg!(windows) { "where" } else { "which" };
    Command::new(probe)
        .arg(command)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn bundled_clamscan() -> Option<ClamAvCommand> {
    let executable_name = if cfg!(windows) {
        "clamscan.exe"
    } else {
        "clamscan"
    };

    let mut roots = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = env::current_dir() {
        roots.push(current_dir);
    }

    for root in roots {
        let candidates = [
            root.join("ClamAV").join(executable_name),
            root.join(executable_name),
        ];
        for candidate in candidates {
            if candidate.is_file() {
                return Some(command_from_path(candidate));
            }
        }
    }

    None
}

fn configured_clamscan() -> Option<ClamAvCommand> {
    let executable = PathBuf::from(env::var("PASUS_CLAMAV_CLAMSCAN").ok()?);
    if executable.is_file() {
        Some(command_from_path(executable))
    } else {
        None
    }
}

fn command_from_path(executable: PathBuf) -> ClamAvCommand {
    let database_dir = executable
        .parent()
        .map(|parent| parent.join("database"))
        .filter(|path| path.is_dir());
    ClamAvCommand {
        engine_name: executable.display().to_string(),
        executable,
        database_dir,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_eicar_signature_bytes_are_detected() {
        assert!(local_eicar_signature_match_bytes(
            EICAR_TEST_SIGNATURE.as_bytes()
        ));
        assert!(!local_eicar_signature_match_bytes(b"normal installer"));
    }
}
