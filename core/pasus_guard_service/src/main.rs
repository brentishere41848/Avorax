use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct GuardCommand {
    command: String,
    process_id: Option<u32>,
    process_path: Option<String>,
    known_malicious_hashes: Option<Vec<String>>,
    poll_interval_ms: Option<u64>,
    max_iterations: Option<u32>,
}

#[derive(Debug, Serialize)]
struct GuardEvent {
    ok: bool,
    action: String,
    message: String,
    process_id: Option<u32>,
    process_path: Option<String>,
    quarantine_path: Option<String>,
    created_at: DateTime<Utc>,
}

fn main() -> anyhow::Result<()> {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let command: GuardCommand = serde_json::from_str(&line)?;
        let response = handle(command);
        println!("{}", serde_json::to_string(&response)?);
    }
    Ok(())
}

fn handle(command: GuardCommand) -> GuardEvent {
    match command.command.as_str() {
        "health" => GuardEvent {
            ok: true,
            action: "health".to_string(),
            message: "Pasus Guard Service ready for user-mode post-launch protection.".to_string(),
            process_id: None,
            process_path: None,
            quarantine_path: None,
            created_at: Utc::now(),
        },
        "process_started" => {
            let Some(path) = command.process_path else {
                return error("process_path is required");
            };
            let pid = command.process_id;
            let malicious = command
                .known_malicious_hashes
                .unwrap_or_default()
                .into_iter()
                .collect::<HashSet<_>>();
            match handle_process_started(pid, Path::new(&path), &malicious) {
                Ok(event) => event,
                Err(error) => error_event(pid, Some(path), error.to_string()),
            }
        }
        "watch_processes" => {
            let malicious = command
                .known_malicious_hashes
                .unwrap_or_default()
                .into_iter()
                .collect::<HashSet<_>>();
            match watch_processes(
                &malicious,
                command.poll_interval_ms.unwrap_or(750),
                command.max_iterations,
            ) {
                Ok(event) => event,
                Err(error) => error_event(None, None, error.to_string()),
            }
        }
        _ => error("unknown command"),
    }
}

fn handle_process_started(
    process_id: Option<u32>,
    process_path: &Path,
    known_malicious_hashes: &HashSet<String>,
) -> anyhow::Result<GuardEvent> {
    let hash = sha256_file(process_path)?;
    let signature = local_signature_match(process_path)?;
    let clamav_signature = if signature.is_none() {
        clamav_signature_match(process_path).unwrap_or(None)
    } else {
        None
    };
    let confirmed_reason = if known_malicious_hashes.contains(&hash) {
        Some("known malicious hash".to_string())
    } else if let Some(signature) = signature {
        Some(signature)
    } else {
        clamav_signature.map(|signature| format!("ClamAV signature: {signature}"))
    };

    let Some(reason) = confirmed_reason else {
        return Ok(GuardEvent {
            ok: true,
            action: "monitored".to_string(),
            message: "Process monitored. No confirmed local threat hash matched.".to_string(),
            process_id,
            process_path: Some(process_path.display().to_string()),
            quarantine_path: None,
            created_at: Utc::now(),
        });
    };

    if let Some(pid) = process_id {
        stop_process(pid);
    }
    let quarantine_path = quarantine_file(process_path)
        .with_context(|| "known malicious process was stopped but quarantine failed")?;
    Ok(GuardEvent {
        ok: true,
        action: "stoppedAndQuarantined".to_string(),
        message: format!(
            "Pasus stopped the process and moved the file to quarantine. Reason: {reason}."
        ),
        process_id,
        process_path: Some(process_path.display().to_string()),
        quarantine_path: Some(quarantine_path.display().to_string()),
        created_at: Utc::now(),
    })
}

fn watch_processes(
    known_malicious_hashes: &HashSet<String>,
    poll_interval_ms: u64,
    max_iterations: Option<u32>,
) -> anyhow::Result<GuardEvent> {
    let mut seen: HashSet<u32> = list_processes()?
        .into_iter()
        .map(|process| process.process_id)
        .collect();
    let mut cache: HashMap<PathBuf, String> = HashMap::new();
    let mut iterations = 0u32;

    loop {
        iterations = iterations.saturating_add(1);
        for process in list_processes()? {
            if !seen.insert(process.process_id) {
                continue;
            }
            if should_skip_process_path(&process.path) {
                continue;
            }
            let hash = match cache.get(&process.path) {
                Some(hash) => hash.clone(),
                None => {
                    let hash = sha256_file(&process.path).unwrap_or_default();
                    cache.insert(process.path.clone(), hash.clone());
                    hash
                }
            };
            let eicar_or_signature = local_signature_match(&process.path)
                .ok()
                .flatten()
                .or_else(|| clamav_signature_match(&process.path).ok().flatten());

            if known_malicious_hashes.contains(&hash) || eicar_or_signature.is_some() {
                return handle_process_started(
                    Some(process.process_id),
                    &process.path,
                    known_malicious_hashes,
                );
            }
        }

        if let Some(max_iterations) = max_iterations {
            if iterations >= max_iterations {
                return Ok(GuardEvent {
                    ok: true,
                    action: "watchCompleted".to_string(),
                    message: "Process watch completed. No confirmed threat process was observed."
                        .to_string(),
                    process_id: None,
                    process_path: None,
                    quarantine_path: None,
                    created_at: Utc::now(),
                });
            }
        }
        thread::sleep(Duration::from_millis(poll_interval_ms.max(100)));
    }
}

#[derive(Debug)]
struct ObservedProcess {
    process_id: u32,
    path: PathBuf,
}

fn list_processes() -> anyhow::Result<Vec<ObservedProcess>> {
    #[cfg(windows)]
    {
        return list_processes_windows();
    }
    #[cfg(not(windows))]
    {
        return list_processes_procfs();
    }
}

#[cfg(windows)]
fn list_processes_windows() -> anyhow::Result<Vec<ObservedProcess>> {
    let script = "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | Select-Object ProcessId,ExecutablePath | ConvertTo-Json -Compress";
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .context("failed to query Windows processes")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Windows process query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    parse_windows_process_json(&String::from_utf8_lossy(&output.stdout))
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum WindowsProcessJson {
    One(WindowsProcessRow),
    Many(Vec<WindowsProcessRow>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsProcessRow {
    process_id: u32,
    executable_path: String,
}

#[cfg(windows)]
fn parse_windows_process_json(json: &str) -> anyhow::Result<Vec<ObservedProcess>> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: WindowsProcessJson = serde_json::from_str(trimmed)?;
    let rows = match parsed {
        WindowsProcessJson::One(row) => vec![row],
        WindowsProcessJson::Many(rows) => rows,
    };
    Ok(rows
        .into_iter()
        .map(|row| ObservedProcess {
            process_id: row.process_id,
            path: PathBuf::from(row.executable_path),
        })
        .filter(|process| process.path.is_file())
        .collect())
}

#[cfg(not(windows))]
fn list_processes_procfs() -> anyhow::Result<Vec<ObservedProcess>> {
    let mut processes = Vec::new();
    let proc = Path::new("/proc");
    if !proc.is_dir() {
        return Ok(processes);
    }
    for entry in fs::read_dir(proc)? {
        let Ok(entry) = entry else {
            continue;
        };
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let Ok(path) = fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        if path.is_file() {
            processes.push(ObservedProcess {
                process_id: pid,
                path,
            });
        }
    }
    Ok(processes)
}

fn stop_process(process_id: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &process_id.to_string(), "/F"])
            .output();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &process_id.to_string()])
            .output();
    }
}

fn quarantine_file(path: &Path) -> anyhow::Result<PathBuf> {
    let base = quarantine_base();
    fs::create_dir_all(&base)?;
    let destination = base.join(format!("{}.pasusq", Uuid::new_v4()));
    let mut last_error = None;
    for _ in 0..10 {
        match fs::rename(path, &destination) {
            Ok(()) => {
                remove_executable_permissions(&destination)?;
                return Ok(destination);
            }
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(150));
            }
        }
    }
    return Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("quarantine failed")));
}

fn remove_executable_permissions(_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(_path)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() & !0o111);
        fs::set_permissions(_path, permissions)?;
    }
    Ok(())
}

fn quarantine_base() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(program_data) = std::env::var("PROGRAMDATA") {
            return PathBuf::from(program_data)
                .join("Pasus")
                .join("GuardQuarantine");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/pasus/guard-quarantine");
    }
    PathBuf::from(".pasus/guard-quarantine")
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn local_signature_match(path: &Path) -> anyhow::Result<Option<String>> {
    let bytes = fs::read(path)?;
    Ok(local_signature_match_bytes(&bytes))
}

fn local_signature_match_bytes(bytes: &[u8]) -> Option<String> {
    if bytes
        .windows(EICAR_TEST_SIGNATURE.len())
        .any(|window| window == EICAR_TEST_SIGNATURE.as_bytes())
        || bytes
            .windows(PASUS_SAFE_EICAR_SIMULATOR.len())
            .any(|window| window == PASUS_SAFE_EICAR_SIMULATOR.as_bytes())
    {
        return Some("EICAR test signature".to_string());
    }
    None
}

const EICAR_TEST_SIGNATURE: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const PASUS_SAFE_EICAR_SIMULATOR: &str = "PASUS-SAFE-EICAR-SIMULATOR-FILE";

fn clamav_signature_match(path: &Path) -> anyhow::Result<Option<String>> {
    let Some(clamscan) = find_clamscan() else {
        return Ok(None);
    };
    let output = Command::new(&clamscan)
        .arg("--no-summary")
        .arg(path)
        .output()?;
    if output.status.code() != Some(1) {
        return Ok(None);
    }
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(combined
        .split(':')
        .nth(1)
        .map(|value| value.replace("FOUND", "").trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn find_clamscan() -> Option<PathBuf> {
    if let Ok(configured) = std::env::var("PASUS_CLAMAV_CLAMSCAN") {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return Some(path);
        }
    }
    let executable_name = if cfg!(windows) {
        "clamscan.exe"
    } else {
        "clamscan"
    };
    let mut roots = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir);
    }
    for root in roots {
        for candidate in [
            root.join("ClamAV").join(executable_name),
            root.join(executable_name),
        ] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn should_skip_process_path(path: &Path) -> bool {
    let lower = path.display().to_string().to_lowercase();
    lower.contains("\\windows\\system32\\")
        || lower.contains("\\windows\\syswow64\\")
        || lower == "c:\\windows\\explorer.exe"
        || lower.starts_with("/usr/")
        || lower.starts_with("/bin/")
        || lower.starts_with("/sbin/")
        || lower.starts_with("/system/")
}

fn error(message: &str) -> GuardEvent {
    error_event(None, None, message.to_string())
}

fn error_event(
    process_id: Option<u32>,
    process_path: Option<String>,
    message: String,
) -> GuardEvent {
    GuardEvent {
        ok: false,
        action: "error".to_string(),
        message,
        process_id,
        process_path,
        quarantine_path: None,
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn mock_process_start_without_known_hash_is_monitored() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("tool.exe");
        fs::write(&file, b"developer tool").unwrap();
        let result = handle_process_started(None, &file, &HashSet::new()).unwrap();
        assert_eq!(result.action, "monitored");
        assert!(file.exists());
    }

    #[test]
    fn known_malicious_hash_is_quarantined() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.exe");
        fs::write(&file, b"known bad fixture").unwrap();
        let hash = sha256_file(&file).unwrap();
        let result = handle_process_started(None, &file, &HashSet::from([hash])).unwrap();
        assert_eq!(result.action, "stoppedAndQuarantined");
        assert!(!file.exists());
        assert!(Path::new(result.quarantine_path.as_ref().unwrap()).exists());
    }

    #[test]
    fn eicar_signature_bytes_are_detected_as_confirmed_test_threat() {
        assert_eq!(
            local_signature_match_bytes(EICAR_TEST_SIGNATURE.as_bytes()).as_deref(),
            Some("EICAR test signature")
        );
        assert_eq!(
            local_signature_match_bytes(PASUS_SAFE_EICAR_SIMULATOR.as_bytes()).as_deref(),
            Some("EICAR test signature")
        );
        assert!(local_signature_match_bytes(b"normal installer").is_none());
    }

    #[test]
    fn watch_processes_completes_without_fake_detection() {
        let result = watch_processes(&HashSet::new(), 100, Some(1)).unwrap();
        assert_eq!(result.action, "watchCompleted");
        assert!(result.ok);
    }
}
