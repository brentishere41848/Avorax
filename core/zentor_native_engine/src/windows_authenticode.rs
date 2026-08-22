use std::ffi::c_void;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::{Command, ExitStatus, Stdio};
use std::ptr::null_mut;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant, Version};
use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, CERT_E_REVOCATION_FAILURE, CRYPT_E_BAD_ENCODE,
    CRYPT_E_BAD_MSG, CRYPT_E_NO_MATCH, CRYPT_E_NO_SIGNER, CRYPT_E_NO_TRUSTED_SIGNER,
    CRYPT_E_REVOKED, CRYPT_E_SIGNER_NOT_FOUND, ERROR_NOT_FOUND, ERROR_SUCCESS, HANDLE,
    INVALID_HANDLE_VALUE, TRUST_E_BAD_DIGEST, TRUST_E_BASIC_CONSTRAINTS, TRUST_E_CERT_SIGNATURE,
    TRUST_E_COUNTER_SIGNER, TRUST_E_FAIL, TRUST_E_FINANCIAL_CRITERIA, TRUST_E_MALFORMED_SIGNATURE,
    TRUST_E_NO_SIGNER_CERT, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_SUBJECT_NOT_TRUSTED,
    TRUST_E_TIME_STAMP,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    szOID_COMMON_NAME, szOID_ORGANIZATION_NAME, CertGetNameStringW, BCRYPT_SHA256_ALGORITHM,
    CERT_CONTEXT, CERT_NAME_ATTR_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WINTRUST_SIGNATURE_SETTINGS, WSS_GET_SECONDARY_SIG_COUNT,
    WSS_VERIFY_SPECIFIC, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, FileIdInfo, FileStandardInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_BASIC_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_ID_INFO,
    FILE_SHARE_READ, FILE_STANDARD_INFO,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

const MAX_AUTHENTICODE_PATH_UTF16_UNITS: usize = 32_767;
const MAX_SIGNER_ATTRIBUTE_UTF16_UNITS: usize = 2_048;
const MAX_AUTHENTICODE_BIND_BYTES: u64 = 512 * 1024 * 1024;
const AUTHENTICODE_HASH_BUFFER_BYTES: usize = 128 * 1024;
const SHA256_CATALOG_HASH_BYTES: usize = 32;
const MAX_CATALOG_CANDIDATES: usize = 16;
const MAX_EMBEDDED_SIGNATURES: u32 = 16;
const AUTHENTICODE_HELPER_SCHEMA_VERSION: u32 = 1;
const AUTHENTICODE_HELPER_ARGUMENT: &str = "--avorax-authenticode-helper-v1";
const AUTHENTICODE_HELPER_TIMEOUT: Duration = Duration::from_secs(15);
const AUTHENTICODE_HELPER_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const AUTHENTICODE_HELPER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_AUTHENTICODE_HELPER_REQUEST_BYTES: usize = 256 * 1024;
const MAX_AUTHENTICODE_HELPER_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_AUTHENTICODE_HELPER_STDERR_BYTES: usize = 16 * 1024;
const MAX_AUTHENTICODE_HELPER_ERROR_CHARS: usize = 4_096;
const MAX_AUTHENTICODE_HOST_EXE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticodeHelperRequest {
    schema_version: u32,
    nonce: String,
    path_utf16: Vec<u16>,
    expected_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticodeHelperResponse {
    schema_version: u32,
    nonce: String,
    status: String,
    trusted: Option<bool>,
    error: Option<String>,
}

#[derive(Debug)]
struct AuthenticodeHelperOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct KillOnCloseJob(HANDLE);

impl KillOnCloseJob {
    fn create() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(null_mut(), null_mut()) };
        anyhow::ensure!(
            !handle.is_null(),
            "unable to create isolated Authenticode helper job: {}",
            std::io::Error::last_os_error()
        );
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            let error = std::io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            anyhow::bail!("unable to configure isolated Authenticode helper job: {error}");
        }
        Ok(Self(handle))
    }

    fn assign(&self, process: HANDLE) -> Result<()> {
        anyhow::ensure!(
            unsafe { AssignProcessToJobObject(self.0, process) } != 0,
            "unable to assign Authenticode helper to its kill-on-close job: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
}

impl Drop for KillOnCloseJob {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmbeddedSignatureVerdict {
    Microsoft,
    OtherPublisher,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticodeFileSnapshot {
    volume_serial_number: u64,
    file_id: [u8; 16],
    file_index: u64,
    creation_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
    allocation_size: i64,
    end_of_file: i64,
    number_of_links: u32,
    delete_pending: bool,
    directory: bool,
}

pub(crate) fn has_valid_microsoft_signature(path: &Path, expected_sha256: &str) -> Result<bool> {
    if cfg!(debug_assertions) {
        return verify_direct_microsoft_signature(path, expected_sha256);
    }
    verify_with_isolated_helper(path, expected_sha256)
}

fn verify_direct_microsoft_signature(path: &Path, expected_sha256: &str) -> Result<bool> {
    validate_expected_sha256(expected_sha256)?;
    let path_wide = absolute_path_wide(path)?;
    let mut file = open_authenticode_candidate(path)?;
    enforce_content_binding_size(path, &file)?;
    let before = snapshot_authenticode_file(path, &file)?;
    let verdict = match verify_open_file(path, &path_wide, &mut file, expected_sha256) {
        Ok(true) => Ok(true),
        Ok(false) => verify_catalog_signatures(path, &path_wide, &mut file, expected_sha256),
        Err(error) => Err(error),
    };
    let after = snapshot_authenticode_file(path, &file);
    combine_verdict_and_file_snapshot(path, verdict, before, after)
}

pub(crate) fn run_authenticode_helper_stdio() -> Result<()> {
    run_authenticode_stdio(verify_direct_microsoft_signature)
}

pub(crate) fn run_authenticode_client_self_test_stdio() -> Result<()> {
    run_authenticode_stdio(has_valid_microsoft_signature)
}

fn run_authenticode_stdio(verify: impl FnOnce(&Path, &str) -> Result<bool>) -> Result<()> {
    let request = read_authenticode_helper_request(std::io::stdin().lock())?;
    let nonce = validate_authenticode_helper_request(&request)?;
    let path = PathBuf::from(OsString::from_wide(&request.path_utf16));
    let outcome = verify(&path, &request.expected_sha256);
    let response = match outcome {
        Ok(trusted) => AuthenticodeHelperResponse {
            schema_version: AUTHENTICODE_HELPER_SCHEMA_VERSION,
            nonce,
            status: "ok".to_string(),
            trusted: Some(trusted),
            error: None,
        },
        Err(error) => AuthenticodeHelperResponse {
            schema_version: AUTHENTICODE_HELPER_SCHEMA_VERSION,
            nonce,
            status: "error".to_string(),
            trusted: None,
            error: Some(bounded_authenticode_helper_text(&format!("{error:#}"))),
        },
    };
    let encoded = serde_json::to_vec(&response)
        .context("unable to serialize Authenticode helper response")?;
    anyhow::ensure!(
        encoded.len() <= MAX_AUTHENTICODE_HELPER_RESPONSE_BYTES,
        "AuthentiCode helper response exceeds its byte limit"
    );
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&encoded)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn read_authenticode_helper_request(mut input: impl Read) -> Result<AuthenticodeHelperRequest> {
    let mut encoded = Vec::new();
    input
        .by_ref()
        .take((MAX_AUTHENTICODE_HELPER_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .context("unable to read Authenticode helper request")?;
    anyhow::ensure!(!encoded.is_empty(), "AuthentiCode helper request is empty");
    anyhow::ensure!(
        encoded.len() <= MAX_AUTHENTICODE_HELPER_REQUEST_BYTES,
        "AuthentiCode helper request exceeds {} bytes",
        MAX_AUTHENTICODE_HELPER_REQUEST_BYTES
    );
    serde_json::from_slice(&encoded).context("AuthentiCode helper request is not strict JSON")
}

fn validate_authenticode_helper_request(request: &AuthenticodeHelperRequest) -> Result<String> {
    anyhow::ensure!(
        request.schema_version == AUTHENTICODE_HELPER_SCHEMA_VERSION,
        "unsupported Authenticode helper schema version {}",
        request.schema_version
    );
    let nonce = Uuid::parse_str(&request.nonce).context("AuthentiCode helper nonce is invalid")?;
    anyhow::ensure!(
        nonce.get_variant() == Variant::RFC4122 && nonce.get_version() == Some(Version::Random),
        "AuthentiCode helper nonce must be an RFC 4122 random UUID"
    );
    anyhow::ensure!(
        !request.path_utf16.is_empty()
            && request.path_utf16.len() < MAX_AUTHENTICODE_PATH_UTF16_UNITS,
        "AuthentiCode helper path must contain between 1 and {} UTF-16 units",
        MAX_AUTHENTICODE_PATH_UTF16_UNITS - 1
    );
    anyhow::ensure!(
        !request.path_utf16.contains(&0),
        "AuthentiCode helper path contains an embedded NUL"
    );
    validate_expected_sha256(&request.expected_sha256)?;
    Ok(nonce.hyphenated().to_string())
}

fn verify_with_isolated_helper(path: &Path, expected_sha256: &str) -> Result<bool> {
    validate_expected_sha256(expected_sha256)?;
    let path_utf16 = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let request = AuthenticodeHelperRequest {
        schema_version: AUTHENTICODE_HELPER_SCHEMA_VERSION,
        nonce: Uuid::new_v4().hyphenated().to_string(),
        path_utf16,
        expected_sha256: expected_sha256.to_owned(),
    };
    validate_authenticode_helper_request(&request)?;
    let encoded =
        serde_json::to_vec(&request).context("unable to serialize Authenticode helper request")?;
    anyhow::ensure!(
        encoded.len() <= MAX_AUTHENTICODE_HELPER_REQUEST_BYTES,
        "AuthentiCode helper request exceeds {} bytes",
        MAX_AUTHENTICODE_HELPER_REQUEST_BYTES
    );

    let (host_path, _host_lock) = open_current_authenticode_host()?;
    let mut command = Command::new(&host_path);
    command
        .arg(AUTHENTICODE_HELPER_ARGUMENT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);
    let output = run_bounded_authenticode_helper(command, encoded, AUTHENTICODE_HELPER_TIMEOUT)?;
    interpret_authenticode_helper_output(path, &request.nonce, output)
}

fn open_current_authenticode_host() -> Result<(PathBuf, File)> {
    let path =
        std::env::current_exe().context("unable to locate current Authenticode host executable")?;
    anyhow::ensure!(
        path.is_absolute(),
        "AuthentiCode host executable path is not absolute"
    );
    let local_drive = matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    );
    anyhow::ensure!(
        local_drive,
        "AuthentiCode host executable is not on a local drive"
    );
    let units = path.as_os_str().encode_wide().count();
    anyhow::ensure!(
        units > 0 && units < MAX_AUTHENTICODE_PATH_UTF16_UNITS,
        "AuthentiCode host executable path exceeds its UTF-16 limit"
    );
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(&path)
        .with_context(|| {
            format!(
                "unable to lock Authenticode host executable {}",
                path.display()
            )
        })?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "AuthentiCode host executable is not a regular file"
    );
    anyhow::ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "AuthentiCode host executable is a reparse point"
    );
    anyhow::ensure!(
        metadata.len() > 0 && metadata.len() <= MAX_AUTHENTICODE_HOST_EXE_BYTES,
        "AuthentiCode host executable size is outside the 1..={} byte bound",
        MAX_AUTHENTICODE_HOST_EXE_BYTES
    );
    Ok((path, file))
}

fn run_bounded_authenticode_helper(
    mut command: Command,
    request: Vec<u8>,
    timeout: Duration,
) -> Result<AuthenticodeHelperOutput> {
    let job = KillOnCloseJob::create()?;
    let mut child = command
        .spawn()
        .context("unable to start isolated Authenticode helper")?;
    if let Err(error) = job.assign(child.as_raw_handle() as HANDLE) {
        let kill_result = child.kill();
        drop(job);
        let reap_result = wait_for_child_exit(&mut child, AUTHENTICODE_HELPER_REAP_TIMEOUT);
        anyhow::bail!(
            "{error:#}; termination request: {}; reap: {}",
            helper_result_summary(kill_result),
            helper_result_summary(reap_result)
        );
    }
    let stdin = child
        .stdin
        .take()
        .context("AuthentiCode helper stdin is unavailable")?;
    let stdout = child
        .stdout
        .take()
        .context("AuthentiCode helper stdout is unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("AuthentiCode helper stderr is unavailable")?;
    let writer = spawn_helper_worker(move || -> Result<()> {
        let mut stdin = stdin;
        stdin
            .write_all(&request)
            .context("unable to write Authenticode helper request")?;
        stdin
            .flush()
            .context("unable to flush Authenticode helper request")?;
        Ok(())
    });
    let stdout_reader = spawn_bounded_pipe_reader(
        stdout,
        MAX_AUTHENTICODE_HELPER_RESPONSE_BYTES,
        "AuthentiCode helper stdout",
    );
    let stderr_reader = spawn_bounded_pipe_reader(
        stderr,
        MAX_AUTHENTICODE_HELPER_STDERR_BYTES,
        "AuthentiCode helper stderr",
    );

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .context("unable to poll Authenticode helper")?
        {
            break status;
        }
        if started.elapsed() >= timeout {
            let kill_result = child.kill();
            drop(job);
            let reaped = wait_for_child_exit(&mut child, AUTHENTICODE_HELPER_REAP_TIMEOUT);
            let worker_deadline = Instant::now() + AUTHENTICODE_HELPER_REAP_TIMEOUT;
            let writer_result = receive_helper_worker(writer, worker_deadline, "request writer");
            let stdout_result =
                receive_helper_worker(stdout_reader, worker_deadline, "stdout reader");
            let stderr_result =
                receive_helper_worker(stderr_reader, worker_deadline, "stderr reader");
            anyhow::bail!(
                "isolated Authenticode helper timed out after {} ms; termination request: {}; reap: {}; writer: {}; stdout: {}; stderr: {}",
                timeout.as_millis(),
                helper_result_summary(kill_result),
                helper_result_summary(reaped),
                helper_result_summary(writer_result),
                helper_result_summary(stdout_result.map(|_| ())),
                helper_result_summary(stderr_result.map(|_| ()))
            );
        }
        thread::sleep(AUTHENTICODE_HELPER_POLL_INTERVAL);
    };
    drop(job);
    let worker_deadline = Instant::now() + AUTHENTICODE_HELPER_REAP_TIMEOUT;
    let writer_result = receive_helper_worker(writer, worker_deadline, "request writer");
    let stdout = receive_helper_worker(stdout_reader, worker_deadline, "stdout reader")?;
    let stderr = receive_helper_worker(stderr_reader, worker_deadline, "stderr reader")?;
    writer_result?;
    Ok(AuthenticodeHelperOutput {
        status,
        stdout,
        stderr,
    })
}

fn spawn_bounded_pipe_reader<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    label: &'static str,
) -> Receiver<Result<Vec<u8>>> {
    spawn_helper_worker(move || {
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("unable to read {label}"))?;
        anyhow::ensure!(bytes.len() <= limit, "{label} exceeds {limit} bytes");
        Ok(bytes)
    })
}

fn spawn_helper_worker<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Receiver<Result<T>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        drop(sender.send(work()));
    });
    receiver
}

fn receive_helper_worker<T>(
    receiver: Receiver<Result<T>>,
    deadline: Instant,
    label: &str,
) -> Result<T> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    anyhow::ensure!(
        !remaining.is_zero(),
        "AuthentiCode helper {label} exceeded the bounded completion deadline"
    );
    match receiver.recv_timeout(remaining) {
        Ok(result) => result.with_context(|| format!("AuthentiCode helper {label} failed")),
        Err(RecvTimeoutError::Timeout) => {
            anyhow::bail!("AuthentiCode helper {label} exceeded the bounded completion deadline")
        }
        Err(RecvTimeoutError::Disconnected) => {
            anyhow::bail!("AuthentiCode helper {label} panicked or disconnected")
        }
    }
}

fn wait_for_child_exit(child: &mut std::process::Child, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        anyhow::ensure!(
            started.elapsed() < timeout,
            "helper did not exit within {} ms after termination",
            timeout.as_millis()
        );
        thread::sleep(AUTHENTICODE_HELPER_POLL_INTERVAL);
    }
}

fn helper_result_summary<T, E: std::fmt::Display>(result: std::result::Result<T, E>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(error) => bounded_authenticode_helper_text(&format!("error: {error:#}")),
    }
}

fn interpret_authenticode_helper_output(
    path: &Path,
    expected_nonce: &str,
    output: AuthenticodeHelperOutput,
) -> Result<bool> {
    let stderr = bounded_authenticode_helper_text(&String::from_utf8_lossy(&output.stderr));
    anyhow::ensure!(
        output.status.success(),
        "isolated Authenticode helper failed for {} with status {}; stderr: {}",
        path.display(),
        output.status,
        stderr
    );
    anyhow::ensure!(
        stderr.trim().is_empty(),
        "isolated Authenticode helper returned unexpected stderr for {}: {}",
        path.display(),
        stderr
    );
    anyhow::ensure!(
        output.stdout.len() <= MAX_AUTHENTICODE_HELPER_RESPONSE_BYTES,
        "isolated Authenticode helper response exceeds its byte limit"
    );
    let response: AuthenticodeHelperResponse = serde_json::from_slice(&output.stdout)
        .context("isolated Authenticode helper response is not strict JSON")?;
    anyhow::ensure!(
        response.schema_version == AUTHENTICODE_HELPER_SCHEMA_VERSION,
        "isolated Authenticode helper response schema mismatch"
    );
    anyhow::ensure!(
        response.nonce == expected_nonce,
        "isolated Authenticode helper response nonce mismatch"
    );
    match response.status.as_str() {
        "ok" => {
            anyhow::ensure!(
                response.error.is_none(),
                "successful Authenticode helper response contains an error"
            );
            response
                .trusted
                .context("successful Authenticode helper response has no verdict")
        }
        "error" => {
            anyhow::ensure!(
                response.trusted.is_none(),
                "failed Authenticode helper response contains a verdict"
            );
            let error = response
                .error
                .context("failed Authenticode helper response has no diagnostic")?;
            anyhow::ensure!(
                !error.trim().is_empty(),
                "failed Authenticode helper response diagnostic is blank"
            );
            anyhow::bail!(
                "isolated Authenticode verification failed for {}: {}",
                path.display(),
                bounded_authenticode_helper_text(&error)
            )
        }
        other => anyhow::bail!("isolated Authenticode helper response has unknown status {other}"),
    }
}

fn bounded_authenticode_helper_text(text: &str) -> String {
    let normalized = text
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
                '\u{FFFD}'
            } else {
                character
            }
        })
        .collect::<String>();
    if normalized.chars().count() <= MAX_AUTHENTICODE_HELPER_ERROR_CHARS {
        return normalized;
    }
    normalized
        .chars()
        .take(MAX_AUTHENTICODE_HELPER_ERROR_CHARS)
        .collect::<String>()
        + "...[truncated]"
}

fn enforce_content_binding_size(path: &Path, file: &File) -> Result<()> {
    let metadata = file.metadata().with_context(|| {
        format!(
            "unable to inspect Microsoft-signed file content-binding size {}",
            path.display()
        )
    })?;
    anyhow::ensure!(
        metadata.len() <= MAX_AUTHENTICODE_BIND_BYTES,
        "Microsoft-signed file exceeds the {} byte content-binding limit: {}",
        MAX_AUTHENTICODE_BIND_BYTES,
        path.display()
    );
    Ok(())
}

fn validate_expected_sha256(expected_sha256: &str) -> Result<()> {
    anyhow::ensure!(
        expected_sha256.len() == 64 && expected_sha256.as_bytes().iter().all(u8::is_ascii_hexdigit),
        "expected Authenticode content SHA-256 must contain exactly 64 hexadecimal characters"
    );
    Ok(())
}

fn absolute_path_wide(path: &Path) -> Result<Vec<u16>> {
    anyhow::ensure!(
        path.is_absolute(),
        "Authenticode candidate path must be absolute: {}",
        path.display()
    );
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    anyhow::ensure!(
        !wide.contains(&0),
        "Authenticode candidate path contains NUL: {}",
        path.display()
    );
    anyhow::ensure!(
        wide.len() < MAX_AUTHENTICODE_PATH_UTF16_UNITS,
        "Authenticode candidate path exceeds {} UTF-16 units: {}",
        MAX_AUTHENTICODE_PATH_UTF16_UNITS - 1,
        path.display()
    );
    wide.push(0);
    Ok(wide)
}

fn open_authenticode_candidate(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN);
    let file = options.open(path).with_context(|| {
        format!(
            "unable to open Authenticode candidate without write/delete sharing {}",
            path.display()
        )
    })?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "unable to inspect opened Authenticode candidate {}",
            path.display()
        )
    })?;
    anyhow::ensure!(
        metadata.is_file(),
        "opened Authenticode candidate is not a regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing reparse-point Authenticode candidate {}",
        path.display()
    );
    Ok(file)
}

fn snapshot_authenticode_file(path: &Path, file: &File) -> Result<AuthenticodeFileSnapshot> {
    let handle = file.as_raw_handle() as HANDLE;
    anyhow::ensure!(
        !handle.is_null() && handle != INVALID_HANDLE_VALUE,
        "Authenticode candidate has an invalid file handle while capturing identity: {}",
        path.display()
    );

    let mut legacy = BY_HANDLE_FILE_INFORMATION::default();
    anyhow::ensure!(
        unsafe { GetFileInformationByHandle(handle, &mut legacy) } != 0,
        "unable to capture Authenticode file identity for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    let basic: FILE_BASIC_INFO = query_authenticode_handle_info(path, handle, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO =
        query_authenticode_handle_info(path, handle, FileStandardInfo)?;
    let id: FILE_ID_INFO = query_authenticode_handle_info(path, handle, FileIdInfo)?;

    let legacy_size = (u64::from(legacy.nFileSizeHigh) << 32) | u64::from(legacy.nFileSizeLow);
    let legacy_creation_time = (u64::from(legacy.ftCreationTime.dwHighDateTime) << 32)
        | u64::from(legacy.ftCreationTime.dwLowDateTime);
    let legacy_last_write_time = (u64::from(legacy.ftLastWriteTime.dwHighDateTime) << 32)
        | u64::from(legacy.ftLastWriteTime.dwLowDateTime);
    anyhow::ensure!(
        !standard.Directory,
        "opened Authenticode candidate became a directory: {}",
        path.display()
    );
    anyhow::ensure!(
        !standard.DeletePending,
        "opened Authenticode candidate is pending deletion: {}",
        path.display()
    );
    anyhow::ensure!(
        standard.EndOfFile >= 0
            && standard.AllocationSize >= 0
            && standard.EndOfFile as u64 == legacy_size,
        "inconsistent Authenticode file size metadata for {}",
        path.display()
    );
    anyhow::ensure!(
        standard.NumberOfLinks > 0 && legacy.nNumberOfLinks > 0,
        "opened Authenticode candidate has no stable filesystem link: {}",
        path.display()
    );
    anyhow::ensure!(
        standard.NumberOfLinks == legacy.nNumberOfLinks,
        "inconsistent Authenticode file link-count metadata for {}",
        path.display()
    );
    anyhow::ensure!(
        basic.FileAttributes == legacy.dwFileAttributes
            && basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "inconsistent or reparse-point Authenticode file attributes for {}",
        path.display()
    );
    anyhow::ensure!(
        id.VolumeSerialNumber as u32 == legacy.dwVolumeSerialNumber,
        "inconsistent Authenticode file volume identity for {}",
        path.display()
    );
    anyhow::ensure!(
        basic.CreationTime as u64 == legacy_creation_time
            && basic.LastWriteTime as u64 == legacy_last_write_time,
        "inconsistent Authenticode file timestamp metadata for {}",
        path.display()
    );

    Ok(AuthenticodeFileSnapshot {
        volume_serial_number: id.VolumeSerialNumber,
        file_id: id.FileId.Identifier,
        file_index: (u64::from(legacy.nFileIndexHigh) << 32) | u64::from(legacy.nFileIndexLow),
        creation_time: basic.CreationTime,
        last_write_time: basic.LastWriteTime,
        change_time: basic.ChangeTime,
        file_attributes: basic.FileAttributes,
        allocation_size: standard.AllocationSize,
        end_of_file: standard.EndOfFile,
        number_of_links: standard.NumberOfLinks,
        delete_pending: standard.DeletePending,
        directory: standard.Directory,
    })
}

fn query_authenticode_handle_info<T: Default>(
    path: &Path,
    handle: HANDLE,
    class: i32,
) -> Result<T> {
    let mut value = T::default();
    anyhow::ensure!(
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                class,
                (&mut value as *mut T).cast::<c_void>(),
                size_of::<T>() as u32,
            )
        } != 0,
        "unable to capture Authenticode handle information class {} for {}: {}",
        class,
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(value)
}

fn ensure_authenticode_file_unchanged(
    path: &Path,
    before: &AuthenticodeFileSnapshot,
    after: &AuthenticodeFileSnapshot,
) -> Result<()> {
    anyhow::ensure!(
        before == after,
        "Authenticode candidate identity or mutation metadata changed while verifying {}",
        path.display()
    );
    Ok(())
}

fn combine_verdict_and_file_snapshot(
    path: &Path,
    verdict: Result<bool>,
    before: AuthenticodeFileSnapshot,
    after: Result<AuthenticodeFileSnapshot>,
) -> Result<bool> {
    let stability =
        after.and_then(|after| ensure_authenticode_file_unchanged(path, &before, &after));
    match (verdict, stability) {
        (Ok(verdict), Ok(())) => Ok(verdict),
        (Ok(_), Err(stability_error)) => Err(stability_error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(stability_error)) => anyhow::bail!(
            "{error:#}; Authenticode file identity verification also failed for {}: {stability_error:#}",
            path.display()
        ),
    }
}

fn verify_open_file(
    path: &Path,
    path_wide: &[u16],
    file: &mut File,
    expected_sha256: &str,
) -> Result<bool> {
    let handle = file.as_raw_handle() as HANDLE;
    anyhow::ensure!(
        !handle.is_null() && handle != INVALID_HANDLE_VALUE,
        "Authenticode candidate has an invalid file handle: {}",
        path.display()
    );

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path_wide.as_ptr(),
        hFile: handle,
        pgKnownSubject: null_mut(),
    };
    let mut signature_settings = WINTRUST_SIGNATURE_SETTINGS {
        cbStruct: size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32,
        dwIndex: 0,
        dwFlags: WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC,
        cSecondarySigs: 0,
        dwVerifiedSigIndex: 0,
        pCryptoPolicy: null_mut(),
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: null_mut(),
        pwszURLReference: null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            | WTD_DISABLE_MD2_MD4,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: &mut signature_settings,
    };

    let primary = verify_specific_embedded_signature(
        path,
        &mut trust_data,
        &mut signature_settings,
        file,
        expected_sha256,
    )?;
    if primary == EmbeddedSignatureVerdict::Invalid {
        return Ok(false);
    }
    let secondary_count = signature_settings.cSecondarySigs;
    aggregate_valid_embedded_signatures(path, primary, secondary_count, |index| {
        signature_settings.dwIndex = index;
        let verdict = verify_specific_embedded_signature(
            path,
            &mut trust_data,
            &mut signature_settings,
            file,
            expected_sha256,
        )?;
        anyhow::ensure!(
            signature_settings.cSecondarySigs == secondary_count,
            "embedded Authenticode secondary-signature count changed from {} to {} while verifying {}",
            secondary_count,
            signature_settings.cSecondarySigs,
            path.display()
        );
        Ok(verdict)
    })
}

fn verify_specific_embedded_signature(
    path: &Path,
    trust_data: &mut WINTRUST_DATA,
    signature_settings: &mut WINTRUST_SIGNATURE_SETTINGS,
    file: &mut File,
    expected_sha256: &str,
) -> Result<EmbeddedSignatureVerdict> {
    file.seek(SeekFrom::Start(0)).with_context(|| {
        format!(
            "unable to rewind Authenticode candidate for embedded signature {} verification: {}",
            signature_settings.dwIndex,
            path.display()
        )
    })?;
    let requested_index = signature_settings.dwIndex;
    signature_settings.dwVerifiedSigIndex = u32::MAX;
    verify_wintrust_data_with(
        path,
        trust_data,
        file,
        EmbeddedSignatureVerdict::Invalid,
        |trust_data, file| {
            anyhow::ensure!(
                verified_signature_index_is_acceptable(
                    requested_index,
                    signature_settings.dwVerifiedSigIndex
                ),
                "WinVerifyTrust reported unexpected embedded signature index {} for requested index {} for {}",
                signature_settings.dwVerifiedSigIndex,
                requested_index,
                path.display()
            );
            if verified_signer_is_microsoft(trust_data)? {
                bind_verified_signature_to_expected_hash(path, file, expected_sha256)?;
                Ok(EmbeddedSignatureVerdict::Microsoft)
            } else {
                Ok(EmbeddedSignatureVerdict::OtherPublisher)
            }
        },
    )
}

fn verified_signature_index_is_acceptable(requested: u32, reported: u32) -> bool {
    if requested == 0 {
        return reported == 0 || reported == u32::MAX;
    }
    reported == requested
}

fn aggregate_valid_embedded_signatures<F>(
    path: &Path,
    primary: EmbeddedSignatureVerdict,
    secondary_count: u32,
    mut verify_secondary: F,
) -> Result<bool>
where
    F: FnMut(u32) -> Result<EmbeddedSignatureVerdict>,
{
    if primary == EmbeddedSignatureVerdict::Invalid {
        return Ok(false);
    }
    let total = secondary_count
        .checked_add(1)
        .context("embedded Authenticode signature count overflowed")?;
    anyhow::ensure!(
        total <= MAX_EMBEDDED_SIGNATURES,
        "embedded Authenticode signature count {} exceeds the {} signature limit for {}",
        total,
        MAX_EMBEDDED_SIGNATURES,
        path.display()
    );
    if primary == EmbeddedSignatureVerdict::Microsoft {
        return Ok(true);
    }
    for index in 1..=secondary_count {
        if verify_secondary(index)? == EmbeddedSignatureVerdict::Microsoft {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_wintrust_data(
    path: &Path,
    trust_data: &mut WINTRUST_DATA,
    file: &mut File,
    expected_sha256: &str,
) -> Result<bool> {
    verify_wintrust_data_with(path, trust_data, file, false, |trust_data, file| {
        if verified_signer_is_microsoft(trust_data)? {
            bind_verified_signature_to_expected_hash(path, file, expected_sha256)
        } else {
            Ok(false)
        }
    })
}

fn verify_wintrust_data_with<T, F>(
    path: &Path,
    trust_data: &mut WINTRUST_DATA,
    file: &mut File,
    invalid_verdict: T,
    evaluate_success: F,
) -> Result<T>
where
    F: FnOnce(&WINTRUST_DATA, &mut File) -> Result<T>,
{
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let verify_status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    let outcome = if verify_status == 0 {
        evaluate_success(trust_data, file)
    } else if definitively_untrusted_status(verify_status) {
        Ok(invalid_verdict)
    } else {
        Err(inconclusive_wintrust_error(path, verify_status))
    };

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let close_status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    let combined = combine_verdict_and_close(path, outcome, close_status);
    if close_status == 0 {
        trust_data.hWVTStateData = null_mut();
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    }
    combined
}

struct CatalogResources {
    admin: isize,
    current: isize,
}

impl CatalogResources {
    fn acquire(path: &Path) -> Result<Self> {
        let mut admin = 0_isize;
        let acquired = unsafe {
            CryptCATAdminAcquireContext2(
                &mut admin,
                std::ptr::null(),
                BCRYPT_SHA256_ALGORITHM,
                std::ptr::null(),
                0,
            )
        };
        anyhow::ensure!(
            acquired != 0 && admin != 0,
            "unable to acquire SHA-256 Authenticode catalog context for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        Ok(Self { admin, current: 0 })
    }

    fn next_catalog(&mut self, path: &Path, hash: &[u8]) -> Result<Option<isize>> {
        let mut previous = self.current;
        unsafe { SetLastError(ERROR_SUCCESS) };
        let next = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                self.admin,
                hash.as_ptr(),
                hash.len() as u32,
                0,
                if previous == 0 {
                    null_mut()
                } else {
                    &mut previous
                },
            )
        };
        self.current = next;
        if next != 0 {
            return Ok(Some(next));
        }
        let status = unsafe { GetLastError() };
        anyhow::ensure!(
            status == ERROR_SUCCESS || status == ERROR_NOT_FOUND,
            "Authenticode catalog enumeration failed for {}: status {}",
            path.display(),
            status
        );
        Ok(None)
    }

    fn cleanup(&mut self, path: &Path) -> Result<()> {
        let mut failures = Vec::new();
        if self.current != 0 {
            let current = std::mem::replace(&mut self.current, 0);
            unsafe { SetLastError(ERROR_SUCCESS) };
            if unsafe { CryptCATAdminReleaseCatalogContext(self.admin, current, 0) } == 0 {
                failures.push(format!(
                    "catalog context cleanup failed with status {}",
                    unsafe { GetLastError() }
                ));
            }
        }
        if self.admin != 0 {
            let admin = std::mem::replace(&mut self.admin, 0);
            unsafe { SetLastError(ERROR_SUCCESS) };
            if unsafe { CryptCATAdminReleaseContext(admin, 0) } == 0 {
                failures.push(format!(
                    "catalog administrator cleanup failed with status {}",
                    unsafe { GetLastError() }
                ));
            }
        }
        anyhow::ensure!(
            failures.is_empty(),
            "Authenticode catalog cleanup failed for {}: {}",
            path.display(),
            failures.join("; ")
        );
        Ok(())
    }
}

fn verify_catalog_signatures(
    path: &Path,
    path_wide: &[u16],
    file: &mut File,
    expected_sha256: &str,
) -> Result<bool> {
    let mut resources = CatalogResources::acquire(path)?;
    let outcome =
        verify_catalog_signatures_inner(path, path_wide, file, expected_sha256, &mut resources);
    let cleanup = resources.cleanup(path);
    combine_catalog_outcome_and_cleanup(path, outcome, cleanup)
}

fn verify_catalog_signatures_inner(
    path: &Path,
    path_wide: &[u16],
    file: &mut File,
    expected_sha256: &str,
    resources: &mut CatalogResources,
) -> Result<bool> {
    let hash = calculate_catalog_hash(path, file, resources.admin)?;
    let member_tag = catalog_member_tag(&hash);

    for _ in 0..MAX_CATALOG_CANDIDATES {
        let Some(catalog_handle) = resources.next_catalog(path, &hash)? else {
            return Ok(false);
        };
        let catalog_path_wide = catalog_path_from_context(path, catalog_handle)?;
        if verify_catalog_candidate(
            path,
            path_wide,
            file,
            expected_sha256,
            resources.admin,
            &catalog_path_wide,
            &member_tag,
            &hash,
        )? {
            return Ok(true);
        }
    }
    anyhow::bail!(
        "Authenticode catalog lookup exceeded the {} candidate limit for {}",
        MAX_CATALOG_CANDIDATES,
        path.display()
    )
}

fn calculate_catalog_hash(path: &Path, file: &mut File, admin: isize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0)).with_context(|| {
        format!(
            "unable to rewind Authenticode candidate for catalog hashing {}",
            path.display()
        )
    })?;
    let handle = file.as_raw_handle() as HANDLE;
    let mut hash_bytes = 0_u32;
    let sized = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut hash_bytes, null_mut(), 0)
    };
    anyhow::ensure!(
        sized != 0,
        "unable to size SHA-256 Authenticode catalog hash for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    anyhow::ensure!(
        hash_bytes as usize == SHA256_CATALOG_HASH_BYTES,
        "unexpected SHA-256 Authenticode catalog hash size {} for {}",
        hash_bytes,
        path.display()
    );
    let mut hash = vec![0_u8; hash_bytes as usize];
    let calculated = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut hash_bytes, hash.as_mut_ptr(), 0)
    };
    anyhow::ensure!(
        calculated != 0,
        "unable to calculate SHA-256 Authenticode catalog hash for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    anyhow::ensure!(
        hash_bytes as usize == hash.len(),
        "SHA-256 Authenticode catalog hash size changed while reading {}",
        path.display()
    );
    Ok(hash)
}

fn catalog_member_tag(hash: &[u8]) -> Vec<u16> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut tag = Vec::with_capacity(hash.len() * 2 + 1);
    for byte in hash {
        tag.push(HEX[(byte >> 4) as usize] as u16);
        tag.push(HEX[(byte & 0x0F) as usize] as u16);
    }
    tag.push(0);
    tag
}

fn catalog_path_from_context(path: &Path, catalog_handle: isize) -> Result<Vec<u16>> {
    let mut info = CATALOG_INFO {
        cbStruct: size_of::<CATALOG_INFO>() as u32,
        ..Default::default()
    };
    let read = unsafe { CryptCATCatalogInfoFromContext(catalog_handle, &mut info, 0) };
    anyhow::ensure!(
        read != 0,
        "unable to read Authenticode catalog path for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    validate_catalog_path_buffer(path, &info.wszCatalogFile)
}

fn validate_catalog_path_buffer(member_path: &Path, buffer: &[u16]) -> Result<Vec<u16>> {
    let terminator = buffer.iter().position(|unit| *unit == 0).with_context(|| {
        format!(
            "Authenticode catalog path is not NUL terminated for {}",
            member_path.display()
        )
    })?;
    anyhow::ensure!(
        terminator > 0,
        "Authenticode catalog path is empty for {}",
        member_path.display()
    );
    anyhow::ensure!(
        buffer[terminator..].iter().all(|unit| *unit == 0),
        "Authenticode catalog path contains data after its terminator for {}",
        member_path.display()
    );
    let catalog_path = PathBuf::from(OsString::from_wide(&buffer[..terminator]));
    let local_drive = matches!(
        catalog_path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    );
    anyhow::ensure!(
        catalog_path.is_absolute() && local_drive,
        "Authenticode catalog path is not an absolute local-drive path for {}: {}",
        member_path.display(),
        catalog_path.display()
    );
    let mut validated = buffer[..=terminator].to_vec();
    anyhow::ensure!(
        validated.len() <= MAX_AUTHENTICODE_PATH_UTF16_UNITS,
        "Authenticode catalog path exceeds {} UTF-16 units for {}",
        MAX_AUTHENTICODE_PATH_UTF16_UNITS - 1,
        member_path.display()
    );
    validated.shrink_to_fit();
    Ok(validated)
}

#[allow(clippy::too_many_arguments)]
fn verify_catalog_candidate(
    path: &Path,
    path_wide: &[u16],
    file: &mut File,
    expected_sha256: &str,
    admin: isize,
    catalog_path_wide: &[u16],
    member_tag: &[u16],
    hash: &[u8],
) -> Result<bool> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut catalog_info = WINTRUST_CATALOG_INFO {
        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
        dwCatalogVersion: 0,
        pcwszCatalogFilePath: catalog_path_wide.as_ptr(),
        pcwszMemberTag: member_tag.as_ptr(),
        pcwszMemberFilePath: path_wide.as_ptr(),
        hMemberFile: handle,
        pbCalculatedFileHash: hash.as_ptr().cast_mut(),
        cbCalculatedFileHash: hash.len() as u32,
        pcCatalogContext: null_mut(),
        hCatAdmin: admin,
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 {
            pCatalog: &mut catalog_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: null_mut(),
        pwszURLReference: null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            | WTD_DISABLE_MD2_MD4,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: null_mut(),
    };
    verify_wintrust_data(path, &mut trust_data, file, expected_sha256)
}

fn combine_catalog_outcome_and_cleanup(
    path: &Path,
    outcome: Result<bool>,
    cleanup: Result<()>,
) -> Result<bool> {
    match (outcome, cleanup) {
        (Ok(verdict), Ok(())) => Ok(verdict),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup_error)) => anyhow::bail!(
            "{error:#}; Authenticode catalog cleanup also failed for {}: {cleanup_error:#}",
            path.display()
        ),
    }
}

fn bind_verified_signature_to_expected_hash(
    path: &Path,
    file: &mut File,
    expected_sha256: &str,
) -> Result<bool> {
    let before = snapshot_authenticode_file(path, file)?;
    enforce_content_binding_size(path, file)?;
    file.seek(SeekFrom::Start(0)).with_context(|| {
        format!(
            "unable to rewind Microsoft-signed file for content binding {}",
            path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; AUTHENTICODE_HASH_BUFFER_BYTES];
    let mut total_bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer).with_context(|| {
            format!(
                "unable to read Microsoft-signed file for content binding {}",
                path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(read as u64)
            .context("Microsoft-signed file content-binding byte count overflowed")?;
        anyhow::ensure!(
            total_bytes <= MAX_AUTHENTICODE_BIND_BYTES,
            "Microsoft-signed file grew beyond the {} byte content-binding limit while reading: {}",
            MAX_AUTHENTICODE_BIND_BYTES,
            path.display()
        );
        hasher.update(&buffer[..read]);
    }
    let after = snapshot_authenticode_file(path, file)?;
    ensure_authenticode_file_unchanged(path, &before, &after)?;
    let actual_sha256 = format!("{:x}", hasher.finalize());
    anyhow::ensure!(
        actual_sha256.eq_ignore_ascii_case(expected_sha256),
        "Microsoft Authenticode verdict content SHA-256 does not match the bytes already scanned for {}",
        path.display()
    );
    Ok(true)
}

fn inconclusive_wintrust_error(path: &Path, status: i32) -> anyhow::Error {
    anyhow::anyhow!(
        "WinVerifyTrust could not establish a definitive verdict for {}: status 0x{:08X}",
        path.display(),
        status as u32
    )
}

fn definitively_untrusted_status(status: i32) -> bool {
    let code = status as u32;
    let certificate_policy_failure = (0x800B0100..=0x800B0114).contains(&code)
        && status != CERT_E_REVOCATION_FAILURE
        && status != TRUST_E_FAIL;
    certificate_policy_failure
        || matches!(
            status,
            TRUST_E_SUBJECT_FORM_UNKNOWN
                | TRUST_E_SUBJECT_NOT_TRUSTED
                | TRUST_E_BAD_DIGEST
                | TRUST_E_CERT_SIGNATURE
                | TRUST_E_COUNTER_SIGNER
                | TRUST_E_MALFORMED_SIGNATURE
                | TRUST_E_NO_SIGNER_CERT
                | TRUST_E_TIME_STAMP
                | TRUST_E_BASIC_CONSTRAINTS
                | TRUST_E_FINANCIAL_CRITERIA
                | CRYPT_E_BAD_ENCODE
                | CRYPT_E_BAD_MSG
                | CRYPT_E_NO_MATCH
                | CRYPT_E_NO_SIGNER
                | CRYPT_E_NO_TRUSTED_SIGNER
                | CRYPT_E_REVOKED
                | CRYPT_E_SIGNER_NOT_FOUND
        )
}

fn combine_verdict_and_close<T>(path: &Path, outcome: Result<T>, close_status: i32) -> Result<T> {
    if close_status == 0 {
        return outcome;
    }
    match outcome {
        Ok(_) => anyhow::bail!(
            "WinVerifyTrust state cleanup failed for {}: status 0x{:08X}",
            path.display(),
            close_status as u32
        ),
        Err(error) => anyhow::bail!(
            "{error:#}; WinVerifyTrust state cleanup also failed for {}: status 0x{:08X}",
            path.display(),
            close_status as u32
        ),
    }
}

fn verified_signer_is_microsoft(trust_data: &WINTRUST_DATA) -> Result<bool> {
    anyhow::ensure!(
        !trust_data.hWVTStateData.is_null(),
        "successful WinVerifyTrust result is missing state data"
    );
    let provider = unsafe { WTHelperProvDataFromStateData(trust_data.hWVTStateData) };
    anyhow::ensure!(
        !provider.is_null(),
        "unable to obtain WinVerifyTrust provider state"
    );
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    anyhow::ensure!(
        !signer.is_null(),
        "verified Authenticode state is missing its selected signer"
    );
    let signer_ref = unsafe { &*signer };
    anyhow::ensure!(
        signer_ref.csCertChain > 0 && !signer_ref.pasCertChain.is_null(),
        "verified Authenticode signer has no certificate chain"
    );
    let provider_cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    anyhow::ensure!(
        !provider_cert.is_null(),
        "verified Authenticode signer is missing its leaf certificate"
    );
    let certificate = unsafe { (*provider_cert).pCert };
    anyhow::ensure!(
        !certificate.is_null(),
        "verified Authenticode signer leaf certificate is null"
    );
    signer_certificate_is_microsoft(certificate)
}

fn signer_certificate_is_microsoft(certificate: *const CERT_CONTEXT) -> Result<bool> {
    let organization =
        certificate_subject_attribute(certificate, szOID_ORGANIZATION_NAME, "organization")?;
    let common_name = certificate_subject_attribute(certificate, szOID_COMMON_NAME, "common name")?;
    Ok(subject_attributes_are_microsoft(
        organization.as_deref(),
        common_name.as_deref(),
    ))
}

fn certificate_subject_attribute(
    certificate: *const CERT_CONTEXT,
    oid: PCSTR,
    label: &str,
) -> Result<Option<String>> {
    let required = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_ATTR_TYPE,
            0,
            oid.cast::<c_void>(),
            null_mut(),
            0,
        )
    } as usize;
    anyhow::ensure!(
        required > 0,
        "unable to size Authenticode signer {label}: {}",
        std::io::Error::last_os_error()
    );
    if required == 1 {
        return Ok(None);
    }
    anyhow::ensure!(
        required <= MAX_SIGNER_ATTRIBUTE_UTF16_UNITS + 1,
        "Authenticode signer {label} exceeds {} UTF-16 units",
        MAX_SIGNER_ATTRIBUTE_UTF16_UNITS
    );

    let mut buffer = vec![u16::MAX; required];
    let written = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_ATTR_TYPE,
            0,
            oid.cast::<c_void>(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    anyhow::ensure!(
        written > 1 && written <= buffer.len(),
        "unable to read Authenticode signer {label}: wrote {written} UTF-16 units"
    );
    anyhow::ensure!(
        buffer[written - 1] == 0,
        "Authenticode signer {label} is not NUL terminated"
    );
    anyhow::ensure!(
        !buffer[..written - 1].contains(&0),
        "Authenticode signer {label} contains embedded NUL"
    );
    String::from_utf16(&buffer[..written - 1])
        .with_context(|| format!("Authenticode signer {label} is invalid UTF-16"))
        .map(Some)
}

fn subject_attributes_are_microsoft(organization: Option<&str>, common_name: Option<&str>) -> bool {
    let organization_matches = organization
        .map(canonical_subject_attribute)
        .is_some_and(|value| value == "microsoft corporation");
    let common_name_matches = common_name
        .map(canonical_subject_attribute)
        .is_some_and(|value| {
            matches!(
                value.as_str(),
                "microsoft corporation" | "microsoft windows" | "microsoft windows publisher"
            )
        });
    organization_matches && common_name_matches
}

fn canonical_subject_attribute(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::windows::process::ExitStatusExt;
    use windows_sys::Win32::Foundation::{
        CRYPT_E_FILE_ERROR, CRYPT_E_NO_REVOCATION_CHECK, CRYPT_E_REVOCATION_OFFLINE,
        CRYPT_E_SECURITY_SETTINGS, TRUST_E_ACTION_UNKNOWN, TRUST_E_FAIL, TRUST_E_NOSIGNATURE,
        TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SYSTEM_ERROR,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_WRITE};

    fn fixture_sha256(path: &Path) -> String {
        let bytes = fs::read(path).unwrap();
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn signer_subject_policy_requires_exact_microsoft_attributes() {
        assert!(subject_attributes_are_microsoft(
            Some(" Microsoft   Corporation "),
            Some("Microsoft Windows")
        ));
        assert!(!subject_attributes_are_microsoft(
            Some("Contoso"),
            Some("Microsoft Windows Publisher")
        ));
        assert!(!subject_attributes_are_microsoft(
            Some("Microsoft Corporation"),
            Some("Microsoft Corporation Tools")
        ));
        assert!(!subject_attributes_are_microsoft(
            Some("Not Microsoft Corporation"),
            Some("Microsoft Corporation Tools")
        ));
        assert!(!subject_attributes_are_microsoft(None, None));
    }

    #[test]
    fn wintrust_status_policy_separates_invalid_from_inconclusive() {
        assert!(definitively_untrusted_status(TRUST_E_NOSIGNATURE));
        assert!(definitively_untrusted_status(TRUST_E_BAD_DIGEST));
        assert!(!definitively_untrusted_status(CERT_E_REVOCATION_FAILURE));
        assert!(!definitively_untrusted_status(CRYPT_E_REVOCATION_OFFLINE));
        assert!(!definitively_untrusted_status(CRYPT_E_NO_REVOCATION_CHECK));
        assert!(!definitively_untrusted_status(CRYPT_E_FILE_ERROR));
        assert!(!definitively_untrusted_status(CRYPT_E_SECURITY_SETTINGS));
        assert!(!definitively_untrusted_status(TRUST_E_PROVIDER_UNKNOWN));
        assert!(!definitively_untrusted_status(TRUST_E_ACTION_UNKNOWN));
        assert!(!definitively_untrusted_status(TRUST_E_SYSTEM_ERROR));
        assert!(!definitively_untrusted_status(TRUST_E_FAIL));
        assert!(!definitively_untrusted_status(0x8123_4567_u32 as i32));
    }

    fn helper_request(path: &Path, expected_sha256: String) -> AuthenticodeHelperRequest {
        AuthenticodeHelperRequest {
            schema_version: AUTHENTICODE_HELPER_SCHEMA_VERSION,
            nonce: Uuid::new_v4().hyphenated().to_string(),
            path_utf16: path.as_os_str().encode_wide().collect(),
            expected_sha256,
        }
    }

    #[test]
    fn native_authenticode_helper_protocol_is_strict_bounded_and_nonce_bound() {
        let request = helper_request(
            Path::new(r"C:\Windows\System32\fixture.exe"),
            "a".repeat(64),
        );
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded = read_authenticode_helper_request(encoded.as_slice()).unwrap();
        assert_eq!(
            validate_authenticode_helper_request(&decoded).unwrap(),
            request.nonce
        );

        let unknown = format!(
            r#"{{"schema_version":1,"nonce":"{}","path_utf16":[67,58,92,102],"expected_sha256":null,"unknown":true}}"#,
            request.nonce
        );
        assert!(read_authenticode_helper_request(unknown.as_bytes()).is_err());
        let null_hash = format!(
            r#"{{"schema_version":1,"nonce":"{}","path_utf16":[67,58,92,102],"expected_sha256":null}}"#,
            request.nonce
        );
        assert!(read_authenticode_helper_request(null_hash.as_bytes()).is_err());
        assert!(read_authenticode_helper_request(&[][..]).is_err());
        assert!(read_authenticode_helper_request(
            vec![b' '; MAX_AUTHENTICODE_HELPER_REQUEST_BYTES + 1].as_slice()
        )
        .is_err());

        let mut invalid = request;
        invalid.schema_version += 1;
        assert!(validate_authenticode_helper_request(&invalid).is_err());
        invalid.schema_version = AUTHENTICODE_HELPER_SCHEMA_VERSION;
        invalid.nonce = Uuid::nil().hyphenated().to_string();
        assert!(validate_authenticode_helper_request(&invalid).is_err());
        invalid.nonce = Uuid::new_v4().hyphenated().to_string();
        invalid.path_utf16 = vec![b'C' as u16, 0, b'X' as u16];
        assert!(validate_authenticode_helper_request(&invalid).is_err());
        invalid.path_utf16 = vec![b'C' as u16];
        invalid.expected_sha256 = "not-a-digest".to_string();
        assert!(validate_authenticode_helper_request(&invalid).is_err());

        let missing_hash = format!(
            r#"{{"schema_version":1,"nonce":"{}","path_utf16":[67,58,92,102]}}"#,
            invalid.nonce
        );
        assert!(read_authenticode_helper_request(missing_hash.as_bytes()).is_err());
    }

    #[test]
    fn native_authenticode_file_identity_requires_a_mandatory_hash() {
        let nonce = Uuid::new_v4().hyphenated().to_string();
        let missing_hash =
            format!(r#"{{"schema_version":1,"nonce":"{nonce}","path_utf16":[67,58,92,102]}}"#);
        let null_hash = format!(
            r#"{{"schema_version":1,"nonce":"{nonce}","path_utf16":[67,58,92,102],"expected_sha256":null}}"#
        );
        assert!(read_authenticode_helper_request(missing_hash.as_bytes()).is_err());
        assert!(read_authenticode_helper_request(null_hash.as_bytes()).is_err());
        assert!(validate_expected_sha256(&"a".repeat(64)).is_ok());
        assert!(validate_expected_sha256(&"A".repeat(64)).is_ok());
        assert!(validate_expected_sha256(&"a".repeat(63)).is_err());
        assert!(validate_expected_sha256(&"g".repeat(64)).is_err());
    }

    #[test]
    fn native_authenticode_helper_response_cannot_fake_or_cross_nonce_verdicts() {
        let path = Path::new(r"C:\benign-fixture.exe");
        let nonce = Uuid::new_v4().hyphenated().to_string();
        let success = AuthenticodeHelperResponse {
            schema_version: AUTHENTICODE_HELPER_SCHEMA_VERSION,
            nonce: nonce.clone(),
            status: "ok".to_string(),
            trusted: Some(true),
            error: None,
        };
        let output = |response: &AuthenticodeHelperResponse| AuthenticodeHelperOutput {
            status: ExitStatus::from_raw(0),
            stdout: serde_json::to_vec(response).unwrap(),
            stderr: Vec::new(),
        };
        assert!(interpret_authenticode_helper_output(path, &nonce, output(&success)).unwrap());
        assert!(
            interpret_authenticode_helper_output(path, "wrong-nonce", output(&success)).is_err()
        );

        let hidden_diagnostic = AuthenticodeHelperOutput {
            status: ExitStatus::from_raw(0),
            stdout: serde_json::to_vec(&success).unwrap(),
            stderr: b"hidden failure".to_vec(),
        };
        assert!(interpret_authenticode_helper_output(path, &nonce, hidden_diagnostic).is_err());

        let fake_success = AuthenticodeHelperResponse {
            error: Some("contradictory".to_string()),
            ..success
        };
        assert!(interpret_authenticode_helper_output(path, &nonce, output(&fake_success)).is_err());

        let failed_with_verdict = AuthenticodeHelperResponse {
            schema_version: AUTHENTICODE_HELPER_SCHEMA_VERSION,
            nonce: nonce.clone(),
            status: "error".to_string(),
            trusted: Some(false),
            error: Some("verification failed".to_string()),
        };
        assert!(
            interpret_authenticode_helper_output(path, &nonce, output(&failed_with_verdict))
                .is_err()
        );

        let oversized = AuthenticodeHelperOutput {
            status: ExitStatus::from_raw(0),
            stdout: vec![b'X'; MAX_AUTHENTICODE_HELPER_RESPONSE_BYTES + 1],
            stderr: Vec::new(),
        };
        assert!(interpret_authenticode_helper_output(path, &nonce, oversized).is_err());
    }

    #[test]
    fn native_authenticode_helper_timeout_kills_and_reaps_the_isolated_process() {
        const CASE_ENV: &str = "AVORAX_TEST_AUTHENTICODE_HELPER_TIMEOUT";
        if std::env::var_os(CASE_ENV).is_some() {
            thread::sleep(Duration::from_secs(30));
            return;
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("windows_authenticode::tests::native_authenticode_helper_timeout_kills_and_reaps_the_isolated_process")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(CASE_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW);
        let started = Instant::now();
        let error = run_bounded_authenticode_helper(
            command,
            br#"{"benign":"fixture"}"#.to_vec(),
            Duration::from_millis(100),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("timed out after 100 ms"));
        assert!(error.contains("termination request: ok"));
        assert!(error.contains("reap: ok"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn native_authenticode_helper_locks_a_bounded_non_reparse_current_executable() {
        let (path, file) = open_current_authenticode_host().unwrap();
        assert_eq!(path, std::env::current_exe().unwrap());
        let metadata = file.metadata().unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT, 0);
        assert!(metadata.len() > 0);
        assert!(metadata.len() <= MAX_AUTHENTICODE_HOST_EXE_BYTES);
    }

    #[test]
    fn native_secondary_authenticode_aggregation_is_bounded_ordered_and_fail_visible() {
        let path = Path::new(r"C:\benign-multisigned-fixture.dll");
        let mut requested = Vec::new();
        let accepted = aggregate_valid_embedded_signatures(
            path,
            EmbeddedSignatureVerdict::OtherPublisher,
            2,
            |index| {
                requested.push(index);
                Ok(if index == 2 {
                    EmbeddedSignatureVerdict::Microsoft
                } else {
                    EmbeddedSignatureVerdict::Invalid
                })
            },
        )
        .unwrap();
        assert!(accepted);
        assert_eq!(requested, [1, 2]);

        let mut primary_callback_used = false;
        assert!(aggregate_valid_embedded_signatures(
            path,
            EmbeddedSignatureVerdict::Microsoft,
            2,
            |_| {
                primary_callback_used = true;
                Ok(EmbeddedSignatureVerdict::Invalid)
            },
        )
        .unwrap());
        assert!(!primary_callback_used);

        let mut invalid_primary_callback_used = false;
        assert!(!aggregate_valid_embedded_signatures(
            path,
            EmbeddedSignatureVerdict::Invalid,
            u32::MAX,
            |_| {
                invalid_primary_callback_used = true;
                Ok(EmbeddedSignatureVerdict::Microsoft)
            },
        )
        .unwrap());
        assert!(!invalid_primary_callback_used);

        assert!(!aggregate_valid_embedded_signatures(
            path,
            EmbeddedSignatureVerdict::OtherPublisher,
            2,
            |_| Ok(EmbeddedSignatureVerdict::Invalid),
        )
        .unwrap());

        let error = aggregate_valid_embedded_signatures(
            path,
            EmbeddedSignatureVerdict::OtherPublisher,
            1,
            |_| anyhow::bail!("secondary verification failed visibly"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("secondary verification failed visibly"));

        let mut over_limit_callback_used = false;
        let error = aggregate_valid_embedded_signatures(
            path,
            EmbeddedSignatureVerdict::OtherPublisher,
            MAX_EMBEDDED_SIGNATURES,
            |_| {
                over_limit_callback_used = true;
                Ok(EmbeddedSignatureVerdict::Microsoft)
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("exceeds the 16 signature limit"));
        assert!(!over_limit_callback_used);
    }

    #[test]
    fn native_secondary_authenticode_index_policy_is_exact_and_primary_provider_aware() {
        assert!(verified_signature_index_is_acceptable(0, 0));
        assert!(verified_signature_index_is_acceptable(0, u32::MAX));
        assert!(!verified_signature_index_is_acceptable(0, 1));
        assert!(verified_signature_index_is_acceptable(1, 1));
        assert!(!verified_signature_index_is_acceptable(1, 0));
        assert!(!verified_signature_index_is_acceptable(2, u32::MAX));
    }

    #[test]
    fn native_secondary_authenticode_microsoft_signed_edge_dll_verifies_exact_index() {
        const MAX_EDGE_VERSION_DIRECTORIES: usize = 64;
        const FIXTURE_NAMES: [&str; 8] = [
            "concrt140.dll",
            "d3dcompiler_47.dll",
            "dual_engine_adapter_x64.dll",
            "dxil.dll",
            "msvcp140_codecvt_ids.dll",
            "msvcp140.dll",
            "prefs_enclave_x64.dll",
            "vccorlib140.dll",
        ];

        let edge_root = PathBuf::from(
            std::env::var_os("ProgramFiles(x86)")
                .expect("x64 Windows ProgramFiles(x86) is required for the Edge fixture"),
        )
        .join("Microsoft")
        .join("Edge")
        .join("Application");
        let root_metadata = fs::symlink_metadata(&edge_root).unwrap();
        assert!(root_metadata.is_dir());
        assert_eq!(
            root_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );

        let version_directories = fs::read_dir(&edge_root)
            .unwrap()
            .take(MAX_EDGE_VERSION_DIRECTORIES + 1)
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert!(
            version_directories.len() <= MAX_EDGE_VERSION_DIRECTORIES,
            "Edge fixture discovery exceeded {MAX_EDGE_VERSION_DIRECTORIES} entries"
        );
        let mut checked_version_directories = Vec::new();
        for entry in version_directories {
            let name = entry.file_name();
            let text = name.to_string_lossy();
            if text.is_empty()
                || !text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
            {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path()).unwrap_or_else(|error| {
                panic!(
                    "unable to inspect benign Edge version directory {}: {error}",
                    entry.path().display()
                )
            });
            if metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                checked_version_directories.push(entry);
            }
        }
        let mut version_directories = checked_version_directories;
        version_directories.sort_by_key(|entry| std::cmp::Reverse(entry.file_name()));

        let mut fixture = None;
        for directory in version_directories {
            for name in FIXTURE_NAMES {
                let candidate = directory.path().join(name);
                match fs::symlink_metadata(&candidate) {
                    Ok(metadata)
                        if metadata.is_file()
                            && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 =>
                    {
                        fixture = Some(candidate);
                        break;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!(
                        "unable to inspect benign Edge fixture {}: {error}",
                        candidate.display()
                    ),
                }
            }
            if fixture.is_some() {
                break;
            }
        }
        let path = fixture.expect("no bounded benign multi-signature Edge DLL fixture was found");
        let sha256 = fixture_sha256(&path);
        let path_wide = absolute_path_wide(&path).unwrap();
        let mut file = open_authenticode_candidate(&path).unwrap();
        let handle = file.as_raw_handle() as HANDLE;
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path_wide.as_ptr(),
            hFile: handle,
            pgKnownSubject: null_mut(),
        };
        let mut signature_settings = WINTRUST_SIGNATURE_SETTINGS {
            cbStruct: size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32,
            dwIndex: 0,
            dwFlags: WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC,
            cSecondarySigs: 0,
            dwVerifiedSigIndex: u32::MAX,
            pCryptoPolicy: null_mut(),
        };
        let mut trust_data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: null_mut(),
            pSIPClientData: null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: null_mut(),
            pwszURLReference: null_mut(),
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
                | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                | WTD_DISABLE_MD2_MD4,
            dwUIContext: WTD_UICONTEXT_EXECUTE,
            pSignatureSettings: &mut signature_settings,
        };

        let primary = verify_specific_embedded_signature(
            &path,
            &mut trust_data,
            &mut signature_settings,
            &mut file,
            &sha256,
        )
        .unwrap();
        assert_eq!(primary, EmbeddedSignatureVerdict::OtherPublisher);
        assert!(verified_signature_index_is_acceptable(
            0,
            signature_settings.dwVerifiedSigIndex
        ));
        let secondary_count = signature_settings.cSecondarySigs;
        assert!(secondary_count > 0);
        assert!(secondary_count < MAX_EMBEDDED_SIGNATURES);
        assert!(trust_data.hWVTStateData.is_null());
        assert_eq!(trust_data.dwStateAction, WTD_STATEACTION_VERIFY);

        let mut microsoft_secondary = None;
        for index in 1..=secondary_count {
            signature_settings.dwIndex = index;
            let secondary = verify_specific_embedded_signature(
                &path,
                &mut trust_data,
                &mut signature_settings,
                &mut file,
                &sha256,
            )
            .unwrap();
            assert_eq!(signature_settings.dwVerifiedSigIndex, index);
            assert_eq!(signature_settings.cSecondarySigs, secondary_count);
            assert!(trust_data.hWVTStateData.is_null());
            assert_eq!(trust_data.dwStateAction, WTD_STATEACTION_VERIFY);
            if secondary == EmbeddedSignatureVerdict::Microsoft {
                microsoft_secondary = Some(index);
            }
        }
        assert!(
            microsoft_secondary.is_some(),
            "benign multi-signed Edge fixture has no exact-Microsoft secondary signature"
        );
    }

    #[test]
    fn opened_candidate_denies_rename_until_handle_is_closed() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("candidate.exe");
        let renamed = dir.path().join("renamed.exe");
        fs::write(&source, b"benign fixture").unwrap();

        let file = open_authenticode_candidate(&source).unwrap();
        assert!(fs::rename(&source, &renamed).is_err());
        drop(file);
        fs::rename(&source, &renamed).unwrap();
    }

    #[test]
    fn native_authenticode_file_identity_denies_a_preexisting_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.exe");
        fs::write(&path, b"benign fixture").unwrap();

        let mut writer_options = OpenOptions::new();
        writer_options
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        let writer = writer_options.open(&path).unwrap();
        assert!(open_authenticode_candidate(&path).is_err());
        drop(writer);
        open_authenticode_candidate(&path).unwrap();
    }

    #[test]
    fn native_authenticode_file_identity_detects_benign_link_count_drift() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.exe");
        let link = dir.path().join("candidate-hardlink.exe");
        fs::write(&path, b"benign fixture").unwrap();

        let file = open_authenticode_candidate(&path).unwrap();
        let before = snapshot_authenticode_file(&path, &file).unwrap();
        let stable = snapshot_authenticode_file(&path, &file).unwrap();
        ensure_authenticode_file_unchanged(&path, &before, &stable).unwrap();
        fs::hard_link(&path, &link).unwrap();
        let after = snapshot_authenticode_file(&path, &file).unwrap();
        let error = ensure_authenticode_file_unchanged(&path, &before, &after)
            .unwrap_err()
            .to_string();
        assert!(error.contains("identity or mutation metadata changed"));
        assert_eq!(after.number_of_links, before.number_of_links + 1);
    }

    #[test]
    fn native_authenticode_file_identity_failure_cannot_return_or_hide_trust() {
        let path = Path::new(r"C:\benign-fixture.exe");
        let stable = AuthenticodeFileSnapshot {
            volume_serial_number: 1,
            file_id: [2; 16],
            file_index: 3,
            creation_time: 4,
            last_write_time: 5,
            change_time: 6,
            file_attributes: 7,
            allocation_size: 8,
            end_of_file: 8,
            number_of_links: 1,
            delete_pending: false,
            directory: false,
        };
        let mut changed = stable.clone();
        changed.change_time += 1;
        let query_error = combine_verdict_and_file_snapshot(
            path,
            Ok(true),
            stable.clone(),
            Err(anyhow::anyhow!("final identity query failed")),
        )
        .unwrap_err()
        .to_string();
        assert!(query_error.contains("final identity query failed"));

        let trust_error =
            combine_verdict_and_file_snapshot(path, Ok(true), stable.clone(), Ok(changed.clone()))
                .unwrap_err()
                .to_string();
        assert!(trust_error.contains("identity or mutation metadata changed"));

        let combined = combine_verdict_and_file_snapshot(
            path,
            Err(anyhow::anyhow!("verification failed")),
            stable,
            Ok(changed),
        )
        .unwrap_err()
        .to_string();
        assert!(combined.contains("verification failed"));
        assert!(combined.contains("identity verification also failed"));
    }

    #[test]
    fn direct_authenticode_path_requires_absolute_bounded_non_nul_text() {
        assert!(absolute_path_wide(Path::new("relative.exe")).is_err());
        assert!(absolute_path_wide(Path::new("C:\\fixture\0.exe")).is_err());
        let oversized = format!("C:\\\\{}", "a".repeat(MAX_AUTHENTICODE_PATH_UTF16_UNITS));
        assert!(absolute_path_wide(Path::new(&oversized)).is_err());
    }

    #[test]
    fn expected_content_hash_requires_exact_sha256_text() {
        assert!(validate_expected_sha256(&"a".repeat(64)).is_ok());
        assert!(validate_expected_sha256(&"A".repeat(64)).is_ok());
        assert!(validate_expected_sha256(&"a".repeat(63)).is_err());
        assert!(validate_expected_sha256(&"g".repeat(64)).is_err());
    }

    #[test]
    fn catalog_member_tag_is_uppercase_hex_with_one_terminator() {
        assert_eq!(
            catalog_member_tag(&[0x00, 0xAF, 0x19]),
            [48, 48, 65, 70, 49, 57, 0]
        );
    }

    #[test]
    fn catalog_path_buffer_requires_one_bounded_local_absolute_path() {
        let member = Path::new(r"C:\Windows\System32\fixture.exe");
        let mut local = [0_u16; 260];
        let local_text: Vec<u16> = OsString::from(r"C:\Windows\System32\CatRoot\fixture.cat")
            .encode_wide()
            .collect();
        local[..local_text.len()].copy_from_slice(&local_text);
        let validated = validate_catalog_path_buffer(member, &local).unwrap();
        assert_eq!(validated.last(), Some(&0));

        let mut relative = [0_u16; 260];
        let relative_text: Vec<u16> = OsString::from(r"CatRoot\fixture.cat")
            .encode_wide()
            .collect();
        relative[..relative_text.len()].copy_from_slice(&relative_text);
        assert!(validate_catalog_path_buffer(member, &relative).is_err());

        let mut unc = [0_u16; 260];
        let unc_text: Vec<u16> = OsString::from(r"\\server\share\fixture.cat")
            .encode_wide()
            .collect();
        unc[..unc_text.len()].copy_from_slice(&unc_text);
        assert!(validate_catalog_path_buffer(member, &unc).is_err());

        let unterminated = [65_u16; 260];
        assert!(validate_catalog_path_buffer(member, &unterminated).is_err());

        let mut trailing_data = local;
        trailing_data[local_text.len() + 1] = 65;
        assert!(validate_catalog_path_buffer(member, &trailing_data).is_err());
    }

    #[test]
    fn native_catalog_authenticode_windows_powershell_requires_catalog_fallback() {
        let path = crate::windows_system::checked_system32_file(
            &["WindowsPowerShell", "v1.0", "powershell.exe"],
            "catalog-signed WindowsPowerShell fixture",
        )
        .unwrap();
        let path_wide = absolute_path_wide(&path).unwrap();
        let mut file = open_authenticode_candidate(&path).unwrap();
        let sha256 = fixture_sha256(&path);

        assert!(!verify_open_file(&path, &path_wide, &mut file, &sha256).unwrap());
        assert!(verify_catalog_signatures(&path, &path_wide, &mut file, &sha256).unwrap());
    }

    #[test]
    fn content_binding_rejects_oversized_file_before_wintrust() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized-benign-fixture.exe");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_AUTHENTICODE_BIND_BYTES + 1).unwrap();

        let error = enforce_content_binding_size(&path, &file)
            .unwrap_err()
            .to_string();
        assert!(error.contains("content-binding limit"));
    }

    #[test]
    fn wintrust_cleanup_failure_cannot_return_a_verdict() {
        let path = Path::new(r"C:\benign-fixture.exe");
        let success_error = combine_verdict_and_close(path, Ok(true), TRUST_E_FAIL)
            .unwrap_err()
            .to_string();
        assert!(success_error.contains("state cleanup failed"));

        let combined_error = combine_verdict_and_close(
            path,
            Err::<bool, _>(anyhow::anyhow!("verification failed")),
            TRUST_E_FAIL,
        )
        .unwrap_err()
        .to_string();
        assert!(combined_error.contains("verification failed"));
        assert!(combined_error.contains("cleanup also failed"));
    }

    #[test]
    fn catalog_cleanup_failure_cannot_return_a_verdict_or_hide_verification_error() {
        let path = Path::new(r"C:\benign-fixture.exe");
        let cleanup = || anyhow::anyhow!("catalog administrator cleanup failed");
        let success_error = combine_catalog_outcome_and_cleanup(path, Ok(true), Err(cleanup()))
            .unwrap_err()
            .to_string();
        assert!(success_error.contains("catalog administrator cleanup failed"));

        let combined_error = combine_catalog_outcome_and_cleanup(
            path,
            Err(anyhow::anyhow!("catalog verification failed")),
            Err(cleanup()),
        )
        .unwrap_err()
        .to_string();
        assert!(combined_error.contains("catalog verification failed"));
        assert!(combined_error.contains("cleanup also failed"));
    }
}
