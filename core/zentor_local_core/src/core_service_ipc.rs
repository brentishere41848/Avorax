//! Minimal authenticated Windows service boundary.
//!
//! The broad stdio command handler is intentionally not reachable here. Protocol
//! v1 exposes only read-only health until per-user mutation authorization exists.

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_MORE_DATA,
    ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
    ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, ImpersonateNamedPipeClient, SetNamedPipeHandleState,
    WaitNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE,
};
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentThread, OpenThreadToken};
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
};

pub const CORE_SERVICE_PIPE_NAME: &str = r"\\.\pipe\AvoraxCoreService.v1";
const CORE_SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";
const PROTOCOL_VERSION: u32 = 1;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_REQUEST_ID_CHARS: usize = 128;
const MAX_HEALTH_LIMITATIONS: usize = 16;
const MAX_HEALTH_LIMITATION_CHARS: usize = 256;
const MAX_REPORTED_DEFINITION_COUNT: usize = 10_000_000;
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(5);
const PIPE_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceHealth {
    service_ready: bool,
    engine_ready: bool,
    native_signature_count: usize,
    native_rule_count: usize,
    native_ml_production_ready: bool,
    transport: String,
    network_exposed: bool,
    command_scope: String,
    limitations: Vec<String>,
}

impl ServiceHealth {
    pub fn ready(
        engine_ready: bool,
        native_signature_count: usize,
        native_rule_count: usize,
        native_ml_production_ready: bool,
    ) -> Self {
        Self {
            service_ready: true,
            engine_ready,
            native_signature_count,
            native_rule_count,
            native_ml_production_ready,
            transport: "windowsNamedPipe".to_string(),
            network_exposed: false,
            command_scope: "healthOnly".to_string(),
            limitations: vec![
                "mutating commands are denied".to_string(),
                "UI command mediation is not implemented".to_string(),
                "user-mode service IPC does not provide pre-execution blocking".to_string(),
            ],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceRequest {
    protocol_version: u32,
    request_id: String,
    command: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceResponse {
    protocol_version: u32,
    request_id: Option<String>,
    ok: bool,
    authenticated: bool,
    client_pid: u32,
    command_scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<ServiceHealth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ServiceError>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceError {
    code: String,
    message: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceHealthProbe {
    ok: bool,
    protocol_version: u32,
    transport: String,
    network_exposed: bool,
    command_scope: String,
    client_authenticated: bool,
    server_authenticated: bool,
    server_pid: u32,
    service_pid: u32,
    service_ready: bool,
    engine_ready: bool,
    native_signature_count: usize,
    native_rule_count: usize,
    native_ml_production_ready: bool,
    limitations: Vec<String>,
}

pub struct CoreServiceIpcServer {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl CoreServiceIpcServer {
    pub fn start(health: ServiceHealth) -> Result<Self> {
        Self::start_with_pipe_name_and_timeout(health, CORE_SERVICE_PIPE_NAME, CLIENT_READ_TIMEOUT)
    }

    #[cfg(test)]
    fn start_with_pipe_name(health: ServiceHealth, pipe_name: &str) -> Result<Self> {
        Self::start_with_pipe_name_and_timeout(health, pipe_name, CLIENT_READ_TIMEOUT)
    }

    fn start_with_pipe_name_and_timeout(
        health: ServiceHealth,
        pipe_name: &str,
        client_read_timeout: Duration,
    ) -> Result<Self> {
        if client_read_timeout.is_zero() || client_read_timeout > CLIENT_READ_TIMEOUT {
            anyhow::bail!("Core Service IPC client timeout is outside its safe bounds");
        }
        let pipe = create_service_pipe(pipe_name)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("avorax-core-service-ipc".to_string())
            .spawn(move || run_server(pipe, health, worker_stop, client_read_timeout))
            .context("failed to spawn Core Service IPC worker")?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }

    pub fn ensure_running(&self) -> Result<()> {
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            anyhow::bail!("Core Service IPC worker exited")
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        let Some(worker) = self.worker.take() else {
            anyhow::bail!("Core Service IPC was already stopped");
        };
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("Core Service IPC worker panicked"))?
    }
}

pub fn probe_service_health() -> Result<ServiceHealthProbe> {
    probe_service_health_with(CORE_SERVICE_PIPE_NAME, CLIENT_READ_TIMEOUT, || {
        crate::windows_tools::query_running_windows_service_process_id("avorax_core_service")
    })
}

fn probe_service_health_with<F>(
    pipe_name: &str,
    timeout: Duration,
    mut running_service_pid: F,
) -> Result<ServiceHealthProbe>
where
    F: FnMut() -> Result<u32>,
{
    if timeout.is_zero() || timeout > CLIENT_READ_TIMEOUT {
        anyhow::bail!("Core Service IPC probe timeout is outside its safe bounds");
    }
    let service_pid_before = running_service_pid()
        .context("failed to authenticate the Core Service through Windows SCM")?;
    anyhow::ensure!(
        service_pid_before != 0,
        "Windows SCM returned an invalid zero Core Service process ID"
    );

    let pipe = open_client_pipe(pipe_name, timeout)?;
    let server_pid = named_pipe_server_process_id(pipe.get())?;
    anyhow::ensure!(
        server_pid == service_pid_before,
        "Core Service pipe server PID {server_pid} does not match SCM service PID {service_pid_before}"
    );
    configure_client_pipe_message_mode(pipe.get())?;

    let request_id = format!("health-{}", uuid::Uuid::new_v4());
    let request = ServiceRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: request_id.clone(),
        command: "health".to_string(),
    };
    let request_bytes =
        serde_json::to_vec(&request).context("failed to serialize Core Service health request")?;
    anyhow::ensure!(
        request_bytes.len() <= MAX_REQUEST_BYTES,
        "Core Service health request exceeded its configured bound"
    );
    write_client_request(pipe.get(), &request_bytes, timeout)?;
    let response_bytes = read_client_response(pipe.get(), timeout)?;

    let service_pid_after = running_service_pid()
        .context("failed to re-authenticate the Core Service through Windows SCM")?;
    anyhow::ensure!(
        service_pid_after == service_pid_before,
        "Core Service process changed during the health probe"
    );
    let health = validate_health_response(&response_bytes, &request_id, std::process::id())?;

    Ok(ServiceHealthProbe {
        ok: health.engine_ready,
        protocol_version: PROTOCOL_VERSION,
        transport: health.transport,
        network_exposed: health.network_exposed,
        command_scope: health.command_scope,
        client_authenticated: true,
        server_authenticated: true,
        server_pid,
        service_pid: service_pid_after,
        service_ready: health.service_ready,
        engine_ready: health.engine_ready,
        native_signature_count: health.native_signature_count,
        native_rule_count: health.native_rule_count,
        native_ml_production_ready: health.native_ml_production_ready,
        limitations: health.limitations,
    })
}

fn open_client_pipe(pipe_name: &str, timeout: Duration) -> Result<OwnedHandle> {
    let pipe_name_wide = wide_string(pipe_name);
    let deadline = Instant::now() + timeout;
    loop {
        let handle = unsafe {
            CreateFileW(
                pipe_name_wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(OwnedHandle::new(handle));
        }
        let code = unsafe { GetLastError() };
        if Instant::now() >= deadline {
            return Err(std::io::Error::from_raw_os_error(code as i32))
                .context("timed out opening the local Core Service pipe");
        }
        match code {
            ERROR_PIPE_BUSY => {
                let wait_ms = remaining_timeout_ms(deadline);
                if unsafe { WaitNamedPipeW(pipe_name_wide.as_ptr(), wait_ms) } == 0 {
                    let wait_code = unsafe { GetLastError() };
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::from_raw_os_error(wait_code as i32))
                            .context("timed out waiting for the local Core Service pipe");
                    }
                }
            }
            ERROR_FILE_NOT_FOUND => thread::sleep(PIPE_POLL_INTERVAL),
            _ => {
                return Err(std::io::Error::from_raw_os_error(code as i32))
                    .context("failed to open the local Core Service pipe")
            }
        }
    }
}

fn remaining_timeout_ms(deadline: Instant) -> u32 {
    let remaining = deadline.saturating_duration_since(Instant::now());
    remaining.as_millis().clamp(1, u32::MAX as u128) as u32
}

fn named_pipe_server_process_id(pipe: HANDLE) -> Result<u32> {
    let mut server_pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut server_pid) } == 0 {
        return Err(last_os_error()).context("failed to identify the Core Service pipe server");
    }
    anyhow::ensure!(
        server_pid != 0,
        "Core Service pipe returned an invalid zero server process ID"
    );
    Ok(server_pid)
}

fn configure_client_pipe_message_mode(pipe: HANDLE) -> Result<()> {
    let mode = PIPE_READMODE_MESSAGE;
    if unsafe { SetNamedPipeHandleState(pipe, &mode, null(), null()) } == 0 {
        return Err(last_os_error())
            .context("failed to configure Core Service message-mode pipe client");
    }
    Ok(())
}

fn write_client_request(pipe: HANDLE, bytes: &[u8], timeout: Duration) -> Result<()> {
    let event = create_overlapped_event()?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.get();
    let mut written = 0;
    let ok = unsafe {
        WriteFile(
            pipe,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            &mut overlapped,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_IO_PENDING {
            return Err(std::io::Error::from_raw_os_error(code as i32))
                .context("failed to write Core Service health request");
        }
        written = wait_for_overlapped(pipe, &mut overlapped, timeout, "health request write")?;
    }
    anyhow::ensure!(
        written as usize == bytes.len(),
        "Core Service health request write was incomplete: wrote {written} of {} bytes",
        bytes.len()
    );
    Ok(())
}

fn read_client_response(pipe: HANDLE, timeout: Duration) -> Result<Vec<u8>> {
    let event = create_overlapped_event()?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.get();
    let mut bytes = vec![0u8; MAX_RESPONSE_BYTES];
    let mut read = 0;
    let ok = unsafe {
        ReadFile(
            pipe,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            &mut read,
            &mut overlapped,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        match code {
            ERROR_IO_PENDING => {
                read = wait_for_overlapped(pipe, &mut overlapped, timeout, "health response read")?
            }
            ERROR_MORE_DATA => anyhow::bail!(
                "Core Service health response exceeds maximum size of {MAX_RESPONSE_BYTES} bytes"
            ),
            _ => {
                return Err(std::io::Error::from_raw_os_error(code as i32))
                    .context("failed to read Core Service health response")
            }
        }
    }
    anyhow::ensure!(read != 0, "Core Service returned an empty health response");
    bytes.truncate(read as usize);
    Ok(bytes)
}

fn create_overlapped_event() -> Result<OwnedHandle> {
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(last_os_error()).context("failed to create Core Service I/O event");
    }
    Ok(OwnedHandle::new(event))
}

fn wait_for_overlapped(
    pipe: HANDLE,
    overlapped: &mut OVERLAPPED,
    timeout: Duration,
    description: &str,
) -> Result<u32> {
    let mut transferred = 0;
    if unsafe {
        GetOverlappedResultEx(
            pipe,
            overlapped,
            &mut transferred,
            timeout.as_millis().clamp(1, u32::MAX as u128) as u32,
            0,
        )
    } != 0
    {
        return Ok(transferred);
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_MORE_DATA {
        anyhow::bail!(
            "Core Service health response exceeds maximum size of {MAX_RESPONSE_BYTES} bytes"
        );
    }
    if code == WAIT_TIMEOUT {
        cancel_and_reap_overlapped(pipe, overlapped);
        anyhow::bail!("Core Service {description} timed out");
    }
    cancel_and_reap_overlapped(pipe, overlapped);
    Err(std::io::Error::from_raw_os_error(code as i32))
        .context(format!("Core Service {description} failed"))
}

fn cancel_and_reap_overlapped(pipe: HANDLE, overlapped: &mut OVERLAPPED) {
    unsafe {
        CancelIoEx(pipe, overlapped);
        let mut ignored = 0;
        GetOverlappedResult(pipe, overlapped, &mut ignored, 1);
    }
}

fn validate_health_response(
    response_bytes: &[u8],
    request_id: &str,
    client_pid: u32,
) -> Result<ServiceHealth> {
    anyhow::ensure!(
        !response_bytes.is_empty() && response_bytes.len() <= MAX_RESPONSE_BYTES,
        "Core Service health response is outside its configured size bound"
    );
    let response: ServiceResponse = serde_json::from_slice(response_bytes)
        .context("Core Service health response did not match the strict protocol schema")?;
    anyhow::ensure!(
        response.protocol_version == PROTOCOL_VERSION,
        "Core Service returned an unsupported protocol version"
    );
    anyhow::ensure!(
        response.request_id.as_deref() == Some(request_id),
        "Core Service response request ID did not match"
    );
    anyhow::ensure!(response.ok, "Core Service rejected the health request");
    anyhow::ensure!(
        response.authenticated,
        "Core Service did not authenticate the health client"
    );
    anyhow::ensure!(
        response.client_pid == client_pid,
        "Core Service response client PID did not match"
    );
    anyhow::ensure!(
        response.command_scope == "healthOnly",
        "Core Service returned an unexpected command scope"
    );
    anyhow::ensure!(
        response.error.is_none(),
        "Core Service returned contradictory health data and error fields"
    );
    let health = response
        .data
        .ok_or_else(|| anyhow::anyhow!("Core Service health response omitted health data"))?;
    validate_health(&health)?;
    Ok(health)
}

fn validate_health(health: &ServiceHealth) -> Result<()> {
    anyhow::ensure!(health.service_ready, "Core Service did not report ready");
    anyhow::ensure!(
        health.transport == "windowsNamedPipe",
        "Core Service returned an unexpected health transport"
    );
    anyhow::ensure!(
        !health.network_exposed,
        "Core Service unexpectedly reported a network-exposed transport"
    );
    anyhow::ensure!(
        health.command_scope == "healthOnly",
        "Core Service health data returned an unexpected command scope"
    );
    anyhow::ensure!(
        health.native_signature_count <= MAX_REPORTED_DEFINITION_COUNT
            && health.native_rule_count <= MAX_REPORTED_DEFINITION_COUNT,
        "Core Service health definition counts exceed their safe bounds"
    );
    anyhow::ensure!(
        !health.limitations.is_empty()
            && health.limitations.len() <= MAX_HEALTH_LIMITATIONS
            && health.limitations.iter().all(|limitation| {
                !limitation.is_empty() && limitation.chars().count() <= MAX_HEALTH_LIMITATION_CHARS
            }),
        "Core Service health limitations exceed their safe bounds"
    );
    Ok(())
}

fn run_server(
    pipe: OwnedHandle,
    health: ServiceHealth,
    stop: Arc<AtomicBool>,
    client_read_timeout: Duration,
) -> Result<()> {
    while !stop.load(Ordering::Acquire) {
        match connect_client(pipe.get())? {
            false => thread::sleep(PIPE_POLL_INTERVAL),
            true => {
                let request_result = read_request(pipe.get(), &stop, client_read_timeout);
                let connection_result = match request_result {
                    Ok(request_bytes) => match authenticate_client(pipe.get()) {
                        Ok(client_pid) => serve_authenticated_client(
                            pipe.get(),
                            client_pid,
                            &request_bytes,
                            &health,
                        ),
                        Err(AuthenticationError::Recoverable(error)) => Err(error),
                        Err(AuthenticationError::Fatal(error)) => {
                            let disconnect_result = disconnect_client(pipe.get());
                            return match disconnect_result {
                                Ok(()) => Err(error),
                                Err(disconnect_error) => Err(error).context(format!(
                                    "failed to disconnect Core Service IPC after fatal authentication error: {disconnect_error:#}"
                                )),
                            };
                        }
                    },
                    Err(error) => Err(error),
                };
                let disconnect_result = disconnect_client(pipe.get());
                if let Err(error) = connection_result {
                    eprintln!("Core Service IPC client request failed: {error:#}");
                    if let Err(disconnect_error) = disconnect_result {
                        return Err(error).context(format!(
                            "failed to disconnect Core Service IPC after client error: {disconnect_error:#}"
                        ));
                    }
                } else {
                    disconnect_result?;
                }
            }
        }
    }
    Ok(())
}

fn create_service_pipe(pipe_name: &str) -> Result<OwnedHandle> {
    let pipe_name = wide_string(pipe_name);
    let sddl = wide_string(CORE_SERVICE_PIPE_SDDL);
    let mut descriptor = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(last_os_error())
            .context("failed to build Core Service pipe security descriptor");
    }
    let descriptor = LocalAllocation::new(descriptor);
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.get(),
        bInheritHandle: 0,
    };
    let handle = unsafe {
        CreateNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_RESPONSE_BYTES as u32,
            MAX_REQUEST_BYTES as u32,
            CLIENT_READ_TIMEOUT.as_millis() as u32,
            &security,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_os_error()).context(
            "failed to create exclusive local Core Service pipe (another instance may own the name)",
        );
    }
    Ok(OwnedHandle::new(handle))
}

fn connect_client(pipe: HANDLE) -> Result<bool> {
    if unsafe { ConnectNamedPipe(pipe, null_mut()) } != 0 {
        return Ok(true);
    }
    match unsafe { GetLastError() } {
        ERROR_PIPE_CONNECTED => Ok(true),
        ERROR_PIPE_LISTENING | ERROR_NO_DATA => Ok(false),
        code => Err(std::io::Error::from_raw_os_error(code as i32))
            .context("failed while listening for a Core Service IPC client"),
    }
}

fn serve_authenticated_client(
    pipe: HANDLE,
    client_pid: u32,
    request_bytes: &[u8],
    health: &ServiceHealth,
) -> Result<()> {
    let response = build_response(request_bytes, client_pid, health);
    let response_bytes =
        serde_json::to_vec(&response).context("failed to serialize Core Service IPC response")?;
    if response_bytes.len() > MAX_RESPONSE_BYTES {
        anyhow::bail!("Core Service IPC response exceeded its configured bound");
    }
    write_pipe_message(pipe, &response_bytes, "health response")
}

enum AuthenticationError {
    Recoverable(anyhow::Error),
    Fatal(anyhow::Error),
}

fn authenticate_client(pipe: HANDLE) -> std::result::Result<u32, AuthenticationError> {
    let mut client_pid = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut client_pid) } == 0 {
        return Err(AuthenticationError::Recoverable(
            anyhow::Error::new(last_os_error())
                .context("failed to identify Core Service IPC client process"),
        ));
    }
    if client_pid == 0 {
        return Err(AuthenticationError::Recoverable(anyhow::anyhow!(
            "Core Service IPC returned an invalid zero client process ID"
        )));
    }
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(AuthenticationError::Recoverable(
            anyhow::Error::new(last_os_error())
                .context("failed to impersonate Core Service IPC client"),
        ));
    }
    let mut token = null_mut();
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let open_error = if opened == 0 {
        Some(last_os_error())
    } else {
        None
    };
    let close_error = (!token.is_null() && unsafe { CloseHandle(token) } == 0).then(last_os_error);
    if unsafe { RevertToSelf() } == 0 {
        return Err(AuthenticationError::Fatal(anyhow::anyhow!(
            "failed to revert Core Service IPC client impersonation: {}",
            last_os_error()
        )));
    }
    if let Some(error) = open_error {
        return Err(AuthenticationError::Recoverable(
            anyhow::Error::new(error)
                .context("failed to open authenticated Core Service IPC client token"),
        ));
    }
    if let Some(error) = close_error {
        return Err(AuthenticationError::Recoverable(
            anyhow::Error::new(error)
                .context("failed to close authenticated Core Service IPC client token"),
        ));
    }
    Ok(client_pid)
}

fn read_request(pipe: HANDLE, stop: &AtomicBool, client_read_timeout: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + client_read_timeout;
    let mut bytes = vec![0u8; MAX_REQUEST_BYTES];
    loop {
        if stop.load(Ordering::Acquire) {
            anyhow::bail!("Core Service IPC stopped while awaiting a client request");
        }
        let mut read = 0;
        let ok = unsafe {
            ReadFile(
                pipe,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        if ok != 0 {
            if read == 0 {
                anyhow::bail!("Core Service IPC client sent an empty request");
            }
            bytes.truncate(read as usize);
            return Ok(bytes);
        }
        match unsafe { GetLastError() } {
            ERROR_NO_DATA if Instant::now() < deadline => thread::sleep(PIPE_POLL_INTERVAL),
            ERROR_NO_DATA => anyhow::bail!("Core Service IPC client request timed out"),
            ERROR_MORE_DATA => anyhow::bail!(
                "Core Service IPC request exceeds maximum size of {MAX_REQUEST_BYTES} bytes"
            ),
            code => {
                return Err(std::io::Error::from_raw_os_error(code as i32))
                    .context("failed to read Core Service IPC request")
            }
        }
    }
}

fn build_response(
    request_bytes: &[u8],
    client_pid: u32,
    health: &ServiceHealth,
) -> ServiceResponse {
    let request = match serde_json::from_slice::<ServiceRequest>(request_bytes) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                None,
                client_pid,
                "invalidRequest",
                "request must match the strict protocol schema",
            )
        }
    };
    if request.protocol_version != PROTOCOL_VERSION {
        return error_response(
            Some(request.request_id.clone()),
            client_pid,
            "unsupportedProtocol",
            "unsupported Core Service IPC protocol version",
        );
    }
    if request.request_id.is_empty() || request.request_id.chars().count() > MAX_REQUEST_ID_CHARS {
        return error_response(
            None,
            client_pid,
            "invalidRequestId",
            "requestId must contain between 1 and 128 characters",
        );
    }
    if request.command != "health" {
        return error_response(
            Some(request.request_id.clone()),
            client_pid,
            "commandDenied",
            "only the read-only health command is allowed",
        );
    }
    ServiceResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id: Some(request.request_id),
        ok: true,
        authenticated: true,
        client_pid,
        command_scope: "healthOnly".to_string(),
        data: Some(health.clone()),
        error: None,
    }
}

fn error_response(
    request_id: Option<String>,
    client_pid: u32,
    code: &'static str,
    message: &'static str,
) -> ServiceResponse {
    ServiceResponse {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        ok: false,
        authenticated: true,
        client_pid,
        command_scope: "healthOnly".to_string(),
        data: None,
        error: Some(ServiceError {
            code: code.to_string(),
            message: message.to_string(),
        }),
    }
}

fn write_pipe_message(pipe: HANDLE, bytes: &[u8], description: &str) -> Result<()> {
    let mut written = 0;
    if unsafe {
        WriteFile(
            pipe,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            null_mut(),
        )
    } == 0
    {
        return Err(last_os_error()).context(format!("failed to write Core Service {description}"));
    }
    if written as usize != bytes.len() {
        anyhow::bail!(
            "Core Service {description} write was incomplete: wrote {written} of {} bytes",
            bytes.len()
        );
    }
    Ok(())
}

fn disconnect_client(pipe: HANDLE) -> Result<()> {
    if unsafe { DisconnectNamedPipe(pipe) } == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_NO_DATA && code != ERROR_PIPE_NOT_CONNECTED {
            return Err(std::io::Error::from_raw_os_error(code as i32))
                .context("failed to disconnect Core Service IPC client");
        }
    }
    Ok(())
}

fn last_os_error() -> std::io::Error {
    std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

fn wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct OwnedHandle(HANDLE);

// Windows kernel handles are process-wide and may be used by the worker thread
// after ownership has moved there. This wrapper remains the sole closer.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalAllocation(*mut c_void);

impl LocalAllocation {
    fn new(value: *mut c_void) -> Self {
        Self(value)
    }

    fn get(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;

    fn health() -> ServiceHealth {
        ServiceHealth::ready(true, 7, 5, false)
    }

    fn response(request: &str) -> serde_json::Value {
        serde_json::to_value(build_response(request.as_bytes(), 4242, &health())).unwrap()
    }

    fn open_test_pipe(pipe_name: &str) -> OwnedHandle {
        let pipe_name = wide_string(pipe_name);
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let handle = unsafe {
                CreateFileW(
                    pipe_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                return OwnedHandle::new(handle);
            }
            let code = unsafe { GetLastError() };
            assert_eq!(code, ERROR_PIPE_BUSY, "{}", last_os_error());
            assert!(Instant::now() < deadline, "timed out opening test pipe");
            thread::sleep(PIPE_POLL_INTERVAL);
        }
    }

    fn send_pipe_request(pipe_name: &str, request: &str) -> serde_json::Value {
        let handle = open_test_pipe(pipe_name);
        write_pipe_message(handle.get(), request.as_bytes(), "test request").unwrap();

        let mut bytes = vec![0u8; MAX_RESPONSE_BYTES];
        let mut read = 0;
        let ok = unsafe {
            ReadFile(
                handle.get(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", last_os_error());
        bytes.truncate(read as usize);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn send_oversized_pipe_request(pipe_name: &str) {
        let handle = open_test_pipe(pipe_name);
        let request = vec![b'x'; MAX_REQUEST_BYTES + 1];
        let mut written = 0;
        let write_ok = unsafe {
            WriteFile(
                handle.get(),
                request.as_ptr(),
                request.len() as u32,
                &mut written,
                null_mut(),
            )
        };
        if write_ok == 0 {
            let code = unsafe { GetLastError() };
            assert!(
                matches!(
                    code,
                    ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
                ),
                "unexpected oversized-request write error: {}",
                std::io::Error::from_raw_os_error(code as i32)
            );
            return;
        }

        let mut response = [0u8; 1];
        let mut read = 0;
        let read_ok = unsafe {
            ReadFile(
                handle.get(),
                response.as_mut_ptr(),
                response.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        assert_eq!(
            read_ok, 0,
            "oversized request unexpectedly received a response"
        );
        assert!(matches!(
            unsafe { GetLastError() },
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
        ));
    }

    fn hold_idle_pipe_until_server_disconnects(pipe_name: &str) {
        let handle = open_test_pipe(pipe_name);
        let mut response = [0u8; 1];
        let mut read = 0;
        let read_ok = unsafe {
            ReadFile(
                handle.get(),
                response.as_mut_ptr(),
                response.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        assert_eq!(read_ok, 0, "idle client unexpectedly received a response");
        assert!(matches!(
            unsafe { GetLastError() },
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
        ));
    }

    #[test]
    fn health_protocol_is_versioned_authenticated_and_narrow() {
        let value = response(r#"{"protocolVersion":1,"requestId":"req-1","command":"health"}"#);
        assert_eq!(value["ok"], true);
        assert_eq!(value["authenticated"], true);
        assert_eq!(value["clientPid"], 4242);
        assert_eq!(value["commandScope"], "healthOnly");
        assert_eq!(value["data"]["transport"], "windowsNamedPipe");
        assert_eq!(value["data"]["networkExposed"], false);
        assert_eq!(value["data"]["nativeSignatureCount"], 7);
        assert_eq!(value["data"]["nativeMlProductionReady"], false);
        assert!(value["data"].get("installPath").is_none());
    }

    #[test]
    fn mutating_and_unknown_commands_are_denied() {
        for command in [
            "scan",
            "quarantine",
            "restore",
            "delete",
            "update",
            "unknown",
        ] {
            let request =
                format!(r#"{{"protocolVersion":1,"requestId":"req-2","command":"{command}"}}"#);
            let value = response(&request);
            assert_eq!(value["ok"], false);
            assert_eq!(value["error"]["code"], "commandDenied");
            assert!(value.get("data").is_none());
        }
    }

    #[test]
    fn malformed_unknown_field_and_wrong_version_requests_fail_closed() {
        let malformed = response("not-json");
        assert_eq!(malformed["error"]["code"], "invalidRequest");
        let unknown =
            response(r#"{"protocolVersion":1,"requestId":"req","command":"health","admin":true}"#);
        assert_eq!(unknown["error"]["code"], "invalidRequest");
        let wrong_version =
            response(r#"{"protocolVersion":2,"requestId":"req","command":"health"}"#);
        assert_eq!(wrong_version["error"]["code"], "unsupportedProtocol");
    }

    #[test]
    fn request_ids_are_bounded() {
        let empty = response(r#"{"protocolVersion":1,"requestId":"","command":"health"}"#);
        assert_eq!(empty["error"]["code"], "invalidRequestId");
        let long_id = "x".repeat(MAX_REQUEST_ID_CHARS + 1);
        let value = response(&format!(
            r#"{{"protocolVersion":1,"requestId":"{long_id}","command":"health"}}"#
        ));
        assert_eq!(value["error"]["code"], "invalidRequestId");
    }

    #[test]
    fn health_client_validation_rejects_spoofed_or_broadened_responses() {
        let request_id = "client-validation";
        let valid = serde_json::to_vec(&build_response(
            format!(r#"{{"protocolVersion":1,"requestId":"{request_id}","command":"health"}}"#)
                .as_bytes(),
            std::process::id(),
            &health(),
        ))
        .unwrap();
        assert_eq!(
            validate_health_response(&valid, request_id, std::process::id()).unwrap(),
            health()
        );

        for (field, value) in [
            ("protocolVersion", serde_json::json!(2)),
            ("requestId", serde_json::json!("wrong-request")),
            ("authenticated", serde_json::json!(false)),
            ("clientPid", serde_json::json!(0)),
            ("commandScope", serde_json::json!("scanAndHealth")),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&valid).unwrap();
            changed[field] = value;
            assert!(validate_health_response(
                &serde_json::to_vec(&changed).unwrap(),
                request_id,
                std::process::id()
            )
            .is_err());
        }

        let mut unknown: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        unknown["admin"] = serde_json::json!(true);
        assert!(validate_health_response(
            &serde_json::to_vec(&unknown).unwrap(),
            request_id,
            std::process::id()
        )
        .is_err());

        for (field, value) in [
            ("transport", serde_json::json!("tcp")),
            ("networkExposed", serde_json::json!(true)),
            ("commandScope", serde_json::json!("mutationAllowed")),
            ("serviceReady", serde_json::json!(false)),
            (
                "nativeSignatureCount",
                serde_json::json!(MAX_REPORTED_DEFINITION_COUNT + 1),
            ),
            ("limitations", serde_json::json!([])),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&valid).unwrap();
            changed["data"][field] = value;
            assert!(validate_health_response(
                &serde_json::to_vec(&changed).unwrap(),
                request_id,
                std::process::id()
            )
            .is_err());
        }
    }

    #[test]
    fn pipe_contract_rejects_remote_clients_and_uses_explicit_acl() {
        let source = include_str!("core_service_ipc.rs");
        assert!(source.contains("PIPE_REJECT_REMOTE_CLIENTS"));
        assert!(source.contains("FILE_FLAG_FIRST_PIPE_INSTANCE"));
        assert!(source.contains("ImpersonateNamedPipeClient"));
        assert!(source.contains("OpenThreadToken"));
        assert!(source.contains("RevertToSelf"));
        assert_eq!(
            CORE_SERVICE_PIPE_SDDL,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
        );
    }

    #[test]
    fn real_local_pipe_authenticates_bounds_scope_and_stops_cleanly() {
        let pipe_name = format!(r"\\.\pipe\AvoraxCoreService.test.{}", uuid::Uuid::new_v4());
        let mut server = CoreServiceIpcServer::start_with_pipe_name_and_timeout(
            health(),
            &pipe_name,
            Duration::from_millis(200),
        )
        .unwrap();
        assert!(CoreServiceIpcServer::start_with_pipe_name(health(), &pipe_name).is_err());

        let health_response = send_pipe_request(
            &pipe_name,
            r#"{"protocolVersion":1,"requestId":"integration-health","command":"health"}"#,
        );
        assert_eq!(health_response["ok"], true);
        assert_eq!(health_response["authenticated"], true);
        assert_eq!(health_response["clientPid"], std::process::id());

        let denied_response = send_pipe_request(
            &pipe_name,
            r#"{"protocolVersion":1,"requestId":"integration-delete","command":"delete"}"#,
        );
        assert_eq!(denied_response["ok"], false);
        assert_eq!(denied_response["error"]["code"], "commandDenied");

        let malformed_response = send_pipe_request(&pipe_name, "not-json");
        assert_eq!(malformed_response["ok"], false);
        assert_eq!(malformed_response["error"]["code"], "invalidRequest");

        send_oversized_pipe_request(&pipe_name);
        let recovery_response = send_pipe_request(
            &pipe_name,
            r#"{"protocolVersion":1,"requestId":"after-oversize","command":"health"}"#,
        );
        assert_eq!(recovery_response["ok"], true);

        hold_idle_pipe_until_server_disconnects(&pipe_name);
        let timeout_recovery_response = send_pipe_request(
            &pipe_name,
            r#"{"protocolVersion":1,"requestId":"after-timeout","command":"health"}"#,
        );
        assert_eq!(timeout_recovery_response["ok"], true);

        server.ensure_running().unwrap();
        server.stop().unwrap();
        assert!(server.stop().is_err());
    }

    #[test]
    fn real_health_probe_authenticates_pipe_server_pid_and_protocol() {
        let pipe_name = format!(r"\\.\pipe\AvoraxCoreService.probe.{}", uuid::Uuid::new_v4());
        let mut server = CoreServiceIpcServer::start_with_pipe_name_and_timeout(
            health(),
            &pipe_name,
            Duration::from_millis(200),
        )
        .unwrap();

        let report =
            probe_service_health_with(
                &pipe_name,
                Duration::from_secs(1),
                || Ok(std::process::id()),
            )
            .unwrap();
        assert!(report.ok);
        assert!(report.client_authenticated);
        assert!(report.server_authenticated);
        assert_eq!(report.server_pid, std::process::id());
        assert_eq!(report.service_pid, std::process::id());
        assert_eq!(report.command_scope, "healthOnly");
        assert!(!report.network_exposed);

        server.ensure_running().unwrap();
        server.stop().unwrap();
    }

    #[test]
    fn authenticated_probe_does_not_report_ok_for_degraded_engine() {
        let pipe_name = format!(
            r"\\.\pipe\AvoraxCoreService.degraded.{}",
            uuid::Uuid::new_v4()
        );
        let mut server = CoreServiceIpcServer::start_with_pipe_name_and_timeout(
            ServiceHealth::ready(false, 0, 0, false),
            &pipe_name,
            Duration::from_millis(200),
        )
        .unwrap();

        let report =
            probe_service_health_with(
                &pipe_name,
                Duration::from_secs(1),
                || Ok(std::process::id()),
            )
            .unwrap();
        assert!(!report.ok);
        assert!(!report.engine_ready);
        assert!(report.client_authenticated);
        assert!(report.server_authenticated);

        server.ensure_running().unwrap();
        server.stop().unwrap();
    }

    #[test]
    fn health_probe_rejects_pipe_server_pid_mismatch() {
        let pipe_name = format!(r"\\.\pipe\AvoraxCoreService.spoof.{}", uuid::Uuid::new_v4());
        let mut server = CoreServiceIpcServer::start_with_pipe_name_and_timeout(
            health(),
            &pipe_name,
            Duration::from_millis(100),
        )
        .unwrap();

        let spoofed_pid = std::process::id().saturating_add(1);
        let error =
            probe_service_health_with(&pipe_name, Duration::from_secs(1), || Ok(spoofed_pid))
                .unwrap_err()
                .to_string();
        assert!(error.contains("does not match SCM service PID"));

        thread::sleep(Duration::from_millis(150));
        server.ensure_running().unwrap();
        server.stop().unwrap();
    }

    #[test]
    fn health_probe_cancels_a_stalled_pipe_response() {
        let pipe_name = format!(r"\\.\pipe\AvoraxCoreService.stall.{}", uuid::Uuid::new_v4());
        let pipe = create_service_pipe(&pipe_name).unwrap();
        let fake_server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !connect_client(pipe.get()).unwrap() {
                assert!(Instant::now() < deadline, "test client did not connect");
                thread::sleep(PIPE_POLL_INTERVAL);
            }
            let stop = AtomicBool::new(false);
            let request = read_request(pipe.get(), &stop, Duration::from_millis(200)).unwrap();
            let parsed: ServiceRequest = serde_json::from_slice(&request).unwrap();
            assert_eq!(parsed.command, "health");
            thread::sleep(Duration::from_millis(150));
            disconnect_client(pipe.get()).unwrap();
        });

        let started = Instant::now();
        let error = probe_service_health_with(&pipe_name, Duration::from_millis(50), || {
            Ok(std::process::id())
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
        fake_server.join().unwrap();
    }

    #[test]
    fn health_probe_rejects_service_restart_during_response() {
        let pipe_name = format!(
            r"\\.\pipe\AvoraxCoreService.restart.{}",
            uuid::Uuid::new_v4()
        );
        let mut server = CoreServiceIpcServer::start_with_pipe_name_and_timeout(
            health(),
            &pipe_name,
            Duration::from_millis(200),
        )
        .unwrap();
        let mut query_count = 0;
        let error = probe_service_health_with(&pipe_name, Duration::from_secs(1), || {
            query_count += 1;
            Ok(if query_count == 1 {
                std::process::id()
            } else {
                std::process::id().saturating_add(1)
            })
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("process changed during the health probe"));
        assert_eq!(query_count, 2);

        server.ensure_running().unwrap();
        server.stop().unwrap();
    }
}
