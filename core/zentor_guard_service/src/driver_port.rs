#![cfg(windows)]

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use chrono::Utc;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};

use crate::driver_ipc::{
    evaluate_driver_request, DriverEventType, DriverVerdictAction, FinalVerdict, ScanRequest,
    VerdictConfidence,
};
use crate::known_bad_cache;

const ZENTOR_FILTER_PORT_NAME: &[u16] = &[
    b'\\' as u16,
    b'Z' as u16,
    b'e' as u16,
    b'n' as u16,
    b't' as u16,
    b'o' as u16,
    b'r' as u16,
    b'A' as u16,
    b'v' as u16,
    b'F' as u16,
    b'i' as u16,
    b'l' as u16,
    b't' as u16,
    b'e' as u16,
    b'r' as u16,
    b'P' as u16,
    b'o' as u16,
    b'r' as u16,
    b't' as u16,
    0,
];

const STATUS_SUCCESS: i32 = 0;
const S_OK: i32 = 0;
const ERROR_FLT_FILTER_NOT_FOUND_HRESULT: i32 = 0x801F0013u32 as i32;
const ERROR_PIPE_NOT_CONNECTED_HRESULT: i32 = 0x800700E9u32 as i32;

#[repr(C)]
#[derive(Clone, Copy)]
struct FilterMessageHeader {
    reply_length: u32,
    message_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FilterReplyHeader {
    status: i32,
    message_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeScanRequest {
    version: u32,
    request_id: u32,
    event_type: u32,
    process_id: u32,
    parent_process_id: u32,
    desired_access: u32,
    create_disposition: u32,
    file_attributes: u32,
    file_size: i64,
    timestamp_utc: i64,
    file_path: [u16; 1024],
    rename_target: [u16; 512],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeScanVerdict {
    version: u32,
    request_id: u32,
    action: u32,
    final_verdict: u32,
    confidence: u32,
    cache_ttl_ms: u32,
    quarantine_after_block: u8,
    reason: [u16; 256],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DriverMessage {
    header: FilterMessageHeader,
    request: NativeScanRequest,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DriverReply {
    header: FilterReplyHeader,
    verdict: NativeScanVerdict,
}

#[link(name = "FltLib")]
extern "system" {
    fn FilterConnectCommunicationPort(
        lpPortName: *const u16,
        dwOptions: u32,
        lpContext: *const c_void,
        wSizeOfContext: u16,
        lpSecurityAttributes: *const c_void,
        hPort: *mut HANDLE,
    ) -> i32;

    fn FilterGetMessage(
        hPort: HANDLE,
        lpMessageBuffer: *mut FilterMessageHeader,
        dwMessageBufferSize: u32,
        lpOverlapped: *mut c_void,
    ) -> i32;

    fn FilterReplyMessage(
        hPort: HANDLE,
        lpReplyBuffer: *mut FilterReplyHeader,
        dwReplyBufferSize: u32,
    ) -> i32;
}

pub fn start_background_worker() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    if let Err(error) = thread::Builder::new()
        .name("avorax-driver-port".to_string())
        .spawn(move || {
            if let Err(error) = run_message_loop(worker_stop) {
                crate::report_guard_fatal_error("driver_port_error.log", &format!("{error:#}"));
            }
        })
    {
        crate::report_guard_fatal_error(
            "driver_port_error.log",
            &format!("failed to spawn Avorax driver port worker: {error}"),
        );
    }
    stop
}

fn run_message_loop(stop: Arc<AtomicBool>) -> Result<()> {
    let mut port: HANDLE = null_mut();
    let hr = unsafe {
        FilterConnectCommunicationPort(
            ZENTOR_FILTER_PORT_NAME.as_ptr(),
            0,
            null(),
            0,
            null(),
            &mut port,
        )
    };
    if hr != S_OK {
        if hr == ERROR_FLT_FILTER_NOT_FOUND_HRESULT || hr == ERROR_PIPE_NOT_CONNECTED_HRESULT {
            return Ok(());
        }
        anyhow::bail!("FilterConnectCommunicationPort(\\ZentorAvFilterPort) failed: 0x{hr:08x}");
    }

    let _guard = PortHandle(port);
    while !stop.load(Ordering::Relaxed) {
        let mut message: DriverMessage = unsafe { zeroed() };
        let hr = unsafe {
            FilterGetMessage(
                port,
                &mut message.header,
                size_of::<DriverMessage>() as u32,
                null_mut(),
            )
        };
        if hr != S_OK {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            anyhow::bail!("FilterGetMessage failed: 0x{hr:08x}");
        }

        let verdict = match evaluate_native_request(&message.request) {
            Ok(verdict) => verdict,
            Err(error) => fail_open_verdict(
                message.request.request_id,
                &format!("guard evaluation error: {error:#}"),
            ),
        };
        let mut reply = DriverReply {
            header: FilterReplyHeader {
                status: STATUS_SUCCESS,
                message_id: message.header.message_id,
            },
            verdict,
        };
        let hr =
            unsafe { FilterReplyMessage(port, &mut reply.header, size_of::<DriverReply>() as u32) };
        if hr != S_OK {
            anyhow::bail!("FilterReplyMessage failed: 0x{hr:08x}");
        }
    }
    Ok(())
}

fn evaluate_native_request(native: &NativeScanRequest) -> Result<NativeScanVerdict> {
    let request = native_to_domain(native)?;
    let mut config = crate::driver_ipc::DriverVerdictConfig::default();
    config.known_bad_hashes = known_bad_cache::load_known_bad_hashes()
        .context("failed to load guard known-bad cache for driver port verdict")?;
    let verdict = evaluate_driver_request(&request, &config)?;
    Ok(domain_to_native(native.request_id, &verdict))
}

fn native_to_domain(native: &NativeScanRequest) -> Result<ScanRequest> {
    let file_path =
        utf16z_to_string(&native.file_path).context("driver request path is not valid UTF-16")?;
    let rename_target = utf16z_to_string(&native.rename_target)
        .context("driver rename target is not valid UTF-16")?;
    let normalized_file_path = if rename_target.is_empty() {
        Some(file_path.clone())
    } else {
        Some(rename_target)
    };
    let event_type = match native.event_type {
        0 => DriverEventType::FileOpen,
        1 => DriverEventType::FileCreate,
        2 => DriverEventType::FileWrite,
        3 => DriverEventType::FileRename,
        4 => DriverEventType::ImageExecuteAttempt,
        5 => DriverEventType::SectionCreateAttempt,
        value => anyhow::bail!("unsupported driver event type: {value}"),
    };
    Ok(ScanRequest {
        request_id: native.request_id.to_string(),
        event_type,
        file_path,
        normalized_file_path,
        process_id: nonzero_u32(native.process_id),
        parent_process_id: nonzero_u32(native.parent_process_id),
        user_sid: None,
        desired_access: Some(native.desired_access),
        file_size: (native.file_size >= 0).then_some(native.file_size as u64),
        file_attributes: Some(native.file_attributes),
        signature_status: None,
        publisher: None,
        signature_verified_by: None,
        parent_process_path: None,
        sha256: None,
        sha256_verified_by: None,
        timestamp_utc: Utc::now(),
    })
}

fn domain_to_native(
    request_id: u32,
    verdict: &crate::driver_ipc::ScanVerdict,
) -> NativeScanVerdict {
    let mut native = NativeScanVerdict {
        version: 1,
        request_id,
        action: match verdict.action {
            DriverVerdictAction::Allow => 0,
            DriverVerdictAction::Block => 1,
            DriverVerdictAction::Quarantine => 2,
            DriverVerdictAction::AllowAndMonitor => 3,
            DriverVerdictAction::TimeoutAllow => 4,
            DriverVerdictAction::TimeoutBlock => 5,
        },
        final_verdict: match verdict.final_verdict {
            FinalVerdict::Clean => 0,
            FinalVerdict::LikelyClean => 1,
            FinalVerdict::Unknown => 2,
            FinalVerdict::Observation => 3,
            FinalVerdict::Suspicious => 4,
            FinalVerdict::ProbableMalware => 5,
            FinalVerdict::ConfirmedMalware => 6,
        },
        confidence: match verdict.confidence {
            VerdictConfidence::Low => 0,
            VerdictConfidence::Medium => 1,
            VerdictConfidence::High => 2,
            VerdictConfidence::Confirmed => 3,
        },
        cache_ttl_ms: verdict.cache_ttl_ms.min(u32::MAX as u64) as u32,
        quarantine_after_block: u8::from(verdict.quarantine_after_block),
        reason: [0; 256],
    };
    write_utf16z(&mut native.reason, &verdict.reason_summary);
    native
}

fn fail_open_verdict(request_id: u32, reason: &str) -> NativeScanVerdict {
    let mut verdict = NativeScanVerdict {
        version: 1,
        request_id,
        action: 4,
        final_verdict: 2,
        confidence: 0,
        cache_ttl_ms: 1_000,
        quarantine_after_block: 0,
        reason: [0; 256],
    };
    write_utf16z(&mut verdict.reason, reason);
    verdict
}

fn nonzero_u32(value: u32) -> Option<u32> {
    (value != 0).then_some(value)
}

fn utf16z_to_string(input: &[u16]) -> Result<String, std::string::FromUtf16Error> {
    String::from_utf16(utf16z_payload(input))
}

fn utf16z_payload(input: &[u16]) -> &[u16] {
    match input.iter().position(|ch| *ch == 0) {
        Some(end) => &input[..end],
        None => input,
    }
}

fn write_utf16z(output: &mut [u16], value: &str) {
    if output.is_empty() {
        return;
    }
    let max = output.len() - 1;
    for (slot, ch) in output.iter_mut().take(max).zip(value.encode_utf16()) {
        *slot = ch;
    }
    output[max] = 0;
}

struct PortHandle(HANDLE);

impl Drop for PortHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_request() -> NativeScanRequest {
        let mut request = NativeScanRequest {
            version: 1,
            request_id: 42,
            event_type: 4,
            process_id: 0,
            parent_process_id: 0,
            desired_access: 0,
            create_disposition: 0,
            file_attributes: 0,
            file_size: 0,
            timestamp_utc: 0,
            file_path: [0; 1024],
            rename_target: [0; 512],
        };
        write_utf16z(&mut request.file_path, r"C:\AvoraxFixtures\notepad.exe");
        request
    }

    #[test]
    fn native_request_rejects_invalid_rename_target_utf16() {
        let mut request = native_request();
        request.rename_target[0] = 0xD800;

        let error = native_to_domain(&request).unwrap_err().to_string();

        assert!(error.contains("driver rename target is not valid UTF-16"));
    }

    #[test]
    fn native_request_rejects_unknown_event_type() {
        let mut request = native_request();
        request.event_type = 99;

        let error = native_to_domain(&request).unwrap_err().to_string();

        assert!(error.contains("unsupported driver event type: 99"));
    }

    #[test]
    fn driver_port_utf16z_payload_uses_explicit_no_terminator_branch() {
        assert_eq!(utf16z_payload(&[65, 0, 66]), &[65]);
        assert_eq!(utf16z_payload(&[65, 66]), &[65, 66]);

        let source = include_str!("driver_port.rs");
        let start = source.find("fn utf16z_to_string").unwrap();
        let end = source.find("fn write_utf16z").unwrap();
        let utf16_source = &source[start..end];

        assert!(utf16_source.contains("fn utf16z_payload(input: &[u16]) -> &[u16]"));
        assert!(utf16_source.contains("Some(end) => &input[..end]"));
        assert!(utf16_source.contains("None => input"));
        assert!(!utf16_source.contains(".unwrap_or(input.len())"));
    }

    #[test]
    fn native_driver_request_fields_are_not_silently_defaulted() {
        let source = include_str!("driver_port.rs");
        let start = source.find("fn native_to_domain").unwrap();
        let end = source.find("fn domain_to_native").unwrap();
        let native_source = &source[start..end];

        assert!(native_source.contains("driver rename target is not valid UTF-16"));
        assert!(native_source.contains("unsupported driver event type"));
        assert!(!native_source.contains(".ok()"));
        assert!(!native_source.contains("_ => DriverEventType::FileOpen"));
    }

    #[test]
    fn driver_port_known_bad_cache_load_errors_are_reported() {
        let source = include_str!("driver_port.rs");
        let start = source.find("fn evaluate_native_request").unwrap();
        let end = source.find("fn native_to_domain").unwrap();
        let evaluate_source = &source[start..end];
        let old_assignment =
            ["config.known_bad_hashes = known_bad_cache::load_known_bad_hashes();"].concat();

        assert!(evaluate_source
            .contains("failed to load guard known-bad cache for driver port verdict"));
        assert!(evaluate_source.contains("known_bad_cache::load_known_bad_hashes()"));
        assert!(evaluate_source.contains(".context("));
        assert!(!evaluate_source.contains(&old_assignment));
    }

    #[test]
    fn driver_port_evaluation_fail_open_branch_is_explicit() {
        let source = include_str!("driver_port.rs");
        let start = source.find("fn run_message_loop").unwrap();
        let end = source.find("fn evaluate_native_request").unwrap();
        let loop_source = &source[start..end];

        assert!(
            loop_source.contains("let verdict = match evaluate_native_request(&message.request)")
        );
        assert!(loop_source.contains("Ok(verdict) => verdict"));
        assert!(loop_source.contains("Err(error) => fail_open_verdict"));
        assert!(loop_source.contains("guard evaluation error: {error:#}"));
        assert!(!loop_source.contains("evaluate_native_request(&message.request).unwrap_or_else"));
    }

    #[test]
    fn driver_port_worker_spawn_errors_are_reported() {
        let source = include_str!("driver_port.rs");
        let start = source.find("pub fn start_background_worker").unwrap();
        let end = source.find("fn run_message_loop").unwrap();
        let worker_source = &source[start..end];

        assert!(worker_source.contains("if let Err(error) = thread::Builder::new()"));
        assert!(worker_source.contains(".name(\"avorax-driver-port\".to_string())"));
        assert!(worker_source
            .contains("report_guard_fatal_error(\n            \"driver_port_error.log\""));
        assert!(worker_source.contains("failed to spawn Avorax driver port worker: {error}"));
        assert!(!worker_source.contains(".expect(\"failed to spawn Zentor driver port worker\")"));
    }
}
