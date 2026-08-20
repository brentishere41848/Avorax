use std::ffi::OsString;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

const MAX_WINDOWS_PROCESS_IMAGE_CHARS: u32 = 32_768;

#[derive(Debug)]
pub(crate) struct WindowsProcessImage {
    pub(crate) process_id: u32,
    pub(crate) path: PathBuf,
}

#[derive(Debug, Default)]
pub(crate) struct WindowsProcessSnapshot {
    pub(crate) processes: Vec<WindowsProcessImage>,
    pub(crate) coverage_gaps: u64,
    pub(crate) first_coverage_detail: Option<String>,
}

impl WindowsProcessSnapshot {
    fn record_gap(&mut self, detail: impl Into<String>) {
        self.record_gaps(1, detail);
    }

    fn record_gaps(&mut self, count: u64, detail: impl Into<String>) {
        if count == 0 {
            return;
        }
        self.coverage_gaps = self.coverage_gaps.saturating_add(count);
        if self.first_coverage_detail.is_none() {
            self.first_coverage_detail = Some(detail.into());
        }
    }
}

#[derive(Debug, Default)]
struct WindowsProcessIds {
    process_ids: Vec<u32>,
    coverage_gaps: u64,
    first_coverage_detail: Option<String>,
}

impl WindowsProcessIds {
    fn record_gap(&mut self, detail: impl Into<String>) {
        self.coverage_gaps = self.coverage_gaps.saturating_add(1);
        if self.first_coverage_detail.is_none() {
            self.first_coverage_detail = Some(detail.into());
        }
    }
}

enum ProcessImageLookup {
    Found(PathBuf),
    Exited,
    Unavailable(String),
}

pub(crate) fn collect_windows_process_images(
    max_records: usize,
    time_budget: Duration,
) -> Result<WindowsProcessSnapshot> {
    if max_records == 0 {
        anyhow::bail!("native Windows process record limit must be positive");
    }
    if time_budget.is_zero() {
        anyhow::bail!("native Windows process collection time budget must be positive");
    }

    let started = Instant::now();
    let process_ids = enumerate_process_ids(max_records)?;
    let mut image_buffer = vec![0u16; MAX_WINDOWS_PROCESS_IMAGE_CHARS as usize];
    Ok(collect_process_images_with(
        process_ids,
        max_records,
        time_budget,
        || started.elapsed(),
        |process_id| query_process_image(process_id, &mut image_buffer),
    ))
}

fn enumerate_process_ids(max_records: usize) -> Result<WindowsProcessIds> {
    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw_snapshot == INVALID_HANDLE_VALUE {
        return Err(last_windows_error(
            "unable to create native Windows process snapshot",
        ));
    }
    let _snapshot = OwnedHandle(raw_snapshot);

    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>())
            .map_err(|_| anyhow::anyhow!("native Windows process entry size exceeded u32"))?,
        ..PROCESSENTRY32W::default()
    };
    if unsafe { Process32FirstW(raw_snapshot, &mut entry) } == 0 {
        let error = unsafe { GetLastError() };
        if error == ERROR_NO_MORE_FILES {
            return Ok(WindowsProcessIds::default());
        }
        return Err(windows_error_with_code(
            "unable to read first native Windows process snapshot entry",
            error,
        ));
    }

    let mut result = WindowsProcessIds::default();
    loop {
        result.process_ids.push(entry.th32ProcessID);

        if unsafe { Process32NextW(raw_snapshot, &mut entry) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_NO_MORE_FILES {
                result.record_gap(format!(
                    "native Windows process snapshot ended early: {}",
                    io::Error::from_raw_os_error(error as i32)
                ));
            }
            break;
        }

        if result.process_ids.len() >= max_records {
            result.record_gap(format!(
                "native Windows process record limit of {max_records} was reached"
            ));
            break;
        }
    }
    Ok(result)
}

fn collect_process_images_with<Elapsed, Query>(
    mut process_ids: WindowsProcessIds,
    max_records: usize,
    time_budget: Duration,
    mut elapsed: Elapsed,
    mut query: Query,
) -> WindowsProcessSnapshot
where
    Elapsed: FnMut() -> Duration,
    Query: FnMut(u32) -> ProcessImageLookup,
{
    let mut result = WindowsProcessSnapshot {
        coverage_gaps: process_ids.coverage_gaps,
        first_coverage_detail: process_ids.first_coverage_detail.take(),
        ..WindowsProcessSnapshot::default()
    };

    if process_ids.process_ids.len() > max_records {
        let omitted = process_ids.process_ids.len() - max_records;
        process_ids.process_ids.truncate(max_records);
        result.record_gaps(
            omitted as u64,
            format!("native Windows process record limit of {max_records} was reached"),
        );
    }

    for (index, process_id) in process_ids.process_ids.iter().copied().enumerate() {
        if matches!(process_id, 0 | 4) {
            continue;
        }
        if elapsed() >= time_budget {
            let unqueried = process_ids.process_ids[index..]
                .iter()
                .filter(|process_id| !matches!(process_id, 0 | 4))
                .count()
                .max(1);
            result.record_gaps(
                unqueried as u64,
                format!(
                    "native Windows process collection exceeded its {} ms time budget",
                    time_budget.as_millis()
                ),
            );
            break;
        }

        match query(process_id) {
            ProcessImageLookup::Found(path) => result
                .processes
                .push(WindowsProcessImage { process_id, path }),
            ProcessImageLookup::Exited => {}
            ProcessImageLookup::Unavailable(detail) => result.record_gap(detail),
        }
    }
    result
}

fn query_process_image(process_id: u32, buffer: &mut [u16]) -> ProcessImageLookup {
    let raw_process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if raw_process.is_null() {
        return process_lookup_error("open", process_id);
    }
    let _process = OwnedHandle(raw_process);

    let mut chars = MAX_WINDOWS_PROCESS_IMAGE_CHARS;
    if unsafe {
        QueryFullProcessImageNameW(
            raw_process,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &mut chars,
        )
    } == 0
    {
        return process_lookup_error("query executable image for", process_id);
    }
    let chars = chars as usize;
    if chars == 0 || chars > buffer.len() {
        return ProcessImageLookup::Unavailable(format!(
            "native Windows process image query returned an invalid length for PID {process_id}"
        ));
    }

    ProcessImageLookup::Found(PathBuf::from(OsString::from_wide(&buffer[..chars])))
}

fn process_lookup_error(action: &str, process_id: u32) -> ProcessImageLookup {
    let error = unsafe { GetLastError() };
    if error == ERROR_INVALID_PARAMETER {
        return ProcessImageLookup::Exited;
    }
    ProcessImageLookup::Unavailable(format!(
        "unable to {action} native Windows process PID {process_id}: {}",
        io::Error::from_raw_os_error(error as i32)
    ))
}

fn last_windows_error(context: &str) -> anyhow::Error {
    let error = unsafe { GetLastError() };
    windows_error_with_code(context, error)
}

fn windows_error_with_code(context: &str, error: u32) -> anyhow::Error {
    anyhow::anyhow!("{context}: {}", io::Error::from_raw_os_error(error as i32))
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    #[test]
    fn process_collection_windows_native_rejects_zero_limits() {
        assert!(collect_windows_process_images(0, Duration::from_secs(1))
            .unwrap_err()
            .to_string()
            .contains("record limit must be positive"));
        assert!(collect_windows_process_images(1, Duration::ZERO)
            .unwrap_err()
            .to_string()
            .contains("time budget must be positive"));
    }

    #[test]
    fn process_collection_windows_native_runtime_observes_current_process() {
        let snapshot = collect_windows_process_images(65_536, Duration::from_secs(2)).unwrap();

        assert!(snapshot.processes.len() <= 65_536);
        assert!(snapshot
            .processes
            .iter()
            .any(|process| process.process_id == std::process::id()));
        if snapshot.coverage_gaps > 0 {
            assert!(snapshot.first_coverage_detail.is_some());
        }
    }

    #[test]
    fn process_collection_windows_native_query_gaps_and_churn_are_distinct() {
        let calls = RefCell::new(Vec::new());
        let process_ids = WindowsProcessIds {
            process_ids: vec![0, 4, 10, 11, 12],
            ..WindowsProcessIds::default()
        };

        let snapshot = collect_process_images_with(
            process_ids,
            10,
            Duration::from_secs(1),
            || Duration::ZERO,
            |process_id| {
                calls.borrow_mut().push(process_id);
                match process_id {
                    10 => ProcessImageLookup::Found(PathBuf::from(r"C:\Fixture\safe.exe")),
                    11 => ProcessImageLookup::Exited,
                    _ => ProcessImageLookup::Unavailable(format!(
                        "access denied for benign test PID {process_id}"
                    )),
                }
            },
        );

        assert_eq!(*calls.borrow(), vec![10, 11, 12]);
        assert_eq!(snapshot.processes.len(), 1);
        assert_eq!(snapshot.coverage_gaps, 1);
        assert!(snapshot
            .first_coverage_detail
            .unwrap()
            .contains("access denied"));
    }

    #[test]
    fn process_collection_windows_native_budget_is_fail_visible() {
        let elapsed = RefCell::new(VecDeque::from([
            Duration::ZERO,
            Duration::ZERO,
            Duration::from_millis(50),
        ]));
        let calls = RefCell::new(Vec::new());
        let process_ids = WindowsProcessIds {
            process_ids: vec![10, 11, 12],
            ..WindowsProcessIds::default()
        };

        let snapshot = collect_process_images_with(
            process_ids,
            10,
            Duration::from_millis(25),
            || elapsed.borrow_mut().pop_front().unwrap(),
            |process_id| {
                calls.borrow_mut().push(process_id);
                ProcessImageLookup::Found(PathBuf::from(format!(r"C:\Fixture\{process_id}.exe")))
            },
        );

        assert_eq!(*calls.borrow(), vec![10, 11]);
        assert_eq!(snapshot.processes.len(), 2);
        assert_eq!(snapshot.coverage_gaps, 1);
        assert!(snapshot
            .first_coverage_detail
            .unwrap()
            .contains("25 ms time budget"));
    }

    #[test]
    fn process_collection_windows_native_record_limit_is_fail_visible() {
        let process_ids = WindowsProcessIds {
            process_ids: vec![10, 11, 12, 13],
            ..WindowsProcessIds::default()
        };
        let snapshot = collect_process_images_with(
            process_ids,
            2,
            Duration::from_secs(1),
            || Duration::ZERO,
            |process_id| {
                ProcessImageLookup::Found(PathBuf::from(format!(r"C:\Fixture\{process_id}.exe")))
            },
        );

        assert_eq!(snapshot.processes.len(), 2);
        assert_eq!(snapshot.coverage_gaps, 2);
        assert!(snapshot
            .first_coverage_detail
            .unwrap()
            .contains("record limit of 2"));
    }
}
