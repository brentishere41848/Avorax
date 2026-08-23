use std::ffi::c_void;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::os::windows::process::ExitStatusExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::ExitStatus;
use std::ptr::{null, null_mut};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant, Version};
use windows_sys::core::PCSTR;

use crate::windows_system::{checked_system_directory, checked_system_windows_directory};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetHandleInformation, SetLastError, CERT_E_REVOCATION_FAILURE,
    CRYPT_E_BAD_ENCODE, CRYPT_E_BAD_MSG, CRYPT_E_NO_MATCH, CRYPT_E_NO_SIGNER,
    CRYPT_E_NO_TRUSTED_SIGNER, CRYPT_E_REVOKED, CRYPT_E_SIGNER_NOT_FOUND,
    ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND, ERROR_NO_TOKEN, ERROR_SUCCESS, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LUID, TRUST_E_BAD_DIGEST, TRUST_E_BASIC_CONSTRAINTS,
    TRUST_E_CERT_SIGNATURE, TRUST_E_COUNTER_SIGNER, TRUST_E_FAIL, TRUST_E_FINANCIAL_CRITERIA,
    TRUST_E_MALFORMED_SIGNATURE, TRUST_E_NO_SIGNER_CERT, TRUST_E_SUBJECT_FORM_UNKNOWN,
    TRUST_E_SUBJECT_NOT_TRUSTED, TRUST_E_TIME_STAMP, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
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
use windows_sys::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, DuplicateTokenEx, GetLengthSid, GetTokenInformation,
    IsValidSid, LookupPrivilegeValueW, RevertToSelf, SecurityImpersonation, SetTokenInformation,
    TokenImpersonation, TokenImpersonationLevel, TokenIntegrityLevel, TokenMandatoryPolicy,
    TokenPrimary, TokenPrivileges, TokenRestrictedSids, TokenType, WinLowLabelSid,
    WinRestrictedCodeSid, DISABLE_MAX_PRIVILEGE, LUID_AND_ATTRIBUTES, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED, SID, SID_AND_ATTRIBUTES,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_IMPERSONATE,
    TOKEN_MANDATORY_LABEL, TOKEN_MANDATORY_POLICY, TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
    TOKEN_MANDATORY_POLICY_VALID_MASK, TOKEN_PRIVILEGES, TOKEN_QUERY, WELL_KNOWN_SID_TYPE,
    WRITE_RESTRICTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, FileIdInfo, FileStandardInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_BASIC_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_ID_INFO,
    FILE_SHARE_READ, FILE_STANDARD_INFO,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemServices::{
    SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED,
    SE_GROUP_MANDATORY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, DeleteProcThreadAttributeList, GetCurrentProcess, GetCurrentThread,
    GetExitCodeProcess, GetProcessMitigationPolicy, InitializeProcThreadAttributeList,
    OpenProcessToken, OpenThreadToken, ProcessDynamicCodePolicy,
    ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessSignaturePolicy,
    ProcessStrictHandleCheckPolicy, ResumeThread, SetThreadToken, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

const MAX_AUTHENTICODE_PATH_UTF16_UNITS: usize = 32_767;
const MAX_SIGNER_ATTRIBUTE_UTF16_UNITS: usize = 2_048;
const MAX_AUTHENTICODE_BIND_BYTES: u64 = 512 * 1024 * 1024;
const AUTHENTICODE_HASH_BUFFER_BYTES: usize = 128 * 1024;
const SHA256_CATALOG_HASH_BYTES: usize = 32;
const MAX_CATALOG_CANDIDATES: usize = 16;
const MAX_AUTHENTICODE_SIGNATURES: u32 = 16;
const AUTHENTICODE_HELPER_SCHEMA_VERSION: u32 = 1;
const AUTHENTICODE_HELPER_ARGUMENT: &str = "--avorax-authenticode-helper-v1";
const AUTHENTICODE_HELPER_TIMEOUT: Duration = Duration::from_secs(15);
const AUTHENTICODE_HELPER_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const AUTHENTICODE_HELPER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const AUTHENTICODE_HELPER_USER_CPU_100NS: i64 = 12 * 10_000_000;
const AUTHENTICODE_HELPER_PROCESS_MEMORY_BYTES: usize = 1024 * 1024 * 1024;
const AUTHENTICODE_HELPER_JOB_MEMORY_BYTES: usize = 1024 * 1024 * 1024;
const AUTHENTICODE_HELPER_ACTIVE_PROCESS_LIMIT: u32 = 1;
const MAX_AUTHENTICODE_HELPER_REQUEST_BYTES: usize = 256 * 1024;
const MAX_AUTHENTICODE_HELPER_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_AUTHENTICODE_HELPER_STDERR_BYTES: usize = 16 * 1024;
const MAX_AUTHENTICODE_HELPER_ERROR_CHARS: usize = 4_096;
const MAX_AUTHENTICODE_HOST_EXE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_AUTHENTICODE_HELPER_TOKEN_INFO_BYTES: usize = 64 * 1024;
const MAX_AUTHENTICODE_HELPER_TOKEN_PRIVILEGES: usize = 256;
const MAX_AUTHENTICODE_HELPER_RESTRICTED_SIDS: usize = 16;
const AUTHENTICODE_HELPER_RESTRICTED_SID_ATTRIBUTES: u32 =
    (SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED) as u32;
const AUTHENTICODE_HELPER_SET_INTEGRITY_SID_ATTRIBUTES: u32 = SE_GROUP_INTEGRITY as u32;
const AUTHENTICODE_HELPER_READBACK_INTEGRITY_SID_ATTRIBUTES: u32 =
    (SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED) as u32;
const AUTHENTICODE_HELPER_SID_STORAGE_WORDS: usize =
    (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<usize>());
const MAX_AUTHENTICODE_HELPER_ATTRIBUTE_LIST_BYTES: usize = 64 * 1024;
const AUTHENTICODE_HELPER_ATTRIBUTE_COUNT: u32 = 2;
// windows-sys 0.61.2 binds the attribute key but not these documented policy values.
const AUTHENTICODE_HELPER_STRICT_HANDLE_CHECKS: u64 = 1u64 << 24;
const AUTHENTICODE_HELPER_EXTENSION_POINT_DISABLE: u64 = 1u64 << 32;
const AUTHENTICODE_HELPER_PROHIBIT_DYNAMIC_CODE: u64 = 1u64 << 36;
const AUTHENTICODE_HELPER_MICROSOFT_SIGNED_ONLY: u64 = 1u64 << 44;
const AUTHENTICODE_HELPER_NO_REMOTE_IMAGES: u64 = 1u64 << 52;
const AUTHENTICODE_HELPER_NO_LOW_LABEL_IMAGES: u64 = 1u64 << 56;
const AUTHENTICODE_HELPER_PREFER_SYSTEM32_IMAGES: u64 = 1u64 << 60;
const AUTHENTICODE_HELPER_PROCESS_MITIGATION_POLICY: u64 = AUTHENTICODE_HELPER_STRICT_HANDLE_CHECKS
    | AUTHENTICODE_HELPER_EXTENSION_POINT_DISABLE
    | AUTHENTICODE_HELPER_PROHIBIT_DYNAMIC_CODE
    | AUTHENTICODE_HELPER_MICROSOFT_SIGNED_ONLY
    | AUTHENTICODE_HELPER_NO_REMOTE_IMAGES
    | AUTHENTICODE_HELPER_NO_LOW_LABEL_IMAGES
    | AUTHENTICODE_HELPER_PREFER_SYSTEM32_IMAGES;
const AUTHENTICODE_HELPER_SIGNATURE_REQUIRED_FLAGS: u32 = 0b0001;
const AUTHENTICODE_HELPER_SIGNATURE_SELECTION_MASK: u32 = 0b0011;
const AUTHENTICODE_HELPER_DYNAMIC_CODE_REQUIRED_FLAGS: u32 = 0b0001;
const AUTHENTICODE_HELPER_EXTENSION_POINT_REQUIRED_FLAGS: u32 = 0b0001;
const AUTHENTICODE_HELPER_IMAGE_LOAD_REQUIRED_FLAGS: u32 = 0b0111;
const AUTHENTICODE_HELPER_STRICT_HANDLE_REQUIRED_FLAGS: u32 = 0b0011;
const AUTHENTICODE_HELPER_ENVIRONMENT_NAMES: [&str; 2] = ["SystemRoot", "WINDIR"];
const AUTHENTICODE_HELPER_TERMINATION_EXIT_CODE: u32 = 0xA710_0001;

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

struct SanitizedAuthenticodeLaunchContext {
    environment: Vec<u16>,
    current_directory: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenSidEvidence {
    sid: Vec<u8>,
    attributes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthenticodeProcessMitigationEvidence {
    signature: u32,
    dynamic_code: u32,
    extension_point: u32,
    image_load: u32,
    strict_handle: u32,
}

struct VerifiedWellKnownSid {
    storage: [usize; AUTHENTICODE_HELPER_SID_STORAGE_WORDS],
    length: usize,
}

impl VerifiedWellKnownSid {
    fn create(sid_type: WELL_KNOWN_SID_TYPE, label: &str) -> Result<Self> {
        let mut sid = Self {
            storage: [0; AUTHENTICODE_HELPER_SID_STORAGE_WORDS],
            length: SECURITY_MAX_SID_SIZE as usize,
        };
        let mut length = sid.length as u32;
        anyhow::ensure!(
            unsafe { CreateWellKnownSid(sid_type, null_mut(), sid.as_mut_ptr(), &mut length,) }
                != 0,
            "unable to create the Authenticode helper {label} SID: {}",
            std::io::Error::last_os_error()
        );
        sid.length = length as usize;
        anyhow::ensure!(
            sid.length >= offset_of!(SID, SubAuthority)
                && sid.length <= SECURITY_MAX_SID_SIZE as usize,
            "AuthentiCode helper {label} SID length is outside its bound"
        );
        anyhow::ensure!(
            unsafe { IsValidSid(sid.as_ptr()) } != 0,
            "AuthentiCode helper {label} SID is invalid"
        );
        anyhow::ensure!(
            unsafe { GetLengthSid(sid.as_ptr()) } as usize == sid.length,
            "AuthentiCode helper {label} SID length changed after validation"
        );
        Ok(sid)
    }

    fn as_ptr(&self) -> *mut c_void {
        self.storage.as_ptr().cast_mut().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), self.length) }
    }
}

struct OwnedToken(HANDLE);

impl OwnedToken {
    fn from_raw(handle: HANDLE, operation: &str) -> Result<Self> {
        anyhow::ensure!(
            !handle.is_null(),
            "{operation}: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(handle))
    }
}

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

struct OwnedKernelHandle(HANDLE);

impl OwnedKernelHandle {
    fn from_raw(handle: HANDLE, operation: &str) -> Result<Self> {
        anyhow::ensure!(
            !handle.is_null() && handle != INVALID_HANDLE_VALUE,
            "{operation}: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(handle))
    }

    fn into_file(mut self) -> File {
        let handle = std::mem::replace(&mut self.0, null_mut());
        unsafe { File::from_raw_handle(handle) }
    }
}

impl Drop for OwnedKernelHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
            self.0 = null_mut();
        }
    }
}

struct InheritedPipe {
    parent: OwnedKernelHandle,
    child: OwnedKernelHandle,
}

impl InheritedPipe {
    fn create(parent_reads: bool, label: &str) -> Result<Self> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let mut read = null_mut();
        let mut write = null_mut();
        anyhow::ensure!(
            unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } != 0,
            "unable to create Authenticode helper {label} pipe: {}",
            std::io::Error::last_os_error()
        );
        let read = OwnedKernelHandle::from_raw(
            read,
            &format!("unable to create Authenticode helper {label} read handle"),
        )?;
        let write = OwnedKernelHandle::from_raw(
            write,
            &format!("unable to create Authenticode helper {label} write handle"),
        )?;
        let (parent, child) = if parent_reads {
            (read, write)
        } else {
            (write, read)
        };
        anyhow::ensure!(
            unsafe { SetHandleInformation(parent.0, HANDLE_FLAG_INHERIT, 0) } != 0,
            "unable to make Authenticode helper parent {label} handle non-inheritable: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self { parent, child })
    }
}

struct ProcessThreadAttributeList {
    storage: Vec<usize>,
    pointer: *mut c_void,
    mitigation_policy: Box<u64>,
}

impl ProcessThreadAttributeList {
    fn for_authenticode_helper(handles: &[HANDLE; 3]) -> Result<Self> {
        validate_authenticode_child_handle_list(handles)?;
        let mitigation_policy = Box::new(AUTHENTICODE_HELPER_PROCESS_MITIGATION_POLICY);
        let mut required = 0usize;
        unsafe { SetLastError(ERROR_SUCCESS) };
        let sized = unsafe {
            InitializeProcThreadAttributeList(
                null_mut(),
                AUTHENTICODE_HELPER_ATTRIBUTE_COUNT,
                0,
                &mut required,
            )
        };
        let size_error = unsafe { GetLastError() };
        anyhow::ensure!(
            sized == 0 && size_error == ERROR_INSUFFICIENT_BUFFER,
            "unable to size Authenticode helper process attribute list: {}",
            std::io::Error::from_raw_os_error(size_error as i32)
        );
        anyhow::ensure!(
            required > 0 && required <= MAX_AUTHENTICODE_HELPER_ATTRIBUTE_LIST_BYTES,
            "AuthentiCode helper process attribute list is outside its byte bound"
        );
        let words = required.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words];
        let pointer = storage.as_mut_ptr().cast::<c_void>();
        anyhow::ensure!(
            unsafe {
                InitializeProcThreadAttributeList(
                    pointer.cast(),
                    AUTHENTICODE_HELPER_ATTRIBUTE_COUNT,
                    0,
                    &mut required,
                )
            } != 0,
            "unable to initialize Authenticode helper process attribute list: {}",
            std::io::Error::last_os_error()
        );
        let updated = unsafe {
            UpdateProcThreadAttribute(
                pointer.cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast::<c_void>(),
                size_of::<[HANDLE; 3]>(),
                null_mut(),
                null(),
            )
        };
        if updated == 0 {
            let error = std::io::Error::last_os_error();
            unsafe { DeleteProcThreadAttributeList(pointer.cast()) };
            anyhow::bail!("unable to restrict Authenticode helper inherited handles: {error}");
        }
        let updated = unsafe {
            UpdateProcThreadAttribute(
                pointer.cast(),
                0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
                mitigation_policy.as_ref() as *const u64 as *mut c_void,
                size_of::<u64>(),
                null_mut(),
                null(),
            )
        };
        if updated == 0 {
            let error = std::io::Error::last_os_error();
            unsafe { DeleteProcThreadAttributeList(pointer.cast()) };
            anyhow::bail!(
                "unable to apply the Authenticode helper process mitigation policy: {error}"
            );
        }
        Ok(Self {
            storage,
            pointer,
            mitigation_policy,
        })
    }

    fn pointer(&self) -> *mut c_void {
        let _keep_storage_alive = &self.storage;
        let _keep_mitigation_policy_alive = &self.mitigation_policy;
        self.pointer
    }
}

impl Drop for ProcessThreadAttributeList {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            unsafe { DeleteProcThreadAttributeList(self.pointer.cast()) };
            self.pointer = null_mut();
        }
    }
}

struct RestrictedAuthenticodeProcess {
    process: OwnedKernelHandle,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
}

impl RestrictedAuthenticodeProcess {
    fn try_wait(&self) -> Result<Option<ExitStatus>> {
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                anyhow::ensure!(
                    unsafe { GetExitCodeProcess(self.process.0, &mut code) } != 0,
                    "unable to read Authenticode helper exit code: {}",
                    std::io::Error::last_os_error()
                );
                Ok(Some(ExitStatus::from_raw(code)))
            }
            WAIT_FAILED => anyhow::bail!(
                "unable to poll Authenticode helper: {}",
                std::io::Error::last_os_error()
            ),
            status => anyhow::bail!("unexpected Authenticode helper wait status {status}"),
        }
    }

    fn terminate(&self) -> Result<()> {
        anyhow::ensure!(
            unsafe { TerminateProcess(self.process.0, AUTHENTICODE_HELPER_TERMINATION_EXIT_CODE) }
                != 0,
            "unable to terminate Authenticode helper: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
}

fn validate_authenticode_child_handle_list(handles: &[HANDLE; 3]) -> Result<()> {
    for handle in handles {
        anyhow::ensure!(
            !handle.is_null() && *handle != INVALID_HANDLE_VALUE,
            "AuthentiCode helper inherited handle list contains an invalid handle"
        );
    }
    anyhow::ensure!(
        handles[0] != handles[1] && handles[0] != handles[2] && handles[1] != handles[2],
        "AuthentiCode helper inherited handle list contains a duplicate handle"
    );
    Ok(())
}

struct RestrictedAuthenticodeThreadToken {
    token: OwnedToken,
    active: bool,
}

impl RestrictedAuthenticodeThreadToken {
    fn enter() -> Result<Self> {
        anyhow::ensure!(
            open_current_thread_token()?.is_none(),
            "AuthentiCode helper thread already has an impersonation token"
        );

        let mut process_token = null_mut();
        anyhow::ensure!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY,
                    &mut process_token,
                )
            } != 0,
            "unable to open Authenticode helper process token: {}",
            std::io::Error::last_os_error()
        );
        let process_token = OwnedToken::from_raw(
            process_token,
            "unable to open Authenticode helper process token",
        )?;

        let mut impersonation_token = null_mut();
        anyhow::ensure!(
            unsafe {
                DuplicateTokenEx(
                    process_token.0,
                    TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
                    null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut impersonation_token,
                )
            } != 0,
            "unable to duplicate Authenticode helper impersonation token: {}",
            std::io::Error::last_os_error()
        );
        let impersonation_token = OwnedToken::from_raw(
            impersonation_token,
            "unable to duplicate Authenticode helper impersonation token",
        )?;

        let restricted_token = create_write_restricted_token(
            impersonation_token.0,
            "unable to create the Authenticode helper restricted impersonation token",
        )?;
        validate_restricted_authenticode_impersonation_token(restricted_token.0)?;

        anyhow::ensure!(
            unsafe { SetThreadToken(null(), restricted_token.0) } != 0,
            "unable to apply write-restricted Authenticode helper token: {}",
            std::io::Error::last_os_error()
        );
        let current = match open_current_thread_token() {
            Ok(Some(token)) => token,
            Ok(None) => {
                let cleanup = revert_authenticode_helper_thread_token();
                anyhow::bail!(
                    "restricted Authenticode helper token was not present after assignment; revert: {}",
                    helper_result_summary(cleanup)
                );
            }
            Err(error) => {
                let cleanup = revert_authenticode_helper_thread_token();
                anyhow::bail!(
                    "unable to read back restricted Authenticode helper token: {error:#}; revert: {}",
                    helper_result_summary(cleanup)
                );
            }
        };
        if let Err(error) = validate_restricted_authenticode_impersonation_token(current.0) {
            let cleanup = revert_authenticode_helper_thread_token();
            anyhow::bail!(
                "restricted Authenticode helper token read-back failed: {error:#}; revert: {}",
                helper_result_summary(cleanup)
            );
        }

        Ok(Self {
            token: restricted_token,
            active: true,
        })
    }

    fn finish<T>(mut self, operation: Result<T>) -> Result<T> {
        let reverted = revert_authenticode_helper_thread_token();
        if reverted.is_ok() {
            self.active = false;
        }
        match (operation, reverted) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(revert_error)) => Err(revert_error),
            (Err(error), Err(revert_error)) => Err(anyhow::anyhow!(
                "AuthentiCode verification failed: {error:#}; additionally unable to revert restricted helper token: {revert_error:#}"
            )),
        }
    }
}

impl Drop for RestrictedAuthenticodeThreadToken {
    fn drop(&mut self) {
        let _keep_token_alive = &self.token;
        if self.active {
            let _ = revert_authenticode_helper_thread_token();
        }
    }
}

fn open_current_thread_token() -> Result<Option<OwnedToken>> {
    let mut token = null_mut();
    unsafe { SetLastError(ERROR_SUCCESS) };
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        return OwnedToken::from_raw(token, "unable to open Authenticode helper thread token")
            .map(Some);
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_NO_TOKEN {
        Ok(None)
    } else {
        anyhow::bail!(
            "unable to inspect Authenticode helper thread token: {}",
            std::io::Error::from_raw_os_error(error as i32)
        )
    }
}

fn revert_authenticode_helper_thread_token() -> Result<()> {
    anyhow::ensure!(
        unsafe { RevertToSelf() } != 0,
        "unable to revert restricted Authenticode helper token: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn query_token_scalar<T: Copy>(token: HANDLE, class: i32, label: &str) -> Result<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let mut returned = 0u32;
    anyhow::ensure!(
        unsafe {
            GetTokenInformation(
                token,
                class,
                value.as_mut_ptr().cast::<c_void>(),
                size_of::<T>() as u32,
                &mut returned,
            )
        } != 0,
        "unable to query Authenticode helper token {label}: {}",
        std::io::Error::last_os_error()
    );
    anyhow::ensure!(
        returned as usize == size_of::<T>(),
        "AuthentiCode helper token {label} returned an unexpected size"
    );
    Ok(unsafe { value.assume_init() })
}

fn validate_restricted_authenticode_impersonation_token(token: HANDLE) -> Result<()> {
    let token_type: i32 = query_token_scalar(token, TokenType, "type")?;
    anyhow::ensure!(
        token_type == TokenImpersonation,
        "AuthentiCode helper token is not an impersonation token"
    );
    let level: i32 = query_token_scalar(token, TokenImpersonationLevel, "impersonation level")?;
    anyhow::ensure!(
        level == SecurityImpersonation,
        "AuthentiCode helper token impersonation level mismatch"
    );

    validate_restricted_authenticode_token(token)
}

fn create_low_integrity_privilege_stripped_primary_token() -> Result<OwnedToken> {
    let mut process_token = null_mut();
    anyhow::ensure!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                &mut process_token,
            )
        } != 0,
        "unable to open Authenticode parent process token for restricted launch: {}",
        std::io::Error::last_os_error()
    );
    let process_token = OwnedToken::from_raw(
        process_token,
        "unable to open Authenticode parent process token for restricted launch",
    )?;
    let mut restricted_token = null_mut();
    anyhow::ensure!(
        unsafe {
            CreateRestrictedToken(
                process_token.0,
                DISABLE_MAX_PRIVILEGE,
                0,
                null(),
                0,
                null(),
                0,
                null(),
                &mut restricted_token,
            )
        } != 0,
        "unable to create the Authenticode helper privilege-stripped primary token: {}",
        std::io::Error::last_os_error()
    );
    let restricted_token = OwnedToken::from_raw(
        restricted_token,
        "unable to create the Authenticode helper privilege-stripped primary token",
    )?;
    set_authenticode_token_low_integrity(restricted_token.0)?;
    validate_authenticode_primary_token(restricted_token.0)?;
    Ok(restricted_token)
}

fn set_authenticode_token_low_integrity(token: HANDLE) -> Result<()> {
    let low_integrity_sid = VerifiedWellKnownSid::create(WinLowLabelSid, "Low Mandatory Level")?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low_integrity_sid.as_ptr(),
            Attributes: AUTHENTICODE_HELPER_SET_INTEGRITY_SID_ATTRIBUTES,
        },
    };
    let information_length = size_of::<TOKEN_MANDATORY_LABEL>()
        .checked_add(low_integrity_sid.length)
        .and_then(|length| u32::try_from(length).ok())
        .context("AuthentiCode helper low-integrity token information size overflow")?;
    anyhow::ensure!(
        unsafe {
            SetTokenInformation(
                token,
                TokenIntegrityLevel,
                (&label as *const TOKEN_MANDATORY_LABEL).cast::<c_void>(),
                information_length,
            )
        } != 0,
        "unable to set the Authenticode helper primary token to low integrity: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn create_write_restricted_token(existing: HANDLE, operation: &str) -> Result<OwnedToken> {
    let restricted_code_sid =
        VerifiedWellKnownSid::create(WinRestrictedCodeSid, "Restricted Code")?;
    let sid_to_restrict = SID_AND_ATTRIBUTES {
        Sid: restricted_code_sid.as_ptr(),
        Attributes: 0,
    };
    let mut restricted_token = null_mut();
    anyhow::ensure!(
        unsafe {
            CreateRestrictedToken(
                existing,
                DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,
                0,
                null(),
                0,
                null(),
                1,
                &sid_to_restrict,
                &mut restricted_token,
            )
        } != 0,
        "{operation}: {}",
        std::io::Error::last_os_error()
    );
    OwnedToken::from_raw(restricted_token, operation)
}

fn validate_current_process_authenticode_primary_token() -> Result<()> {
    let mut token = null_mut();
    anyhow::ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "unable to open Authenticode helper process token for read-back: {}",
        std::io::Error::last_os_error()
    );
    let token = OwnedToken::from_raw(
        token,
        "unable to open Authenticode helper process token for read-back",
    )?;
    validate_authenticode_primary_token(token.0)
}

fn validate_current_process_authenticode_mitigations() -> Result<()> {
    let evidence = AuthenticodeProcessMitigationEvidence {
        signature: query_current_process_mitigation_flags(
            ProcessSignaturePolicy,
            "binary-signature",
        )?,
        dynamic_code: query_current_process_mitigation_flags(
            ProcessDynamicCodePolicy,
            "dynamic-code",
        )?,
        extension_point: query_current_process_mitigation_flags(
            ProcessExtensionPointDisablePolicy,
            "extension-point",
        )?,
        image_load: query_current_process_mitigation_flags(ProcessImageLoadPolicy, "image-load")?,
        strict_handle: query_current_process_mitigation_flags(
            ProcessStrictHandleCheckPolicy,
            "strict-handle",
        )?,
    };
    validate_authenticode_process_mitigation_evidence(evidence)
}

fn query_current_process_mitigation_flags(policy: i32, label: &str) -> Result<u32> {
    let mut flags = 0u32;
    anyhow::ensure!(
        unsafe {
            GetProcessMitigationPolicy(
                GetCurrentProcess(),
                policy,
                (&mut flags as *mut u32).cast::<c_void>(),
                size_of::<u32>(),
            )
        } != 0,
        "unable to read back Authenticode helper {label} mitigation policy: {}",
        std::io::Error::last_os_error()
    );
    Ok(flags)
}

fn validate_authenticode_process_mitigation_evidence(
    evidence: AuthenticodeProcessMitigationEvidence,
) -> Result<()> {
    anyhow::ensure!(
        evidence.signature & AUTHENTICODE_HELPER_SIGNATURE_SELECTION_MASK
            == AUTHENTICODE_HELPER_SIGNATURE_REQUIRED_FLAGS,
        "AuthentiCode helper Microsoft-signed-only image policy is not active"
    );
    anyhow::ensure!(
        evidence.dynamic_code & AUTHENTICODE_HELPER_DYNAMIC_CODE_REQUIRED_FLAGS
            == AUTHENTICODE_HELPER_DYNAMIC_CODE_REQUIRED_FLAGS,
        "AuthentiCode helper dynamic-code prohibition is not active"
    );
    anyhow::ensure!(
        evidence.extension_point & AUTHENTICODE_HELPER_EXTENSION_POINT_REQUIRED_FLAGS
            == AUTHENTICODE_HELPER_EXTENSION_POINT_REQUIRED_FLAGS,
        "AuthentiCode helper extension-point disable policy is not active"
    );
    anyhow::ensure!(
        evidence.image_load & AUTHENTICODE_HELPER_IMAGE_LOAD_REQUIRED_FLAGS
            == AUTHENTICODE_HELPER_IMAGE_LOAD_REQUIRED_FLAGS,
        "AuthentiCode helper remote/low-label/System32 image policy is incomplete"
    );
    anyhow::ensure!(
        evidence.strict_handle & AUTHENTICODE_HELPER_STRICT_HANDLE_REQUIRED_FLAGS
            == AUTHENTICODE_HELPER_STRICT_HANDLE_REQUIRED_FLAGS,
        "AuthentiCode helper permanent strict-handle policy is not active"
    );
    Ok(())
}

fn validate_authenticode_primary_token(token: HANDLE) -> Result<()> {
    let token_type: i32 = query_token_scalar(token, TokenType, "type")?;
    anyhow::ensure!(
        token_type == TokenPrimary,
        "AuthentiCode helper process token is not a primary token"
    );
    validate_privilege_stripped_token_privileges(token)?;
    let integrity = query_token_integrity_label(token)?;
    let expected = VerifiedWellKnownSid::create(WinLowLabelSid, "Low Mandatory Level")?;
    validate_authenticode_integrity_label_evidence(&integrity, expected.as_bytes())?;
    let mandatory_policy: TOKEN_MANDATORY_POLICY =
        query_token_scalar(token, TokenMandatoryPolicy, "mandatory integrity policy")?;
    validate_authenticode_mandatory_policy(mandatory_policy.Policy)
}

fn validate_restricted_authenticode_token(token: HANDLE) -> Result<()> {
    validate_privilege_stripped_token_privileges(token)?;
    let restricted_sids = query_token_restricted_sids(token)?;
    let expected = VerifiedWellKnownSid::create(WinRestrictedCodeSid, "Restricted Code")?;
    validate_authenticode_restricted_sid_evidence(&restricted_sids, expected.as_bytes())
}

fn validate_privilege_stripped_token_privileges(token: HANDLE) -> Result<()> {
    let entries = query_token_privileges(token)?;
    let mut allowed = LUID::default();
    anyhow::ensure!(
        unsafe { LookupPrivilegeValueW(null(), SE_CHANGE_NOTIFY_NAME, &mut allowed) } != 0,
        "unable to resolve the Authenticode helper traverse privilege: {}",
        std::io::Error::last_os_error()
    );
    validate_enabled_authenticode_privileges(&entries, allowed)
}

fn query_token_integrity_label(token: HANDLE) -> Result<TokenSidEvidence> {
    let mut required = 0u32;
    unsafe { SetLastError(ERROR_SUCCESS) };
    let first =
        unsafe { GetTokenInformation(token, TokenIntegrityLevel, null_mut(), 0, &mut required) };
    let first_error = unsafe { GetLastError() };
    anyhow::ensure!(
        first == 0 && first_error == ERROR_INSUFFICIENT_BUFFER,
        "unable to size Authenticode helper token integrity label: {}",
        std::io::Error::from_raw_os_error(first_error as i32)
    );
    let required = required as usize;
    anyhow::ensure!(
        required >= size_of::<TOKEN_MANDATORY_LABEL>()
            && required <= MAX_AUTHENTICODE_HELPER_TOKEN_INFO_BYTES,
        "AuthentiCode helper token integrity-label data is outside its byte bound"
    );
    let words = required.div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    let mut returned = 0u32;
    anyhow::ensure!(
        unsafe {
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                buffer.as_mut_ptr().cast::<c_void>(),
                required as u32,
                &mut returned,
            )
        } != 0,
        "unable to query Authenticode helper token integrity label: {}",
        std::io::Error::last_os_error()
    );
    let returned = returned as usize;
    anyhow::ensure!(
        returned >= size_of::<TOKEN_MANDATORY_LABEL>() && returned <= required,
        "AuthentiCode helper token integrity-label data returned an invalid size"
    );
    let mandatory_label = unsafe { &*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
    token_sid_evidence_from_entry(&buffer, returned, &mandatory_label.Label, "integrity label")
}

fn query_token_privileges(token: HANDLE) -> Result<Vec<LUID_AND_ATTRIBUTES>> {
    let mut required = 0u32;
    unsafe { SetLastError(ERROR_SUCCESS) };
    let first =
        unsafe { GetTokenInformation(token, TokenPrivileges, null_mut(), 0, &mut required) };
    let first_error = unsafe { GetLastError() };
    anyhow::ensure!(
        first == 0 && first_error == ERROR_INSUFFICIENT_BUFFER,
        "unable to size Authenticode helper token privileges: {}",
        std::io::Error::from_raw_os_error(first_error as i32)
    );
    let required = required as usize;
    anyhow::ensure!(
        required >= size_of::<TOKEN_PRIVILEGES>()
            && required <= MAX_AUTHENTICODE_HELPER_TOKEN_INFO_BYTES,
        "AuthentiCode helper token privilege data is outside its byte bound"
    );
    let words = required.div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    let mut returned = 0u32;
    anyhow::ensure!(
        unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                buffer.as_mut_ptr().cast::<c_void>(),
                required as u32,
                &mut returned,
            )
        } != 0,
        "unable to query Authenticode helper token privileges: {}",
        std::io::Error::last_os_error()
    );
    anyhow::ensure!(
        returned as usize <= required && returned as usize >= size_of::<TOKEN_PRIVILEGES>(),
        "AuthentiCode helper token privilege data returned an invalid size"
    );

    let privileges = unsafe { &*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let count = privileges.PrivilegeCount as usize;
    anyhow::ensure!(
        count <= MAX_AUTHENTICODE_HELPER_TOKEN_PRIVILEGES,
        "AuthentiCode helper token privilege count exceeds {}",
        MAX_AUTHENTICODE_HELPER_TOKEN_PRIVILEGES
    );
    let entries_bytes = count
        .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
        .and_then(|bytes| bytes.checked_add(offset_of!(TOKEN_PRIVILEGES, Privileges)))
        .context("AuthentiCode helper token privilege size overflow")?;
    anyhow::ensure!(
        entries_bytes <= returned as usize,
        "AuthentiCode helper token privilege count exceeds returned data"
    );
    let entries = unsafe { std::slice::from_raw_parts(privileges.Privileges.as_ptr(), count) };
    Ok(entries.to_vec())
}

fn query_token_restricted_sids(token: HANDLE) -> Result<Vec<TokenSidEvidence>> {
    let mut required = 0u32;
    unsafe { SetLastError(ERROR_SUCCESS) };
    let first =
        unsafe { GetTokenInformation(token, TokenRestrictedSids, null_mut(), 0, &mut required) };
    let first_error = unsafe { GetLastError() };
    anyhow::ensure!(
        first == 0 && first_error == ERROR_INSUFFICIENT_BUFFER,
        "unable to size Authenticode helper restricting SIDs: {}",
        std::io::Error::from_raw_os_error(first_error as i32)
    );
    let required = required as usize;
    anyhow::ensure!(
        required >= size_of::<TOKEN_GROUPS>()
            && required <= MAX_AUTHENTICODE_HELPER_TOKEN_INFO_BYTES,
        "AuthentiCode helper restricting SID data is outside its byte bound"
    );
    let words = required.div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    let mut returned = 0u32;
    anyhow::ensure!(
        unsafe {
            GetTokenInformation(
                token,
                TokenRestrictedSids,
                buffer.as_mut_ptr().cast::<c_void>(),
                required as u32,
                &mut returned,
            )
        } != 0,
        "unable to query Authenticode helper restricting SIDs: {}",
        std::io::Error::last_os_error()
    );
    let returned = returned as usize;
    anyhow::ensure!(
        returned >= size_of::<TOKEN_GROUPS>() && returned <= required,
        "AuthentiCode helper restricting SID data returned an invalid size"
    );

    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let count = groups.GroupCount as usize;
    anyhow::ensure!(
        count > 0 && count <= MAX_AUTHENTICODE_HELPER_RESTRICTED_SIDS,
        "AuthentiCode helper restricting SID count is outside 1..={} entries",
        MAX_AUTHENTICODE_HELPER_RESTRICTED_SIDS
    );
    let entries_end = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|bytes| bytes.checked_add(offset_of!(TOKEN_GROUPS, Groups)))
        .context("AuthentiCode helper restricting SID entry size overflow")?;
    anyhow::ensure!(
        entries_end <= returned,
        "AuthentiCode helper restricting SID count exceeds returned data"
    );
    let entries = unsafe {
        std::slice::from_raw_parts(
            buffer
                .as_ptr()
                .cast::<u8>()
                .add(offset_of!(TOKEN_GROUPS, Groups))
                .cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let mut evidence = Vec::with_capacity(count);
    for entry in entries {
        evidence.push(token_sid_evidence_from_entry(
            &buffer,
            returned,
            entry,
            "restricting SID",
        )?);
    }
    Ok(evidence)
}

fn token_sid_evidence_from_entry(
    buffer: &[usize],
    returned: usize,
    entry: &SID_AND_ATTRIBUTES,
    label: &str,
) -> Result<TokenSidEvidence> {
    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start
        .checked_add(returned)
        .context("AuthentiCode helper token SID buffer size overflow")?;
    let minimum_sid_bytes = offset_of!(SID, SubAuthority);
    let sid_start = entry.Sid as usize;
    let sid_header_end = sid_start
        .checked_add(minimum_sid_bytes)
        .context("AuthentiCode helper token SID header overflow")?;
    anyhow::ensure!(
        sid_start >= buffer_start && sid_header_end <= buffer_end,
        "AuthentiCode helper token {label} pointer is outside returned data"
    );
    let sub_authority_count = unsafe {
        entry
            .Sid
            .cast::<u8>()
            .add(offset_of!(SID, SubAuthorityCount))
            .read()
    } as usize;
    let sid_length = sub_authority_count
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| bytes.checked_add(minimum_sid_bytes))
        .context("AuthentiCode helper token SID length overflow")?;
    anyhow::ensure!(
        sid_length >= minimum_sid_bytes && sid_length <= SECURITY_MAX_SID_SIZE as usize,
        "AuthentiCode helper token {label} length is outside its byte bound"
    );
    let sid_end = sid_start
        .checked_add(sid_length)
        .context("AuthentiCode helper token SID range overflow")?;
    anyhow::ensure!(
        sid_end <= buffer_end,
        "AuthentiCode helper token {label} exceeds returned data"
    );
    anyhow::ensure!(
        unsafe { IsValidSid(entry.Sid) } != 0,
        "AuthentiCode helper token {label} is invalid"
    );
    anyhow::ensure!(
        unsafe { GetLengthSid(entry.Sid) } as usize == sid_length,
        "AuthentiCode helper token {label} length changed after validation"
    );
    let sid = unsafe { std::slice::from_raw_parts(entry.Sid.cast::<u8>(), sid_length) };
    Ok(TokenSidEvidence {
        sid: sid.to_vec(),
        attributes: entry.Attributes,
    })
}

fn validate_authenticode_integrity_label_evidence(
    evidence: &TokenSidEvidence,
    expected_low_integrity_sid: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        evidence.sid == expected_low_integrity_sid,
        "AuthentiCode helper primary token does not contain the exact Low Mandatory Level SID"
    );
    anyhow::ensure!(
        evidence.attributes & AUTHENTICODE_HELPER_SET_INTEGRITY_SID_ATTRIBUTES
            == AUTHENTICODE_HELPER_SET_INTEGRITY_SID_ATTRIBUTES,
        "AuthentiCode helper primary token integrity label is not marked as an integrity SID"
    );
    anyhow::ensure!(
        evidence.attributes & !AUTHENTICODE_HELPER_READBACK_INTEGRITY_SID_ATTRIBUTES == 0,
        "AuthentiCode helper primary token integrity label has unexpected attributes"
    );
    Ok(())
}

fn validate_authenticode_mandatory_policy(policy: u32) -> Result<()> {
    anyhow::ensure!(
        policy & TOKEN_MANDATORY_POLICY_NO_WRITE_UP == TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        "AuthentiCode helper primary token mandatory policy does not enforce no-write-up"
    );
    anyhow::ensure!(
        policy & !TOKEN_MANDATORY_POLICY_VALID_MASK == 0,
        "AuthentiCode helper primary token mandatory policy contains unknown bits"
    );
    Ok(())
}

fn validate_authenticode_restricted_sid_evidence(
    entries: &[TokenSidEvidence],
    expected_restricted_code_sid: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        entries.len() == 1,
        "AuthentiCode helper token must contain exactly one restricting SID"
    );
    anyhow::ensure!(
        entries[0].attributes == AUTHENTICODE_HELPER_RESTRICTED_SID_ATTRIBUTES,
        "AuthentiCode helper restricting SID attributes must be exactly 0x{:08X}, found 0x{:08X}",
        AUTHENTICODE_HELPER_RESTRICTED_SID_ATTRIBUTES,
        entries[0].attributes
    );
    anyhow::ensure!(
        entries[0].sid == expected_restricted_code_sid,
        "AuthentiCode helper token does not contain the exact Restricted Code SID"
    );
    Ok(())
}

fn validate_enabled_authenticode_privileges(
    entries: &[LUID_AND_ATTRIBUTES],
    allowed_traverse: LUID,
) -> Result<()> {
    for entry in entries {
        if entry.Attributes & SE_PRIVILEGE_ENABLED == 0 {
            continue;
        }
        anyhow::ensure!(
            entry.Luid.LowPart == allowed_traverse.LowPart
                && entry.Luid.HighPart == allowed_traverse.HighPart,
            "privilege-stripped Authenticode helper token retained an unexpected enabled privilege"
        );
    }
    Ok(())
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
        let limits = required_authenticode_helper_job_limits();
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
        if let Err(error) = query_and_validate_authenticode_helper_job_limits(handle) {
            unsafe { CloseHandle(handle) };
            return Err(error);
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

fn required_authenticode_helper_job_limits() -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.BasicLimitInformation.PerProcessUserTimeLimit = AUTHENTICODE_HELPER_USER_CPU_100NS;
    limits.BasicLimitInformation.ActiveProcessLimit = AUTHENTICODE_HELPER_ACTIVE_PROCESS_LIMIT;
    limits.ProcessMemoryLimit = AUTHENTICODE_HELPER_PROCESS_MEMORY_BYTES;
    limits.JobMemoryLimit = AUTHENTICODE_HELPER_JOB_MEMORY_BYTES;
    limits
}

fn query_and_validate_authenticode_helper_job_limits(
    handle: HANDLE,
) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION> {
    let mut actual = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    anyhow::ensure!(
        unsafe {
            QueryInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&mut actual as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                null_mut(),
            )
        } != 0,
        "unable to query isolated Authenticode helper job limits: {}",
        std::io::Error::last_os_error()
    );
    validate_authenticode_helper_job_limits(&actual)?;
    Ok(actual)
}

fn validate_authenticode_helper_job_limits(
    actual: &JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
) -> Result<()> {
    let required = required_authenticode_helper_job_limits();
    anyhow::ensure!(
        actual.BasicLimitInformation.LimitFlags == required.BasicLimitInformation.LimitFlags,
        "isolated Authenticode helper job limit flags mismatch"
    );
    anyhow::ensure!(
        actual.BasicLimitInformation.PerProcessUserTimeLimit
            == required.BasicLimitInformation.PerProcessUserTimeLimit,
        "isolated Authenticode helper per-process user-CPU limit mismatch"
    );
    anyhow::ensure!(
        actual.BasicLimitInformation.ActiveProcessLimit
            == required.BasicLimitInformation.ActiveProcessLimit,
        "isolated Authenticode helper active-process limit mismatch"
    );
    anyhow::ensure!(
        actual.ProcessMemoryLimit == required.ProcessMemoryLimit,
        "isolated Authenticode helper per-process commit limit mismatch"
    );
    anyhow::ensure!(
        actual.JobMemoryLimit == required.JobMemoryLimit,
        "isolated Authenticode helper job commit limit mismatch"
    );
    Ok(())
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
enum AuthenticodeSignatureVerdict {
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

struct PreparedAuthenticodeVerification {
    path: PathBuf,
    expected_sha256: String,
    path_wide: Vec<u16>,
    file: File,
    before: AuthenticodeFileSnapshot,
}

pub(crate) fn has_valid_microsoft_signature(path: &Path, expected_sha256: &str) -> Result<bool> {
    if cfg!(debug_assertions) {
        return verify_direct_microsoft_signature(path, expected_sha256);
    }
    verify_with_isolated_helper(path, expected_sha256)
}

fn verify_direct_microsoft_signature(path: &Path, expected_sha256: &str) -> Result<bool> {
    verify_prepared_microsoft_signature(prepare_microsoft_signature_verification(
        path,
        expected_sha256,
    )?)
}

fn prepare_microsoft_signature_verification(
    path: &Path,
    expected_sha256: &str,
) -> Result<PreparedAuthenticodeVerification> {
    validate_expected_sha256(expected_sha256)?;
    let path_wide = absolute_path_wide(path)?;
    let file = open_authenticode_candidate(path)?;
    enforce_content_binding_size(path, &file)?;
    let before = snapshot_authenticode_file(path, &file)?;
    Ok(PreparedAuthenticodeVerification {
        path: path.to_path_buf(),
        expected_sha256: expected_sha256.to_string(),
        path_wide,
        file,
        before,
    })
}

fn verify_prepared_microsoft_signature(prepared: PreparedAuthenticodeVerification) -> Result<bool> {
    let PreparedAuthenticodeVerification {
        path,
        expected_sha256,
        path_wide,
        mut file,
        before,
    } = prepared;
    let verdict = match verify_open_file(&path, &path_wide, &mut file, &expected_sha256) {
        Ok(true) => Ok(true),
        Ok(false) => verify_catalog_signatures(&path, &path_wide, &mut file, &expected_sha256),
        Err(error) => Err(error),
    };
    let after = snapshot_authenticode_file(&path, &file);
    combine_verdict_and_file_snapshot(&path, verdict, before, after)
}

pub(crate) fn run_authenticode_helper_stdio() -> Result<()> {
    validate_current_process_authenticode_primary_token()?;
    validate_current_process_authenticode_mitigations()?;
    let restricted = RestrictedAuthenticodeThreadToken::enter()?;
    let (nonce, prepared) = restricted.finish(read_and_prepare_authenticode_helper_request())?;
    let outcome = prepared.and_then(verify_prepared_microsoft_signature);
    let restricted = RestrictedAuthenticodeThreadToken::enter()?;
    restricted.finish(write_authenticode_helper_response(nonce, outcome))
}

pub(crate) fn run_authenticode_client_self_test_stdio() -> Result<()> {
    run_authenticode_stdio(has_valid_microsoft_signature)
}

fn run_authenticode_stdio(verify: impl FnOnce(&Path, &str) -> Result<bool>) -> Result<()> {
    let request = read_authenticode_helper_request(std::io::stdin().lock())?;
    let nonce = validate_authenticode_helper_request(&request)?;
    let path = PathBuf::from(OsString::from_wide(&request.path_utf16));
    let outcome = verify(&path, &request.expected_sha256);
    write_authenticode_helper_response(nonce, outcome)
}

fn read_and_prepare_authenticode_helper_request(
) -> Result<(String, Result<PreparedAuthenticodeVerification>)> {
    let request = read_authenticode_helper_request(std::io::stdin().lock())?;
    let nonce = validate_authenticode_helper_request(&request)?;
    let path = PathBuf::from(OsString::from_wide(&request.path_utf16));
    let prepared = prepare_microsoft_signature_verification(&path, &request.expected_sha256);
    Ok((nonce, prepared))
}

fn write_authenticode_helper_response(nonce: String, outcome: Result<bool>) -> Result<()> {
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
    let output = run_bounded_authenticode_helper(
        &host_path,
        &[AUTHENTICODE_HELPER_ARGUMENT],
        encoded,
        AUTHENTICODE_HELPER_TIMEOUT,
    )?;
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
    application: &Path,
    arguments: &[&str],
    request: Vec<u8>,
    timeout: Duration,
) -> Result<AuthenticodeHelperOutput> {
    let job = KillOnCloseJob::create()?;
    let mut child = spawn_restricted_authenticode_process(application, arguments, &job)?;
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
            let kill_result = child.terminate();
            drop(job);
            let reaped = wait_for_child_exit(&child, AUTHENTICODE_HELPER_REAP_TIMEOUT);
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

fn spawn_restricted_authenticode_process(
    application: &Path,
    arguments: &[&str],
    job: &KillOnCloseJob,
) -> Result<RestrictedAuthenticodeProcess> {
    let application_wide = absolute_application_path_wide(application)?;
    let mut command_line = restricted_process_command_line(application, arguments)?;
    let launch_context = sanitized_authenticode_launch_context()?;
    let token = create_low_integrity_privilege_stripped_primary_token()?;
    let stdin = InheritedPipe::create(false, "stdin")?;
    let stdout = InheritedPipe::create(true, "stdout")?;
    let stderr = InheritedPipe::create(true, "stderr")?;
    let inherited = [stdin.child.0, stdout.child.0, stderr.child.0];
    let attributes = ProcessThreadAttributeList::for_authenticode_helper(&inherited)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.child.0;
    startup.StartupInfo.hStdOutput = stdout.child.0;
    startup.StartupInfo.hStdError = stderr.child.0;
    startup.lpAttributeList = attributes.pointer().cast();
    let mut process_info = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessAsUserW(
            token.0,
            application_wide.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_NO_WINDOW
                | CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            launch_context.environment.as_ptr().cast::<c_void>(),
            launch_context.current_directory.as_ptr(),
            &startup.StartupInfo as *const _,
            &mut process_info,
        )
    };
    anyhow::ensure!(
        created != 0,
        "unable to start Authenticode helper with a privilege-stripped primary token: {}",
        std::io::Error::last_os_error()
    );
    let process = OwnedKernelHandle::from_raw(
        process_info.hProcess,
        "AuthentiCode restricted process creation returned no process handle",
    )?;
    let thread_handle = OwnedKernelHandle::from_raw(
        process_info.hThread,
        "AuthentiCode restricted process creation returned no thread handle",
    )?;
    drop(stdin.child);
    drop(stdout.child);
    drop(stderr.child);

    if let Err(error) = job.assign(process.0) {
        let termination = terminate_and_reap_suspended_authenticode_process(&process);
        anyhow::bail!(
            "{error:#}; restricted suspended-process cleanup: {}",
            helper_result_summary(termination)
        );
    }
    if unsafe { ResumeThread(thread_handle.0) } == u32::MAX {
        let error = std::io::Error::last_os_error();
        let termination = terminate_and_reap_suspended_authenticode_process(&process);
        anyhow::bail!(
            "unable to resume job-assigned restricted Authenticode helper: {error}; cleanup: {}",
            helper_result_summary(termination)
        );
    }
    drop(thread_handle);
    Ok(RestrictedAuthenticodeProcess {
        process,
        stdin: Some(stdin.parent.into_file()),
        stdout: Some(stdout.parent.into_file()),
        stderr: Some(stderr.parent.into_file()),
    })
}

fn sanitized_authenticode_launch_context() -> Result<SanitizedAuthenticodeLaunchContext> {
    let windows_root = checked_system_windows_directory()
        .context("unable to resolve the Authenticode helper sanitized environment root")?;
    let current_directory = checked_system_directory(
        "System32",
        "AuthentiCode helper sanitized current directory",
    )?;
    Ok(SanitizedAuthenticodeLaunchContext {
        environment: build_authenticode_helper_environment_block(&windows_root)?,
        current_directory: absolute_launch_directory_wide(&current_directory)?,
    })
}

fn build_authenticode_helper_environment_block(windows_root: &Path) -> Result<Vec<u16>> {
    validate_authenticode_launch_directory(
        windows_root,
        "AuthentiCode helper sanitized environment root",
    )?;
    let value = windows_root.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut block =
        Vec::with_capacity(value.len() * AUTHENTICODE_HELPER_ENVIRONMENT_NAMES.len() + 32);
    for name in AUTHENTICODE_HELPER_ENVIRONMENT_NAMES {
        block.extend(name.encode_utf16());
        block.push(b'=' as u16);
        block.extend_from_slice(&value);
        block.push(0);
    }
    block.push(0);
    anyhow::ensure!(
        block.len() <= MAX_AUTHENTICODE_PATH_UTF16_UNITS,
        "AuthentiCode helper sanitized environment exceeds its UTF-16 bound"
    );
    Ok(block)
}

fn absolute_launch_directory_wide(path: &Path) -> Result<Vec<u16>> {
    validate_authenticode_launch_directory(
        path,
        "AuthentiCode helper sanitized current directory",
    )?;
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    Ok(wide)
}

fn validate_authenticode_launch_directory(path: &Path, label: &str) -> Result<()> {
    let mut components = path.components();
    anyhow::ensure!(
        matches!(
            (components.next(), components.next()),
            (Some(Component::Prefix(prefix)), Some(Component::RootDir))
                if matches!(prefix.kind(), Prefix::Disk(_))
        ) && components.all(|component| matches!(component, Component::Normal(_))),
        "{label} must be a normalized absolute local drive path"
    );
    let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    anyhow::ensure!(
        !wide.is_empty() && wide.len() < MAX_AUTHENTICODE_PATH_UTF16_UNITS,
        "{label} is outside its UTF-16 bound"
    );
    anyhow::ensure!(!wide.contains(&0), "{label} contains an embedded NUL");
    Ok(())
}

fn terminate_and_reap_suspended_authenticode_process(process: &OwnedKernelHandle) -> Result<()> {
    anyhow::ensure!(
        unsafe { TerminateProcess(process.0, AUTHENTICODE_HELPER_TERMINATION_EXIT_CODE) } != 0,
        "unable to terminate suspended Authenticode helper after launch failure: {}",
        std::io::Error::last_os_error()
    );
    let wait = unsafe {
        WaitForSingleObject(
            process.0,
            AUTHENTICODE_HELPER_REAP_TIMEOUT.as_millis() as u32,
        )
    };
    anyhow::ensure!(
        wait == WAIT_OBJECT_0,
        "suspended Authenticode helper did not terminate within {} ms (wait status {})",
        AUTHENTICODE_HELPER_REAP_TIMEOUT.as_millis(),
        wait
    );
    Ok(())
}

fn absolute_application_path_wide(path: &Path) -> Result<Vec<u16>> {
    anyhow::ensure!(
        path.is_absolute(),
        "AuthentiCode helper application path is not absolute"
    );
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    anyhow::ensure!(
        !wide.is_empty() && wide.len() < MAX_AUTHENTICODE_PATH_UTF16_UNITS,
        "AuthentiCode helper application path is outside its UTF-16 bound"
    );
    anyhow::ensure!(
        !wide.contains(&0) && !wide.contains(&(b'"' as u16)),
        "AuthentiCode helper application path contains an invalid command-line character"
    );
    wide.push(0);
    Ok(wide)
}

fn restricted_process_command_line(application: &Path, arguments: &[&str]) -> Result<Vec<u16>> {
    let application_units = application.as_os_str().encode_wide().collect::<Vec<_>>();
    anyhow::ensure!(
        !application_units.is_empty()
            && !application_units.contains(&0)
            && !application_units.contains(&(b'"' as u16)),
        "AuthentiCode helper application path cannot be encoded safely"
    );
    let mut command = Vec::with_capacity(application_units.len() + 64);
    command.push(b'"' as u16);
    command.extend(application_units);
    command.push(b'"' as u16);
    for argument in arguments {
        anyhow::ensure!(
            !argument.is_empty()
                && argument.is_ascii()
                && !argument
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte == b'"' || byte == 0),
            "AuthentiCode helper argument is outside the strict ASCII token policy"
        );
        command.push(b' ' as u16);
        command.extend(argument.encode_utf16());
    }
    command.push(0);
    anyhow::ensure!(
        command.len() <= MAX_AUTHENTICODE_PATH_UTF16_UNITS,
        "AuthentiCode helper command line exceeds its UTF-16 bound"
    );
    Ok(command)
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

fn wait_for_child_exit(child: &RestrictedAuthenticodeProcess, timeout: Duration) -> Result<()> {
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

    let primary = verify_specific_authenticode_signature(
        path,
        "embedded",
        &mut trust_data,
        &mut signature_settings,
        file,
        expected_sha256,
    )?;
    if primary == AuthenticodeSignatureVerdict::Invalid {
        return Ok(false);
    }
    let secondary_count = signature_settings.cSecondarySigs;
    aggregate_valid_authenticode_signatures(path, "embedded", primary, secondary_count, |index| {
        signature_settings.dwIndex = index;
        let verdict = verify_specific_authenticode_signature(
            path,
            "embedded",
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

fn verify_specific_authenticode_signature(
    path: &Path,
    signature_source: &str,
    trust_data: &mut WINTRUST_DATA,
    signature_settings: &mut WINTRUST_SIGNATURE_SETTINGS,
    file: &mut File,
    expected_sha256: &str,
) -> Result<AuthenticodeSignatureVerdict> {
    file.seek(SeekFrom::Start(0)).with_context(|| {
        format!(
            "unable to rewind Authenticode candidate for {signature_source} signature {} verification: {}",
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
        AuthenticodeSignatureVerdict::Invalid,
        |trust_data, file| {
            anyhow::ensure!(
                verified_signature_index_is_acceptable(
                    requested_index,
                    signature_settings.dwVerifiedSigIndex
                ),
                "WinVerifyTrust reported unexpected {signature_source} signature index {} for requested index {} for {}",
                signature_settings.dwVerifiedSigIndex,
                requested_index,
                path.display()
            );
            if verified_signer_is_microsoft(trust_data)? {
                bind_verified_signature_to_expected_hash(path, file, expected_sha256)?;
                Ok(AuthenticodeSignatureVerdict::Microsoft)
            } else {
                Ok(AuthenticodeSignatureVerdict::OtherPublisher)
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

fn aggregate_valid_authenticode_signatures<F>(
    path: &Path,
    signature_source: &str,
    primary: AuthenticodeSignatureVerdict,
    secondary_count: u32,
    mut verify_secondary: F,
) -> Result<bool>
where
    F: FnMut(u32) -> Result<AuthenticodeSignatureVerdict>,
{
    if primary == AuthenticodeSignatureVerdict::Invalid {
        return Ok(false);
    }
    let total = secondary_count
        .checked_add(1)
        .with_context(|| format!("{signature_source} Authenticode signature count overflowed"))?;
    anyhow::ensure!(
        total <= MAX_AUTHENTICODE_SIGNATURES,
        "{signature_source} Authenticode signature count {} exceeds the {} signature limit for {}",
        total,
        MAX_AUTHENTICODE_SIGNATURES,
        path.display()
    );
    if primary == AuthenticodeSignatureVerdict::Microsoft {
        return Ok(true);
    }
    for index in 1..=secondary_count {
        if verify_secondary(index)? == AuthenticodeSignatureVerdict::Microsoft {
            return Ok(true);
        }
    }
    Ok(false)
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
        pSignatureSettings: &mut signature_settings,
    };
    let primary = verify_specific_authenticode_signature(
        path,
        "catalog",
        &mut trust_data,
        &mut signature_settings,
        file,
        expected_sha256,
    )?;
    if primary == AuthenticodeSignatureVerdict::Invalid {
        return Ok(false);
    }
    let secondary_count = signature_settings.cSecondarySigs;
    aggregate_valid_authenticode_signatures(path, "catalog", primary, secondary_count, |index| {
        signature_settings.dwIndex = index;
        let verdict = verify_specific_authenticode_signature(
            path,
            "catalog",
            &mut trust_data,
            &mut signature_settings,
            file,
            expected_sha256,
        )?;
        anyhow::ensure!(
                signature_settings.cSecondarySigs == secondary_count,
                "catalog Authenticode secondary-signature count changed from {} to {} while verifying {}",
                secondary_count,
                signature_settings.cSecondarySigs,
                path.display()
            );
        Ok(verdict)
    })
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
        let application = std::env::current_exe().unwrap();
        let arguments = [
            "--ignored",
            "--exact",
            "windows_authenticode::tests::authenticode_timeout_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ];
        let started = Instant::now();
        let error = run_bounded_authenticode_helper(
            &application,
            &arguments,
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
    #[ignore = "isolated child fixture invoked by the bounded timeout regression"]
    fn authenticode_timeout_child_fixture() {
        thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn native_authenticode_helper_restricted_process_token_is_verified_in_child() {
        let application = std::env::current_exe().unwrap();
        let arguments = [
            "--ignored",
            "--exact",
            "windows_authenticode::tests::authenticode_restricted_primary_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ];
        let output = run_bounded_authenticode_helper(
            &application,
            &arguments,
            Vec::new(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "restricted-primary child failed with {:?}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("AVORAX_RESTRICTED_PRIMARY_TOKEN_OK"));
    }

    #[test]
    #[ignore = "isolated child fixture invoked by the restricted-process regression"]
    fn authenticode_restricted_primary_child_fixture() {
        validate_current_process_authenticode_primary_token().unwrap();
        println!("AVORAX_RESTRICTED_PRIMARY_TOKEN_OK");
    }

    #[test]
    fn native_authenticode_helper_low_integrity_primary_denies_medium_file_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("medium-integrity-write-target.txt");
        let original = b"benign low-integrity fixture\n";
        fs::write(&path, original).unwrap();
        let request = helper_request(&path, fixture_sha256(&path));
        let encoded = serde_json::to_vec(&request).unwrap();
        let application = std::env::current_exe().unwrap();
        let arguments = [
            "--ignored",
            "--exact",
            "windows_authenticode::tests::authenticode_low_integrity_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ];

        let output = run_bounded_authenticode_helper(
            &application,
            &arguments,
            encoded,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "low-integrity child failed with {:?}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("AVORAX_LOW_INTEGRITY_MUTATION_DENIED"));
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    #[ignore = "isolated child fixture invoked by the low-integrity regression"]
    fn authenticode_low_integrity_child_fixture() {
        revert_authenticode_helper_thread_token().unwrap();
        validate_current_process_authenticode_primary_token().unwrap();
        let request = read_authenticode_helper_request(std::io::stdin().lock()).unwrap();
        validate_authenticode_helper_request(&request).unwrap();
        let path = PathBuf::from(OsString::from_wide(&request.path_utf16));
        assert_eq!(fixture_sha256(&path), request.expected_sha256);
        let error = OpenOptions::new().write(true).open(&path).expect_err(
            "low-integrity helper unexpectedly opened a medium-integrity file for write",
        );
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(fixture_sha256(&path), request.expected_sha256);
        println!("AVORAX_LOW_INTEGRITY_MUTATION_DENIED");
    }

    #[test]
    fn native_authenticode_helper_low_integrity_sid_policy_is_exact() {
        let expected = VerifiedWellKnownSid::create(WinLowLabelSid, "Low Mandatory Level").unwrap();
        for attributes in [
            AUTHENTICODE_HELPER_SET_INTEGRITY_SID_ATTRIBUTES,
            AUTHENTICODE_HELPER_READBACK_INTEGRITY_SID_ATTRIBUTES,
        ] {
            validate_authenticode_integrity_label_evidence(
                &TokenSidEvidence {
                    sid: expected.as_bytes().to_vec(),
                    attributes,
                },
                expected.as_bytes(),
            )
            .unwrap();
        }

        let mut wrong_sid = expected.as_bytes().to_vec();
        *wrong_sid.last_mut().unwrap() ^= 1;
        for invalid in [
            TokenSidEvidence {
                sid: wrong_sid,
                attributes: AUTHENTICODE_HELPER_READBACK_INTEGRITY_SID_ATTRIBUTES,
            },
            TokenSidEvidence {
                sid: expected.as_bytes().to_vec(),
                attributes: 0,
            },
            TokenSidEvidence {
                sid: expected.as_bytes().to_vec(),
                attributes: SE_GROUP_INTEGRITY_ENABLED as u32,
            },
            TokenSidEvidence {
                sid: expected.as_bytes().to_vec(),
                attributes: AUTHENTICODE_HELPER_READBACK_INTEGRITY_SID_ATTRIBUTES
                    | SE_GROUP_ENABLED as u32,
            },
        ] {
            assert!(
                validate_authenticode_integrity_label_evidence(&invalid, expected.as_bytes(),)
                    .is_err()
            );
        }
    }

    #[test]
    fn native_authenticode_helper_mandatory_policy_is_verified_in_child() {
        let application = std::env::current_exe().unwrap();
        let arguments = [
            "--ignored",
            "--exact",
            "windows_authenticode::tests::authenticode_mandatory_policy_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ];
        let output = run_bounded_authenticode_helper(
            &application,
            &arguments,
            Vec::new(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "mandatory-policy child failed with {:?}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("AVORAX_MANDATORY_NO_WRITE_UP_POLICY_OK"));
    }

    #[test]
    #[ignore = "isolated child fixture invoked by the mandatory-policy regression"]
    fn authenticode_mandatory_policy_child_fixture() {
        validate_current_process_authenticode_primary_token().unwrap();
        println!("AVORAX_MANDATORY_NO_WRITE_UP_POLICY_OK");
    }

    #[test]
    fn native_authenticode_helper_mandatory_policy_rejects_off_new_process_only_and_unknown_bits() {
        validate_authenticode_mandatory_policy(TOKEN_MANDATORY_POLICY_NO_WRITE_UP).unwrap();
        validate_authenticode_mandatory_policy(
            TOKEN_MANDATORY_POLICY_NO_WRITE_UP
                | windows_sys::Win32::Security::TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
        )
        .unwrap();

        for invalid in [
            0,
            windows_sys::Win32::Security::TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
            TOKEN_MANDATORY_POLICY_NO_WRITE_UP | 0x8000_0000,
        ] {
            assert!(validate_authenticode_mandatory_policy(invalid).is_err());
        }
    }

    #[test]
    fn native_authenticode_helper_process_mitigations_are_verified_in_child() {
        let application = std::env::current_exe().unwrap();
        let arguments = [
            "--ignored",
            "--exact",
            "windows_authenticode::tests::authenticode_process_mitigation_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ];
        let output = run_bounded_authenticode_helper(
            &application,
            &arguments,
            Vec::new(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "mitigation-policy child failed with {:?}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("AVORAX_PROCESS_MITIGATION_POLICY_OK"));
    }

    #[test]
    #[ignore = "isolated child fixture invoked by the process-mitigation regression"]
    fn authenticode_process_mitigation_child_fixture() {
        validate_current_process_authenticode_primary_token().unwrap();
        validate_current_process_authenticode_mitigations().unwrap();
        println!("AVORAX_PROCESS_MITIGATION_POLICY_OK");
    }

    #[test]
    fn native_authenticode_helper_process_mitigation_policy_is_exact_and_fail_closed() {
        assert_eq!(
            AUTHENTICODE_HELPER_PROCESS_MITIGATION_POLICY,
            (1u64 << 24)
                | (1u64 << 32)
                | (1u64 << 36)
                | (1u64 << 44)
                | (1u64 << 52)
                | (1u64 << 56)
                | (1u64 << 60)
        );
        let expected = AuthenticodeProcessMitigationEvidence {
            signature: AUTHENTICODE_HELPER_SIGNATURE_REQUIRED_FLAGS,
            dynamic_code: AUTHENTICODE_HELPER_DYNAMIC_CODE_REQUIRED_FLAGS,
            extension_point: AUTHENTICODE_HELPER_EXTENSION_POINT_REQUIRED_FLAGS,
            image_load: AUTHENTICODE_HELPER_IMAGE_LOAD_REQUIRED_FLAGS,
            strict_handle: AUTHENTICODE_HELPER_STRICT_HANDLE_REQUIRED_FLAGS,
        };
        validate_authenticode_process_mitigation_evidence(expected).unwrap();

        let invalid = [
            AuthenticodeProcessMitigationEvidence {
                signature: 0,
                ..expected
            },
            AuthenticodeProcessMitigationEvidence {
                signature: 0b0010,
                ..expected
            },
            AuthenticodeProcessMitigationEvidence {
                dynamic_code: 0,
                ..expected
            },
            AuthenticodeProcessMitigationEvidence {
                extension_point: 0,
                ..expected
            },
            AuthenticodeProcessMitigationEvidence {
                image_load: 0b0110,
                ..expected
            },
            AuthenticodeProcessMitigationEvidence {
                image_load: 0b0101,
                ..expected
            },
            AuthenticodeProcessMitigationEvidence {
                image_load: 0b0011,
                ..expected
            },
            AuthenticodeProcessMitigationEvidence {
                strict_handle: 0,
                ..expected
            },
            AuthenticodeProcessMitigationEvidence {
                strict_handle: 0b0001,
                ..expected
            },
        ];
        for evidence in invalid {
            assert!(validate_authenticode_process_mitigation_evidence(evidence).is_err());
        }
    }

    #[test]
    fn native_authenticode_helper_sanitized_launch_context_is_verified_in_child() {
        let application = std::env::current_exe().unwrap();
        let arguments = [
            "--ignored",
            "--exact",
            "windows_authenticode::tests::authenticode_sanitized_launch_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ];
        let output = run_bounded_authenticode_helper(
            &application,
            &arguments,
            Vec::new(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "sanitized-launch child failed with {:?}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("AVORAX_SANITIZED_LAUNCH_CONTEXT_OK"));
    }

    #[test]
    #[ignore = "isolated child fixture invoked by the sanitized-launch regression"]
    fn authenticode_sanitized_launch_child_fixture() {
        validate_current_process_authenticode_primary_token().unwrap();
        let windows_root = checked_system_windows_directory().unwrap();
        let expected_current = checked_system_directory(
            "System32",
            "AuthentiCode helper sanitized current directory fixture",
        )
        .unwrap();
        assert_eq!(std::env::current_dir().unwrap(), expected_current);

        let mut environment = std::env::vars_os()
            .map(|(name, value)| (name.to_string_lossy().into_owned(), PathBuf::from(value)))
            .collect::<Vec<_>>();
        environment.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            environment,
            vec![
                ("SystemRoot".to_string(), windows_root.clone()),
                ("WINDIR".to_string(), windows_root),
            ]
        );
        println!("AVORAX_SANITIZED_LAUNCH_CONTEXT_OK");
    }

    #[test]
    fn native_authenticode_helper_sanitized_environment_block_is_exact_and_bounded() {
        let block = build_authenticode_helper_environment_block(Path::new(r"C:\Windows")).unwrap();
        assert_eq!(block.last(), Some(&0));
        assert_eq!(block[block.len() - 2], 0);
        let entries = block[..block.len() - 1]
            .split(|unit| *unit == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| String::from_utf16(entry).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(entries, [r"SystemRoot=C:\Windows", r"WINDIR=C:\Windows"]);

        for invalid in [
            Path::new(r"relative\Windows"),
            Path::new(r"C:\Windows\..\Temp"),
            Path::new(r"\\server\share\Windows"),
            Path::new(r"\\?\C:\Windows"),
        ] {
            assert!(build_authenticode_helper_environment_block(invalid).is_err());
            assert!(absolute_launch_directory_wide(invalid).is_err());
        }
        let embedded_nul = PathBuf::from(OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            b'X' as u16,
            0,
            b'Y' as u16,
        ]));
        assert!(build_authenticode_helper_environment_block(&embedded_nul).is_err());
        assert!(absolute_launch_directory_wide(&embedded_nul).is_err());
    }

    #[test]
    fn native_authenticode_helper_write_restricted_access_denies_ordinary_file_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ordinary-user-write-target.txt");
        let original = b"benign write-restriction fixture\n";
        fs::write(&path, original).unwrap();
        let request = helper_request(&path, fixture_sha256(&path));
        let encoded = serde_json::to_vec(&request).unwrap();
        let application = std::env::current_exe().unwrap();
        let arguments = [
            "--ignored",
            "--exact",
            "windows_authenticode::tests::authenticode_write_restricted_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ];

        let output = run_bounded_authenticode_helper(
            &application,
            &arguments,
            encoded,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "write-restricted child failed with {:?}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("AVORAX_WRITE_RESTRICTED_MUTATION_DENIED"));
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    #[ignore = "isolated child fixture invoked by the write-restriction regression"]
    fn authenticode_write_restricted_child_fixture() {
        validate_current_process_authenticode_primary_token().unwrap();
        let restricted = RestrictedAuthenticodeThreadToken::enter().unwrap();
        let operation = (|| -> Result<()> {
            let request = read_authenticode_helper_request(std::io::stdin().lock())?;
            validate_authenticode_helper_request(&request)?;
            let path = PathBuf::from(OsString::from_wide(&request.path_utf16));
            anyhow::ensure!(
                fixture_sha256(&path) == request.expected_sha256,
                "benign write-restriction fixture changed before write-open"
            );
            let error = OpenOptions::new().write(true).open(&path).expect_err(
                "write-restricted helper unexpectedly opened an ordinary file for write",
            );
            anyhow::ensure!(
                error.kind() == std::io::ErrorKind::PermissionDenied,
                "write-restricted helper returned an unexpected write-open error: {error}"
            );
            anyhow::ensure!(
                fixture_sha256(&path) == request.expected_sha256,
                "benign write-restriction fixture changed after denied write-open"
            );
            println!("AVORAX_WRITE_RESTRICTED_MUTATION_DENIED");
            Ok(())
        })();
        restricted.finish(operation).unwrap();
    }

    #[test]
    fn native_authenticode_helper_write_restricted_sid_policy_is_exact() {
        let expected =
            VerifiedWellKnownSid::create(WinRestrictedCodeSid, "Restricted Code").unwrap();
        let valid = TokenSidEvidence {
            sid: expected.as_bytes().to_vec(),
            attributes: AUTHENTICODE_HELPER_RESTRICTED_SID_ATTRIBUTES,
        };
        validate_authenticode_restricted_sid_evidence(
            std::slice::from_ref(&valid),
            expected.as_bytes(),
        )
        .unwrap();
        assert!(validate_authenticode_restricted_sid_evidence(&[], expected.as_bytes()).is_err());
        assert!(validate_authenticode_restricted_sid_evidence(
            &[valid.clone(), valid.clone()],
            expected.as_bytes(),
        )
        .is_err());
        let mut wrong_sid = valid.clone();
        *wrong_sid.sid.last_mut().unwrap() ^= 1;
        assert!(
            validate_authenticode_restricted_sid_evidence(&[wrong_sid], expected.as_bytes(),)
                .is_err()
        );
        let mut wrong_attributes = valid;
        wrong_attributes.attributes = 0;
        assert!(validate_authenticode_restricted_sid_evidence(
            &[wrong_attributes],
            expected.as_bytes(),
        )
        .is_err());
    }

    #[test]
    fn native_authenticode_helper_restricted_process_handle_and_command_contract_is_strict() {
        let handles = [1usize as HANDLE, 2usize as HANDLE, 3usize as HANDLE];
        validate_authenticode_child_handle_list(&handles).unwrap();
        assert!(validate_authenticode_child_handle_list(&[
            null_mut(),
            2usize as HANDLE,
            3usize as HANDLE,
        ])
        .is_err());
        assert!(validate_authenticode_child_handle_list(&[
            1usize as HANDLE,
            1usize as HANDLE,
            3usize as HANDLE,
        ])
        .is_err());

        let command = restricted_process_command_line(
            Path::new(r"C:\Program Files\Avorax\avorax_core_service.exe"),
            &[AUTHENTICODE_HELPER_ARGUMENT],
        )
        .unwrap();
        assert_eq!(command.last(), Some(&0));
        let text = String::from_utf16(&command[..command.len() - 1]).unwrap();
        assert_eq!(
            text,
            r#""C:\Program Files\Avorax\avorax_core_service.exe" --avorax-authenticode-helper-v1"#
        );
        assert!(restricted_process_command_line(
            Path::new(r"C:\Avorax\core.exe"),
            &["argument with spaces"],
        )
        .is_err());
    }

    #[test]
    fn native_authenticode_helper_job_limits_are_exact_queryable_and_fail_visible() {
        let job = KillOnCloseJob::create().unwrap();
        let actual = query_and_validate_authenticode_helper_job_limits(job.0).unwrap();
        let required = required_authenticode_helper_job_limits();
        assert_eq!(
            actual.BasicLimitInformation.LimitFlags,
            required.BasicLimitInformation.LimitFlags
        );
        assert_eq!(
            actual.BasicLimitInformation.PerProcessUserTimeLimit,
            AUTHENTICODE_HELPER_USER_CPU_100NS
        );
        assert_eq!(
            actual.BasicLimitInformation.ActiveProcessLimit,
            AUTHENTICODE_HELPER_ACTIVE_PROCESS_LIMIT
        );
        assert_eq!(
            actual.ProcessMemoryLimit,
            AUTHENTICODE_HELPER_PROCESS_MEMORY_BYTES
        );
        assert_eq!(actual.JobMemoryLimit, AUTHENTICODE_HELPER_JOB_MEMORY_BYTES);

        let mut mismatched = actual;
        mismatched.BasicLimitInformation.LimitFlags ^= JOB_OBJECT_LIMIT_PROCESS_TIME;
        assert!(validate_authenticode_helper_job_limits(&mismatched)
            .unwrap_err()
            .to_string()
            .contains("job limit flags mismatch"));

        let mut mismatched = actual;
        mismatched.BasicLimitInformation.PerProcessUserTimeLimit += 1;
        assert!(validate_authenticode_helper_job_limits(&mismatched)
            .unwrap_err()
            .to_string()
            .contains("user-CPU limit mismatch"));

        let mut mismatched = actual;
        mismatched.BasicLimitInformation.ActiveProcessLimit += 1;
        assert!(validate_authenticode_helper_job_limits(&mismatched)
            .unwrap_err()
            .to_string()
            .contains("active-process limit mismatch"));

        let mut mismatched = actual;
        mismatched.ProcessMemoryLimit += 1;
        assert!(validate_authenticode_helper_job_limits(&mismatched)
            .unwrap_err()
            .to_string()
            .contains("per-process commit limit mismatch"));

        let mut mismatched = actual;
        mismatched.JobMemoryLimit += 1;
        assert!(validate_authenticode_helper_job_limits(&mismatched)
            .unwrap_err()
            .to_string()
            .contains("job commit limit mismatch"));
    }

    #[test]
    fn native_authenticode_helper_restricted_thread_token_is_verified_and_reverted() {
        assert!(open_current_thread_token().unwrap().is_none());

        let restricted = RestrictedAuthenticodeThreadToken::enter().unwrap();
        let current = open_current_thread_token().unwrap().unwrap();
        validate_restricted_authenticode_impersonation_token(current.0).unwrap();
        let error = restricted
            .finish::<()>(Err(anyhow::anyhow!(
                "benign synthetic verification failure"
            )))
            .unwrap_err()
            .to_string();
        assert!(error.contains("benign synthetic verification failure"));
        assert!(open_current_thread_token().unwrap().is_none());

        let restricted = RestrictedAuthenticodeThreadToken::enter().unwrap();
        restricted.finish(Ok(())).unwrap();
        assert!(open_current_thread_token().unwrap().is_none());
    }

    #[test]
    fn native_authenticode_helper_restricted_thread_token_rejects_sensitive_privilege() {
        let mut allowed = LUID::default();
        assert_ne!(
            unsafe { LookupPrivilegeValueW(null(), SE_CHANGE_NOTIFY_NAME, &mut allowed) },
            0
        );
        let allowed_entry = LUID_AND_ATTRIBUTES {
            Luid: allowed,
            Attributes: SE_PRIVILEGE_ENABLED,
        };
        let disabled_sensitive = LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: allowed.LowPart.wrapping_add(1),
                HighPart: allowed.HighPart,
            },
            Attributes: 0,
        };
        assert!(validate_enabled_authenticode_privileges(
            &[allowed_entry, disabled_sensitive],
            allowed
        )
        .is_ok());

        let enabled_sensitive = LUID_AND_ATTRIBUTES {
            Attributes: SE_PRIVILEGE_ENABLED,
            ..disabled_sensitive
        };
        assert!(
            validate_enabled_authenticode_privileges(&[enabled_sensitive], allowed)
                .unwrap_err()
                .to_string()
                .contains("retained an unexpected enabled privilege")
        );
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
        let accepted = aggregate_valid_authenticode_signatures(
            path,
            "embedded",
            AuthenticodeSignatureVerdict::OtherPublisher,
            2,
            |index| {
                requested.push(index);
                Ok(if index == 2 {
                    AuthenticodeSignatureVerdict::Microsoft
                } else {
                    AuthenticodeSignatureVerdict::Invalid
                })
            },
        )
        .unwrap();
        assert!(accepted);
        assert_eq!(requested, [1, 2]);

        let mut primary_callback_used = false;
        assert!(aggregate_valid_authenticode_signatures(
            path,
            "embedded",
            AuthenticodeSignatureVerdict::Microsoft,
            2,
            |_| {
                primary_callback_used = true;
                Ok(AuthenticodeSignatureVerdict::Invalid)
            },
        )
        .unwrap());
        assert!(!primary_callback_used);

        let mut invalid_primary_callback_used = false;
        assert!(!aggregate_valid_authenticode_signatures(
            path,
            "embedded",
            AuthenticodeSignatureVerdict::Invalid,
            u32::MAX,
            |_| {
                invalid_primary_callback_used = true;
                Ok(AuthenticodeSignatureVerdict::Microsoft)
            },
        )
        .unwrap());
        assert!(!invalid_primary_callback_used);

        assert!(!aggregate_valid_authenticode_signatures(
            path,
            "embedded",
            AuthenticodeSignatureVerdict::OtherPublisher,
            2,
            |_| Ok(AuthenticodeSignatureVerdict::Invalid),
        )
        .unwrap());

        let error = aggregate_valid_authenticode_signatures(
            path,
            "embedded",
            AuthenticodeSignatureVerdict::OtherPublisher,
            1,
            |_| anyhow::bail!("secondary verification failed visibly"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("secondary verification failed visibly"));

        let mut over_limit_callback_used = false;
        let error = aggregate_valid_authenticode_signatures(
            path,
            "embedded",
            AuthenticodeSignatureVerdict::OtherPublisher,
            MAX_AUTHENTICODE_SIGNATURES,
            |_| {
                over_limit_callback_used = true;
                Ok(AuthenticodeSignatureVerdict::Microsoft)
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("exceeds the 16 signature limit"));
        assert!(!over_limit_callback_used);
    }

    #[test]
    fn native_secondary_catalog_authenticode_aggregation_is_bounded_ordered_and_fail_visible() {
        let path = Path::new(r"C:\benign-catalog-member.exe");
        let mut requested = Vec::new();
        let accepted = aggregate_valid_authenticode_signatures(
            path,
            "catalog",
            AuthenticodeSignatureVerdict::OtherPublisher,
            2,
            |index| {
                requested.push(index);
                Ok(if index == 2 {
                    AuthenticodeSignatureVerdict::Microsoft
                } else {
                    AuthenticodeSignatureVerdict::OtherPublisher
                })
            },
        )
        .unwrap();
        assert!(accepted);
        assert_eq!(requested, [1, 2]);

        let mut invalid_primary_callback_used = false;
        assert!(!aggregate_valid_authenticode_signatures(
            path,
            "catalog",
            AuthenticodeSignatureVerdict::Invalid,
            u32::MAX,
            |_| {
                invalid_primary_callback_used = true;
                Ok(AuthenticodeSignatureVerdict::Microsoft)
            },
        )
        .unwrap());
        assert!(!invalid_primary_callback_used);

        let visible = aggregate_valid_authenticode_signatures(
            path,
            "catalog",
            AuthenticodeSignatureVerdict::OtherPublisher,
            1,
            |_| anyhow::bail!("catalog secondary verification failed visibly"),
        )
        .unwrap_err()
        .to_string();
        assert!(visible.contains("catalog secondary verification failed visibly"));

        let mut over_limit_callback_used = false;
        let over_limit = aggregate_valid_authenticode_signatures(
            path,
            "catalog",
            AuthenticodeSignatureVerdict::OtherPublisher,
            MAX_AUTHENTICODE_SIGNATURES,
            |_| {
                over_limit_callback_used = true;
                Ok(AuthenticodeSignatureVerdict::Microsoft)
            },
        )
        .unwrap_err()
        .to_string();
        assert!(over_limit.contains("catalog Authenticode signature count 17"));
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

        let primary = verify_specific_authenticode_signature(
            &path,
            "embedded",
            &mut trust_data,
            &mut signature_settings,
            &mut file,
            &sha256,
        )
        .unwrap();
        assert_eq!(primary, AuthenticodeSignatureVerdict::OtherPublisher);
        assert!(verified_signature_index_is_acceptable(
            0,
            signature_settings.dwVerifiedSigIndex
        ));
        let secondary_count = signature_settings.cSecondarySigs;
        assert!(secondary_count > 0);
        assert!(secondary_count < MAX_AUTHENTICODE_SIGNATURES);
        assert!(trust_data.hWVTStateData.is_null());
        assert_eq!(trust_data.dwStateAction, WTD_STATEACTION_VERIFY);

        let mut microsoft_secondary = None;
        for index in 1..=secondary_count {
            signature_settings.dwIndex = index;
            let secondary = verify_specific_authenticode_signature(
                &path,
                "embedded",
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
            if secondary == AuthenticodeSignatureVerdict::Microsoft {
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
    fn native_secondary_catalog_authenticode_primary_runtime_is_exact_and_hash_bound() {
        let path = crate::windows_system::checked_system32_file(
            &["WindowsPowerShell", "v1.0", "powershell.exe"],
            "secondary-catalog Authenticode runtime fixture",
        )
        .unwrap();
        let path_wide = absolute_path_wide(&path).unwrap();
        let mut file = open_authenticode_candidate(&path).unwrap();
        let sha256 = fixture_sha256(&path);

        assert!(verify_catalog_signatures(&path, &path_wide, &mut file, &sha256).unwrap());
        let mut wrong_sha256 = sha256.clone();
        let replacement = if wrong_sha256.as_bytes().first() == Some(&b'0') {
            "1"
        } else {
            "0"
        };
        wrong_sha256.replace_range(..1, replacement);
        let error = verify_catalog_signatures(&path, &path_wide, &mut file, &wrong_sha256)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match the bytes already scanned"));
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
