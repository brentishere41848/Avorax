use std::ffi::c_void;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::null_mut;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::{
    GetLastError, SetLastError, CERT_E_REVOCATION_FAILURE, CRYPT_E_BAD_ENCODE, CRYPT_E_BAD_MSG,
    CRYPT_E_NO_MATCH, CRYPT_E_NO_SIGNER, CRYPT_E_NO_TRUSTED_SIGNER, CRYPT_E_REVOKED,
    CRYPT_E_SIGNER_NOT_FOUND, ERROR_NOT_FOUND, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
    TRUST_E_BAD_DIGEST, TRUST_E_BASIC_CONSTRAINTS, TRUST_E_CERT_SIGNATURE, TRUST_E_COUNTER_SIGNER,
    TRUST_E_FAIL, TRUST_E_FINANCIAL_CRITERIA, TRUST_E_MALFORMED_SIGNATURE, TRUST_E_NO_SIGNER_CERT,
    TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_SUBJECT_NOT_TRUSTED, TRUST_E_TIME_STAMP,
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
    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
    WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE,
    WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
    FILE_SHARE_READ,
};

const MAX_AUTHENTICODE_PATH_UTF16_UNITS: usize = 32_767;
const MAX_SIGNER_ATTRIBUTE_UTF16_UNITS: usize = 2_048;
const MAX_AUTHENTICODE_BIND_BYTES: u64 = 512 * 1024 * 1024;
const AUTHENTICODE_HASH_BUFFER_BYTES: usize = 128 * 1024;
const SHA256_CATALOG_HASH_BYTES: usize = 32;
const MAX_CATALOG_CANDIDATES: usize = 16;

pub(crate) fn has_valid_microsoft_signature(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<bool> {
    if let Some(expected_sha256) = expected_sha256 {
        validate_expected_sha256(expected_sha256)?;
    }
    let path_wide = absolute_path_wide(path)?;
    let mut file = open_authenticode_candidate(path)?;
    if expected_sha256.is_some() {
        enforce_content_binding_size(path, &file)?;
    }
    match verify_open_file(path, &path_wide, &mut file, expected_sha256)? {
        true => Ok(true),
        false => verify_catalog_signatures(path, &path_wide, &mut file, expected_sha256),
    }
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

fn verify_open_file(
    path: &Path,
    path_wide: &[u16],
    file: &mut File,
    expected_sha256: Option<&str>,
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
        pSignatureSettings: null_mut(),
    };
    verify_wintrust_data(path, &mut trust_data, file, expected_sha256)
}

fn verify_wintrust_data(
    path: &Path,
    trust_data: &mut WINTRUST_DATA,
    file: &mut File,
    expected_sha256: Option<&str>,
) -> Result<bool> {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let verify_status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    let outcome = if verify_status == 0 {
        verified_signer_is_microsoft(trust_data).and_then(|signer_is_microsoft| {
            if signer_is_microsoft {
                bind_verified_signature_to_expected_hash(path, file, expected_sha256)
            } else {
                Ok(false)
            }
        })
    } else {
        classify_untrusted_status(path, verify_status)
    };

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let close_status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    combine_verdict_and_close(path, outcome, close_status)
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
    expected_sha256: Option<&str>,
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
    expected_sha256: Option<&str>,
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
    expected_sha256: Option<&str>,
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
    expected_sha256: Option<&str>,
) -> Result<bool> {
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(true);
    };
    let before = file.metadata().with_context(|| {
        format!(
            "unable to inspect Microsoft-signed file before content binding {}",
            path.display()
        )
    })?;
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
    let after = file.metadata().with_context(|| {
        format!(
            "unable to inspect Microsoft-signed file after content binding {}",
            path.display()
        )
    })?;
    anyhow::ensure!(
        before.len() == after.len()
            && before.last_write_time() == after.last_write_time()
            && before.file_attributes() == after.file_attributes(),
        "Microsoft-signed file metadata changed during content binding: {}",
        path.display()
    );
    let actual_sha256 = format!("{:x}", hasher.finalize());
    anyhow::ensure!(
        actual_sha256.eq_ignore_ascii_case(expected_sha256),
        "Microsoft Authenticode verdict content SHA-256 does not match the bytes already scanned for {}",
        path.display()
    );
    Ok(true)
}

fn classify_untrusted_status(path: &Path, status: i32) -> Result<bool> {
    if definitively_untrusted_status(status) {
        return Ok(false);
    }
    anyhow::bail!(
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

fn combine_verdict_and_close(
    path: &Path,
    outcome: Result<bool>,
    close_status: i32,
) -> Result<bool> {
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
        "verified Authenticode state is missing its primary signer"
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
    use windows_sys::Win32::Foundation::{
        CRYPT_E_FILE_ERROR, CRYPT_E_NO_REVOCATION_CHECK, CRYPT_E_REVOCATION_OFFLINE,
        CRYPT_E_SECURITY_SETTINGS, TRUST_E_ACTION_UNKNOWN, TRUST_E_FAIL, TRUST_E_NOSIGNATURE,
        TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SYSTEM_ERROR,
    };

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

        assert!(!verify_open_file(&path, &path_wide, &mut file, None).unwrap());
        assert!(verify_catalog_signatures(&path, &path_wide, &mut file, None).unwrap());
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
            Err(anyhow::anyhow!("verification failed")),
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
