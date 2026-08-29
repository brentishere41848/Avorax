use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

const MAX_QUARANTINE_DIRECTORY_ENTRIES: usize = 65_536;
const MAX_QUARANTINE_ENTRY_NAME_CHARS: usize = 512;
const MAX_QUARANTINE_ID_CHARS: usize = 128;

pub fn ensure_open_file_has_single_link(file: &fs::File, path: &Path, label: &str) -> Result<()> {
    let link_count = open_file_link_count(file, path, label)?;
    if link_count != 1 {
        return Err(anyhow!(
            "refusing to use {label} {} because its hard-link count is {link_count}; quarantine requires exactly one filesystem link",
            path.display()
        ));
    }
    Ok(())
}

pub fn ensure_path_matches_open_file(file: &fs::File, path: &Path, label: &str) -> Result<()> {
    let current = fs::File::open(path)
        .with_context(|| format!("failed to reopen {label} {}", path.display()))?;
    if open_file_identity(file, path, label)? != open_file_identity(&current, path, label)? {
        return Err(anyhow!(
            "refusing to use {label} {} because its path now identifies a different file",
            path.display()
        ));
    }
    Ok(())
}

/// Atomically moves a staged file into an absent destination without replacing
/// a competing filesystem object that appears after caller preflight.
pub fn rename_file_no_replace(source: &Path, destination: &Path, label: &str) -> Result<()> {
    rename_file_no_replace_impl(source, destination, label)
}

#[cfg(windows)]
const WINDOWS_UNC_PREFIX: &[u16] = &[b'\\' as u16, b'\\' as u16];
#[cfg(windows)]
const WINDOWS_VERBATIM_PREFIX: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
#[cfg(windows)]
const WINDOWS_VERBATIM_UNC_PREFIX: &[u16] = &[
    b'\\' as u16,
    b'\\' as u16,
    b'?' as u16,
    b'\\' as u16,
    b'U' as u16,
    b'N' as u16,
    b'C' as u16,
    b'\\' as u16,
];
#[cfg(windows)]
const WINDOWS_DEVICE_NAMESPACE_PREFIX: &[u16] =
    &[b'\\' as u16, b'\\' as u16, b'.' as u16, b'\\' as u16];

#[cfg(windows)]
fn windows_drive_absolute_at(path: &[u16], offset: usize) -> bool {
    let drive = path.get(offset).copied().unwrap_or_default();
    path.len() > offset + 2
        && ((drive >= b'A' as u16 && drive <= b'Z' as u16)
            || (drive >= b'a' as u16 && drive <= b'z' as u16))
        && path[offset + 1] == b':' as u16
        && path[offset + 2] == b'\\' as u16
}

#[cfg(windows)]
fn bounded_windows_move_path(path: &Path, role: &str, label: &str) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let raw: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .take(MAX_WINDOWS_SECURITY_PATH_UNITS.saturating_add(1))
        .collect();
    if raw.is_empty() {
        return Err(anyhow!("{label} {role} path is empty"));
    }
    if raw.len() > MAX_WINDOWS_SECURITY_PATH_UNITS {
        return Err(anyhow!("{label} {role} path is too long"));
    }
    if raw.contains(&0) {
        return Err(anyhow!("{label} {role} path contains NUL"));
    }
    if raw.starts_with(WINDOWS_DEVICE_NAMESPACE_PREFIX) {
        return Err(anyhow!(
            "{label} {role} path uses a forbidden Windows device namespace"
        ));
    }

    let mut wide = if raw.starts_with(WINDOWS_VERBATIM_UNC_PREFIX) {
        anyhow::ensure!(
            raw.len() > WINDOWS_VERBATIM_UNC_PREFIX.len(),
            "{label} {role} verbatim UNC path is incomplete"
        );
        raw
    } else if raw.starts_with(WINDOWS_VERBATIM_PREFIX) {
        anyhow::ensure!(
            windows_drive_absolute_at(&raw, WINDOWS_VERBATIM_PREFIX.len()),
            "{label} {role} path uses a forbidden Windows verbatim device namespace"
        );
        raw
    } else if path.is_absolute() {
        if raw.starts_with(WINDOWS_UNC_PREFIX) {
            anyhow::ensure!(
                raw.len() > WINDOWS_UNC_PREFIX.len(),
                "{label} {role} UNC path is incomplete"
            );
            let mut prefixed = Vec::with_capacity(
                WINDOWS_VERBATIM_UNC_PREFIX.len() + raw.len() - WINDOWS_UNC_PREFIX.len() + 1,
            );
            prefixed.extend_from_slice(WINDOWS_VERBATIM_UNC_PREFIX);
            prefixed.extend_from_slice(&raw[WINDOWS_UNC_PREFIX.len()..]);
            prefixed
        } else {
            anyhow::ensure!(
                windows_drive_absolute_at(&raw, 0),
                "{label} {role} absolute path is not a local drive or UNC path"
            );
            let mut prefixed = Vec::with_capacity(WINDOWS_VERBATIM_PREFIX.len() + raw.len() + 1);
            prefixed.extend_from_slice(WINDOWS_VERBATIM_PREFIX);
            prefixed.extend_from_slice(&raw);
            prefixed
        }
    } else {
        raw
    };
    if wide.len() > MAX_WINDOWS_SECURITY_PATH_UNITS {
        return Err(anyhow!(
            "{label} {role} path is too long after Windows verbatim normalization"
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
fn rename_file_no_replace_impl(source: &Path, destination: &Path, label: &str) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

    let source_wide = bounded_windows_move_path(source, "source", label)?;
    let destination_wide = bounded_windows_move_path(destination, "destination", label)?;
    if unsafe { MoveFileExW(source_wide.as_ptr(), destination_wide.as_ptr(), 0) } == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to atomically activate {label} {} without replacing {}",
                source.display(),
                destination.display()
            )
        });
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_file_no_replace_impl(source: &Path, destination: &Path, label: &str) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source_c = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| anyhow!("{label} source path contains NUL"))?;
    let destination_c = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| anyhow!("{label} destination path contains NUL"))?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source_c.as_ptr(),
            libc::AT_FDCWD,
            destination_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to atomically activate {label} {} without replacing {}",
                source.display(),
                destination.display()
            )
        });
    }
    Ok(())
}

#[cfg(all(unix, target_vendor = "apple"))]
fn rename_file_no_replace_impl(source: &Path, destination: &Path, label: &str) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source_c = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| anyhow!("{label} source path contains NUL"))?;
    let destination_c = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| anyhow!("{label} destination path contains NUL"))?;
    if unsafe { libc::renamex_np(source_c.as_ptr(), destination_c.as_ptr(), libc::RENAME_EXCL) }
        != 0
    {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to atomically activate {label} {} without replacing {}",
                source.display(),
                destination.display()
            )
        });
    }
    Ok(())
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    all(unix, target_vendor = "apple")
)))]
fn rename_file_no_replace_impl(source: &Path, destination: &Path, label: &str) -> Result<()> {
    Err(anyhow!(
        "atomic no-replace activation is unsupported for {label} {} to {} on this platform",
        source.display(),
        destination.display()
    ))
}

#[cfg(unix)]
fn open_file_identity(file: &fs::File, path: &Path, label: &str) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .with_context(|| format!("failed to identify opened {label} {}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("opened {label} {} is not a file", path.display()));
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn open_file_identity(file: &fs::File, path: &Path, label: &str) -> Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to identify opened {label} {}", path.display()));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(anyhow!("opened {label} {} is not a file", path.display()));
    }
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(not(any(unix, windows)))]
fn open_file_identity(_file: &fs::File, path: &Path, label: &str) -> Result<(u64, u64)> {
    Err(anyhow!(
        "file identity inspection is unsupported for {label} {} on this platform",
        path.display()
    ))
}

#[cfg(unix)]
fn open_file_link_count(file: &fs::File, path: &Path, label: &str) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened {label} {}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("opened {label} {} is not a file", path.display()));
    }
    Ok(metadata.nlink())
}

#[cfg(windows)]
fn open_file_link_count(file: &fs::File, path: &Path, label: &str) -> Result<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to inspect opened {label} {}", path.display()));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(anyhow!("opened {label} {} is not a file", path.display()));
    }
    Ok(u64::from(info.nNumberOfLinks))
}

#[cfg(not(any(unix, windows)))]
fn open_file_link_count(_file: &fs::File, path: &Path, label: &str) -> Result<u64> {
    Err(anyhow!(
        "hard-link count inspection is unsupported for {label} {} on this platform",
        path.display()
    ))
}

pub fn validate_quarantine_directory_contents(path: &Path) -> Result<()> {
    let directory = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect quarantine directory before permission changes {}",
            path.display()
        )
    })?;
    if directory.file_type().is_symlink() || !directory.is_dir() {
        return Err(anyhow!(
            "quarantine permission target is not a non-link directory {}",
            path.display()
        ));
    }
    #[cfg(windows)]
    if windows_metadata_is_reparse_point(&directory) {
        return Err(anyhow!(
            "quarantine permission target is a Windows reparse point {}",
            path.display()
        ));
    }

    let mut count = 0_usize;
    for entry in fs::read_dir(path).with_context(|| {
        format!(
            "failed to enumerate quarantine directory before permission changes {}",
            path.display()
        )
    })? {
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow!("quarantine directory entry count overflow"))?;
        if count > MAX_QUARANTINE_DIRECTORY_ENTRIES {
            return Err(anyhow!(
                "quarantine directory exceeds the preflight limit of {MAX_QUARANTINE_DIRECTORY_ENTRIES} entries"
            ));
        }
        let entry = entry.with_context(|| {
            format!(
                "failed to enumerate a quarantine directory entry in {}",
                path.display()
            )
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("quarantine directory contains a non-Unicode entry name"))?;
        if !is_recognized_quarantine_artifact_name(&name) {
            return Err(anyhow!(
                "refusing to change permissions on a directory containing unrecognized entry {name}"
            ));
        }
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path).with_context(|| {
            format!(
                "failed to inspect quarantine entry before permission changes {}",
                entry_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(anyhow!(
                "quarantine directory entry is not a non-link regular file {}",
                entry_path.display()
            ));
        }
        #[cfg(windows)]
        if windows_metadata_is_reparse_point(&metadata) {
            return Err(anyhow!(
                "quarantine directory entry is a Windows reparse point {}",
                entry_path.display()
            ));
        }
        let opened = fs::File::open(&entry_path).with_context(|| {
            format!(
                "failed to open quarantine entry before permission changes {}",
                entry_path.display()
            )
        })?;
        ensure_open_file_has_single_link(&opened, &entry_path, "quarantine directory entry")?;
    }
    Ok(())
}

fn is_recognized_quarantine_artifact_name(name: &str) -> bool {
    if name.is_empty()
        || name.chars().count() > MAX_QUARANTINE_ENTRY_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return false;
    }
    if name == ".metadata_auth_key" || name == ".metadata_auth_key.tmp" {
        return true;
    }
    if let Some(token) = name.strip_prefix(".metadata_auth_key.tmp-") {
        return is_safe_quarantine_component(token, MAX_QUARANTINE_ID_CHARS);
    }
    for marker in [
        ".pending.auth.tmp-",
        ".pending.tmp-",
        ".json.auth.tmp-",
        ".json.tmp-",
    ] {
        if let Some((id, token)) = name.split_once(marker) {
            return is_safe_quarantine_component(id, MAX_QUARANTINE_ID_CHARS)
                && is_safe_quarantine_component(token, MAX_QUARANTINE_ID_CHARS);
        }
    }
    for suffix in [
        ".pending.auth",
        ".pending",
        ".json.auth.tmp",
        ".json.tmp",
        ".json.auth",
        ".json",
        ".avoraxq",
    ] {
        if let Some(id) = name.strip_suffix(suffix) {
            return is_safe_quarantine_component(id, MAX_QUARANTINE_ID_CHARS);
        }
    }
    false
}

fn is_safe_quarantine_component(value: &str, max_chars: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= max_chars
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(windows)]
fn windows_metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(unix)]
pub fn harden_unix_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let expected = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private directory {}", path.display()))?;
    if expected.file_type().is_symlink() || !expected.is_dir() {
        return Err(anyhow!(
            "private directory is not a non-link directory {}",
            path.display()
        ));
    }
    let opened = fs::File::open(path)
        .with_context(|| format!("failed to open private directory {}", path.display()))?;
    let opened_metadata = opened.metadata().with_context(|| {
        format!(
            "failed to inspect opened private directory {}",
            path.display()
        )
    })?;
    if !opened_metadata.is_dir()
        || expected.dev() != opened_metadata.dev()
        || expected.ino() != opened_metadata.ino()
    {
        return Err(anyhow!(
            "private directory changed before permission hardening {}",
            path.display()
        ));
    }
    let owned_metadata =
        enforce_unix_opened_owner(&opened, &opened_metadata, path, "private directory")?;
    let mut permissions = owned_metadata.permissions();
    permissions.set_mode(0o700);
    opened.set_permissions(permissions).with_context(|| {
        format!(
            "failed to set private directory permissions {}",
            path.display()
        )
    })?;
    let current = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to re-inspect private directory after permission hardening {}",
            path.display()
        )
    })?;
    if current.file_type().is_symlink()
        || !current.is_dir()
        || current.dev() != opened_metadata.dev()
        || current.ino() != opened_metadata.ino()
        || current.uid() != unsafe { libc::geteuid() }
        || current.gid() != unsafe { libc::getegid() }
        || current.permissions().mode() & 0o7777 != 0o700
    {
        return Err(anyhow!(
            "private directory permission hardening verification failed {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub fn harden_unix_private_file(file: &fs::File, path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    ensure_open_file_has_single_link(file, path, "private file")?;
    let expected = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private file {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("failed to inspect opened private file {}", path.display()))?;
    if expected.file_type().is_symlink()
        || !expected.is_file()
        || !opened.is_file()
        || expected.dev() != opened.dev()
        || expected.ino() != opened.ino()
    {
        return Err(anyhow!(
            "private file changed before permission hardening {}",
            path.display()
        ));
    }
    let owned = enforce_unix_opened_owner(file, &opened, path, "private file")?;
    let mut permissions = owned.permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
        .with_context(|| format!("failed to set private file permissions {}", path.display()))?;
    let current = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to re-inspect private file after permission hardening {}",
            path.display()
        )
    })?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || current.dev() != opened.dev()
        || current.ino() != opened.ino()
        || current.uid() != unsafe { libc::geteuid() }
        || current.gid() != unsafe { libc::getegid() }
        || current.permissions().mode() & 0o7777 != 0o600
    {
        return Err(anyhow!(
            "private file permission hardening verification failed {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn enforce_unix_opened_owner(
    file: &fs::File,
    opened: &fs::Metadata,
    path: &Path,
    label: &str,
) -> Result<fs::Metadata> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let expected_uid = unsafe { libc::geteuid() };
    let expected_gid = unsafe { libc::getegid() };
    if opened.uid() != expected_uid || opened.gid() != expected_gid {
        let uid = if opened.uid() == expected_uid {
            libc::uid_t::MAX
        } else {
            expected_uid
        };
        let gid = if opened.gid() == expected_gid {
            libc::gid_t::MAX
        } else {
            expected_gid
        };
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to transfer {label} ownership to the current process identity {}",
                    path.display()
                )
            });
        }
    }
    let current = file.metadata().with_context(|| {
        format!(
            "failed to verify opened {label} ownership {}",
            path.display()
        )
    })?;
    if current.uid() != expected_uid || current.gid() != expected_gid {
        return Err(anyhow!(
            "opened {label} ownership verification failed {}",
            path.display()
        ));
    }
    Ok(current)
}

#[cfg(windows)]
const MAX_WINDOWS_TOKEN_USER_BYTES: u32 = 64 * 1024;
#[cfg(windows)]
const MAX_WINDOWS_SID_STRING_UNITS: usize = 256;
#[cfg(windows)]
const MAX_WINDOWS_SECURITY_PATH_UNITS: usize = 32_767;
#[cfg(windows)]
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[cfg(windows)]
pub fn current_windows_process_sid() -> Result<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open the current Windows process token");
    }
    let result = windows_token_user_sid(token);
    finish_windows_handle(result, token, "current Windows process token")
}

#[cfg(windows)]
pub fn harden_windows_private_directory(path: &Path) -> Result<()> {
    let sid = current_windows_process_sid()?;
    let mut aces = vec![
        "(A;OICI;FA;;;SY)".to_string(),
        "(A;OICI;FA;;;BA)".to_string(),
    ];
    if sid != "S-1-5-18" {
        aces.push(format!("(A;OICI;FA;;;{sid})"));
    }
    let sddl = format!("O:{sid}D:P{}", aces.join(""));
    set_and_verify_windows_dacl(path, true, &sddl, None)
        .with_context(|| format!("failed to harden private directory ACL {}", path.display()))
}

#[cfg(windows)]
pub fn harden_windows_quarantine_file(file: &fs::File, path: &Path) -> Result<()> {
    ensure_open_file_has_single_link(file, path, "quarantine file")?;
    let sid = current_windows_process_sid()?;
    let mut aces = vec![
        "(D;;0x20;;;WD)".to_string(),
        "(A;;FA;;;SY)".to_string(),
        "(A;;FA;;;BA)".to_string(),
    ];
    if sid != "S-1-5-18" {
        aces.push(format!("(A;;FA;;;{sid})"));
    }
    let sddl = format!("O:{sid}D:P{}", aces.join(""));
    set_and_verify_windows_dacl(path, false, &sddl, Some(file))
        .with_context(|| format!("failed to harden quarantine file ACL {}", path.display()))
}

#[cfg(windows)]
fn windows_token_user_sid(token: windows_sys::Win32::Foundation::HANDLE) -> Result<String> {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::Security::{GetTokenInformation, IsValidSid, TokenUser, TOKEN_USER};

    let mut required = 0_u32;
    let probe = unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required) };
    let probe_error = std::io::Error::last_os_error();
    if probe != 0
        || probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || required < size_of::<TOKEN_USER>() as u32
        || required > MAX_WINDOWS_TOKEN_USER_BYTES
    {
        return Err(anyhow!(
            "invalid Windows token-user size probe: status={probe}, required={required}, error={probe_error}"
        ));
    }
    let word_bytes = size_of::<usize>();
    let word_count = (required as usize).div_ceil(word_bytes);
    let mut buffer = vec![0_usize; word_count];
    let buffer_bytes = buffer
        .len()
        .checked_mul(word_bytes)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| anyhow!("Windows token-user buffer size overflow"))?;
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            buffer_bytes,
            &mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to read the current Windows process token user");
    }
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    if token_user.User.Sid.is_null() || unsafe { IsValidSid(token_user.User.Sid) } == 0 {
        return Err(anyhow!(
            "current Windows process token contains an invalid user SID"
        ));
    }
    windows_sid_to_string(token_user.User.Sid)
}

#[cfg(windows)]
fn windows_sid_to_string(sid: windows_sys::Win32::Security::PSID) -> Result<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut raw = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to format Windows user SID");
    }
    let result = bounded_windows_wide_string(raw, MAX_WINDOWS_SID_STRING_UNITS)
        .context("Windows user SID string is invalid");
    finish_local_allocation(result, raw.cast(), "Windows user SID string")
}

#[cfg(windows)]
fn set_and_verify_windows_dacl(
    path: &Path,
    directory: bool,
    sddl: &str,
    expected_file: Option<&fs::File>,
) -> Result<()> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let handle = open_windows_security_handle(path, directory, expected_file)?;
    let result = (|| -> Result<()> {
        let descriptor = windows_security_descriptor_from_sddl(sddl)?;
        let set_result = (|| -> Result<()> {
            let owner = windows_security_descriptor_owner(descriptor, "expected")?;
            let mut dacl_present = 0;
            let mut dacl_defaulted = 0;
            let mut dacl = null_mut();
            if unsafe {
                GetSecurityDescriptorDacl(
                    descriptor,
                    &mut dacl_present,
                    &mut dacl,
                    &mut dacl_defaulted,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("failed to read expected Windows quarantine DACL");
            }
            if dacl_present == 0 || dacl.is_null() {
                return Err(anyhow!("expected Windows quarantine DACL is missing"));
            }
            let status = unsafe {
                SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    owner,
                    null_mut(),
                    dacl,
                    null_mut(),
                )
            };
            if status != 0 {
                return Err(std::io::Error::from_raw_os_error(status as i32))
                    .context("failed to set exact Windows quarantine DACL");
            }
            verify_windows_handle_dacl(handle, descriptor)
        })();
        finish_local_allocation(
            set_result,
            descriptor.cast(),
            "expected Windows quarantine security descriptor",
        )
    })();
    finish_windows_handle(result, handle, "Windows quarantine filesystem handle")
}

#[cfg(windows)]
fn open_windows_security_handle(
    path: &Path,
    directory: bool,
    expected_file: Option<&fs::File>,
) -> Result<windows_sys::Win32::Foundation::HANDLE> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };

    let mut path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .take(MAX_WINDOWS_SECURITY_PATH_UNITS.saturating_add(1))
        .collect();
    if path_wide.is_empty() {
        return Err(anyhow!("Windows quarantine security path is empty"));
    }
    if path_wide.len() > MAX_WINDOWS_SECURITY_PATH_UNITS {
        return Err(anyhow!("Windows quarantine security path is too long"));
    }
    if path_wide.contains(&0) {
        return Err(anyhow!("Windows quarantine security path contains NUL"));
    }
    path_wide.push(0);
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open Windows security handle {}", path.display()));
    }
    let inspection = (|| -> Result<()> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect Windows quarantine security handle");
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(anyhow!("refusing to harden a Windows reparse point"));
        }
        let opened_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if opened_directory != directory {
            return Err(anyhow!("Windows quarantine security object kind changed"));
        }
        if let Some(expected_file) = expected_file {
            let expected_handle =
                expected_file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
            let mut expected_info = BY_HANDLE_FILE_INFORMATION::default();
            if unsafe { GetFileInformationByHandle(expected_handle, &mut expected_info) } == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to inspect already-opened Windows quarantine file");
            }
            if expected_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                return Err(anyhow!(
                    "already-opened Windows quarantine object is not a file"
                ));
            }
            if expected_info.dwVolumeSerialNumber != info.dwVolumeSerialNumber
                || expected_info.nFileIndexHigh != info.nFileIndexHigh
                || expected_info.nFileIndexLow != info.nFileIndexLow
            {
                return Err(anyhow!(
                    "Windows quarantine file changed between data and security opens"
                ));
            }
        }
        Ok(())
    })();
    match inspection {
        Ok(()) => Ok(handle),
        Err(error) => finish_windows_handle(
            Err(error),
            handle,
            "invalid Windows quarantine filesystem handle",
        ),
    }
}

#[cfg(windows)]
fn verify_windows_handle_dacl(
    handle: windows_sys::Win32::Foundation::HANDLE,
    expected: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<()> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };

    let mut actual: PSECURITY_DESCRIPTOR = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut actual,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("failed to read back Windows quarantine DACL");
    }
    let verification = (|| -> Result<()> {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        if unsafe { GetSecurityDescriptorControl(actual, &mut control, &mut revision) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect Windows quarantine DACL control flags");
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(anyhow!("Windows quarantine DACL is not protected"));
        }
        let expected_owner = windows_security_descriptor_owner(expected, "expected")?;
        let actual_owner = windows_security_descriptor_owner(actual, "actual")?;
        if unsafe { EqualSid(actual_owner, expected_owner) } == 0 {
            return Err(anyhow!("Windows quarantine owner verification mismatch"));
        }
        let expected_sddl = windows_security_descriptor_dacl_sddl(expected)?;
        let actual_sddl = windows_security_descriptor_dacl_sddl(actual)?;
        let expected_aces = windows_dacl_ace_text(&expected_sddl)?;
        let actual_aces = windows_dacl_ace_text(&actual_sddl)?;
        if actual_aces != expected_aces {
            return Err(anyhow!(
                "Windows quarantine DACL verification mismatch: expected {expected_sddl}, actual {actual_sddl}"
            ));
        }
        Ok(())
    })();
    finish_local_allocation(
        verification,
        actual.cast(),
        "actual Windows quarantine security descriptor",
    )
}

#[cfg(windows)]
fn windows_security_descriptor_owner(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    label: &str,
) -> Result<windows_sys::Win32::Security::PSID> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::{GetSecurityDescriptorOwner, IsValidSid, PSID};

    let mut owner: PSID = null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to read {label} Windows quarantine owner"));
    }
    if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(anyhow!("{label} Windows quarantine owner SID is invalid"));
    }
    Ok(owner)
}

#[cfg(windows)]
fn windows_security_descriptor_from_sddl(
    sddl: &str,
) -> Result<windows_sys::Win32::Security::PSECURITY_DESCRIPTOR> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    if sddl.contains('\0') {
        return Err(anyhow!("Windows quarantine SDDL contains NUL"));
    }
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to parse Windows quarantine SDDL");
    }
    Ok(descriptor)
}

#[cfg(windows)]
fn windows_security_descriptor_dacl_sddl(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    let mut raw = null_mut();
    let mut units = 0_u32;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut raw,
            &mut units,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to format Windows quarantine DACL");
    }
    let result = if units == 0 || units as usize > 4096 {
        Err(anyhow!("Windows quarantine DACL string has invalid length"))
    } else {
        bounded_windows_wide_string(raw, 4096).context("Windows quarantine DACL string is invalid")
    };
    finish_local_allocation(result, raw.cast(), "Windows quarantine DACL string")
}

#[cfg(windows)]
fn windows_dacl_ace_text(sddl: &str) -> Result<&str> {
    let body = sddl
        .strip_prefix("D:")
        .ok_or_else(|| anyhow!("Windows quarantine DACL SDDL has no DACL prefix"))?;
    let ace_start = body
        .find('(')
        .ok_or_else(|| anyhow!("Windows quarantine DACL SDDL has no access entries"))?;
    if !body[..ace_start].contains('P') {
        return Err(anyhow!("Windows quarantine DACL SDDL is not protected"));
    }
    Ok(&body[ace_start..])
}

#[cfg(windows)]
fn bounded_windows_wide_string(raw: *const u16, max_units: usize) -> Result<String> {
    if raw.is_null() {
        return Err(anyhow!("Windows wide string pointer is null"));
    }
    let mut units = 0_usize;
    while units < max_units && unsafe { *raw.add(units) } != 0 {
        units += 1;
    }
    if units == max_units {
        return Err(anyhow!("Windows wide string exceeds maximum length"));
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(raw, units) })
        .context("Windows wide string is invalid UTF-16")
}

#[cfg(windows)]
fn finish_windows_handle<T>(
    result: Result<T>,
    handle: windows_sys::Win32::Foundation::HANDLE,
    label: &str,
) -> Result<T> {
    use windows_sys::Win32::Foundation::CloseHandle;

    let cleanup = if unsafe { CloseHandle(handle) } == 0 {
        Err(std::io::Error::last_os_error()).with_context(|| format!("failed to close {label}"))
    } else {
        Ok(())
    };
    combine_result_and_cleanup(result, cleanup, label)
}

#[cfg(windows)]
fn finish_local_allocation<T>(
    result: Result<T>,
    allocation: windows_sys::Win32::Foundation::HLOCAL,
    label: &str,
) -> Result<T> {
    use windows_sys::Win32::Foundation::LocalFree;

    let cleanup = if unsafe { LocalFree(allocation) }.is_null() {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).with_context(|| format!("failed to free {label}"))
    };
    combine_result_and_cleanup(result, cleanup, label)
}

#[cfg(windows)]
fn combine_result_and_cleanup<T>(result: Result<T>, cleanup: Result<()>, label: &str) -> Result<T> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "additional cleanup failure for {label}: {cleanup_error:#}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        all(unix, target_vendor = "apple")
    ))]
    #[test]
    fn quarantine_restore_no_replace_activation_moves_into_absent_destination() {
        let root = tempfile::tempdir().unwrap();
        let staged = root.path().join("staged.tmp");
        let destination = root.path().join("restored.bin");
        fs::write(&staged, b"harmless restored bytes").unwrap();

        rename_file_no_replace(&staged, &destination, "quarantine restore fixture").unwrap();

        assert!(!staged.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"harmless restored bytes");
    }

    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        all(unix, target_vendor = "apple")
    ))]
    #[test]
    fn quarantine_restore_no_replace_activation_preserves_competing_destination() {
        let root = tempfile::tempdir().unwrap();
        let staged = root.path().join("staged.tmp");
        let destination = root.path().join("restored.bin");
        fs::write(&staged, b"harmless restored bytes").unwrap();
        fs::write(&destination, b"harmless competing bytes").unwrap();

        let error = rename_file_no_replace(&staged, &destination, "quarantine restore fixture")
            .unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("without replacing"), "{detail}");
        assert_eq!(fs::read(&staged).unwrap(), b"harmless restored bytes");
        assert_eq!(fs::read(&destination).unwrap(), b"harmless competing bytes");
    }

    #[cfg(windows)]
    #[test]
    fn quarantine_restore_no_replace_supports_long_absolute_windows_paths() {
        use std::os::windows::ffi::OsStrExt;

        let root = tempfile::tempdir().unwrap();
        let mut long_parent = root.path().to_path_buf();
        while long_parent.as_os_str().encode_wide().count() < 280 {
            long_parent.push("harmless-long-path-segment-2267");
        }
        fs::create_dir_all(&long_parent).unwrap();
        let staged = long_parent.join("staged.tmp");
        let destination = long_parent.join("restored.bin");
        assert!(destination.as_os_str().encode_wide().count() > 260);
        fs::write(&staged, b"harmless long-path restored bytes").unwrap();

        rename_file_no_replace(&staged, &destination, "long quarantine restore fixture").unwrap();

        assert!(!staged.exists());
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"harmless long-path restored bytes"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_no_replace_path_builder_normalizes_local_unc_and_rejects_devices() {
        let local = bounded_windows_move_path(
            Path::new(r"C:\harmless\staged.tmp"),
            "source",
            "path fixture",
        )
        .unwrap();
        assert!(local.starts_with(WINDOWS_VERBATIM_PREFIX));

        let unc = bounded_windows_move_path(
            Path::new(r"\\server\share\harmless\staged.tmp"),
            "source",
            "path fixture",
        )
        .unwrap();
        assert!(unc.starts_with(WINDOWS_VERBATIM_UNC_PREFIX));

        let relative =
            bounded_windows_move_path(Path::new(r"harmless\staged.tmp"), "source", "path fixture")
                .unwrap();
        assert!(!relative.starts_with(WINDOWS_VERBATIM_PREFIX));

        for forbidden in [
            Path::new(r"\\.\PhysicalDrive0"),
            Path::new(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"),
        ] {
            let detail = bounded_windows_move_path(forbidden, "source", "path fixture")
                .unwrap_err()
                .to_string();
            assert!(detail.contains("forbidden Windows"), "{detail}");
        }
    }

    #[test]
    fn scan_quarantine_binding_accepts_unchanged_open_file_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("unchanged.bin");
        fs::write(&path, b"harmless identity fixture").unwrap();
        let opened = fs::File::open(&path).unwrap();

        ensure_path_matches_open_file(&opened, &path, "fixture source").unwrap();
    }

    #[test]
    fn scan_quarantine_binding_rejects_replaced_open_file_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("candidate.bin");
        let displaced = root.path().join("displaced.bin");
        fs::write(&path, b"harmless scanned fixture").unwrap();
        let opened = fs::File::open(&path).unwrap();
        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, b"harmless replacement fixture").unwrap();

        let error = ensure_path_matches_open_file(&opened, &path, "fixture source").unwrap_err();

        assert!(format!("{error:#}").contains("path now identifies a different file"));
        assert_eq!(fs::read(&path).unwrap(), b"harmless replacement fixture");
        assert_eq!(fs::read(&displaced).unwrap(), b"harmless scanned fixture");
    }

    #[test]
    fn quarantine_directory_preflight_accepts_only_vault_shaped_files() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("quarantine");
        fs::create_dir(&directory).unwrap();
        for name in [
            ".metadata_auth_key",
            ".metadata_auth_key.tmp-fixture",
            "record.avoraxq",
            "record.pending",
            "record.pending.auth",
            "record.pending.tmp-fixture",
            "record.pending.auth.tmp-fixture",
            "record.json",
            "record.json.auth",
            "record.json.tmp-fixture",
            "record.json.auth.tmp-fixture",
        ] {
            fs::write(directory.join(name), b"fixture").unwrap();
        }

        validate_quarantine_directory_contents(&directory).unwrap();
    }

    #[test]
    fn quarantine_directory_preflight_rejects_unknown_or_wrong_kind_entries() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("quarantine");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("unrelated.txt"), b"fixture").unwrap();

        let unknown = validate_quarantine_directory_contents(&directory).unwrap_err();
        assert!(format!("{unknown:#}").contains("unrecognized entry unrelated.txt"));

        fs::remove_file(directory.join("unrelated.txt")).unwrap();
        fs::create_dir(directory.join("record.json")).unwrap();
        let wrong_kind = validate_quarantine_directory_contents(&directory).unwrap_err();
        assert!(format!("{wrong_kind:#}").contains("not a non-link regular file"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn opened_file_hard_link_count_must_be_exactly_one() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("fixture.avoraxq");
        let alternate = root.path().join("alternate.avoraxq");
        fs::write(&path, b"benign fixture").unwrap();
        fs::hard_link(&path, &alternate).unwrap();
        let file = fs::File::open(&path).unwrap();

        let error = ensure_open_file_has_single_link(&file, &path, "test payload").unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("hard-link count is 2"), "{detail}");
        assert!(
            detail.contains("requires exactly one filesystem link"),
            "{detail}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn quarantine_directory_preflight_rejects_hard_linked_entries() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("quarantine");
        fs::create_dir(&directory).unwrap();
        let entry = directory.join("record.avoraxq");
        let alternate = root.path().join("alternate");
        fs::write(&entry, b"benign fixture").unwrap();
        fs::hard_link(&entry, &alternate).unwrap();

        let error = validate_quarantine_directory_contents(&directory).unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("hard-link count is 2"), "{detail}");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn private_file_hardening_rejects_hard_linked_payload() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("fixture.avoraxq");
        let alternate = root.path().join("alternate.avoraxq");
        fs::write(&path, b"benign fixture").unwrap();
        fs::hard_link(&path, &alternate).unwrap();
        let file = fs::File::open(&path).unwrap();

        #[cfg(unix)]
        let error = harden_unix_private_file(&file, &path).unwrap_err();
        #[cfg(windows)]
        let error = harden_windows_quarantine_file(&file, &path).unwrap_err();
        let detail = format!("{error:#}");

        assert!(detail.contains("hard-link count is 2"), "{detail}");
        assert_eq!(fs::read(&alternate).unwrap(), b"benign fixture");
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_directory_is_exactly_owner_only() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();

        harden_unix_private_directory(&directory).unwrap();

        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(fs::metadata(&directory).unwrap().uid(), unsafe {
            libc::geteuid()
        });
        assert_eq!(fs::metadata(&directory).unwrap().gid(), unsafe {
            libc::getegid()
        });
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_file_is_exactly_owner_read_write() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private-file");
        fs::write(&path, b"fixture").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        let file = fs::File::open(&path).unwrap();

        harden_unix_private_file(&file, &path).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(fs::metadata(&path).unwrap().uid(), unsafe {
            libc::geteuid()
        });
        assert_eq!(fs::metadata(&path).unwrap().gid(), unsafe {
            libc::getegid()
        });
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_file_rejects_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private-file");
        let moved = root.path().join("moved-file");
        fs::write(&path, b"fixture").unwrap();
        let file = fs::File::open(&path).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"replacement").unwrap();

        let error = harden_unix_private_file(&file, &path).unwrap_err();

        assert!(error
            .to_string()
            .contains("changed before permission hardening"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_process_sid_ignores_spoofed_account_environment() {
        let original_user = std::env::var_os("USERNAME");
        let original_domain = std::env::var_os("USERDOMAIN");
        let first = current_windows_process_sid().unwrap();
        std::env::set_var("USERNAME", "Everyone");
        std::env::set_var("USERDOMAIN", "UntrustedDomain");
        let second = current_windows_process_sid().unwrap();
        match original_user {
            Some(value) => std::env::set_var("USERNAME", value),
            None => std::env::remove_var("USERNAME"),
        }
        match original_domain {
            Some(value) => std::env::set_var("USERDOMAIN", value),
            None => std::env::remove_var("USERDOMAIN"),
        }

        assert!(first.starts_with("S-1-"));
        assert_eq!(first, second);
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_directory_and_file_dacls_are_applied_and_verified() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("quarantine");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("fixture.avoraxq");
        fs::write(&file, b"fixture").unwrap();

        harden_windows_private_directory(&directory).unwrap();
        let opened = fs::File::open(&file).unwrap();
        harden_windows_quarantine_file(&opened, &file).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_quarantine_file_rejects_open_handle_path_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let expected_path = root.path().join("expected.avoraxq");
        let replacement_path = root.path().join("replacement.avoraxq");
        fs::write(&expected_path, b"expected").unwrap();
        fs::write(&replacement_path, b"replacement").unwrap();
        let replacement = fs::File::open(&replacement_path).unwrap();

        let error = harden_windows_quarantine_file(&replacement, &expected_path).unwrap_err();
        let detail = format!("{error:#}");

        assert!(
            detail.contains("changed between data and security opens"),
            "{detail}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_security_paths_are_bounded_and_reject_nul() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use std::path::PathBuf;

        let nul_path = PathBuf::from(OsString::from_wide(&[b'a' as u16, 0, b'b' as u16]));
        let nul_error = open_windows_security_handle(&nul_path, false, None).unwrap_err();
        assert!(nul_error.to_string().contains("contains NUL"));

        let long_path = PathBuf::from(OsString::from_wide(&vec![
            b'a' as u16;
            MAX_WINDOWS_SECURITY_PATH_UNITS
                + 1
        ]));
        let long_error = open_windows_security_handle(&long_path, false, None).unwrap_err();
        assert!(long_error.to_string().contains("is too long"));
    }
}
