use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

const MAX_SYSTEM_WINDOWS_DIRECTORY_CHARS: usize = 32_768;
const MAX_SYSTEM32_RELATIVE_COMPONENTS: usize = 8;
const MAX_SYSTEM32_COMPONENT_CHARS: usize = 128;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

static SYSTEM_WINDOWS_DIRECTORY: OnceLock<Result<PathBuf, String>> = OnceLock::new();

pub(crate) fn checked_system_windows_directory() -> Result<PathBuf> {
    let path = cached_system_windows_directory()?;
    anyhow::ensure!(
        is_local_windows_drive_path(&path),
        "system Windows directory must be a rooted local drive path: {}",
        path.display()
    );
    anyhow::ensure!(
        path.components().all(|component| matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::Normal(_)
        )),
        "system Windows directory contains a non-normal path component: {}",
        path.display()
    );
    reject_reparse_ancestors(&path, "system Windows directory")?;
    let metadata = fs::symlink_metadata(&path).with_context(|| {
        format!(
            "unable to inspect system Windows directory {}",
            path.display()
        )
    })?;
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && !metadata_is_reparse_point(&metadata),
        "system Windows directory is not a regular non-reparse directory: {}",
        path.display()
    );
    Ok(path)
}

pub(crate) fn checked_system_directory(name: &str, label: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        matches!(name, "System32" | "SysWOW64"),
        "unsupported {label} directory name"
    );
    let candidate = checked_system_windows_directory()?.join(name);
    reject_reparse_ancestors(&candidate, label)?;
    let metadata = fs::symlink_metadata(&candidate)
        .with_context(|| format!("unable to inspect {label} {}", candidate.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && !metadata_is_reparse_point(&metadata),
        "{label} is not a regular non-reparse directory: {}",
        candidate.display()
    );
    Ok(candidate)
}

pub(crate) fn checked_system32_file(relative_components: &[&str], label: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        !relative_components.is_empty()
            && relative_components.len() <= MAX_SYSTEM32_RELATIVE_COMPONENTS,
        "{label} relative path must contain between 1 and {MAX_SYSTEM32_RELATIVE_COMPONENTS} components"
    );
    for component in relative_components {
        validate_system32_relative_component(component, label)?;
    }

    let mut candidate = checked_system_windows_directory()?.join("System32");
    for component in relative_components {
        candidate.push(component);
    }
    reject_reparse_ancestors(&candidate, label)?;
    let metadata = fs::symlink_metadata(&candidate)
        .with_context(|| format!("unable to inspect {label} {}", candidate.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to use symbolic link {label} {}",
        candidate.display()
    );
    anyhow::ensure!(
        !metadata_is_reparse_point(&metadata),
        "refusing to use reparse point {label} {}",
        candidate.display()
    );
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "{label} {} is not a regular file",
        candidate.display()
    );
    Ok(candidate)
}

fn cached_system_windows_directory() -> Result<PathBuf> {
    match SYSTEM_WINDOWS_DIRECTORY
        .get_or_init(|| query_system_windows_directory().map_err(|error| format!("{error:#}")))
    {
        Ok(path) => Ok(path.clone()),
        Err(error) => anyhow::bail!("{error}"),
    }
}

fn query_system_windows_directory() -> Result<PathBuf> {
    let mut buffer = vec![u16::MAX; MAX_SYSTEM_WINDOWS_DIRECTORY_CHARS];
    let chars = unsafe {
        GetSystemWindowsDirectoryW(
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len())
                .map_err(|_| anyhow::anyhow!("system Windows directory buffer exceeded u32"))?,
        )
    };
    if chars == 0 {
        let error = unsafe { GetLastError() };
        anyhow::bail!(
            "unable to query the system Windows directory: {}",
            io::Error::from_raw_os_error(error as i32)
        );
    }
    system_windows_directory_from_result(chars, &buffer)
}

fn validate_system32_relative_component(component: &str, label: &str) -> Result<()> {
    anyhow::ensure!(
        !component.is_empty() && component.chars().count() <= MAX_SYSTEM32_COMPONENT_CHARS,
        "{label} contains an empty or oversized path component"
    );
    anyhow::ensure!(
        component != "."
            && component != ".."
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')),
        "{label} contains an unsafe path component"
    );
    Ok(())
}

fn is_local_windows_drive_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(
        (components.next(), components.next()),
        (
            Some(Component::Prefix(prefix)),
            Some(Component::RootDir)
        ) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    )
}

fn reject_reparse_ancestors(path: &Path, label: &str) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "refusing to use symbolic link {label} ancestor {}",
                    ancestor.display()
                );
                anyhow::ensure!(
                    !metadata_is_reparse_point(&metadata),
                    "refusing to use reparse point {label} ancestor {}",
                    ancestor.display()
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect {label} ancestor {}", ancestor.display())
                });
            }
        }
    }
    Ok(())
}

fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn system_windows_directory_from_result(chars: u32, buffer: &[u16]) -> Result<PathBuf> {
    let chars = usize::try_from(chars)
        .map_err(|_| anyhow::anyhow!("system Windows directory length exceeded usize"))?;
    if chars == 0 || chars >= buffer.len() {
        anyhow::bail!(
            "system Windows directory exceeded the bounded {} character buffer",
            buffer.len()
        );
    }
    if buffer[..chars].contains(&0) {
        anyhow::bail!("system Windows directory contained an embedded NUL");
    }
    if buffer[chars] != 0 {
        anyhow::bail!("system Windows directory was not NUL terminated");
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..chars])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_windows_system_directory_result_rejects_invalid_lengths_and_text() {
        assert!(system_windows_directory_from_result(0, &[0; 4])
            .unwrap_err()
            .to_string()
            .contains("bounded"));
        assert!(system_windows_directory_from_result(4, &[b'C' as u16; 4])
            .unwrap_err()
            .to_string()
            .contains("bounded"));
        assert!(
            system_windows_directory_from_result(3, &[b'C' as u16, 0, b'X' as u16, 0])
                .unwrap_err()
                .to_string()
                .contains("embedded NUL")
        );
        assert!(system_windows_directory_from_result(
            3,
            &[b'C' as u16, b':' as u16, b'X' as u16, b'Y' as u16]
        )
        .unwrap_err()
        .to_string()
        .contains("not NUL terminated"));
    }

    #[test]
    fn native_windows_system_directory_result_preserves_the_returned_prefix() {
        let wide: Vec<u16> = r"C:\Windows".encode_utf16().collect();
        let mut buffer = wide.clone();
        buffer.push(0);
        buffer.extend([b'X' as u16, b'X' as u16]);

        assert_eq!(
            system_windows_directory_from_result(wide.len() as u32, &buffer).unwrap(),
            PathBuf::from(r"C:\Windows")
        );
    }

    #[test]
    fn native_windows_system_directory_ignores_spoofed_environment() {
        const CASE: &str = "native-windows-system-directory-environment-spoof";
        const FAKE_ROOT: &str = r"Z:\AvoraxEnvironmentSpoof";
        if crate::test_support::is_isolated_environment_case(CASE) {
            assert_eq!(std::env::var("SystemRoot").unwrap(), FAKE_ROOT);
            assert_eq!(std::env::var("WINDIR").unwrap(), FAKE_ROOT);
            let path = checked_system_windows_directory().unwrap();
            assert_ne!(path, PathBuf::from(FAKE_ROOT));
            assert!(path.is_absolute());
            return;
        }

        crate::test_support::run_isolated_environment_case(
            "windows_system::tests::native_windows_system_directory_ignores_spoofed_environment",
            CASE,
            |command| {
                command
                    .env("SystemRoot", FAKE_ROOT)
                    .env("WINDIR", FAKE_ROOT);
            },
        );
    }

    #[test]
    fn native_windows_system32_file_rejects_unsafe_relative_components() {
        for components in [
            Vec::<&str>::new(),
            vec!["..", "powershell.exe"],
            vec!["WindowsPowerShell\\v1.0", "powershell.exe"],
            vec!["C:", "powershell.exe"],
            vec!["powershell.exe", "."],
        ] {
            assert!(checked_system32_file(&components, "test Windows tool").is_err());
        }
    }

    #[test]
    fn native_windows_system_directories_are_checked_and_bounded() {
        let root = checked_system_windows_directory().unwrap();
        for name in ["System32", "SysWOW64"] {
            let path = checked_system_directory(name, "test Windows system directory").unwrap();
            assert_eq!(path, root.join(name));
            assert!(fs::symlink_metadata(path).unwrap().file_type().is_dir());
        }
        assert!(checked_system_directory("..", "test Windows system directory").is_err());
        assert!(
            checked_system_directory("System32\\drivers", "test Windows system directory").is_err()
        );
    }

    #[test]
    fn native_windows_system32_file_runtime_returns_real_tools() {
        let root = checked_system_windows_directory().unwrap();
        let path = checked_system32_file(
            &["WindowsPowerShell", "v1.0", "powershell.exe"],
            "test Windows tool",
        )
        .unwrap();

        assert!(path.starts_with(root.join("System32")));
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_file());
    }
}
