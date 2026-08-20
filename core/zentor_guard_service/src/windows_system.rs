use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use anyhow::Result;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

const MAX_SYSTEM_WINDOWS_DIRECTORY_CHARS: usize = 32_768;

pub(crate) fn system_windows_directory() -> Result<PathBuf> {
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
    fn windows_system_directory_result_rejects_invalid_lengths_and_text() {
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
    fn windows_system_directory_result_preserves_the_returned_prefix() {
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
    fn windows_system_directory_runtime_returns_a_directory() {
        let path = system_windows_directory().unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();

        assert!(path.is_absolute());
        assert!(metadata.file_type().is_dir());
        assert!(!metadata.file_type().is_symlink());
    }
}
