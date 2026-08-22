use std::fs;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub fn is_windows_system_path(path: &Path) -> Result<bool> {
    Ok(windows_system_path_roots()?
        .iter()
        .any(|root| path_starts_with_case_insensitive(path, root)))
}

#[cfg(windows)]
fn windows_system_path_roots() -> Result<Vec<PathBuf>> {
    Ok(vec![
        crate::windows_system::checked_system_directory(
            "System32",
            "Windows System32 trust directory",
        )?,
        crate::windows_system::checked_system_directory(
            "SysWOW64",
            "Windows SysWOW64 trust directory",
        )?,
    ])
}

#[cfg(not(windows))]
fn windows_system_path_roots() -> Result<Vec<PathBuf>> {
    Ok(Vec::new())
}

fn path_starts_with_case_insensitive(path: &Path, root: &Path) -> bool {
    let path_text = normalized_path_text(path);
    let root_text = normalized_path_text(root);
    !root_text.is_empty()
        && (path_text == root_text || path_text.starts_with(&format!("{root_text}\\")))
}

fn normalized_path_text(path: &Path) -> String {
    let path_text = path
        .display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase();
    collapse_windows_system_path_segments(&path_text)
}

fn collapse_windows_system_path_segments(path: &str) -> String {
    let trimmed = path.trim_end_matches('\\');
    if trimmed.is_empty() {
        return String::new();
    }

    let (prefix, rest, absolute) = split_windows_system_path_prefix(trimmed);
    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split('\\') {
        match segment {
            "" | "." => {}
            ".." => {
                if let Some(last) = segments.last() {
                    if *last != ".." {
                        segments.pop();
                        continue;
                    }
                }
                if !absolute {
                    segments.push(segment);
                }
            }
            _ => segments.push(segment),
        }
    }

    let body = segments.join("\\");
    match (prefix, absolute, body.is_empty()) {
        (Some(prefix), _, true) => prefix.to_string(),
        (Some(prefix), _, false) => format!("{prefix}\\{body}"),
        (None, true, true) => "\\".to_string(),
        (None, true, false) => format!("\\{body}"),
        (None, false, _) => body,
    }
}

fn split_windows_system_path_prefix(path: &str) -> (Option<&str>, &str, bool) {
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'\\' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with('\\') {
        return (None, path.trim_start_matches('\\'), true);
    }
    (None, path, false)
}

pub fn microsoft_signature_verdict(path: &Path) -> Result<bool> {
    microsoft_signature_verdict_inner(path, None)
}

pub fn microsoft_signature_verdict_for_sha256(path: &Path, expected_sha256: &str) -> Result<bool> {
    microsoft_signature_verdict_inner(path, Some(expected_sha256))
}

#[cfg(windows)]
fn microsoft_signature_verdict_inner(path: &Path, expected_sha256: Option<&str>) -> Result<bool> {
    if !authenticode_candidate_file(path)? {
        return Ok(false);
    }
    crate::windows_authenticode::has_valid_microsoft_signature(path, expected_sha256)
}

#[cfg(not(windows))]
fn microsoft_signature_verdict_inner(_path: &Path, _expected_sha256: Option<&str>) -> Result<bool> {
    Ok(false)
}

fn authenticode_candidate_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()
            && !metadata.file_type().is_symlink()
            && !is_windows_reparse_point(&metadata)),
        Err(error) => Err(error).with_context(|| {
            format!(
                "unable to inspect Authenticode candidate {}",
                path.display()
            )
        }),
    }
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(windows)]
    fn microsoft_embedded_signature_fixture() -> PathBuf {
        let program_files_x86 = std::env::var_os("ProgramFiles(x86)")
            .expect("x64 Windows ProgramFiles(x86) is required for the Edge signature fixture");
        let path = PathBuf::from(program_files_x86)
            .join("Microsoft")
            .join("Edge")
            .join("Application")
            .join("msedge.exe");
        assert!(path.is_absolute());
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        path
    }

    #[test]
    fn authenticode_candidate_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();

        assert!(!authenticode_candidate_file(dir.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn authenticode_candidate_rejects_symbolic_link() {
        use std::os::unix::fs as unix_fs;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.exe");
        let link = dir.path().join("link.exe");
        fs::write(&target, b"benign fixture").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        assert!(!authenticode_candidate_file(&link).unwrap());
    }

    #[test]
    fn microsoft_signature_path_guard_uses_non_following_inspection() {
        let source = include_str!("microsoft_trust.rs");
        let legacy_exists_probe = ["path", ".exists()"].concat();

        assert!(source.contains("authenticode_candidate_file(path)"));
        assert!(source.contains("fs::symlink_metadata(path)"));
        assert!(source.contains("metadata.file_type().is_symlink()"));
        assert!(!source.contains(&legacy_exists_probe));
    }

    #[cfg(windows)]
    #[test]
    fn native_direct_authenticode_rejects_unsigned_benign_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("unsigned-fixture.exe");
        fs::write(&file, b"benign unsigned fixture").unwrap();

        assert!(!microsoft_signature_verdict(&file).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn native_direct_authenticode_rejects_malformed_non_pe_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("malformed-fixture.exe");
        fs::write(&file, [0_u8, 0xff, b'M', b'Z', 0, 1, 2, 3]).unwrap();

        assert!(!microsoft_signature_verdict(&file).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn native_catalog_authenticode_accepts_catalog_signed_windows_powershell() {
        let powershell = crate::windows_system::checked_system32_file(
            &["WindowsPowerShell", "v1.0", "powershell.exe"],
            "catalog-signed WindowsPowerShell fixture",
        )
        .unwrap();

        assert!(microsoft_signature_verdict(&powershell).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn native_catalog_authenticode_verdict_binds_to_scanned_sha256() {
        let powershell = crate::windows_system::checked_system32_file(
            &["WindowsPowerShell", "v1.0", "powershell.exe"],
            "catalog-signed WindowsPowerShell fixture",
        )
        .unwrap();
        let bytes = fs::read(&powershell).unwrap();
        let sha256 = crate::engine::sha256_bytes(&bytes);

        assert!(microsoft_signature_verdict_for_sha256(&powershell, &sha256).unwrap());
        let error = microsoft_signature_verdict_for_sha256(&powershell, &"0".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match the bytes already scanned"));
    }

    #[cfg(windows)]
    #[test]
    fn native_direct_authenticode_microsoft_signed_embedded_edge_binary() {
        let edge = microsoft_embedded_signature_fixture();

        assert!(microsoft_signature_verdict(&edge).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn native_direct_authenticode_microsoft_signed_embedded_verdict_binds_to_scanned_sha256() {
        let edge = microsoft_embedded_signature_fixture();
        let bytes = fs::read(&edge).unwrap();
        let sha256 = crate::engine::sha256_bytes(&bytes);

        assert!(microsoft_signature_verdict_for_sha256(&edge, &sha256).unwrap());
        let error = microsoft_signature_verdict_for_sha256(&edge, &"0".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match the bytes already scanned"));
    }

    #[test]
    fn native_authenticode_trust_boundary_has_no_script_or_shell_probe() {
        let source = include_str!("microsoft_trust.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(production.contains(
            "crate::windows_authenticode::has_valid_microsoft_signature(path, expected_sha256)"
        ));
        assert!(production.contains("pub fn microsoft_signature_verdict_for_sha256("));
        for removed in [
            "std::process::Command",
            "WindowsPowerShell",
            "powershell.exe",
            "EncodedCommand",
            "PSModulePath",
            "ConvertTo-Json",
            "Get-AuthenticodeSignature",
        ] {
            assert!(
                !production.contains(removed),
                "obsolete helper marker: {removed}"
            );
        }
    }

    #[test]
    fn native_windows_system_path_trust_uses_checked_root_not_hardcoded_root() {
        let source = include_str!("microsoft_trust.rs");
        let helper_start = source.find("pub fn is_windows_system_path").unwrap();
        let verdict_start = source.find("pub fn microsoft_signature_verdict").unwrap();
        let helper_source = &source[helper_start..verdict_start];
        let legacy_system32 = ["c:", "\\\\windows\\\\system32"].concat();
        let legacy_syswow64 = ["c:", "\\\\windows\\\\syswow64"].concat();

        assert!(
            helper_source.contains("pub fn is_windows_system_path(path: &Path) -> Result<bool>")
        );
        assert!(helper_source.contains("windows_system_path_roots()?"));
        assert!(helper_source.contains("crate::windows_system::checked_system_directory("));
        assert!(helper_source.contains("\"System32\""));
        assert!(helper_source.contains("\"SysWOW64\""));
        assert!(helper_source.contains("path_starts_with_case_insensitive(path, root)"));
        assert!(helper_source.contains("path_text.starts_with(&format!"));
        assert!(!helper_source
            .to_ascii_lowercase()
            .contains(&legacy_system32));
        assert!(!helper_source
            .to_ascii_lowercase()
            .contains(&legacy_syswow64));
    }

    #[test]
    fn native_windows_system_path_prefix_requires_component_boundary() {
        assert!(path_starts_with_case_insensitive(
            Path::new(r"C:\Windows\System32\kernel32.dll"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(path_starts_with_case_insensitive(
            Path::new(r"c:/windows/syswow64"),
            Path::new(r"C:\Windows\SysWOW64")
        ));
        assert!(path_starts_with_case_insensitive(
            Path::new(r"C:\Windows\System32\.\kernel32.dll"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(!path_starts_with_case_insensitive(
            Path::new(r"C:\Windows\System32\..\Temp\payload.exe"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(!path_starts_with_case_insensitive(
            Path::new(r"C:\Windows\System32evil\kernel32.dll"),
            Path::new(r"C:\Windows\System32")
        ));
        assert!(!path_starts_with_case_insensitive(
            Path::new(r"C:\Windows"),
            Path::new(r"C:\Windows\System32")
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn native_direct_authenticode_is_conservatively_unavailable_off_windows() {
        assert!(!microsoft_signature_verdict(Path::new("fixture.exe")).unwrap());
        assert!(
            !microsoft_signature_verdict_for_sha256(Path::new("fixture.exe"), &"0".repeat(64))
                .unwrap()
        );
    }
}
