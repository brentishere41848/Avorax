use std::path::{Component, Path, PathBuf};

use crate::signatures::known_bad_hashes::{is_sha256, normalize_hash};

#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    hashes: Vec<String>,
    paths: Vec<String>,
}

impl Allowlist {
    pub fn contains(&self, path: &Path, sha256: &str) -> bool {
        self.hashes
            .iter()
            .any(|hash| is_sha256(sha256) && hash == &normalize_hash(sha256))
            || self
                .paths
                .iter()
                .any(|entry| path_matches_entry(path, entry))
    }

    pub fn add_hash(&mut self, sha256: String) -> anyhow::Result<()> {
        if !is_sha256(&sha256) {
            anyhow::bail!("native allowlist hash entry is malformed");
        }
        self.hashes.push(normalize_hash(&sha256));
        Ok(())
    }

    pub fn add_path(&mut self, path: String) -> anyhow::Result<()> {
        if !Self::validate_path(&path) {
            anyhow::bail!("native allowlist path entry is unsafe");
        }
        self.paths.push(path);
        Ok(())
    }

    pub fn validate_path(path: &str) -> bool {
        let windows_path = normalize_path_text(path);
        let unix_path = normalize_unix_path_text(path);
        !windows_path.is_empty()
            && !is_blocked_windows_allowlist_root(&windows_path)
            && !is_blocked_unix_allowlist_root(&unix_path)
    }
}

fn is_blocked_windows_allowlist_root(path: &str) -> bool {
    if is_windows_drive_root(path) {
        return true;
    }
    let Some(rest) = windows_drive_absolute_rest(path) else {
        return false;
    };
    matches!(
        rest,
        "windows" | "program files" | "program files (x86)" | "programdata" | "users"
    )
}

fn is_windows_drive_root(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() == 2 || (bytes.len() == 3 && bytes[2] == b'\\'))
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
}

fn windows_drive_absolute_rest(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        Some(&path[3..])
    } else {
        None
    }
}

fn is_blocked_unix_allowlist_root(path: &str) -> bool {
    matches!(path, "/" | "/system" | "/usr" | "/bin" | "/sbin" | "/etc")
}

fn path_matches_entry(path: &Path, entry: &str) -> bool {
    let Some(entry_path) = normalized_path_text_for_match(entry) else {
        return false;
    };
    let Some(candidate) = normalized_path_text_for_match(&path.to_string_lossy()) else {
        return false;
    };
    candidate == entry_path || candidate.starts_with(&format!("{entry_path}\\"))
}

fn normalized_path_text_for_match(value: &str) -> Option<String> {
    normalized_path(value).map(|path| normalize_path_text(&path.to_string_lossy()))
}

fn normalized_path(value: &str) -> Option<PathBuf> {
    let normalized = normalize_path_text(value);
    if normalized.is_empty() || !Allowlist::validate_path(&normalized) {
        return None;
    }
    let mut out = PathBuf::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(component.as_os_str()),
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir => return None,
        }
    }
    Some(out)
}

fn normalize_path_text(path: &str) -> String {
    let mut normalized = String::with_capacity(path.len());
    let mut previous_separator = false;
    for ch in path.trim().chars() {
        if ch == '\\' || ch == '/' {
            if !previous_separator {
                normalized.push('\\');
            }
            previous_separator = true;
        } else {
            normalized.push(ch.to_ascii_lowercase());
            previous_separator = false;
        }
    }
    collapse_path_segments(&normalized, '\\')
}

fn normalize_unix_path_text(path: &str) -> String {
    let mut normalized = String::with_capacity(path.len());
    let mut previous_separator = false;
    for ch in path.trim().chars() {
        if ch == '/' {
            if !previous_separator {
                normalized.push('/');
            }
            previous_separator = true;
        } else {
            normalized.push(ch.to_ascii_lowercase());
            previous_separator = false;
        }
    }
    collapse_path_segments(&normalized, '/')
}

fn collapse_path_segments(path: &str, separator: char) -> String {
    let trimmed = path.trim_end_matches(separator);
    if trimmed.is_empty() {
        return String::new();
    }

    let (prefix, rest, absolute) = split_path_prefix(trimmed, separator);
    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split(separator) {
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

    let separator = separator.to_string();
    let body = segments.join(&separator);
    match (prefix, absolute, body.is_empty()) {
        (Some(prefix), _, true) => prefix.to_string(),
        (Some(prefix), _, false) => format!("{prefix}{separator}{body}"),
        (None, true, true) => separator,
        (None, true, false) => format!("{separator}{body}"),
        (None, false, _) => body,
    }
}

fn split_path_prefix(path: &str, separator: char) -> (Option<&str>, &str, bool) {
    let bytes = path.as_bytes();
    if separator == '\\' && bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'\\' {
        return (Some(&path[..2]), &path[3..], true);
    }
    if path.starts_with(separator) {
        return (None, path.trim_start_matches(separator), true);
    }
    (None, path, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_broad_roots() {
        assert!(!Allowlist::validate_path("C:\\"));
        assert!(!Allowlist::validate_path("C:/"));
        assert!(!Allowlist::validate_path("C:\\Windows"));
        assert!(!Allowlist::validate_path("C:\\ProgramData"));
        assert!(!Allowlist::validate_path("C:\\Users"));
        assert!(!Allowlist::validate_path("C:\\\\Windows"));
        assert!(!Allowlist::validate_path("D://ProgramData"));
        assert!(!Allowlist::validate_path("D:\\"));
        assert!(!Allowlist::validate_path("D:\\Windows"));
        assert!(!Allowlist::validate_path("D:\\Program Files"));
        assert!(!Allowlist::validate_path("/"));
        assert!(!Allowlist::validate_path("/usr"));
        assert!(!Allowlist::validate_path("/usr//"));
        assert!(!Allowlist::validate_path("/etc"));
        assert!(!Allowlist::validate_path(
            "C:\\Users\\Brent\\..\\..\\Windows"
        ));
        assert!(!Allowlist::validate_path("/home/brent/../../usr"));
        assert!(Allowlist::validate_path("C:\\Users\\Brent\\Downloads"));
    }

    #[test]
    fn hash_allowlist_is_exact() {
        let mut allowlist = Allowlist::default();
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        allowlist.add_hash(format!("sha256:{hash}")).unwrap();
        assert!(allowlist.contains(Path::new("C:\\Temp\\bad.exe"), hash));
        assert!(!allowlist.contains(
            Path::new("C:\\Temp\\bad.exe"),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
    }

    #[test]
    fn malformed_hash_allowlist_entries_fail_closed() {
        let mut allowlist = Allowlist::default();
        let error = allowlist.add_hash("sha256:abc".to_string()).unwrap_err();
        assert!(error
            .to_string()
            .contains("native allowlist hash entry is malformed"));
        assert!(!allowlist.contains(Path::new("C:\\Temp\\bad.exe"), "sha256:abc"));
    }

    #[test]
    fn path_allowlist_is_component_aware() {
        let mut allowlist = Allowlist::default();
        allowlist
            .add_path("C:\\Users\\Brent\\Downloads".to_string())
            .unwrap();
        assert!(allowlist.contains(
            Path::new("C:\\Users\\Brent\\Downloads\\tool.exe"),
            "sha256:other"
        ));
        assert!(!allowlist.contains(
            Path::new("C:\\Users\\Brent\\Downloads2\\tool.exe"),
            "sha256:other"
        ));
        assert!(!allowlist.contains(
            Path::new("C:\\Users\\Brent\\Downloads\\..\\Temp\\tool.exe"),
            "sha256:other"
        ));
        assert!(allowlist.contains(
            Path::new("C:\\Users\\Brent\\Downloads\\.\\Tools\\..\\tool.exe"),
            "sha256:other"
        ));
        let error = allowlist.add_path("C:\\".to_string()).unwrap_err();
        assert!(error
            .to_string()
            .contains("native allowlist path entry is unsafe"));
    }

    #[test]
    fn path_allowlist_does_not_match_sibling_prefixes() {
        let mut allowlist = Allowlist::default();
        allowlist.add_path("C:\\Users\\A".to_string()).unwrap();

        assert!(allowlist.contains(Path::new("C:\\Users\\A\\tool.exe"), "sha256:other"));
        assert!(!allowlist.contains(Path::new("C:\\Users\\Alice\\tool.exe"), "sha256:other"));
    }
}
