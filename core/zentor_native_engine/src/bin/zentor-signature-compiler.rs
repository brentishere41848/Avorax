use std::env;
use std::fs;
use std::io::{BufReader, ErrorKind, Read, Write};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use uuid::Uuid;
use zentor_native_engine::signatures::pack_format::SignaturePack;
use zentor_native_engine::signatures::signature_compiler;

const MAX_SIGNATURE_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_SIGNATURE_PACK_VERSION: &str = "0.1.0";

#[derive(Debug, PartialEq, Eq)]
struct SignatureCompilerArgs {
    input: String,
    output: String,
    metadata: String,
    version: String,
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_help();
        return Ok(());
    }
    let parsed = parse_signature_compiler_args(&args)?;

    let raw = read_bounded_signature_source(Path::new(&parsed.input))
        .with_context(|| format!("failed to read signature source {}", parsed.input))?;
    let source_pack: SignaturePack = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse signature source {}", parsed.input))?;
    let (compiled_pack, compiled_metadata) =
        signature_compiler::compile_pack(source_pack.signatures, parsed.version)?;

    write_json(PathBuf::from(parsed.output), &compiled_pack)?;
    write_json(PathBuf::from(parsed.metadata), &compiled_metadata)?;
    Ok(())
}

fn read_bounded_signature_source(path: &Path) -> Result<String> {
    let metadata = ensure_regular_signature_source(path)?;
    if metadata.len() > MAX_SIGNATURE_SOURCE_BYTES {
        bail!(
            "signature source {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_SIGNATURE_SOURCE_BYTES
        );
    }
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .context("signature source size overflow")?;
        if total > MAX_SIGNATURE_SOURCE_BYTES {
            bail!(
                "signature source {} exceeds maximum size of {} bytes",
                path.display(),
                MAX_SIGNATURE_SOURCE_BYTES
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes)
        .with_context(|| format!("failed to decode signature source {}", path.display()))
}

fn ensure_regular_signature_source(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect signature source {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing to read symbolic link signature source {}",
            path.display()
        );
    }
    if is_windows_reparse_point(&metadata) {
        bail!(
            "refusing to read reparse point signature source {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        bail!("signature source is not a regular file {}", path.display());
    }
    if metadata.len() > MAX_SIGNATURE_SOURCE_BYTES {
        bail!(
            "signature source {} exceeds maximum size of {} bytes",
            path.display(),
            MAX_SIGNATURE_SOURCE_BYTES
        );
    }
    Ok(metadata)
}

fn parse_signature_compiler_args(args: &[String]) -> Result<SignatureCompilerArgs> {
    let mut input = None;
    let mut output = None;
    let mut metadata = None;
    let mut version = None;
    let mut index = 0;
    while index < args.len() {
        let key = args[index].as_str();
        let slot = match key {
            "--input" => &mut input,
            "--output" => &mut output,
            "--metadata" => &mut metadata,
            "--version" => &mut version,
            "--help" | "-h" => bail!("{key} must be used by itself"),
            _ => bail!("unexpected signature compiler argument {key}"),
        };
        if slot.is_some() {
            bail!("duplicate signature compiler argument {key}");
        }
        let value = args
            .get(index + 1)
            .with_context(|| format!("{key} requires a value"))?;
        if value.starts_with("--") || value == "-h" {
            bail!("{key} requires a value before {value}");
        }
        if value.trim().is_empty() {
            bail!("{key} value must not be empty");
        }
        *slot = Some(value.clone());
        index += 2;
    }

    Ok(SignatureCompilerArgs {
        input: input.context("--input is required")?,
        output: output.context("--output is required")?,
        metadata: metadata.context("--metadata is required")?,
        version: match version {
            Some(version) => version,
            None => default_signature_pack_version().to_string(),
        },
    })
}

#[cfg(test)]
fn signature_compiler_version(args: &[String]) -> Result<String> {
    Ok(parse_signature_compiler_args(args)?.version)
}

fn default_signature_pack_version() -> &'static str {
    DEFAULT_SIGNATURE_PACK_VERSION
}

fn write_json<T: serde::Serialize>(path: PathBuf, value: &T) -> Result<()> {
    let target = checked_output_target(&path)?;
    let json = serde_json::to_string_pretty(value)?;
    if json.trim().is_empty() {
        bail!("refusing to write empty compiler output");
    }
    write_signature_compiler_output(&target, format!("{json}\n").as_bytes())
        .with_context(|| format!("failed to write {}", target.display()))?;
    Ok(())
}

fn checked_output_target(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("signature compiler output path is empty");
    }
    if path.file_name().is_none() {
        bail!(
            "signature compiler output path has no file name: {}",
            path.display()
        );
    }
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let current_dir = env::current_dir()
        .context("failed to read current directory for signature compiler output")?;
    Ok(current_dir.join(path))
}

fn write_signature_compiler_output(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = output_parent(path)?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create compiler output directory {}",
            parent.display()
        )
    })?;
    ensure_output_directory(parent, "signature compiler output directory")?;
    if path.file_name().is_none() {
        bail!(
            "signature compiler output path has no file name: {}",
            path.display()
        );
    }
    let temp_path = temp_output_path(path)?;
    write_output_file_exclusive(&temp_path, bytes, "temporary signature compiler output")?;
    if let Err(error) = remove_existing_signature_output(path, "signature compiler output") {
        cleanup_temp_output(&temp_path, "temporary signature compiler output").with_context(|| {
            format!(
                "failed to clean up temporary signature compiler output {} after preflight failed: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        cleanup_temp_output(&temp_path, "temporary signature compiler output").with_context(|| {
            format!(
                "failed to clean up temporary signature compiler output {} after activation failed: {error:#}",
                temp_path.display()
            )
        })?;
        return Err(error).with_context(|| {
            format!(
                "failed to activate signature compiler output {}",
                path.display()
            )
        });
    }
    Ok(())
}

fn output_parent(path: &Path) -> Result<&Path> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        bail!(
            "signature compiler output path has no parent directory: {}",
            path.display()
        );
    };
    Ok(parent)
}

fn temp_output_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .context("signature compiler output path has no file name")?
        .to_string_lossy();
    Ok(output_parent(path)?.join(format!(".{file_name}.{}.tmp", Uuid::new_v4())))
}

fn ensure_output_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing to use symbolic link {label} {}", path.display());
    }
    if is_windows_reparse_point(&metadata) {
        bail!("refusing to use reparse point {label} {}", path.display());
    }
    if !metadata.is_dir() {
        bail!("{label} is not a directory: {}", path.display());
    }
    Ok(())
}

fn remove_existing_signature_output(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!(
                    "refusing to replace symbolic link {label} {}",
                    path.display()
                );
            }
            if is_windows_reparse_point(&metadata) {
                bail!(
                    "refusing to replace reparse point {label} {}",
                    path.display()
                );
            }
            if !metadata.is_file() {
                bail!("refusing to replace non-file {label} {}", path.display());
            }
            fs::remove_file(path)
                .with_context(|| format!("failed to remove existing {label} {}", path.display()))?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn write_output_file_exclusive(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {label} {}", path.display()))?;
    output
        .write_all(bytes)
        .with_context(|| format!("failed to write {label} {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("failed to sync {label} {}", path.display()))?;
    Ok(())
}

fn cleanup_temp_output(path: &Path, label: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {label} {}", path.display()))
        }
    }
}

fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn print_help() {
    println!(
        "zentor-signature-compiler --input source.json --output zentor_core.zsig --metadata zentor_core.metadata.json [--version {}]",
        DEFAULT_SIGNATURE_PACK_VERSION
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_compiler_rejects_oversized_source_before_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.json");
        fs::write(&path, "x".repeat(MAX_SIGNATURE_SOURCE_BYTES as usize + 1)).unwrap();

        let error = read_bounded_signature_source(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("signature source"));
        assert!(error.contains("exceeds maximum size"));
    }

    #[test]
    fn signature_compiler_rejects_directory_source_before_parse() {
        let dir = tempfile::tempdir().unwrap();

        let error = read_bounded_signature_source(dir.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("signature source"));
        assert!(error.contains("not a regular file"));
    }

    #[test]
    fn signature_compiler_rejects_directory_output_before_replace() {
        let dir = tempfile::tempdir().unwrap();

        let error =
            write_json(dir.path().to_path_buf(), &serde_json::json!({"ok": true})).unwrap_err();
        let error_chain = format!("{error:#}");

        assert!(error_chain.contains("signature compiler output"));
        assert!(error_chain.contains("non-file"));
    }

    #[test]
    fn signature_compiler_io_is_non_following_and_staged() {
        let source = include_str!("zentor-signature-compiler.rs");
        let read_start = source.find("fn read_bounded_signature_source").unwrap();
        let args_start = source.find("fn parse_signature_compiler_args").unwrap();
        let read_source = &source[read_start..args_start];
        let write_start = source.find("fn write_json").unwrap();
        let help_start = source.find("fn print_help").unwrap();
        let write_source = &source[write_start..help_start];
        let direct_write_pattern = ["fs::", "write(&path"].concat();
        let create_new_pattern = [".create_", "new(true)"].concat();
        let uuid_pattern = ["Uuid::", "new_v4()"].concat();

        assert!(read_source.contains("let metadata = ensure_regular_signature_source(path)?"));
        assert!(read_source.contains("metadata.len() > MAX_SIGNATURE_SOURCE_BYTES"));
        assert!(read_source.contains("fs::symlink_metadata(path)"));
        assert!(read_source.contains("is_windows_reparse_point(&metadata)"));
        assert!(read_source.contains("signature source is not a regular file"));
        assert!(read_source.contains("let mut total = 0_u64"));
        assert!(read_source.contains("checked_add(read as u64)"));
        assert!(read_source.contains("total > MAX_SIGNATURE_SOURCE_BYTES"));
        assert!(read_source.contains("bytes.extend_from_slice(&buffer[..read])"));
        assert!(read_source.contains("String::from_utf8(bytes)"));
        assert!(read_source
            .contains("fn ensure_regular_signature_source(path: &Path) -> Result<fs::Metadata>"));
        assert!(write_source.contains("write_signature_compiler_output"));
        assert!(write_source.contains("ensure_output_directory"));
        assert!(write_source.contains("remove_existing_signature_output"));
        assert!(write_source.contains("write_output_file_exclusive"));
        assert!(write_source.contains("cleanup_temp_output"));
        assert!(write_source.contains("sync_all"));
        assert!(write_source.contains("fs::rename(&temp_path, path)"));
        assert!(write_source.contains(&create_new_pattern));
        assert!(write_source.contains(&uuid_pattern));
        assert!(!write_source.contains(&direct_write_pattern));
    }

    #[test]
    fn signature_compiler_version_default_is_explicit() {
        let source = include_str!("zentor-signature-compiler.rs");
        let main_start = source.find("fn main()").unwrap();
        let read_start = source.find("fn read_bounded_signature_source").unwrap();
        let main_source = &source[main_start..read_start];
        let version_start = source.find("fn parse_signature_compiler_args").unwrap();
        let write_start = source.find("fn write_json").unwrap();
        let version_source = &source[version_start..write_start];

        let configured = vec![
            "--input".to_string(),
            "source.json".to_string(),
            "--output".to_string(),
            "zentor_core.zsig".to_string(),
            "--metadata".to_string(),
            "zentor_core.metadata.json".to_string(),
            "--version".to_string(),
            "2026.6.24".to_string(),
        ];
        let defaulted = vec![
            "--input".to_string(),
            "source.json".to_string(),
            "--output".to_string(),
            "zentor_core.zsig".to_string(),
            "--metadata".to_string(),
            "zentor_core.metadata.json".to_string(),
        ];
        assert_eq!(
            signature_compiler_version(&configured).unwrap(),
            "2026.6.24"
        );
        assert_eq!(
            signature_compiler_version(&defaulted).unwrap(),
            DEFAULT_SIGNATURE_PACK_VERSION
        );
        assert!(main_source.contains("let parsed = parse_signature_compiler_args(&args)?;"));
        assert!(version_source.contains("Some(version) => version"));
        assert!(version_source.contains("None => default_signature_pack_version().to_string()"));
        assert!(!main_source.contains("unwrap_or_else(|| \"0.1.0\".to_string())"));
    }

    #[test]
    fn signature_compiler_cli_rejects_ignored_or_malformed_arguments() {
        let valid = vec![
            "--input".to_string(),
            "source.json".to_string(),
            "--output".to_string(),
            "zentor_core.zsig".to_string(),
            "--metadata".to_string(),
            "zentor_core.metadata.json".to_string(),
        ];
        assert_eq!(
            parse_signature_compiler_args(&valid).unwrap(),
            SignatureCompilerArgs {
                input: "source.json".to_string(),
                output: "zentor_core.zsig".to_string(),
                metadata: "zentor_core.metadata.json".to_string(),
                version: DEFAULT_SIGNATURE_PACK_VERSION.to_string(),
            }
        );

        for args in [
            vec!["--input", "source.json", "--output", "out.zsig"],
            vec!["--input", "--output", "out.zsig", "--metadata", "meta.json"],
            vec![
                "--input",
                "source.json",
                "--output",
                "out.zsig",
                "--metadata",
                "meta.json",
                "--extra",
                "ignored",
            ],
            vec![
                "--input",
                "source.json",
                "--input",
                "second.json",
                "--output",
                "out.zsig",
                "--metadata",
                "meta.json",
            ],
            vec!["--help", "--input", "source.json"],
        ] {
            let values = args.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert!(
                parse_signature_compiler_args(&values).is_err(),
                "unexpectedly accepted {values:?}"
            );
        }

        let source = include_str!("zentor-signature-compiler.rs");
        let parse_start = source.find("fn parse_signature_compiler_args").unwrap();
        let version_start = source.find("fn signature_compiler_version").unwrap();
        let parse_source = &source[parse_start..version_start];
        assert!(parse_source.contains("unexpected signature compiler argument"));
        assert!(parse_source.contains("duplicate signature compiler argument"));
        assert!(parse_source.contains("requires a value before"));
        assert!(
            parse_source.contains("--help\" | \"-h\" => bail!(\"{key} must be used by itself\")")
        );
        let old_permissive_helper = ["fn value_", "after"].concat();
        assert!(!source.contains(&old_permissive_helper));
    }
}
