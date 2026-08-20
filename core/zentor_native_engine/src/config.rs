use std::fs;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::Context;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub signature_pack_path: PathBuf,
    pub rule_pack_path: PathBuf,
    pub ml_model_path: PathBuf,
    pub trust_store_path: PathBuf,
    pub quarantine_dir: PathBuf,
    pub compatibility_engines_enabled: bool,
}

impl EngineConfig {
    pub fn from_repo_root(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        if !native_engine_root_is_allowed(&root) {
            anyhow::bail!(
                "native engine root must be an absolute local path: {}",
                root.display()
            );
        }
        let installed_engine = root.join("engine");
        let quarantine_dir = avorax_quarantine_dir()?;
        if installed_engine_dir_is_regular_or_uninspectable(&installed_engine) {
            return Ok(Self {
                signature_pack_path: first_present_path(
                    installed_engine.join("signatures").join("avorax_core.asig"),
                    &[installed_engine.join("signatures").join("zentor_core.zsig")],
                ),
                rule_pack_path: first_present_path(
                    installed_engine.join("rules").join("avorax_core.arule"),
                    &[installed_engine.join("rules").join("zentor_rules.zrule")],
                ),
                ml_model_path: first_present_path(
                    installed_engine
                        .join("ml")
                        .join("avorax_native_model.amodel"),
                    &[installed_engine
                        .join("ml")
                        .join("zentor_native_model.zmodel")],
                ),
                trust_store_path: first_present_path(
                    installed_engine
                        .join("trust")
                        .join("avorax_known_good.atrust"),
                    &[installed_engine
                        .join("trust")
                        .join("zentor_known_good.ztrust")],
                ),
                quarantine_dir,
                compatibility_engines_enabled: false,
            });
        }
        Ok(Self {
            signature_pack_path: root
                .join("assets")
                .join("zentor_native")
                .join("signatures")
                .join("zentor_core.zsig"),
            rule_pack_path: root
                .join("assets")
                .join("zentor_native")
                .join("rules")
                .join("zentor_rules.zrule"),
            ml_model_path: root
                .join("assets")
                .join("zentor_native")
                .join("ml")
                .join("zentor_native_model.zmodel"),
            trust_store_path: root
                .join("assets")
                .join("zentor_native")
                .join("trust")
                .join("zentor_known_good.ztrust"),
            quarantine_dir,
            compatibility_engines_enabled: false,
        })
    }

    pub fn try_default() -> anyhow::Result<Self> {
        let root = native_engine_default_root()?;
        Self::from_repo_root(root)
    }
}

fn native_engine_default_root() -> anyhow::Result<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(engine) = absolute_native_engine_env_path("AVORAX_ENGINE_DIR")? {
        if engine
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("engine"))
        {
            push_native_engine_root(&mut candidates, &engine_dir_parent_or_self(&engine))?;
        } else {
            push_native_engine_root(&mut candidates, &engine)?;
        }
    }
    if let Some(root) = absolute_native_engine_env_path("AVORAX_ENGINE_ROOT")? {
        push_native_engine_root(&mut candidates, &root)?;
    }

    let exe = std::env::current_exe()
        .context("native engine default config discovery failed to resolve current executable")?;
    let parent = exe.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "native engine default config discovery found no parent for {}",
            exe.display()
        )
    })?;
    push_executable_native_engine_roots(&mut candidates, parent)?;

    #[cfg(debug_assertions)]
    {
        let current = std::env::current_dir().context(
            "native engine default config debug discovery failed to read current directory",
        )?;
        push_debug_native_engine_roots(&mut candidates, &current)?;
    }

    let mut checked = Vec::new();
    for candidate in candidates {
        let normalized = canonicalize_native_engine_root(&candidate)?;
        if checked.iter().any(|existing| existing == &normalized) {
            continue;
        }
        checked.push(normalized.clone());
        if native_engine_marker_dir_is_regular(&normalized.join("engine"))?
            || (cfg!(debug_assertions)
                && native_engine_marker_dir_is_regular(
                    &normalized.join("assets").join("zentor_native"),
                )?)
        {
            return Ok(normalized);
        }
    }

    checked.first().cloned().ok_or_else(|| {
        anyhow::anyhow!("native engine default config discovery found no controlled roots")
    })
}

fn absolute_native_engine_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("native engine environment path {name} is empty");
    }
    validate_native_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !native_engine_root_is_allowed(&path) {
        anyhow::bail!("native engine environment path {name} must be an absolute local path");
    }
    Ok(Some(path))
}

fn validate_native_env_root_text(name: &str, text: &str) -> anyhow::Result<()> {
    if text.contains('\0') {
        anyhow::bail!("native environment path {name} contains NUL");
    }
    if native_env_root_has_parent_traversal(text) {
        anyhow::bail!("native environment path {name} must not contain parent traversal");
    }
    Ok(())
}

fn native_env_root_has_parent_traversal(text: &str) -> bool {
    text.replace('\\', "/").split('/').any(|part| part == "..")
}

fn engine_dir_parent_or_self(engine: &Path) -> PathBuf {
    match engine.parent() {
        Some(parent) if parent.as_os_str().is_empty() => parent.to_path_buf(),
        Some(parent) => parent.to_path_buf(),
        None => engine.to_path_buf(),
    }
}

fn push_executable_native_engine_roots(
    candidates: &mut Vec<PathBuf>,
    parent: &Path,
) -> anyhow::Result<()> {
    for candidate in [
        parent.to_path_buf(),
        parent.join(".."),
        parent.join("..").join(".."),
        parent.join("..").join("..").join(".."),
    ] {
        push_native_engine_root(candidates, &candidate)?;
    }
    Ok(())
}

fn push_native_engine_root(candidates: &mut Vec<PathBuf>, root: &Path) -> anyhow::Result<()> {
    if !native_engine_root_is_allowed(root) {
        anyhow::bail!(
            "native engine root {} must be an absolute local path",
            root.display()
        );
    }
    if !candidates.iter().any(|existing| existing == root) {
        candidates.push(root.to_path_buf());
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn push_debug_native_engine_roots(
    candidates: &mut Vec<PathBuf>,
    current: &Path,
) -> anyhow::Result<()> {
    for root in current.ancestors() {
        if is_native_engine_development_root(root)? {
            push_native_engine_root(candidates, root)?;
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn is_native_engine_development_root(root: &Path) -> anyhow::Result<bool> {
    let marker = root
        .join("core")
        .join("zentor_native_engine")
        .join("Cargo.toml");
    native_engine_development_marker_file_present(&marker)
}

#[cfg(debug_assertions)]
fn native_engine_development_marker_file_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "native engine development marker {} is a symbolic link",
                    path.display()
                );
            }
            if is_windows_reparse_point(&metadata) {
                anyhow::bail!(
                    "native engine development marker {} is a reparse point",
                    path.display()
                );
            }
            Ok(metadata.file_type().is_file())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect native engine development marker {}",
                path.display()
            )
        }),
    }
}

fn canonicalize_native_engine_root(candidate: &Path) -> anyhow::Result<PathBuf> {
    match candidate.canonicalize() {
        Ok(normalized) => {
            if !native_engine_root_is_allowed(&normalized) {
                anyhow::bail!(
                    "native engine root {} must resolve to an absolute local path",
                    candidate.display()
                );
            }
            Ok(normalized)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(candidate.to_path_buf()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "native engine default config discovery failed to canonicalize {}",
                candidate.display()
            )
        }),
    }
}

fn native_engine_marker_dir_is_regular(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && !is_windows_reparse_point(&metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect native engine default root marker {}",
                path.display()
            )
        }),
    }
}

#[cfg(windows)]
fn native_engine_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    if !path.is_absolute() {
        return false;
    }
    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn native_engine_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

fn first_present_path(first_candidate: PathBuf, additional_candidates: &[PathBuf]) -> PathBuf {
    for path in std::iter::once(&first_candidate).chain(additional_candidates.iter()) {
        if path_is_present_or_uninspectable(path.as_path()) {
            return path.clone();
        }
    }
    first_declared_asset_candidate(&first_candidate)
}

fn first_declared_asset_candidate(first_candidate: &Path) -> PathBuf {
    first_candidate.to_path_buf()
}

fn path_is_present_or_uninspectable(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

fn installed_engine_dir_is_regular_or_uninspectable(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && !is_windows_reparse_point(&metadata)
        }
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
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

fn avorax_quarantine_dir() -> anyhow::Result<PathBuf> {
    if let Some(path) = absolute_native_quarantine_env_path("AVORAX_QUARANTINE_DIR")? {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        if let Some(program_data) = absolute_native_quarantine_env_path("ProgramData")? {
            return Ok(program_data.join("Avorax").join("Quarantine"));
        }
        if let Some(program_data) = absolute_native_quarantine_env_path("PROGRAMDATA")? {
            return Ok(program_data.join("Avorax").join("Quarantine"));
        }
    }
    if let Some(home) = absolute_native_quarantine_env_path("HOME")? {
        return Ok(home.join(".local/share/avorax/quarantine"));
    }
    anyhow::bail!("native quarantine root is unavailable")
}

fn absolute_native_quarantine_env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let text = value.to_string_lossy().trim().to_string();
    if text.is_empty() {
        anyhow::bail!("native quarantine environment path {name} is empty");
    }
    validate_native_env_root_text(name, &text)?;
    let path = PathBuf::from(text);
    if !native_quarantine_root_is_allowed(&path) {
        anyhow::bail!("native quarantine environment path {name} must be an absolute local path");
    }
    Ok(Some(path))
}

#[cfg(windows)]
fn native_quarantine_root_is_allowed(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    if !path.is_absolute() {
        return false;
    }
    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn native_quarantine_root_is_allowed(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{is_isolated_environment_case, run_isolated_environment_case};
    use std::fs;

    #[test]
    fn first_present_path_defaults_to_first_candidate_when_all_missing() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("avorax_core.asig");
        let second = dir.path().join("zentor_core.zsig");

        assert_eq!(first_present_path(first.clone(), &[second]), first);
    }

    #[test]
    fn first_present_path_uses_first_present_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("avorax_core.asig");
        let second = dir.path().join("zentor_core.zsig");
        fs::write(&second, "{}").unwrap();

        assert_eq!(
            first_present_path(first, std::slice::from_ref(&second)),
            second
        );
    }

    #[test]
    fn first_present_path_fallback_uses_explicit_first_candidate_branch() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("avorax_core.asig");
        let second = dir.path().join("zentor_core.zsig");
        let source = include_str!("config.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        let start = production_source.find("fn first_present_path").unwrap();
        let end = production_source
            .find("fn path_is_present_or_uninspectable")
            .unwrap();
        let candidate_source = &production_source[start..end];

        assert_eq!(first_present_path(first.clone(), &[second]), first);
        assert!(candidate_source.contains("fn first_present_path(first_candidate: PathBuf"));
        assert!(candidate_source
            .contains("std::iter::once(&first_candidate).chain(additional_candidates.iter())"));
        assert!(candidate_source.contains("return path.clone();"));
        assert!(candidate_source.contains("first_declared_asset_candidate(&first_candidate)"));
        assert!(candidate_source.contains("fn first_declared_asset_candidate"));
        assert!(!candidate_source.contains("fn first_asset_candidate"));
        assert!(!candidate_source.contains("native asset candidate list must not be empty"));
        assert!(!candidate_source.contains(".unwrap_or_else(|| first_candidate.clone())"));
    }

    #[cfg(unix)]
    #[test]
    fn first_present_path_treats_broken_symlink_as_present() {
        use std::os::unix::fs as unix_fs;

        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("avorax_core.asig");
        let second = dir.path().join("zentor_core.zsig");
        unix_fs::symlink(dir.path().join("missing-target"), &first).unwrap();
        fs::write(&second, "{}").unwrap();

        assert_eq!(first_present_path(first.clone(), &[second]), first);
    }

    #[test]
    fn installed_engine_dir_uses_regular_directory() {
        let dir = tempfile::tempdir().unwrap();
        let engine = dir.path().join("engine");
        fs::create_dir_all(engine.join("signatures")).unwrap();
        fs::write(engine.join("signatures").join("zentor_core.zsig"), "{}").unwrap();

        let config = EngineConfig::from_repo_root(dir.path()).unwrap();

        assert_eq!(
            config.signature_pack_path,
            engine.join("signatures").join("zentor_core.zsig")
        );
    }

    #[test]
    fn native_engine_root_rejects_relative_repo_root() {
        let error = EngineConfig::from_repo_root(PathBuf::from("relative-native-root"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("native engine root must be an absolute local path"));
    }

    #[test]
    fn native_engine_default_root_rejects_relative_override() {
        const CASE: &str = "engine-root-relative";
        if !is_isolated_environment_case(CASE) {
            run_isolated_environment_case(
                "config::tests::native_engine_default_root_rejects_relative_override",
                CASE,
                |command| {
                    command
                        .env_remove("AVORAX_ENGINE_DIR")
                        .env("AVORAX_ENGINE_ROOT", "relative-native-engine");
                },
            );
            return;
        }

        let result = native_engine_default_root();

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_ENGINE_ROOT"));
        assert!(error.contains("absolute local path"));
    }

    #[test]
    fn native_engine_default_root_rejects_parent_traversal_override() {
        let dir = tempfile::tempdir().unwrap();
        const CASE: &str = "engine-root-parent-traversal";
        if !is_isolated_environment_case(CASE) {
            let override_path = dir.path().join("..");
            run_isolated_environment_case(
                "config::tests::native_engine_default_root_rejects_parent_traversal_override",
                CASE,
                |command| {
                    command
                        .env_remove("AVORAX_ENGINE_DIR")
                        .env("AVORAX_ENGINE_ROOT", override_path);
                },
            );
            return;
        }

        let result = native_engine_default_root();

        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_ENGINE_ROOT"));
        assert!(error.contains("must not contain parent traversal"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_installed_engine_dir_is_not_trusted() {
        use std::os::unix::fs as unix_fs;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("redirected-engine");
        fs::create_dir_all(target.join("signatures")).unwrap();
        fs::write(target.join("signatures").join("avorax_core.asig"), "{}").unwrap();
        unix_fs::symlink(&target, dir.path().join("engine")).unwrap();

        let config = EngineConfig::from_repo_root(dir.path()).unwrap();

        assert_eq!(
            config.signature_pack_path,
            dir.path()
                .join("assets")
                .join("zentor_native")
                .join("signatures")
                .join("zentor_core.zsig")
        );
    }

    #[test]
    fn asset_alias_selection_uses_non_following_presence_check() {
        let source = include_str!("config.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        let legacy_exists_probe = [".find(|path| path", ".exists())"].concat();
        let legacy_installed_engine_probe = ["installed_engine", ".is_dir()"].concat();

        assert!(production_source.contains("fs::symlink_metadata(path)"));
        assert!(production_source.contains("path_is_present_or_uninspectable(path.as_path())"));
        assert!(production_source
            .contains("installed_engine_dir_is_regular_or_uninspectable(&installed_engine)"));
        assert!(!production_source.contains("native asset candidate list must not be empty"));
        assert!(!production_source.contains(".unwrap_or_default()"));
        assert!(!production_source.contains(&legacy_exists_probe));
        assert!(!production_source.contains(&legacy_installed_engine_probe));
    }

    #[test]
    fn installed_engine_dir_uninspectable_errors_select_installed_layout() {
        let source = include_str!("config.rs");
        let old_err_default = ["Err(_)", " => false"].concat();

        assert!(source.contains("fn installed_engine_dir_is_regular_or_uninspectable"));
        assert!(source.contains("Err(error) => error.kind() != std::io::ErrorKind::NotFound"));
        assert!(!source.contains(&old_err_default));
    }

    #[test]
    fn default_config_uses_controlled_roots() {
        let source = include_str!("config.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        let old_current_dir_fallback = [
            "native engine default config discovery failed",
            " to read current directory",
        ]
        .concat();
        let old_hardcoded_program_files =
            ["PathBuf::from(r\"C:\\", "Program Files\\Avorax\")"].concat();
        let old_canonicalize_fallback = ["Err(_)", " => candidate.to_path_buf()"].concat();

        assert!(production_source.contains("pub fn try_default() -> anyhow::Result<Self>"));
        assert!(production_source
            .contains("fn native_engine_default_root() -> anyhow::Result<PathBuf>"));
        assert!(
            production_source.contains("absolute_native_engine_env_path(\"AVORAX_ENGINE_DIR\")?")
        );
        assert!(
            production_source.contains("absolute_native_engine_env_path(\"AVORAX_ENGINE_ROOT\")?")
        );
        assert!(production_source.contains("failed to resolve current executable"));
        assert!(production_source.contains("push_executable_native_engine_roots"));
        assert!(production_source.contains("#[cfg(debug_assertions)]"));
        assert!(production_source.contains("is_native_engine_development_root(root)?"));
        assert!(production_source
            .contains("native engine default config discovery found no controlled roots"));
        assert!(!production_source.contains("impl Default for EngineConfig"));
        assert!(!production_source.contains(&old_current_dir_fallback));
        assert!(!production_source.contains(&old_hardcoded_program_files));
        assert!(!production_source.contains(&old_canonicalize_fallback));
        let old_current_dir_unwrap = ["current_dir()", ".unwrap_or_else"].concat();
        assert!(!production_source.contains(&old_current_dir_unwrap));
        assert!(!production_source.contains("PathBuf::from(\".\")"));
    }

    #[test]
    fn native_quarantine_root_rejects_relative_override() {
        const CASE: &str = "quarantine-root-relative";
        if !is_isolated_environment_case(CASE) {
            run_isolated_environment_case(
                "config::tests::native_quarantine_root_rejects_relative_override",
                CASE,
                |command| {
                    command.env("AVORAX_QUARANTINE_DIR", "relative-native-quarantine");
                },
            );
            return;
        }

        let result = avorax_quarantine_dir();
        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_QUARANTINE_DIR must be an absolute local path"));
    }

    #[test]
    fn native_quarantine_root_rejects_parent_traversal_override() {
        let dir = tempfile::tempdir().unwrap();
        const CASE: &str = "quarantine-root-parent-traversal";
        if !is_isolated_environment_case(CASE) {
            let override_path = dir.path().join("..");
            run_isolated_environment_case(
                "config::tests::native_quarantine_root_rejects_parent_traversal_override",
                CASE,
                |command| {
                    command.env("AVORAX_QUARANTINE_DIR", override_path);
                },
            );
            return;
        }

        let result = avorax_quarantine_dir();
        let error = result.unwrap_err().to_string();
        assert!(error.contains("AVORAX_QUARANTINE_DIR"));
        assert!(error.contains("must not contain parent traversal"));
    }

    #[test]
    fn native_quarantine_root_has_no_temp_fallback() {
        let keys = [
            "AVORAX_QUARANTINE_DIR",
            "ProgramData",
            "PROGRAMDATA",
            "HOME",
        ];
        const CASE: &str = "quarantine-root-unavailable";
        if !is_isolated_environment_case(CASE) {
            run_isolated_environment_case(
                "config::tests::native_quarantine_root_has_no_temp_fallback",
                CASE,
                |command| {
                    for key in keys {
                        command.env_remove(key);
                    }
                },
            );
            return;
        }

        let result = avorax_quarantine_dir();
        let source = include_str!("config.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        let start = production_source.find("fn avorax_quarantine_dir").unwrap();
        let root_source = &production_source[start..];

        let error = result.unwrap_err().to_string();
        assert!(error.contains("native quarantine root is unavailable"));
        assert!(production_source
            .contains("pub fn from_repo_root(root: impl Into<PathBuf>) -> anyhow::Result<Self>"));
        assert!(root_source.contains("fn avorax_quarantine_dir() -> anyhow::Result<PathBuf>"));
        assert!(root_source.contains("fn absolute_native_quarantine_env_path("));
        assert!(
            root_source.contains("absolute_native_quarantine_env_path(\"AVORAX_QUARANTINE_DIR\")?")
        );
        assert!(root_source.contains("absolute_native_quarantine_env_path(\"HOME\")?"));
        assert!(root_source.contains("native_quarantine_root_is_allowed(&path)"));
        assert!(root_source.contains("native quarantine root is unavailable"));
        assert!(!root_source.contains("std::env::temp_dir().join(\"avorax-native-quarantine\")"));
    }
}
