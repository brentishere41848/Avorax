use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::Context;

use super::env_roots;

pub fn quick_scan_roots() -> anyhow::Result<Vec<PathBuf>> {
    let user_profile = env_roots::absolute_env_path("USERPROFILE")?;
    let temp_dir = env_roots::absolute_env_path("TEMP")?;
    let local_appdata = env_roots::absolute_env_path("LOCALAPPDATA")?;
    let program_data = env_roots::absolute_env_path("PROGRAMDATA")?;
    quick_scan_roots_from_env(
        user_profile.as_deref(),
        temp_dir.as_deref(),
        local_appdata.as_deref(),
        program_data.as_deref(),
    )
}

pub(crate) fn quick_scan_roots_from_env(
    user_profile: Option<&Path>,
    temp_dir: Option<&Path>,
    local_appdata: Option<&Path>,
    program_data: Option<&Path>,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut roots = BTreeSet::new();
    if let Some(profile) = user_profile {
        add_if_present(&mut roots, profile.join("Downloads"))?;
        add_if_present(&mut roots, profile.join("Desktop"))?;
        add_if_present(&mut roots, user_startup_folder(profile))?;
    }
    if let Some(temp) = temp_dir {
        add_if_present(&mut roots, temp.to_path_buf())?;
    }
    if let Some(local_appdata) = local_appdata {
        add_if_present(&mut roots, local_appdata.join("Temp"))?;
        add_if_present(
            &mut roots,
            local_appdata
                .join("Microsoft")
                .join("Edge")
                .join("User Data"),
        )?;
        add_if_present(
            &mut roots,
            local_appdata
                .join("Google")
                .join("Chrome")
                .join("User Data"),
        )?;
        add_if_present(
            &mut roots,
            local_appdata
                .join("Mozilla")
                .join("Firefox")
                .join("Profiles"),
        )?;
    }
    if let Some(program_data) = program_data {
        add_if_present(&mut roots, all_users_startup_folder(program_data))?;
    }
    Ok(roots.into_iter().collect())
}

fn add_if_present(roots: &mut BTreeSet<PathBuf>, path: PathBuf) -> anyhow::Result<()> {
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            roots.insert(path);
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect quick scan root {}", path.display())),
    }
}

fn user_startup_folder(profile: &Path) -> PathBuf {
    profile
        .join("AppData")
        .join("Roaming")
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup")
}

fn all_users_startup_folder(program_data: &Path) -> PathBuf {
    program_data
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::quick_scan_roots_from_env;
    #[cfg(unix)]
    use std::fs;

    #[cfg(unix)]
    #[test]
    fn quick_scan_plan_keeps_broken_symlink_candidates_for_walker() {
        let temp = tempfile::tempdir().expect("tempdir");
        let profile = temp.path().join("User");
        fs::create_dir_all(&profile).expect("profile");
        let downloads = profile.join("Downloads");
        std::os::unix::fs::symlink(temp.path().join("missing-target"), &downloads)
            .expect("symlink");

        let roots = quick_scan_roots_from_env(Some(profile.as_path()), None, None, None).unwrap();

        assert!(roots.iter().any(|path| path == &downloads));
    }

    #[test]
    fn quick_scan_planner_uses_non_following_presence_checks() {
        let source = include_str!("quick_scan_planner.rs");
        let helper_pattern = ["fn add_if_", "present"].concat();
        let symlink_metadata_pattern = ["fs::", "symlink_metadata(&path)"].concat();
        let old_exists_pattern = ["path.", "exists()"].concat();
        let old_wildcard_error_pattern = ["Err(_)", " =>"].concat();

        assert!(source.contains(&helper_pattern));
        assert!(source.contains(&symlink_metadata_pattern));
        assert!(source.contains("ErrorKind::NotFound"));
        assert!(source.contains("unable to inspect quick scan root"));
        assert!(source.contains(
            "fn add_if_present(roots: &mut BTreeSet<PathBuf>, path: PathBuf) -> anyhow::Result<()>"
        ));
        assert!(source.contains("add_if_present(&mut roots"));
        assert!(!source.contains(&old_exists_pattern));
        assert!(!source.contains(&old_wildcard_error_pattern));
    }

    #[test]
    fn quick_scan_planner_validates_environment_roots() {
        let source = include_str!("quick_scan_planner.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(
            production_source.contains("pub fn quick_scan_roots() -> anyhow::Result<Vec<PathBuf>>")
        );
        assert!(production_source.contains("env_roots::absolute_env_path(\"USERPROFILE\")?"));
        assert!(production_source.contains("env_roots::absolute_env_path(\"TEMP\")?"));
        assert!(production_source.contains("env_roots::absolute_env_path(\"LOCALAPPDATA\")?"));
        assert!(production_source.contains("env_roots::absolute_env_path(\"PROGRAMDATA\")?"));
        let old_env_conversion_pattern = [".map(PathBuf::", "from).as_deref()"].concat();
        assert!(!production_source.contains(&old_env_conversion_pattern));
        assert!(!production_source.contains("std::env::var_os(\"USERPROFILE\")"));
    }
}
