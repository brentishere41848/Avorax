use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub fn quick_scan_roots() -> Vec<PathBuf> {
    quick_scan_roots_from_env(
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .as_deref(),
        std::env::var_os("TEMP").map(PathBuf::from).as_deref(),
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .as_deref(),
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .as_deref(),
    )
}

pub fn quick_scan_roots_from_env(
    user_profile: Option<&Path>,
    temp_dir: Option<&Path>,
    local_appdata: Option<&Path>,
    program_data: Option<&Path>,
) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    if let Some(profile) = user_profile {
        add_if_exists(&mut roots, profile.join("Downloads"));
        add_if_exists(&mut roots, profile.join("Desktop"));
        add_if_exists(&mut roots, user_startup_folder(profile));
    }
    if let Some(temp) = temp_dir {
        add_if_exists(&mut roots, temp.to_path_buf());
    }
    if let Some(local_appdata) = local_appdata {
        add_if_exists(&mut roots, local_appdata.join("Temp"));
        add_if_exists(
            &mut roots,
            local_appdata
                .join("Microsoft")
                .join("Edge")
                .join("User Data"),
        );
        add_if_exists(
            &mut roots,
            local_appdata
                .join("Google")
                .join("Chrome")
                .join("User Data"),
        );
        add_if_exists(
            &mut roots,
            local_appdata
                .join("Mozilla")
                .join("Firefox")
                .join("Profiles"),
        );
    }
    if let Some(program_data) = program_data {
        add_if_exists(&mut roots, all_users_startup_folder(program_data));
    }
    roots.into_iter().collect()
}

fn add_if_exists(roots: &mut BTreeSet<PathBuf>, path: PathBuf) {
    if path.exists() {
        roots.insert(path);
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
