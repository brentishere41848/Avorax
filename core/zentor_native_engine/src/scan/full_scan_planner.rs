use std::path::PathBuf;

use anyhow::Result;

use super::env_roots;

pub fn full_scan_roots() -> Result<Vec<PathBuf>> {
    if let Some(profile) = env_roots::absolute_env_path("USERPROFILE")? {
        return Ok(vec![profile]);
    }
    if let Some(home) = env_roots::absolute_env_path("HOME")? {
        return Ok(vec![home]);
    }
    anyhow::bail!("native engine full-scan root discovery found no safe absolute user root")
}

#[cfg(test)]
mod tests {
    #[test]
    fn full_scan_planner_uses_checked_environment_roots() {
        let source = include_str!("full_scan_planner.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        assert!(production_source.contains("pub fn full_scan_roots() -> Result<Vec<PathBuf>>"));
        assert!(production_source.contains("env_roots::absolute_env_path(\"USERPROFILE\")?"));
        assert!(production_source.contains("env_roots::absolute_env_path(\"HOME\")?"));
        assert!(production_source
            .contains("native engine full-scan root discovery found no safe absolute user root"));
        let old_current_dir_pattern = ["std::env::", "current_dir"].concat();
        let old_dot_root_pattern = ["PathBuf::", "from(\".\")"].concat();
        assert!(!production_source.contains(&old_current_dir_pattern));
        assert!(!production_source.contains("current_dir().unwrap_or_else"));
        assert!(!production_source.contains(&old_dot_root_pattern));
    }
}
