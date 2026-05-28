pub fn persistence_change_detected(path: &str) -> bool {
    path.to_ascii_lowercase().contains("startup") || path.to_ascii_lowercase().contains("runonce")
}
