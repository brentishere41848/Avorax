pub fn persistence_change_detected(path: &str) -> bool {
    const MAX_OBSERVED_PATH_BYTES: usize = 32 * 1024;

    path.len() <= MAX_OBSERVED_PATH_BYTES
        && ["startup", "runonce"].iter().any(|needle| {
            path.as_bytes()
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_behavior_disabled_persistence_path_classifier_is_bounded() {
        assert!(super::persistence_change_detected(
            r"C:\Users\fixture\Startup\entry.lnk"
        ));
        assert!(!super::persistence_change_detected(
            &"x".repeat(32 * 1024 + 1)
        ));
    }
}
