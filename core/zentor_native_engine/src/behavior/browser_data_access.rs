pub fn is_browser_data_indicator(path: &str) -> bool {
    const MAX_OBSERVED_PATH_BYTES: usize = 32 * 1024;

    path.len() <= MAX_OBSERVED_PATH_BYTES
        && ["login data", "cookies.sqlite", "local state"]
            .iter()
            .any(|needle| {
                path.as_bytes()
                    .windows(needle.len())
                    .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
            })
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_behavior_disabled_browser_classifier_is_bounded() {
        assert!(super::is_browser_data_indicator(r"C:\fixture\LOGIN DATA"));
        assert!(!super::is_browser_data_indicator(
            &"x".repeat(32 * 1024 + 1)
        ));
    }
}
