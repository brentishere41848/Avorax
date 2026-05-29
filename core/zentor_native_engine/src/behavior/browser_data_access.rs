pub fn is_browser_data_indicator(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("login data")
        || lower.contains("cookies.sqlite")
        || lower.contains("local state")
}
