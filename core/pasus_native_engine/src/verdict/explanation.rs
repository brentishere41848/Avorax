pub fn join_reasons(reasons: &[String]) -> String {
    if reasons.is_empty() {
        "No suspicious native-engine evidence was found.".to_string()
    } else {
        reasons.join(" ")
    }
}
