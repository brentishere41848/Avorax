pub fn explain(features: &[String]) -> String {
    if features.is_empty() {
        "Native ML did not find strong feature contributions.".to_string()
    } else {
        format!("Native ML weighted these features: {}.", features.join(", "))
    }
}
