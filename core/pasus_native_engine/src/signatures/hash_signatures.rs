pub fn matches_exact_hash(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}
