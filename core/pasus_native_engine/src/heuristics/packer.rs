pub fn packed_likely(entropy_max: f64, high_entropy_sections: u16) -> bool {
    entropy_max > 7.45 || high_entropy_sections > 1
}
