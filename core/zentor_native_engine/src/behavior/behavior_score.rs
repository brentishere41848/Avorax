pub fn high_write_rate(files_modified: u32) -> bool {
    files_modified >= 25
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_behavior_ransomware_high_write_threshold_is_exact() {
        assert!(!super::high_write_rate(24));
        assert!(super::high_write_rate(25));
        assert!(super::high_write_rate(u32::MAX));
    }
}
