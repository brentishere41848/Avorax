const MIN_SCAN_PARALLELISM: usize = 1;
const MAX_SCAN_PARALLELISM: usize = 8;

pub fn recommended_parallelism() -> usize {
    match std::thread::available_parallelism() {
        Ok(value) => clamp_scan_parallelism(value.get()),
        Err(_error) => minimum_scan_parallelism_when_unavailable(),
    }
}

fn clamp_scan_parallelism(value: usize) -> usize {
    value.clamp(MIN_SCAN_PARALLELISM, MAX_SCAN_PARALLELISM)
}

fn minimum_scan_parallelism_when_unavailable() -> usize {
    MIN_SCAN_PARALLELISM
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_parallelism_bounds_are_explicit() {
        assert_eq!(clamp_scan_parallelism(0), MIN_SCAN_PARALLELISM);
        assert_eq!(clamp_scan_parallelism(1), 1);
        assert_eq!(clamp_scan_parallelism(16), MAX_SCAN_PARALLELISM);
        assert_eq!(
            minimum_scan_parallelism_when_unavailable(),
            MIN_SCAN_PARALLELISM
        );

        let source = include_str!("scan_scheduler.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(production.contains("match std::thread::available_parallelism()"));
        assert!(production.contains("Ok(value) => clamp_scan_parallelism(value.get())"));
        assert!(production.contains("Err(_error) => minimum_scan_parallelism_when_unavailable()"));
        assert!(production.contains("const MIN_SCAN_PARALLELISM: usize = 1"));
        assert!(production.contains("const MAX_SCAN_PARALLELISM: usize = 8"));
        assert!(!production.contains(".unwrap_or(1)"));
        assert!(!production.contains(".clamp(1, 8)"));
    }
}
