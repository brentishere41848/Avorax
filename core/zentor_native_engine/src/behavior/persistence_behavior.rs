pub fn persistence_score(autorun_writes: u32, unsigned_temp_parent: bool) -> u32 {
    autorun_writes
        .saturating_mul(25)
        .saturating_add(u32::from(unsigned_temp_parent).saturating_mul(20))
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_behavior_disabled_persistence_score_saturates() {
        assert_eq!(super::persistence_score(u32::MAX, true), u32::MAX);
    }
}
