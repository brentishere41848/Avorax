pub fn persistence_score(autorun_writes: u32, unsigned_temp_parent: bool) -> u32 {
    autorun_writes.saturating_mul(25) + u32::from(unsigned_temp_parent) * 20
}
