pub fn persistence_score(count: u32) -> i32 {
    (count * 10).min(30) as i32
}
