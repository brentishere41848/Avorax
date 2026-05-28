pub fn import_score(count: u32) -> i32 {
    (count * 10).min(45) as i32
}
