pub fn obfuscation_score(score: u32) -> i32 {
    (score * 8).min(32) as i32
}
