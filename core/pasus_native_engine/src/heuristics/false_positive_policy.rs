pub fn weak_signal_only(score: u8, strong_signal_count: usize) -> bool {
    score < 35 || strong_signal_count == 0
}
