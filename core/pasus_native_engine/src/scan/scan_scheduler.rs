pub fn recommended_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get().clamp(1, 8))
        .unwrap_or(1)
}
