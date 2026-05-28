pub fn has_large_overlay(overlay_size: u64) -> bool {
    overlay_size > 2 * 1024 * 1024
}
