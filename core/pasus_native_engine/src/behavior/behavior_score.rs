pub fn high_write_rate(files_modified: u32) -> bool {
    files_modified >= 25
}
