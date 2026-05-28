pub fn rename_burst_score(files_renamed: u32) -> i32 {
    if files_renamed >= 20 {
        85
    } else {
        (files_renamed * 3).min(45) as i32
    }
}
