pub fn contains_ascii(bytes: &[u8], needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    lower.contains(&needle.to_ascii_lowercase())
}

pub fn contains_utf16(bytes: &[u8], needle: &str) -> bool {
    let encoded = needle
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    !encoded.is_empty() && bytes.windows(encoded.len()).any(|window| window == encoded)
}
