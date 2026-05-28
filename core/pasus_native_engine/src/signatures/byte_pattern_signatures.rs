pub fn contains_hex_pattern(bytes: &[u8], pattern: &str) -> bool {
    let Some(pattern) = decode_hex(pattern) else {
        return false;
    };
    bytes.windows(pattern.len()).any(|window| window == pattern)
}

pub fn contains_masked_hex_pattern(bytes: &[u8], pattern: &str, mask: &str) -> bool {
    let Some(pattern) = decode_hex(pattern) else {
        return false;
    };
    let Some(mask) = decode_hex(mask) else {
        return false;
    };
    if pattern.len() != mask.len() {
        return false;
    }
    bytes.windows(pattern.len()).any(|window| {
        window
            .iter()
            .zip(pattern.iter())
            .zip(mask.iter())
            .all(|((actual, expected), mask)| (*actual & *mask) == (*expected & *mask))
    })
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let clean = value.replace([' ', '_'], "");
    if clean.len() % 2 != 0 {
        return None;
    }
    (0..clean.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&clean[index..index + 2], 16).ok())
        .collect()
}
