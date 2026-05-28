pub fn architecture(bytes: &[u8]) -> &'static str {
    match bytes.get(4).copied() {
        Some(1) => "elf32",
        Some(2) => "elf64",
        _ => "unknown",
    }
}
