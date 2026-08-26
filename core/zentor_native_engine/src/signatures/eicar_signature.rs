use std::sync::OnceLock;

use anyhow::Result;

use super::search;

pub const EICAR_TEST_BYTES_LEN: usize = 68;
const EICAR_TEST_BYTES_XOR_A5: [u8; EICAR_TEST_BYTES_LEN] = [
    0xfd, 0x90, 0xea, 0x84, 0xf5, 0x80, 0xe5, 0xe4, 0xf5, 0xfe, 0x91, 0xf9, 0xf5, 0xff, 0xfd, 0x90,
    0x91, 0x8d, 0xf5, 0xfb, 0x8c, 0x92, 0xe6, 0xe6, 0x8c, 0x92, 0xd8, 0x81, 0xe0, 0xec, 0xe6, 0xe4,
    0xf7, 0x88, 0xf6, 0xf1, 0xe4, 0xeb, 0xe1, 0xe4, 0xf7, 0xe1, 0x88, 0xe4, 0xeb, 0xf1, 0xec, 0xf3,
    0xec, 0xf7, 0xf0, 0xf6, 0x88, 0xf1, 0xe0, 0xf6, 0xf1, 0x88, 0xe3, 0xec, 0xe9, 0xe0, 0x84, 0x81,
    0xed, 0x8e, 0xed, 0x8f,
];

pub fn eicar_test_bytes() -> &'static [u8] {
    static DECODED: OnceLock<[u8; EICAR_TEST_BYTES_LEN]> = OnceLock::new();
    DECODED.get_or_init(|| {
        let mut bytes = EICAR_TEST_BYTES_XOR_A5;
        for byte in &mut bytes {
            *byte ^= 0xa5;
        }
        bytes
    })
}

pub fn eicar_test_string() -> String {
    String::from_utf8(eicar_test_bytes().to_vec())
        .expect("decoded EICAR test bytes must remain ASCII")
}

pub fn contains_eicar(bytes: &[u8]) -> bool {
    let mut never_cancel = || Ok(());
    contains_eicar_with_cancellation(bytes, &mut never_cancel)
        .expect("the infallible EICAR search callback cannot fail")
}

pub fn contains_eicar_with_cancellation(
    bytes: &[u8],
    cancellation_checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    search::contains_exact_with_cancellation(bytes, eicar_test_bytes(), cancellation_checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_test_binary_omits_static_eicar_indicator() {
        let executable = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let marker = eicar_test_bytes();
        assert_eq!(marker.len(), EICAR_TEST_BYTES_LEN);
        assert!(!executable
            .windows(marker.len())
            .any(|window| window == marker));
    }
}
