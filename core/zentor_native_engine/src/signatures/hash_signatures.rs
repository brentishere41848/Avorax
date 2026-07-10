use anyhow::{bail, Result};

use super::known_bad_hashes::{is_sha256, normalize_hash};

pub const MIN_PARTIAL_HASH_HEX_LEN: usize = 32;

pub fn matches_exact_hash(actual: &str, expected: &str) -> Result<bool> {
    if !is_sha256(actual) {
        bail!("actual SHA-256 value is invalid");
    }
    if !is_sha256(expected) {
        bail!("exact hash signature pattern is not a valid SHA-256 value");
    }
    Ok(normalize_hash(actual) == normalize_hash(expected))
}

pub fn matches_partial_hash(actual: &str, expected_prefix: &str) -> Result<bool> {
    if !is_sha256(actual) {
        bail!("actual SHA-256 value is invalid");
    }
    let prefix = normalize_hash(expected_prefix);
    if prefix.len() < MIN_PARTIAL_HASH_HEX_LEN || prefix.len() > 64 {
        bail!(
            "partial hash signature pattern must use {} to 64 hexadecimal SHA-256 prefix characters",
            MIN_PARTIAL_HASH_HEX_LEN
        );
    }
    if !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("partial hash signature pattern contains non-hex characters");
    }
    Ok(normalize_hash(actual).starts_with(&prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn exact_hash_requires_valid_sha256_values() {
        assert!(matches_exact_hash(HASH, &format!("sha256:{HASH}")).unwrap());
        assert!(matches_exact_hash("abc", "abc").is_err());
        assert!(matches_exact_hash(HASH, "not-a-hash").is_err());
    }

    #[test]
    fn partial_hash_requires_long_hex_prefix() {
        assert!(matches_partial_hash(HASH, &HASH[..MIN_PARTIAL_HASH_HEX_LEN]).unwrap());
        assert!(matches_partial_hash(HASH, &HASH[..MIN_PARTIAL_HASH_HEX_LEN - 1]).is_err());
        assert!(matches_partial_hash(HASH, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }
}
